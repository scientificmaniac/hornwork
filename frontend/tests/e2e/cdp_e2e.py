"""用 Chrome DevTools Protocol 做控制台端到端测试（仅标准库，无需第三方依赖）。

为什么要自己写 CDP 客户端：Ubuntu 测试机出站网络不可用（npm / pip 均超时），
装不了 Playwright / selenium / websocket-client。CDP 就是 HTTP + WebSocket，
标准库足够驱动真实 Chrome 完成登录、路由跳转、页面渲染与截图。

用法：
    python3 cdp_e2e.py <base_url> <username> <password> <out_dir>
退出码 0 表示全部检查通过。
"""

from __future__ import annotations

import base64
import json
import secrets
import socket
import struct
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


# ---------------------------------------------------------------------------
# 最小 WebSocket 客户端（RFC 6455：客户端只发掩码帧、接收非掩码帧）
# ---------------------------------------------------------------------------
class WebSocket:
    def __init__(self, url: str, timeout: float = 30.0) -> None:
        if not url.startswith("ws://"):
            raise ValueError(f"仅支持 ws://：{url}")
        host_port, _, path = url[len("ws://"):].partition("/")
        host, _, port = host_port.partition(":")
        self.sock = socket.create_connection((host, int(port or 80)), timeout=timeout)
        self.sock.settimeout(timeout)
        key = base64.b64encode(secrets.token_bytes(16)).decode()
        request = (
            f"GET /{path} HTTP/1.1\r\n"
            f"Host: {host_port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(request.encode())
        self._buffer = b""
        header = self._read_until(b"\r\n\r\n")
        if b"101" not in header.split(b"\r\n")[0]:
            raise ConnectionError(f"WebSocket 握手失败：{header[:200]!r}")

    def _read_until(self, marker: bytes) -> bytes:
        while marker not in self._buffer:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("连接已关闭")
            self._buffer += chunk
        head, _, self._buffer = self._buffer.partition(marker)
        return head + marker

    def _read_exact(self, size: int) -> bytes:
        while len(self._buffer) < size:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("连接已关闭")
            self._buffer += chunk
        data, self._buffer = self._buffer[:size], self._buffer[size:]
        return data

    def send(self, text: str) -> None:
        payload = text.encode("utf-8")
        header = bytearray([0x81])
        length = len(payload)
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header += struct.pack(">H", length)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", length)
        mask = secrets.token_bytes(4)
        header += mask
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def recv(self) -> str:
        while True:
            first, second = self._read_exact(2)
            opcode = first & 0x0F
            length = second & 0x7F
            if length == 126:
                length = struct.unpack(">H", self._read_exact(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self._read_exact(8))[0]
            data = self._read_exact(length) if length else b""
            if opcode == 0x8:
                raise ConnectionError("服务端关闭了 WebSocket")
            if opcode == 0x9:  # ping → pong
                self.sock.sendall(b"\x8a\x80" + secrets.token_bytes(4))
                continue
            if opcode in (0x1, 0x2):
                return data.decode("utf-8", "replace")

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class CDP:
    """单页 CDP 会话：命令 + 事件，带超时。"""

    def __init__(self, ws_url: str) -> None:
        self.ws = WebSocket(ws_url)
        self._id = 0

    def call(self, method: str, **params) -> dict:
        self._id += 1
        message_id = self._id
        self.ws.send(json.dumps({"id": message_id, "method": method, "params": params}))
        deadline = time.time() + 60
        while time.time() < deadline:
            message = json.loads(self.ws.recv())
            if message.get("id") == message_id:
                if "error" in message:
                    raise RuntimeError(f"{method} 失败：{message['error']}")
                return message.get("result", {})
        raise TimeoutError(f"{method} 超时")

    def eval(self, expression: str, timeout_sec: int = 30) -> object:
        result = self.call(
            "Runtime.evaluate",
            expression=expression,
            awaitPromise=True,
            returnByValue=True,
            timeout=timeout_sec * 1000,
        )
        if "exceptionDetails" in result:
            raise RuntimeError(f"JS 异常：{result['exceptionDetails']}")
        return result.get("result", {}).get("value")

    def wait_for(self, expression: str, timeout_sec: float = 20.0, interval: float = 0.25):
        """轮询直到 JS 表达式返回真值。"""
        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            try:
                if self.eval(expression):
                    return True
            except RuntimeError:
                pass
            time.sleep(interval)
        return False

    def screenshot(self, path: Path) -> None:
        data = self.call("Page.captureScreenshot", format="png", captureBeyondViewport=True)
        path.write_bytes(base64.b64decode(data["data"]))

    def close(self) -> None:
        self.ws.close()


# ---------------------------------------------------------------------------
# 用例
# ---------------------------------------------------------------------------
class Runner:
    def __init__(self, base: str, user: str, password: str, out: Path) -> None:
        self.base = base.rstrip("/")
        self.user = user
        self.password = password
        self.out = out
        self.results: list[tuple[str, bool, str]] = []

    def check(self, name: str, ok: bool, detail: str = "") -> bool:
        self.results.append((name, bool(ok), detail))
        flag = "PASS" if ok else "FAIL"
        print(f"[{flag}] {name}{(' — ' + detail) if detail else ''}", flush=True)
        return bool(ok)

    def run(self) -> int:
        self.out.mkdir(parents=True, exist_ok=True)
        profile = Path("/tmp/hw-chrome-profile")
        proc = subprocess.Popen(
            [
                "google-chrome",
                "--headless=new",
                "--disable-gpu",
                "--no-sandbox",
                "--no-first-run",
                "--disable-dev-shm-usage",
                "--remote-debugging-port=9222",
                f"--user-data-dir={profile}",
                "--window-size=1440,1000",
                "about:blank",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            self._wait_devtools()
            page_ws = self._page_target()
            cdp = CDP(page_ws)
            try:
                self._scenarios(cdp)
            finally:
                cdp.close()
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()

        failed = [name for name, ok, _ in self.results if not ok]
        print(f"\n合计 {len(self.results)} 项，失败 {len(failed)} 项", flush=True)
        for name in failed:
            print(f"  ✗ {name}", flush=True)
        return 0 if not failed else 1

    def _wait_devtools(self, timeout: float = 40.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with urllib.request.urlopen("http://127.0.0.1:9222/json/version", timeout=1) as resp:
                    json.loads(resp.read().decode())
                    return
            except Exception:  # noqa: BLE001 - 启动期连接失败属预期
                time.sleep(0.3)
        raise TimeoutError("Chrome DevTools 端口未就绪")

    def _page_target(self) -> str:
        with urllib.request.urlopen("http://127.0.0.1:9222/json/list", timeout=5) as resp:
            targets = json.loads(resp.read().decode())
        for target in targets:
            if target.get("type") == "page":
                return target["webSocketDebuggerUrl"]
        raise RuntimeError("没有可用的 page target")

    # ---------------------------------------------------------------- 场景
    def _scenarios(self, cdp: CDP) -> None:
        cdp.call("Page.enable")
        cdp.call("Runtime.enable")
        cdp.call("Log.enable")

        # 1. 打开控制台：未登录应落在 #/login（守卫会附带 ?redirect=）
        cdp.call("Page.navigate", url=f"{self.base}/")
        ok = cdp.wait_for("document.querySelector('#app')?.children.length > 0", 20)
        self.check("SPA 挂载成功（#app 有内容）", ok)
        hash_value = cdp.eval("location.hash")
        self.check(
            "未登录跳转到登录路由",
            str(hash_value).startswith("#/login"),
            f"hash={hash_value}",
        )

        # 2. 资源加载：无 4xx/5xx（用 performance 条目判断）
        failed_assets = cdp.eval(
            "JSON.stringify(performance.getEntriesByType('resource')"
            ".filter(e => e.transferSize === 0 && e.decodedBodySize === 0)"
            ".map(e => e.name).slice(0, 5))"
        )
        self.check("无加载失败的静态资源", failed_assets == "[]", str(failed_assets))

        self.check(
            "登录页渲染出表单",
            bool(cdp.eval("!!document.querySelector('input[autocomplete=\"username\"]')")),
        )
        cdp.screenshot(self.out / "01-login.png")

        # 3. 真实登录
        cdp.eval(
            "(() => {"
            "const inputs = document.querySelectorAll('input');"
            "const user = document.querySelector('input[autocomplete=\"username\"]');"
            "const pass = document.querySelector('input[type=\"password\"]');"
            "const set = (el, val) => {"
            "  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;"
            "  setter.call(el, val);"
            "  el.dispatchEvent(new Event('input', { bubbles: true }));"
            "};"
            "set(user, " + json.dumps(self.user) + ");"
            "set(pass, " + json.dumps(self.password) + ");"
            "return inputs.length;"
            "})()"
        )
        cdp.eval("document.querySelector('.login__submit').click()")
        logged_in = cdp.wait_for("!location.hash.startsWith('#/login')", 25)
        self.check("登录成功后离开登录页", logged_in, f"hash={cdp.eval('location.hash')}")

        token = cdp.eval("sessionStorage.getItem('hornwork.session') || ''")
        self.check("会话令牌写入 sessionStorage", str(token).startswith("s1."), str(token)[:14] + "…")
        # 4. 总览页数据渲染
        cdp.wait_for("document.querySelector('.stat-card__value')?.textContent?.trim().length > 0", 20)
        stat_cards = cdp.eval("document.querySelectorAll('.stat-card').length")
        self.check("总览页统计卡片渲染", int(stat_cards or 0) >= 6, f"{stat_cards} 张")
        domain_items = cdp.eval("document.querySelectorAll('.domain-item').length")
        self.check("功能域入口渲染", int(domain_items or 0) >= 5, f"{domain_items} 个")
        alert_rows = cdp.eval("document.querySelectorAll('.alert-list li').length")
        self.check("总览页展示近 24h 告警", int(alert_rows or 0) >= 1, f"{alert_rows} 条")
        cdp.screenshot(self.out / "02-overview.png")

        # 5. 逐个路由巡检：渲染出错（空白 / 控制台异常）即失败
        routes = [
            ("#/detection/events", "事件流"),
            ("#/detection/alerts", "告警"),
            ("#/detection/rules", "规则"),
            ("#/detection/intel", "情报"),
            ("#/detection/cases", "工单"),
            ("#/detection/validation", "验证"),
            ("#/detection/engines", "引擎贡献"),
            ("#/vuln", "漏洞档案"),
            ("#/scan/overview", "扫描总览"),
            ("#/scan/findings", "问题清单"),
            ("#/scan/diff", "快照对比"),
            ("#/scan/coverage", "覆盖率"),
            ("#/scan/cve", "CVE 库"),
            ("#/scan/reports", "报告"),
            ("#/auth", "身份认证"),
            ("#/harden", "安全加固"),
            ("#/security", "平台安全"),
        ]
        for index, (route, title) in enumerate(routes):
            cdp.eval(f"location.hash = {json.dumps(route)}")
            # 懒加载路由的组件是异步 chunk：必须等标题切换完成，否则会读到上一个页面
            rendered = cdp.wait_for(
                "(() => {"
                "const main = document.querySelector('.layout__content');"
                "const header = document.querySelector('.header__title')?.textContent?.trim();"
                f"if (!main || header !== {json.dumps(title)}) return false;"
                "return main.querySelectorAll('.el-card, .stat-card, .el-empty').length > 0;"
                "})()",
                20,
            )
            header = cdp.eval("document.querySelector('.header__title')?.textContent?.trim() || ''")
            self.check(
                f"路由 {route} 渲染（{title}）",
                rendered and header == title,
                f"标题={header!r}",
            )
            cdp.screenshot(self.out / f"route-{index:02d}-{route.strip('#/').replace('/', '-')}.png")

        # 6. 主题切换：data-theme 与背景色都应随之变化（不假设初始主题，localStorage 会记住上次选择）
        cdp.eval("location.hash = '#/overview'")
        cdp.wait_for(
            "document.querySelector('.header__title')?.textContent?.trim() === '总览'",
            15,
        )
        before_theme = cdp.eval("document.documentElement.dataset.theme || ''")
        before_bg = cdp.eval("getComputedStyle(document.body).backgroundColor")
        cdp.eval(
            "(() => {"
            "const btn = Array.from(document.querySelectorAll('.header__meta button'))"
            ".find(b => ['深色','浅色'].includes(b.textContent.trim()));"
            "if (btn) btn.click();"
            "return !!btn;"
            "})()"
        )
        time.sleep(0.4)
        after_theme = cdp.eval("document.documentElement.dataset.theme || ''")
        after_bg = cdp.eval("getComputedStyle(document.body).backgroundColor")
        self.check(
            "主题切换生效",
            before_theme != after_theme and after_theme in ("dark", "light"),
            f"{before_theme}→{after_theme}",
        )
        self.check(
            "背景色随主题变化（CSS 变量生效）",
            before_bg != after_bg and bool(after_bg),
            f"{before_bg} → {after_bg}",
        )
        if after_theme == "dark":
            cdp.screenshot(self.out / "03-theme-dark.png")
        else:
            cdp.screenshot(self.out / "03-theme-light.png")

        # 7. 会话令牌有效性：清空 storage 之前校验，确认前后端共用同一会话
        token = str(cdp.eval("sessionStorage.getItem('hornwork.session') || ''"))
        self.check("会话令牌为平台会话（s1. 前缀）", token.startswith("s1."), token[:12] + "…")
        session_user = cdp.eval(
            "fetch('/api/auth/session', { headers: { Authorization: 'Bearer ' + "
            "sessionStorage.getItem('hornwork.session') } })"
            ".then(r => r.json()).then(d => d.user?.username || '')"
        )
        self.check("会话可换取当前用户", session_user == self.user, f"user={session_user!r}")

        # 8. 401 失效处理：清掉 token 后触发请求，应回到登录页
        cdp.eval("sessionStorage.removeItem('hornwork.session')")
        cdp.eval("location.hash = '#/detection/alerts'")
        cdp.wait_for("document.querySelector('.header__title')?.textContent?.trim() === '告警'", 15)
        cdp.eval(
            "(() => { const btn = Array.from(document.querySelectorAll('button'))"
            ".find(b => b.textContent.trim() === '刷新'); if (btn) btn.click(); return !!btn; })()"
        )
        back_to_login = cdp.wait_for("location.hash.startsWith('#/login')", 15)
        self.check("会话失效后跳回登录页", back_to_login, f"hash={cdp.eval('location.hash')}")

        # 9. 无 JS 未捕获异常
        errors = cdp.eval(
            "(() => { try { return JSON.stringify(window.__dshErrors || []) } catch { return '[]' } })()"
        )
        self.check("页面未上报未捕获异常", errors in ("[]", "null", None), str(errors))


def main(argv: list[str]) -> int:
    """用法：cdp_e2e.py <base_url> <username> <password> [截图输出目录]"""
    if len(argv) < 4:
        print(__doc__)
        return 2
    base, user, password = argv[1], argv[2], argv[3]
    out = Path(argv[4] if len(argv) > 4 else "/tmp/hw-e2e-shots")
    return Runner(base, user, password, out).run()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
