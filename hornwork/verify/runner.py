"""验证执行器：按顺序跑模拟脚本，取时间窗，判定并产出 JSON/Markdown 报告。

用例矩阵（TC-01..TC-10 + TC-N1）。执行模式：
- execute=True ：真的用 `bash <script> --run` 跑脚本（工作目录固定为仓库根，脚本里可用相对路径
                 找 hornwork/tools/inject_demo.c），每例记录 t0、等待 settle_sec 后查库判定；
- execute=False：不跑脚本，只用数据库里已有的告警做窗口判定（无 root 演示 / 开发机自测）。

失败、超时、脚本缺失、脚本主动 SKIP 一律标 inconclusive，不计入 TPR/FPR。
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from .. import schema
from ..config import cfg_get
from ..log import get_logger
from .judge import judge_case
from .metrics import compute_metrics

log = get_logger("verify.runner")

# 仓库根目录（hornwork/）：subprocess 的工作目录，也是脚本相对路径的基准
REPO_ROOT = Path(__file__).resolve().parents[2]
# 本包内置脚本目录
PACKAGE_SIM_DIR = Path(__file__).resolve().parent / "simulate"
# 脚本主动跳过时输出的标记（如 "TC-09 SKIP: 缺少 gcc"）
_SKIP_RE = re.compile(r"\bSKIP\b")


def _now() -> str:
    """当前 UTC 时间（独立函数便于测试替换时钟）。"""
    return schema.utc_now()


#  的 11 个用例（技术编号为 ATT&CK，rule_ids 是规则线索，可随规则库调整）
BASELINE_CASES: list[dict] = [
    {
        "case_id": "TC-01",
        "name": "Unix Shell 命令执行",
        "technique": "T1059.004",
        "expected": "alert_present",
        "rule_ids": [],
        "script": "T1059.004.sh",
    },
    {
        "case_id": "TC-02",
        "name": "本地 HTTP 下载 EICAR 样本",
        "technique": "T1105",
        "expected": "alert_present",
        "rule_ids": [],
        "script": "T1105.sh",
    },
    {
        "case_id": "TC-03",
        "name": "创建用户级 systemd 服务",
        "technique": "T1543.002",
        "expected": "alert_present",
        "rule_ids": [],
        "script": "T1543.002.sh",
    },
    {
        "case_id": "TC-04",
        "name": "写入 cron 定时任务",
        "technique": "T1053.003",
        "expected": "alert_present",
        "rule_ids": [],
        "script": "T1053.003.sh",
    },
    {
        "case_id": "TC-05",
        "name": "创建本地账号",
        "technique": "T1136.001",
        "expected": "alert_present",
        "rule_ids": [],
        "script": "T1136.001.sh",
    },
    {
        "case_id": "TC-06",
        "name": "复制 /etc/shadow",
        "technique": "T1003.008",
        "expected": "alert_present",
        "rule_ids": [],
        "script": "T1003.008.sh",
    },
    {
        "case_id": "TC-07",
        "name": "C2 心跳外联（情报域名）",
        "technique": "T1071.001",
        "expected": "alert_present",
        # 任一命中即 TP：N-0103（DNS 查询名命中 IOC 域名）/ N-0106（心跳式外联）
        "rule_ids": ["N-0103", "N-0106"],
        "script": "T1071.001.sh",
    },
    {
        "case_id": "TC-08",
        "name": "本地端口扫描",
        "technique": "T1046",
        "expected": "alert_present",
        "rule_ids": ["N-0101", "N-0102"],
        "script": "T1046.sh",
    },
    {
        "case_id": "TC-09",
        "name": "PTRACE 注入演示",
        "technique": "T1055.008",
        "expected": "alert_present",
        "rule_ids": ["M-0101"],
        "script": "T1055.008.sh",
        # 脚本注入成功后由 runner 通过控制面触发两次内存扫描：第一次建行为基线，
        # 1s 后第二次带 snapshot 触发 A+B 判定（条件 B = 10s 内新连接/线程+5），再睡 settle 判定告警
        "post_ctl": {
            "method": "mem.scan",
            "pid_file": "hornwork-tc09.pid",
            "double_scan": True,
            "snapshot": True,
            "interval_sec": 1,
        },
    },
    {
        "case_id": "TC-10",
        "name": "LD_PRELOAD 劫持",
        "technique": "T1574.006",
        "expected": "alert_present",
        "rule_ids": [],
        "script": "T1574.006.sh",
    },
    {
        "case_id": "TC-N1",
        "name": "正常基线操作（阴性）",
        "technique": None,
        "expected": "no_alert",
        "rule_ids": [],
        "script": "N-baseline.sh",
    },
]

SUITE_BASELINE = "baseline"


class VerifyRunner:
    """验证执行器。ctl_call(method, params) 可空，用于向 daemon 取运行状态。"""

    def __init__(self, store, cfg: dict, ctl_call=None):
        self.store = store
        self.cfg = cfg or {}
        self.ctl_call = ctl_call if callable(ctl_call) else None
        self.repo_root = REPO_ROOT
        self.simulate_dir = self._resolve_simulate_dir()
        self.report_dir = self._resolve_report_dir()

    # ------------------------------------------------------------------ 目录
    def _resolve_simulate_dir(self) -> Path:
        """脚本目录：配置优先，空/不存在时退回本包 simulate/。"""
        configured = str(cfg_get(self.cfg, "verify.simulate_dir", "") or "").strip()
        if configured:
            path = Path(os.path.expanduser(configured))
            if path.is_dir():
                return path
            log.warn("配置的模拟脚本目录不存在，改用内置目录", path=str(path))
        return PACKAGE_SIM_DIR

    def _resolve_report_dir(self) -> Path:
        """报告目录：优先配置，创建失败时退回仓库根 reports/（不依赖系统临时目录）。"""
        configured = str(cfg_get(self.cfg, "verify.report_dir", "") or "").strip()
        candidates = []
        if configured:
            candidates.append(Path(os.path.expanduser(configured)))
        candidates.append(self.repo_root / "reports")
        for path in candidates:
            try:
                path.mkdir(parents=True, exist_ok=True)
                return path
            except OSError as exc:
                log.warn("报告目录不可写，尝试下一个候选", path=str(path), error=str(exc))
        # 兜底：当前工作目录下的 reports（最后一道保险，仍然不用临时目录）
        fallback = Path.cwd() / "reports"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback

    # ------------------------------------------------------------------ 套件
    def suites(self) -> dict:
        """返回内置套件元数据（供 CLI / Web / 报告展示）。"""
        cases = [dict(case) for case in BASELINE_CASES]
        techniques = []
        for case in cases:
            tech = case.get("technique")
            if tech and tech not in techniques:
                techniques.append(tech)
        return {
            SUITE_BASELINE: {
                "name": SUITE_BASELINE,
                "description": "：10 条攻击模拟 + 1 条阴性基线",
                "case_count": len(cases),
                "techniques": techniques,
                "cases": cases,
            }
        }

    # ------------------------------------------------------------------ 执行
    def run(self, suite: str = SUITE_BASELINE, window_sec: int | None = None, execute: bool = True) -> dict:
        """跑一套用例并落盘报告。

        返回（契约第 6 节）：
        {"run_id","cases":[...],"metrics":{...},"report_path","md_path"}
        """
        suite_def = self.suites().get(str(suite))
        if suite_def is None:
            raise ValueError(f"unknown verify suite: {suite}")
        window = int(window_sec if window_sec is not None else cfg_get(self.cfg, "verify.window_sec", 60))
        settle = float(cfg_get(self.cfg, "verify.settle_sec", 3) or 0)
        run_id = "run-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        started_at = _now()
        daemon = self._ctl_status()

        results: list[dict] = []
        for case in suite_def["cases"]:
            results.append(self._run_case(dict(case), window, settle, bool(execute)))
        finished_at = _now()
        metrics = compute_metrics(results)

        report = {
            "run_id": run_id,
            "suite": suite,
            "suite_name": suite_def.get("name"),
            "started_at": started_at,
            "finished_at": finished_at,
            "host": schema.host_info(self.cfg),
            "execute": bool(execute),
            "window_sec": window,
            "settle_sec": settle,
            "simulate_dir": str(self.simulate_dir),
            "repo_root": str(self.repo_root),
            "daemon": daemon,
            "cases": results,
            "metrics": metrics,
        }
        json_path, md_path = self._write_reports(run_id, report)
        report["report_path"] = str(json_path)
        report["md_path"] = str(md_path)
        # 报告路径回填到用例 payload 后统一写 validation 表（/api/validate 可直接取路径）
        for item in results:
            self._save_validation(run_id, item, window, json_path, md_path)

        log.info(
            "验证套件完成",
            run_id=run_id,
            suite=suite,
            execute=bool(execute),
            verdicts={k: metrics[k] for k in ("TP", "TN", "FP", "FN", "inconclusive")},
        )
        return {
            "run_id": run_id,
            "cases": results,
            "metrics": metrics,
            "report_path": str(json_path),
            "md_path": str(md_path),
        }

    def _run_case(self, case: dict, window: int, settle: float, execute: bool) -> dict:
        """执行单个用例并判定；脚本异常/缺失/跳过统一标 inconclusive。"""
        case_id = str(case.get("case_id") or "unknown")
        script = self.simulate_dir / str(case.get("script") or "")
        item: dict = {
            "case_id": case_id,
            "name": case.get("name"),
            "technique": case.get("technique"),
            "expected": case.get("expected"),
            "observed": "unknown",
            "verdict": "inconclusive",
            "mttd_sec": None,
            "alerts": [],
            "alert_count": 0,
            "t0": None,
            "t1": None,
            "window_sec": window,
            "script": str(script),
            "executed": False,
            "returncode": None,
            "skipped": False,
            "error": None,
            "stdout_tail": "",
            "stderr_tail": "",
        }
        t0 = _now()
        item["t0"] = t0

        execute_error = None
        if execute:
            execute_error = self._execute_script(script, item, case)
            # 脚本成功且用例声明了 post_ctl：走控制面做后续动作（TC-09 的内存扫描）
            if execute_error is None and case.get("post_ctl"):
                self._run_post_ctl(case.get("post_ctl") or {}, item)
        if execute and settle > 0:
            time.sleep(settle)

        judged = judge_case(self.store, case, t0, window)
        item.update(
            {
                "observed": judged.get("observed", "unknown"),
                "verdict": judged.get("verdict", "inconclusive"),
                "mttd_sec": judged.get("mttd_sec"),
                "alerts": judged.get("alerts") or [],
            }
        )
        item["alert_count"] = len(item["alerts"])
        item["t1"] = _now()
        if execute_error:
            item["error"] = execute_error
            # 脚本失败/超时/跳过 → inconclusive：观测值保留但判定不可信
            item["verdict"] = "inconclusive"
            if case.get("post_ctl"):
                # 超时/被杀时 EXIT trap 可能没执行，兜底清理脚本留下的目标进程与 pid 文件
                self._cleanup_orphan(case.get("post_ctl") or {})
        return item

    def _execute_script(self, script: Path, item: dict, case: dict | None = None) -> str | None:
        """用 bash 执行模拟脚本；返回错误描述（None 表示正常执行）。"""
        if not script.is_file():
            item["error"] = f"脚本不存在：{script}"
            log.warn("模拟脚本缺失", case_id=item.get("case_id"), script=str(script))
            return item["error"]
        cmd = ["bash", str(script), "--run"]
        item["executed"] = True
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(self.repo_root),
                capture_output=True,
                text=True,
                timeout=max(30, int(item["window_sec"]) + 60),
                check=False,
                env=self._child_env(case or {}),
            )
        except FileNotFoundError:
            item["error"] = "未找到 bash，无法执行模拟脚本"
            return item["error"]
        except subprocess.TimeoutExpired as exc:
            item["error"] = f"脚本执行超时：{exc}"
            return item["error"]
        except OSError as exc:
            item["error"] = f"脚本执行失败：{exc}"
            return item["error"]

        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        item["returncode"] = int(proc.returncode)
        item["stdout_tail"] = stdout[-2000:]
        item["stderr_tail"] = stderr[-1000:]
        combined = stdout + "\n" + stderr
        if _SKIP_RE.search(combined):
            item["skipped"] = True
            item["error"] = "脚本主动跳过：" + self._first_line(combined, _SKIP_RE)
            return item["error"]
        if proc.returncode != 0:
            item["error"] = f"脚本返回码 {proc.returncode}：" + self._first_line(stderr, None)
            return item["error"]
        return None

    def _child_env(self, case: dict) -> dict:
        """脚本子进程环境：标记模拟运行；TC-09 需保留目标进程给 runner 做内存扫描。"""
        env = dict(os.environ)
        env["HORNWORK_SIMULATE"] = "1"
        if case.get("post_ctl") and self.ctl_call is not None:
            # 脚本注入后不自杀，把目标进程与 pid 文件交给 runner，扫描完由 _run_post_ctl 清理
            env["HORNWORK_TC09_KEEP"] = "1"
        return env

    # ------------------------------------------------------------------ post_ctl
    def _run_post_ctl(self, spec: dict, item: dict) -> None:
        """脚本成功后的控制面动作（当前用于 TC-09 的 mem.scan A+B 判定）。

        spec: {"method":"mem.scan","pid_file":"hornwork-tc09.pid",
               "double_scan":True,"snapshot":True,"interval_sec":1}
        - 单次模式：直接调一次（可选 snapshot）；
        - 双次模式：第一次建行为基线（连接/线程 mark），间隔 interval_sec 后第二次带 snapshot
          触发"10s 内新连接"条件 B，第二次结果作为 post_ctl 结果。
        结果写入 item["post_ctl"]，不影响脚本执行状态的判定口径。
        """
        state: dict = {
            "method": spec.get("method"),
            "ok": False,
            "skipped": False,
            "pid": None,
            "result": None,
            "baseline": None,
            "interval_sec": None,
            "error": None,
        }
        item["post_ctl"] = state
        if self.ctl_call is None:
            state["skipped"] = True
            state["error"] = "ctl_call 不可用，跳过控制面动作"
            log.warn("post_ctl 跳过：ctl_call 为空", case_id=item.get("case_id"))
            return
        pid_file_name = str(spec.get("pid_file") or "").strip()
        if not pid_file_name:
            state["error"] = "post_ctl 缺少 pid_file"
            return
        tmp_dir = Path(os.environ.get("HORNWORK_TMP", "/tmp"))
        pid_path = tmp_dir / pid_file_name
        pid = self._read_pid_file(pid_path)
        if not pid:
            state["error"] = f"pid 文件不存在或内容非法：{pid_path}"
            log.warn("post_ctl 找不到目标进程 pid", path=str(pid_path))
            return
        state["pid"] = pid
        method = str(spec.get("method") or "mem.scan")

        if spec.get("double_scan"):
            interval = float(spec.get("interval_sec", 1) or 0)
            state["interval_sec"] = interval
            baseline = self._scan_via_ctl(method, pid, {})
            state["baseline"] = baseline["result"]
            if baseline["error"]:
                log.warn("post_ctl 基线扫描失败", method=method, pid=pid, error=baseline["error"])
            if interval > 0:
                time.sleep(interval)
            extra = {"snapshot": True} if spec.get("snapshot") else {}
            second = self._scan_via_ctl(method, pid, extra)
            state["ok"] = second["ok"]
            state["result"] = second["result"]
            if second["error"]:
                state["error"] = second["error"]
        else:
            extra = {"snapshot": True} if spec.get("snapshot") else {}
            single = self._scan_via_ctl(method, pid, extra)
            state["ok"] = single["ok"]
            state["result"] = single["result"]
            if single["error"]:
                state["error"] = single["error"]

        self._cleanup_kept_target(pid, pid_path)
        log.info("post_ctl 完成", method=method, pid=pid, ok=state["ok"], double=bool(spec.get("double_scan")))

    def _scan_via_ctl(self, method: str, pid: int, extra: dict) -> dict:
        """调用一次 mem.scan 并归一化返回：{"ok","result","error"}。"""
        params = {"pid": pid}
        params.update(extra or {})
        try:
            raw = self.ctl_call(method, params)
        except Exception as exc:  # noqa: BLE001 - 控制面失败按记录处理
            return {"ok": False, "result": None, "error": f"ctl_call({method}) 异常：{exc}"}
        if isinstance(raw, dict) and "result" in raw:
            ok = bool(raw.get("ok", True))
            return {
                "ok": ok,
                "result": self._compact_mem_result(raw.get("result")),
                "error": None if ok else str(raw.get("error") or "ctl 返回失败")[:300],
            }
        return {"ok": True, "result": self._compact_mem_result(raw), "error": None}

    @staticmethod
    def _read_pid_file(path: Path) -> int | None:
        try:
            text = path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return None
        for token in text.splitlines():
            token = token.strip()
            if token.isdigit() and int(token) > 0:
                return int(token)
        return None

    @staticmethod
    def _compact_mem_result(result) -> dict:
        """内存扫描结果瘦身：报告保留判定与少量命中，避免 JSON 过大。"""
        if not isinstance(result, dict):
            return {"raw": str(result)[:500]}
        hits = result.get("hits")
        compact = {
            "pid": result.get("pid"),
            "verdict": result.get("verdict"),
            "score": result.get("score"),
            "region_count": len(result.get("regions") or []) if isinstance(result.get("regions"), list) else None,
            "hit_count": len(hits) if isinstance(hits, list) else None,
            "hits": hits[:10] if isinstance(hits, list) else None,
            "snapshot_dir": result.get("snapshot_dir"),
        }
        return {key: value for key, value in compact.items() if value is not None}

    @staticmethod
    def _cleanup_kept_target(pid: int, pid_path: Path) -> None:
        """清理 KEEP 模式下留给 runner 的目标进程与 pid 文件。"""
        if os.name == "posix":
            try:
                os.kill(pid, 15)  # SIGTERM：只结束本脚本自己启动的无害测试进程
            except (ProcessLookupError, PermissionError, OSError, OverflowError):
                pass
        try:
            pid_path.unlink()
        except OSError:
            pass

    def _cleanup_orphan(self, spec: dict) -> None:
        """脚本异常退出时的兜底清理（读 pid 文件 → 结束目标进程 → 删文件）。"""
        pid_file_name = str(spec.get("pid_file") or "").strip()
        if not pid_file_name:
            return
        pid_path = Path(os.environ.get("HORNWORK_TMP", "/tmp")) / pid_file_name
        pid = self._read_pid_file(pid_path)
        if pid:
            log.warn("脚本异常退出，清理遗留目标进程", pid=pid, path=str(pid_path))
            self._cleanup_kept_target(pid, pid_path)

    @staticmethod
    def _first_line(text: str, pattern: re.Pattern | None) -> str:
        for line in (text or "").splitlines():
            if pattern is None:
                if line.strip():
                    return line.strip()[:300]
            elif pattern.search(line):
                return line.strip()[:300]
        return ""

    # ------------------------------------------------------------------ 报告
    def _write_reports(self, run_id: str, report: dict) -> tuple[Path, Path]:
        """写 JSON + Markdown 报告，文件名带 run_id。"""
        json_path = self.report_dir / f"{run_id}.json"
        md_path = self.report_dir / f"{run_id}.md"
        try:
            json_path.write_text(
                json.dumps(report, ensure_ascii=False, indent=2, default=str),
                encoding="utf-8",
            )
        except OSError as exc:
            log.error("JSON 报告写入失败", path=str(json_path), error=str(exc))
        try:
            md_path.write_text(self._render_markdown(report), encoding="utf-8")
        except OSError as exc:
            log.error("Markdown 报告写入失败", path=str(md_path), error=str(exc))
        return json_path, md_path

    def _render_markdown(self, report: dict) -> str:
        """生成中文 Markdown 摘要（表格：指标 + 用例明细）。"""
        metrics = report.get("metrics") or {}
        host = report.get("host") or {}
        lines = [
            f"# Hornwork 验证报告 {report.get('run_id')}",
            "",
            "| 项 | 值 |",
            "|---|---|",
            f"| 主机 | {host.get('hostname') or host.get('host_id') or '-'} |",
            f"| 套件 | {report.get('suite')} |",
            f"| 开始时间 | {report.get('started_at')} |",
            f"| 结束时间 | {report.get('finished_at')} |",
            f"| 执行模式 | {'真实执行脚本' if report.get('execute') else '仅 DB 判定（未执行脚本）'} |",
            f"| 判定窗口 | {report.get('window_sec')} s |",
            f"| 脚本目录 | {report.get('simulate_dir')} |",
            "",
            "## 指标",
            "",
            "| 指标 | 值 | 说明 |",
            "|---|---|---|",
            f"| TP | {metrics.get('TP', 0)} | 应告警且已告警 |",
            f"| FN | {metrics.get('FN', 0)} | 应告警但漏报 |",
            f"| FP | {metrics.get('FP', 0)} | 不应告警却告警 |",
            f"| TN | {metrics.get('TN', 0)} | 不应告警且未告警 |",
            f"| inconclusive | {metrics.get('inconclusive', 0)} | 脚本失败/跳过，不计入比率 |",
            f"| TPR | {self._pct(metrics.get('tpr'))} | TP/(TP+FN) |",
            f"| FPR | {self._pct(metrics.get('fpr'))} | FP/(FP+TN) |",
            f"| MTTD | {self._fmt_sec(metrics.get('mttd_sec'))} | TP 首个告警时延均值 |",
            f"| 覆盖率 | {self._pct(metrics.get('coverage'))} | 命中技术数/用例技术数 |",
            "",
            "## 用例明细",
            "",
            "| 用例 | 技术 | 期望 | 观测 | 判定 | MTTD(s) | 告警数 | 脚本返回码 | 备注 |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
        for case in report.get("cases") or []:
            lines.append(
                "| {cid} | {tech} | {exp} | {obs} | {verdict} | {mttd} | {n} | {rc} | {note} |".format(
                    cid=case.get("case_id"),
                    tech=case.get("technique") or "-",
                    exp=case.get("expected"),
                    obs=case.get("observed"),
                    verdict=case.get("verdict"),
                    mttd="-" if case.get("mttd_sec") is None else case.get("mttd_sec"),
                    n=case.get("alert_count", 0),
                    rc="-" if case.get("returncode") is None else case.get("returncode"),
                    note=(case.get("error") or "").replace("|", "/")[:120] or "-",
                )
            )
        lines.extend(
            [
                "",
                "## 说明",
                "",
                "- 判定窗口为 `[t0, t0+window]`，t0 为脚本启动前的采样时刻；",
                "- 脚本返回码非 0、超时、缺失或输出 `SKIP` 标记时记为 inconclusive，不计入 TPR/FPR；",
                '- 技术覆盖率只统计「至少出现一次 TP」的技术；',
                "- 完整告警摘要见同名 JSON 报告的 `cases[].alerts`。",
                "",
            ]
        )
        return "\n".join(lines)

    @staticmethod
    def _pct(value) -> str:
        if value is None:
            return "N/A"
        try:
            return f"{float(value) * 100:.1f}%"
        except (TypeError, ValueError):
            return "N/A"

    @staticmethod
    def _fmt_sec(value) -> str:
        if value is None:
            return "N/A"
        try:
            return f"{float(value):.2f} s"
        except (TypeError, ValueError):
            return "N/A"

    # ------------------------------------------------------------------ 落库与 ctl
    def _save_validation(self, run_id: str, item: dict, window: int, json_path: Path, md_path: Path) -> None:
        """每例结果写 validation 表（异常只告警不中断）。"""
        try:
            self.store.insert_validation(
                {
                    "run_id": run_id,
                    "case_id": item.get("case_id"),
                    "technique": item.get("technique"),
                    "expected": item.get("expected"),
                    "observed": item.get("observed"),
                    "verdict": item.get("verdict"),
                    "mttd_sec": item.get("mttd_sec"),
                    "payload": {
                        "name": item.get("name"),
                        "t0": item.get("t0"),
                        "t1": item.get("t1"),
                        "window_sec": window,
                        "script": item.get("script"),
                        "executed": item.get("executed"),
                        "returncode": item.get("returncode"),
                        "skipped": item.get("skipped"),
                        "error": item.get("error"),
                        "alert_count": item.get("alert_count"),
                        "alerts": item.get("alerts"),
                        "post_ctl": item.get("post_ctl"),
                        "report_path": str(json_path),
                        "md_path": str(md_path),
                    },
                }
            )
        except Exception as exc:  # noqa: BLE001 - 单例落库失败不影响整套验证
            log.warn("validation 落库失败", case_id=item.get("case_id"), error=str(exc))

    def _ctl_status(self):
        """可选的控制面状态：ctl_call 返回 {"ok":...,"result":...} 时取 result。"""
        if self.ctl_call is None:
            return None
        try:
            raw = self.ctl_call("status", {})
        except Exception as exc:  # noqa: BLE001 - 控制面不可用不影响验证
            log.warn("ctl_call(status) 失败", error=str(exc))
            return {"ok": False, "error": str(exc)}
        if isinstance(raw, dict) and "result" in raw:
            if "ok" in raw and not raw.get("ok"):
                return {"ok": False, "error": raw.get("error") or raw.get("detail")}
            return raw.get("result")
        return raw
