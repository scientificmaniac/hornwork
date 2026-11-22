"""在 Ubuntu 虚机上启动最小 Hornwork Web 服务（真实后端 + 真实 SQLite）。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from hornwork import schema  # noqa: E402
from hornwork.config import load_config  # noqa: E402
from hornwork.store import Store  # noqa: E402
from hornwork.web import WebServer  # noqa: E402


def seed(store: Store) -> None:
    """灌入可验证的样例数据（幂等：重复启动不会因主键冲突而失败）。

    固定 ID 便于断言，因此写入前先清理同名记录，而不是依赖 INSERT OR IGNORE
    （后者会静默跳过、让“数据没更新”看起来像成功）。
    """
    store.execute("DELETE FROM case_ WHERE case_id='case-e2e-0001'")
    store.execute("DELETE FROM ioc WHERE value='evil.example.com'")

    rule = schema.make_rule("H-0001", "可疑进程执行", "hostrules", level=13, mitre=["T1059.004"])
    alert = schema.new_alert(
        rule,
        ts=schema.utc_now(),
        entity={"host_id": "lab-host"},
        evidence=[{"note": "parent=bash cmdline=/tmp/x.sh", "pid": 4242}],
    )
    store.insert_alert(alert)

    event = schema.new_event(
        "process_create",
        "host",
        "hornwork-test",
        {},
        process={"pid": 4242, "name": "x.sh", "cmdline": "/tmp/x.sh"},
    )
    store.insert_event(event)

    store.insert_case(
        {
            "case_id": "case-e2e-0001",
            "title": "端到端测试工单",
            "severity": "P1",
            "status": "open",
            "dedup_key": "e2e",
            "verdict": "tp",
        }
    )

    store.ioc_upsert({"type": "domain", "value": "evil.example.com", "confidence": 90})
    store.engine_stat_add("yara", files=12, hits=3, malicious=2, cost_ms=140)
    store.engine_stat_add("clamav", files=12, hits=1, malicious=1, cost_ms=320)


def main() -> int:
    cfg = load_config("/tmp/hw-test/config.toml")
    store = Store(Path(cfg["general"]["data_dir"]) / "hornwork.db")
    seed(store)

    server = WebServer(cfg, store)
    server.start()
    status = server.status()
    print(json.dumps({"port": status["port"], "auth": status["auth"]}, ensure_ascii=False), flush=True)
    try:
        # 阻塞直到收到信号
        import signal

        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        signal.pause()
    finally:
        server.stop()
        store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
