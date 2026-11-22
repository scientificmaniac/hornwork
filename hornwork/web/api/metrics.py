"""Prometheus metrics 渲染 handler。

方法体从 server.py 原样搬迁；通过 self 访问传输层（_send_json/app 等），
由 _Handler 多继承装配。
"""

from __future__ import annotations


from ...verify.metrics import compute_metrics


class MetricsMixin:
    """Prometheus metrics 渲染 handler。"""

    def _h_metrics(self, query: dict[str, str]) -> None:
        store = self.app.store
        counts = store.counts()
        lines = [
            "# HELP hornwork_up 服务在线标记",
            "# TYPE hornwork_up gauge",
            "hornwork_up 1",
        ]
        for key in sorted(counts):
            lines.extend(
                [
                    f"# HELP hornwork_{key} Hornwork 计数项：{key}",
                    f"# TYPE hornwork_{key} gauge",
                    f"hornwork_{key} {int(counts.get(key) or 0)}",
                ]
            )
        status = self.app.status()
        lines.extend(
            [
                "# HELP hornwork_web_requests_total Web 控制台累计请求数",
                "# TYPE hornwork_web_requests_total counter",
                f"hornwork_web_requests_total {int(status.get('requests') or 0)}",
                "# HELP hornwork_web_errors_total Web 控制台累计错误数",
                "# TYPE hornwork_web_errors_total counter",
                f"hornwork_web_errors_total {int(status.get('errors') or 0)}",
            ]
        )
        latest = store.latest_run_id()
        if latest:
            metrics = compute_metrics(store.validation_rows(run_id=latest))
            for name in ("TP", "TN", "FP", "FN", "inconclusive"):
                lines.extend(
                    [
                        f"# HELP hornwork_validation_{name.lower()} 最近一次验证的 {name} 数",
                        f"# TYPE hornwork_validation_{name.lower()} gauge",
                        f"hornwork_validation_{name.lower()} {int(metrics.get(name) or 0)}",
                    ]
                )
            for name in ("tpr", "fpr", "coverage", "mttd_sec"):
                value = metrics.get(name)
                lines.extend(
                    [
                        f"# HELP hornwork_validation_{name} 最近一次验证的 {name}",
                        f"# TYPE hornwork_validation_{name} gauge",
                        f"hornwork_validation_{name} {0 if value is None else float(value)}",
                    ]
                )
        body = ("\n".join(lines) + "\n").encode("utf-8")
        self._send_bytes(200, body, "text/plain; version=0.0.4; charset=utf-8")
