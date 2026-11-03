"""前后对比报告：把“有效/可回滚/可复现”变成一张张能直接进报告的表。"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import core, crypto, executor


def build(
    plan: dict[str, Any],
    run: dict[str, Any],
    metrics: dict[str, Any] | None = None,
    second_run: dict[str, Any] | None = None,
    drill: dict[str, Any] | None = None,
    cfg: dict | None = None,
) -> dict[str, Any]:
    counts = executor.counts(run)
    batch_map = {entry["id"]: entry.get("batch") for entry in plan.get("items", [])}
    results = [{**result, "batch": batch_map.get(result["item_id"], "")} for result in run.get("results", [])]
    data: dict[str, Any] = {
        "generated_at": core.utc_now(),
        "plan": {key: plan.get(key) for key in ("plan_id", "asset_id", "role", "generated_at", "baseline_ref", "plan_sha256", "estimated_minutes", "counts", "scenario")},
        "run": {
            "run_id": run.get("run_id"),
            "status": run.get("status"),
            "operator": run.get("operator"),
            "started_at": run.get("started_at"),
            "finished_at": run.get("finished_at"),
            "counts": counts,
            "completion_rate": executor.completion_rate(run),
            "results": results,
        },
        "idempotency": _idempotency(run, second_run),
        "rollback": run.get("rollback"),
        "drill": drill,
        "metrics": metrics,
        "assets": crypto.asset_list(),
        "excluded": plan.get("excluded", []),
        "batches": plan.get("batches", []),
        "boundaries": boundaries(),
    }
    return data


def _idempotency(first: dict[str, Any], second: dict[str, Any] | None) -> dict[str, Any]:
    first_counts = executor.counts(first)
    data: dict[str, Any] = {
        "first_run": {"run_id": first.get("run_id"), "counts": first_counts},
    }
    if second:
        second_counts = executor.counts(second)
        applied = first_counts.get("verified", 0) + first_counts.get("already_ok", 0)
        data.update(
            {
                "second_run": {"run_id": second.get("run_id"), "counts": second_counts},
                "already_ok_ratio": round(second_counts.get("already_ok", 0) / applied, 4) if applied else 0.0,
                "rule": "同一计划连续执行两次，第二次应全部 already_ok（幂等短路）",
            }
        )
    return data


def boundaries() -> list[dict[str, str]]:
    return [
        {"item": "靶场主机故意不加固", "boundary": "靶场主机是受控弱点样本：仅保留审计/时间同步/证书台账，其余项排除并给理由；证据是 plan.excluded + S0-B 快照"},
        {"item": "第三台主机（Windows）", "boundary": "不做跨平台远程执行；四项检查单 + PowerShell 手工执行，回填 source=manual"},
        {"item": "登录失败锁定（pam_faillock）", "boundary": "改 PAM 主认证栈会与远程管理通道冲突，本模块明确不做；只保留 MaxAuthTries/LoginGraceTime 限速类加固"},
        {"item": "磁盘加密", "boundary": "无第二块虚拟盘；用 256 MB 回环文件演示 LUKS2（Argon2id KDF + 双密钥槽 + 裸设备不可读），不做系统盘全盘加密"},
        {"item": "Lynis 指数目标", "boundary": "加固前指数已为 66（检测模块已做过基础审计/服务收敛），原定 +15 未达成，实测 +6；同期 Lynis 建议项 84→43（-49%），说明改善集中在校验类配置。目标按实测口径修正并如实记录"},
        {"item": "testssl.sh", "boundary": "未安装；TLS 效果由自研 Python ssl 探测器（协议/套件/HSTS 三组断言）测量，测量口径写进 §验证"},
        {"item": "口令哈希迁移范围", "boundary": "演示库 demo_users.db 完成 md5/sha1/sha256→Argon2id 迁移；真实登录路径由认证模块登录成功后调用同一 upgrade() 完成，不在本模块重复实现登录"},
        {"item": "跨主机执行", "boundary": "harden 只在本机（防护主机）执行；对 靶场主机只生成计划与排除清单，不用 SSH 推送加固动作"},
    ]


def to_markdown(data: dict[str, Any]) -> str:
    plan = data["plan"]
    run = data["run"]
    lines: list[str] = []
    add = lines.append
    add("# 加固模块 加固运行报告")
    add("")
    add(f"- 生成时间：{data['generated_at']}　计划：`{plan['plan_id']}`　运行：`{run['run_id']}`")
    add(f"- 资产/角色：{plan['asset_id']} / {plan['role']}　场景：{plan['scenario']}")
    add(f"- 基线哈希：`{plan['baseline_ref']['sha256']}`　计划哈希：`{plan['plan_sha256']}`")
    add("")
    add("## 1. 执行结果")
    add("")
    add("| 项 | 标题 | 风险 | 批次 | 状态 | 耗时(ms) | 安全垫 |")
    add("|---|---|---|---|---|---|---|")
    for result in run["results"]:
        guard_info = result.get("guard") or {}
        guard = "已确认" if guard_info.get("confirmed_at") else ("已布防" if guard_info else "—")
        add(f"| {result['item_id']} | {result['title']} | {result['risk']} | {result.get('batch', '')} | {result['status']} | {result['duration_ms']} | {guard} |")
    counts = run["counts"]
    add("")
    add(f"- 状态计数：{counts}")
    add(f"- **加固项完成率：{run['completion_rate'] * 100:.1f}%**（verified+already_ok / 适用项）")
    add("")
    add("## 2. 幂等与回滚")
    add("")
    idem = data.get("idempotency") or {}
    add(f"- 首次运行：{idem.get('first_run', {})}")
    if idem.get("second_run"):
        add(f"- 二次运行：{idem['second_run']}，already_ok 占比 **{idem.get('already_ok_ratio', 0) * 100:.1f}%**")
    rollback = data.get("rollback") or {}
    if rollback:
        add(f"- 回滚：成功 {rollback.get('success')}/{rollback.get('attempted')}（按 run 逆序，未生效即如实标记）")
        for entry in rollback.get("items", []):
            add(f"  - {entry['item_id']}：{entry.get('check_after')}，动作 {[a.get('restored') for a in entry.get('actions', [])]}")
    drill = data.get("drill") or {}
    if drill.get("items"):
        add(f"- 回滚演练：**{drill.get('success')}/{drill.get('attempted')}**（六类各 1 项，sha256 对比）")
        add("")
        add("| 项 | apply 前 sha256 | 回滚后 sha256 | 一致 |")
        add("|---|---|---|---|")
        for entry in drill["items"]:
            before = entry.get("before_sha256") or "（新建文件）"
            after = entry.get("after_sha256") or "（已删除＝恢复原状）"
            add(f"| {entry['item_id']} | `{before[:16]}` | `{after[:16]}` | {entry.get('same')} |")
    add("")
    add("## 3. 加固前后对比")
    add("")
    metrics = data.get("metrics") or {}
    if metrics.get("metrics"):
        add("| 指标 | 加固前 | 加固后 | 变化 | 目标 | 结论 |")
        add("|---|---|---|---|---|---|")
        for metric in metrics["metrics"]:
            verdict = "—" if metric.get("passed") is None else ("通过" if metric["passed"] else "未达成")
            add(f"| {metric['metric']} | {metric['before']} | {metric['after']} | {metric['delta']} | {metric['target']} | {verdict} |")
        changed = metrics.get("sshd_changed") or {}
        if changed:
            add("")
            add("SSH 生效配置变化：")
            add("")
            add("| 配置项 | 加固前 | 加固后 |")
            add("|---|---|---|")
            for key, value in changed.items():
                add(f"| {key} | `{value['before']}` | `{value['after']}` |")
    else:
        add("（未运行 verify，指标标 N/A）")
    add("")
    add("## 4. 密码学落地台账")
    add("")
    assets = data.get("assets") or []
    if assets:
        add("| 类型 | 路径 | 主题 | 指纹前缀 | 到期 | 剩余天数 | 备注 |")
        add("|---|---|---|---|---|---|---|")
        for asset in assets:
            add(f"| {asset.get('kind')} | `{asset.get('path')}` | {asset.get('subject') or '—'} | `{str(asset.get('fingerprint_sha256', ''))[:16]}` | {asset.get('not_after') or '—'} | {asset.get('days_left', '')} | {asset.get('note')} |")
    else:
        add("（无台账记录）")
    add("")
    add("## 5. 场景适配：排除项与理由")
    add("")
    if data.get("excluded"):
        add("| 项 | 标题 | 不适用理由 |")
        add("|---|---|---|")
        for entry in data["excluded"]:
            add(f"| {entry['id']} | {entry['title']} | {entry['reason']} |")
    else:
        add("（该角色无排除项）")
    add("")
    add("## 6. 主动边界（不做什么）")
    add("")
    add("| 项 | 边界 |")
    add("|---|---|")
    for entry in data.get("boundaries", []):
        add(f"| {entry['item']} | {entry['boundary']} |")
    add("")
    add("## 7. 复现命令")
    add("")
    add("```bash")
    add("# 1) 生成画像与计划（含加固前快照）")
    add(f"sudo hardenctl plan --asset {plan['asset_id']} --role {plan['role']} --snapshot")
    add("# 2) 预演（只读）")
    add(f"sudo hardenctl check --plan {plan['plan_id']}")
    add(f"sudo hardenctl apply --plan {plan['plan_id']} --dry-run")
    add("# 3) 分批执行（高危项需 --yes-risk）")
    add(f"sudo hardenctl apply --plan {plan['plan_id']} --batch 1 --batch 2")
    add(f"sudo hardenctl apply --plan {plan['plan_id']} --batch 3 --yes-risk")
    add(f"sudo hardenctl confirm --run {run['run_id']}")
    add(f"sudo hardenctl apply --plan {plan['plan_id']} --batch 4 --batch 5 --yes-risk")
    add("# 4) 复测与报告")
    add(f"sudo hardenctl verify --run {run['run_id']}")
    add(f"sudo hardenctl report --run {run['run_id']} --out /opt/hornwork/reports")
    add("```")
    return "\n".join(lines) + "\n"


def write(data: dict[str, Any], out_dir: str | Path, formats: tuple[str, ...] = ("md", "json")) -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = data["run"]["run_id"]
    written = []
    if "md" in formats:
        path = out / f"harden-report-{stamp}.md"
        path.write_text(to_markdown(data), encoding="utf-8")
        written.append(path)
    if "json" in formats:
        path = out / f"harden-report-{stamp}.json"
        core.write_json(path, data)
        written.append(path)
    return written
