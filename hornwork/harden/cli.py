"""hardenctl：加固模块命令行（plan/check/apply/verify/rollback/confirm/drill/report/asset）。

设计：与 hornworkctl 解耦成独立入口（`hardenctl`），同时由 hornworkctl harden 子命令转发，
避免与其它模块并行开发时改同一个 argparse 大文件。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import core, crypto, executor, items as items_mod, plan as plan_mod, report as report_mod, verify as verify_mod


def _print_json(data: Any) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2, default=str))


def _table(rows: list[dict[str, Any]], columns: list[tuple[str, str]]) -> None:
    if not rows:
        print("（无数据）")
        return
    widths = {key: max(len(title), 6) for key, title in columns}
    for row in rows:
        for key, _title in columns:
            widths[key] = max(widths[key], len(str(row.get(key, ""))[:70]))
    print("  ".join(title.ljust(widths[key]) for key, title in columns))
    print("  ".join("-" * widths[key] for key, _ in columns))
    for row in rows:
        print("  ".join(str(row.get(key, ""))[:70].ljust(widths[key]) for key, _ in columns))


def _load_cfg() -> dict | None:
    try:
        from ..config import load_config

        for candidate in ("/opt/hornwork/config.toml", "config.toml"):
            if Path(candidate).is_file():
                return load_config(candidate)
    except Exception:  # noqa: BLE001
        pass
    return None


# ---------------------------------------------------------------- plan
def cmd_plan(args: argparse.Namespace, cfg: dict | None) -> int:
    items = items_mod.load_items()
    snapshot = {}
    if args.snapshot:
        print("[plan] 采加固前快照（Lynis 审计约 30~90 秒）…", file=sys.stderr)
        pre = verify_mod.snapshot(cfg, tag=f"pre-{args.asset}", lynis=True)
        snapshot = {"tag": pre["tag"], "lynis_index": (pre.get("lynis") or {}).get("hardening_index"), "captured_at": pre["captured_at"]}
    plan = plan_mod.build_plan(items, role=args.role, asset=args.asset, cfg=cfg, snapshot=snapshot)
    path = plan_mod.save_plan(plan, cfg)
    ok, msg = plan_mod.verify_plan_integrity(plan)
    data = {
        "plan_id": plan["plan_id"],
        "path": str(path),
        "asset": plan["asset_id"],
        "role": plan["role"],
        "applicable": plan["counts"]["applicable"],
        "excluded": plan["counts"]["excluded"],
        "high_risk": plan["counts"]["high_risk"],
        "batches": plan["batches"],
        "plan_sha256": plan["plan_sha256"],
        "integrity": msg,
        "snapshot": snapshot,
    }
    if args.json:
        _print_json({**data, "plan": plan})
    else:
        print(f"计划 {plan['plan_id']} 已生成：{path}")
        print(f"资产/角色：{plan['asset_id']}/{plan['role']}　适用 {plan['counts']['applicable']} 项　排除 {plan['counts']['excluded']} 项　高危 {plan['counts']['high_risk']} 项")
        print(f"计划哈希：{plan['plan_sha256']}（{msg}）")
        for batch in plan["batches"]:
            print(f"  批次 {batch['n']}（需确认={batch['requires_confirm']}）：{', '.join(batch['items'])}")
        if plan["excluded"]:
            print("排除项：")
            for entry in plan["excluded"]:
                print(f"  - {entry['id']} {entry['title']}：{entry['reason']}")
    return 0 if ok else 2


def cmd_items(args: argparse.Namespace, cfg: dict | None) -> int:
    rows = [
        {
            "id": item.id,
            "category": item.category,
            "title": item.title,
            "risk": item.risk,
            "batch": item.batch,
            "scope_A": item.scope["A"],
            "guard": item.guard_seconds or "",
        }
        for item in items_mod.load_items()
    ]
    if args.json:
        _print_json(rows)
    else:
        _table(rows, [("id", "ID"), ("category", "类"), ("title", "标题"), ("risk", "风险"), ("batch", "批"), ("scope_A", "A机")])
        print(f"共 {len(rows)} 项，基线哈希 {items_mod.items_hash()}")
    return 0


# ---------------------------------------------------------------- check / apply
def cmd_check(args: argparse.Namespace, cfg: dict | None) -> int:
    plan = plan_mod.load_plan(args.plan, cfg)
    ok, msg = plan_mod.verify_plan_integrity(plan)
    if not ok:
        print(f"[拒绝执行] {msg}", file=sys.stderr)
        return 2
    run = executor.apply_plan(plan, mode="check", cfg=cfg)
    return _print_run(run, args.json)


def _printed_result(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "item": result["item_id"],
        "status": result["status"],
        "risk": result["risk"],
        "ms": result["duration_ms"],
        "verify": result["status"],
        "guard": bool(result.get("guard")),
    }


def _print_run(run: dict[str, Any], as_json: bool) -> int:
    if as_json:
        _print_json(run)
    else:
        rows = [
            {"item": r["item_id"], "title": r["title"], "status": r["status"], "risk": r["risk"], "ms": r["duration_ms"]}
            for r in run["results"]
        ]
        _table(rows, [("item", "项"), ("title", "标题"), ("status", "状态"), ("risk", "风险"), ("ms", "耗时ms")])
        print(f"运行 {run['run_id']}　状态 {run['status']}　计数 {executor.counts(run)}　完成率 {executor.completion_rate(run) * 100:.1f}%")
    return 0 if run["status"] in ("succeeded", "running") else 1


def cmd_apply(args: argparse.Namespace, cfg: dict | None) -> int:
    plan = plan_mod.load_plan(args.plan, cfg)
    ok, msg = plan_mod.verify_plan_integrity(plan)
    if not ok:
        print(f"[拒绝执行] 计划哈希被改动：{msg}", file=sys.stderr)
        return 2
    plan_path = core.state(cfg)["plans"] / f"{args.plan}.json"
    sig = Path(str(plan_path) + ".sig")
    if sig.is_file():
        if not crypto.verify_signature(plan_path, sig):
            print("[拒绝执行] 计划验签失败（签名与内容不匹配，视为计划被篡改）", file=sys.stderr)
            return 2
        print("[apply] 计划签名校验通过")
    else:
        print("[apply] 警告：计划未签名（首次执行前先由 H-CR-03 建立签名链）", file=sys.stderr)
    run = executor.apply_plan(
        plan,
        mode="apply",
        batches=args.batch,
        yes_risk=args.yes_risk,
        dry_run=args.dry_run,
        only=args.only,
        cfg=cfg,
    )
    if args.json:
        _print_json(run)
        return _print_run(run, True)
    print(f"运行 {run['run_id']}（plan={run['plan_id']}，mode={run['mode']}）")
    skipped = [r for r in run["results"] if r["status"] == "skipped_unconfirmed"]
    if skipped and not args.yes_risk:
        print(f"[!] {len(skipped)} 个高危项未执行：{', '.join(r['item_id'] for r in skipped)}（加 --yes-risk 后重跑）")
    return _print_run(run, False)


def cmd_confirm(args: argparse.Namespace, cfg: dict | None) -> int:
    run = executor.load_run(args.run, cfg)
    info = executor.confirm(run, args.item or None, cfg)
    if args.json:
        _print_json(info)
    else:
        print(f"确认完成：{info['confirmed'] or '（无可确认项）'}")
    run = executor.load_run(args.run, cfg)
    return 0


# ---------------------------------------------------------------- verify / rollback
def cmd_verify(args: argparse.Namespace, cfg: dict | None) -> int:
    run = executor.load_run(args.run, cfg)
    plan = plan_mod.load_plan(run["plan_id"], cfg)
    pre_tag = (plan.get("snapshot") or {}).get("tag") or f"pre-{plan.get('asset_id', 'A')}"
    before = verify_mod.load_snapshot(pre_tag, cfg)
    if not before:
        print(f"[!] 未找到加固前快照 {pre_tag}，先执行 plan --snapshot", file=sys.stderr)
        before = verify_mod.snapshot(cfg, tag=pre_tag, lynis=True)
    if args.reuse:
        after_tag = run.get("after_snapshot") or f"post-{run['run_id']}"
        after = verify_mod.load_snapshot(after_tag, cfg)
        if not after:
            print(f"[!] 未找到复测快照 {after_tag}，去掉 --reuse 重新采集", file=sys.stderr)
            return 2
    else:
        after = verify_mod.snapshot(cfg, tag=f"post-{run['run_id']}", lynis=True)
        run["after_snapshot"] = after["tag"]
    metrics = verify_mod.compare(before, after)
    run["metrics"] = metrics
    executor.save_run(run, cfg)
    if args.json:
        _print_json(metrics)
        return 0
    _table(
        [{"metric": m["metric"], "before": m["before"], "after": m["after"], "delta": m["delta"], "pass": "—" if m["passed"] is None else ("通过" if m["passed"] else "未达成")} for m in metrics["metrics"]],
        [("metric", "指标"), ("before", "加固前"), ("after", "加固后"), ("delta", "变化"), ("pass", "结论")],
    )
    print(f"前后快照已入库：{before['tag']} → {after['tag']}")
    return 0


def cmd_rollback(args: argparse.Namespace, cfg: dict | None) -> int:
    run = executor.load_run(args.run, cfg)
    executor.rollback_run(run, args.item or None, cfg, actor="guard" if args.auto else "manual")
    if args.json:
        _print_json(run.get("rollback"))
    else:
        rollback = run.get("rollback") or {}
        print(f"回滚：{rollback.get('success')}/{rollback.get('attempted')} 项恢复到加固前状态（actor={rollback.get('actor')}）")
        for entry in rollback.get("items", []):
            print(f"  - {entry['item_id']}：{entry.get('check_after')}")
    return 0


def cmd_drill(args: argparse.Namespace, cfg: dict | None) -> int:
    plan = plan_mod.load_plan(args.plan, cfg)
    by_id = {item.id: item for item in items_mod.load_items()}
    default = ["H-AL-02", "H-PM-04", "H-KR-01", "H-AC-01", "H-PM-01", "H-CR-01"]
    chosen = [item_id for item_id in (args.items.split(",") if args.items else default) if item_id in by_id]
    run = executor.apply_plan(plan, mode="apply", yes_risk=True, only=chosen, cfg=cfg)
    entries = []
    for result in run["results"]:
        item = by_id[result["item_id"]]
        backup = result.get("backup") or {}
        before_hashes = {entry["path"]: entry.get("sha256", "") for entry in backup.get("entries", []) if entry.get("exists")}
        entries.append({"item_id": item.id, "before_sha256": next(iter(before_hashes.values()), ""), "status_at_apply": result["status"]})
    executor.rollback_run(run, chosen, cfg, actor="drill")
    detail = []
    for entry in entries:
        item = by_id[entry["item_id"]]
        backup_record = None
        for result in run["results"]:
            if result["item_id"] == item.id:
                backup_record = result.get("backup")
        after_hash = ""
        if backup_record:
            for record in backup_record.get("entries", []):
                if record.get("exists"):
                    after_hash = core.sha256_file(record["path"])
                else:
                    after_hash = "" if not Path(record["path"]).is_file() else "unexpected_file"
                break
        same = (not after_hash) if entry["before_sha256"] == "" else after_hash == entry["before_sha256"]
        detail.append(
            {
                "item_id": item.id,
                "category": item.category,
                "before_sha256": entry["before_sha256"],
                "after_sha256": after_hash,
                "same": same,
                "status_at_apply": entry["status_at_apply"],
            }
        )
    drill = {"run_id": run["run_id"], "attempted": len(detail), "success": sum(1 for d in detail if d["same"]), "items": detail, "at": core.utc_now()}
    path = core.write_json(core.state(cfg)["root"] / f"drill-{run['run_id']}.json", drill)
    if args.json:
        _print_json(drill)
    else:
        _table(detail, [("item_id", "项"), ("category", "类"), ("same", "恢复一致"), ("status_at_apply", "演练时状态")])
        print(f"回滚演练：{drill['success']}/{drill['attempted']} 通过　文件：{path}")
    return 0


# ---------------------------------------------------------------- report / asset
def cmd_report(args: argparse.Namespace, cfg: dict | None) -> int:
    run = executor.load_run(args.run, cfg)
    plan = plan_mod.load_plan(run["plan_id"], cfg)
    metrics = run.get("metrics")
    second = executor.load_run(args.second_run, cfg) if args.second_run else None
    drill = core.read_json(args.drill) if args.drill else None
    data = report_mod.build(plan, run, metrics, second, drill, cfg)
    formats = tuple(args.format.split(","))
    written = report_mod.write(data, args.out or str(core.state(cfg)["root"] / "reports"), formats)
    if args.json:
        _print_json(data)
    else:
        for path in written:
            print(f"已生成：{path}")
    return 0


def cmd_asset(args: argparse.Namespace, cfg: dict | None) -> int:
    if args.action == "expiring":
        rows = crypto.asset_expiring(args.days)
    else:
        rows = crypto.asset_list()
    rows = [dict(row) for row in rows]
    if args.json:
        _print_json(rows)
    else:
        _table(
            [{"kind": r.get("kind", ""), "path": r.get("path", ""), "not_after": r.get("not_after", ""), "days": r.get("days_left", ""), "note": r.get("note", "")} for r in rows],
            [("kind", "类型"), ("path", "路径"), ("not_after", "到期"), ("days", "剩余天"), ("note", "备注")],
        )
    return 0


def cmd_status(args: argparse.Namespace, cfg: dict | None) -> int:
    paths = core.state(cfg)
    plans = sorted(paths["plans"].glob("pln-*.json"))
    runs = sorted(paths["runs"].glob("run-*.json"))
    data = {
        "items": len(items_mod.load_items()),
        "baseline_sha256": items_mod.items_hash(),
        "plans": [p.stem for p in plans],
        "runs": [r.stem for r in runs],
        "assets": len(crypto.asset_list()),
        "root": str(paths["root"]),
    }
    if args.json:
        _print_json(data)
    else:
        print(f"加固项 {data['items']} 项　基线 {data['baseline_sha256'][:16]}…　台账 {data['assets']} 条")
        print(f"计划：{data['plans'] or '（无）'}")
        print(f"运行：{data['runs'] or '（无）'}")
    return 0


# ---------------------------------------------------------------- argparse
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hardenctl", description="加固模块：加固编排（plan→check→apply→verify→rollback）")
    parser.add_argument("--json", action="store_true", help="JSON 输出")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_plan = sub.add_parser("plan", help="生成资产画像与加固计划")
    p_plan.add_argument("--asset", default="A")
    p_plan.add_argument("--role", default="A", choices=["A", "B", "C"])
    p_plan.add_argument("--snapshot", action="store_true", help="同时采加固前快照（Lynis/TLS/SSH/sysctl）")
    p_plan.set_defaults(func=cmd_plan)

    p_items = sub.add_parser("items", help="列出基线项")
    p_items.set_defaults(func=cmd_items)

    p_check = sub.add_parser("check", help="只读检查计划内各项")
    p_check.add_argument("--plan", required=True)
    p_check.set_defaults(func=cmd_check)

    p_apply = sub.add_parser("apply", help="执行计划（默认 dry-run 之外才改系统）")
    p_apply.add_argument("--plan", required=True)
    p_apply.add_argument("--batch", type=int, action="append", help="只执行指定批次，可重复")
    p_apply.add_argument("--only", action="append", help="只执行指定项 id，可重复")
    p_apply.add_argument("--dry-run", action="store_true")
    p_apply.add_argument("--yes-risk", action="store_true")
    p_apply.set_defaults(func=cmd_apply)

    p_confirm = sub.add_parser("confirm", help="确认高危项变更（停掉定时回滚保险）")
    p_confirm.add_argument("--run", required=True)
    p_confirm.add_argument("--item", action="append")
    p_confirm.set_defaults(func=cmd_confirm)

    p_verify = sub.add_parser("verify", help="加固后复测并生成前后对比")
    p_verify.add_argument("--run", required=True)
    p_verify.add_argument("--reuse", action="store_true", help="复用已有 post 快照重算指标（不再跑 Lynis）")
    p_verify.set_defaults(func=cmd_verify)

    p_rollback = sub.add_parser("rollback", help="按 run 逆序回滚")
    p_rollback.add_argument("--run", required=True)
    p_rollback.add_argument("--item", action="append")
    p_rollback.add_argument("--auto", action="store_true", help="由定时保险触发（审计标记 actor=guard）")
    p_rollback.set_defaults(func=cmd_rollback)

    p_drill = sub.add_parser("drill", help="回滚演练（六类各 1 项：apply→rollback→sha256 对比）")
    p_drill.add_argument("--plan", required=True)
    p_drill.add_argument("--items", help="逗号分隔的项 id，默认六类各 1 项")
    p_drill.set_defaults(func=cmd_drill)

    p_report = sub.add_parser("report", help="生成 Markdown/JSON 报告")
    p_report.add_argument("--run", required=True)
    p_report.add_argument("--second-run", help="第二次运行的 run_id（用于幂等率）")
    p_report.add_argument("--drill", help="回滚演练 JSON 路径")
    p_report.add_argument("--out")
    p_report.add_argument("--format", default="md,json")
    p_report.set_defaults(func=cmd_report)

    p_asset = sub.add_parser("asset", help="密码学资产台账")
    p_asset.add_argument("action", nargs="?", default="list", choices=["list", "expiring"])
    p_asset.add_argument("--days", type=int, default=30)
    p_asset.set_defaults(func=cmd_asset)

    p_status = sub.add_parser("status", help="本模块状态")
    p_status.set_defaults(func=cmd_status)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = _load_cfg()
    try:
        return args.func(args, cfg)
    except FileNotFoundError as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
