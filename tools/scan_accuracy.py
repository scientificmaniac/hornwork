#!/usr/bin/env python3
"""扫描模块 CVE 匹配准确率评测（DoD-1）：构造可人工复核的标注样本并计算混淆矩阵。

用法（测试主机，读同一个 hornwork.db）：
    sudo /opt/hornwork-venv/bin/python tools/scan_accuracy.py --build --limit 20 \
         --out /opt/hornwork/reports/scan/labels.csv
    sudo /opt/hornwork-venv/bin/python tools/scan_accuracy.py --eval \
         --labels /opt/hornwork/reports/scan/labels.csv \
         --out-json /opt/hornwork/reports/scan/accuracy.json

样本口径（每条都可回查 NVD 的 configurations）：
- **正样本**：在 ``cve_cache`` 里取"有明确版本边界"的行，构造一个落在区间内的版本
  （``version_start_incl`` 本身或 ``cpe_version`` 精确版本），expected=1；
- **负样本**：取区间上界（exclusive）本身或区间下界之前的版本，expected=0；
- 生成后由人工抽查 20 条（脚本会打印每条对应的 cve/cpe/区间），确认后再 eval。
- 评测只统计 matcher 对该 ``cve_id`` 是否命中，不把"同一组件其它 CVE"算错。

指标：TP/FP/FN/TN、准确率 (TP+TN)/N、精确率 TP/(TP+FP)、召回率 TP/(TP+FN)。
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hornwork.config import load_config  # noqa: E402
from hornwork.scan.cve import matcher  # noqa: E402
from hornwork.scan.store import init_schema  # noqa: E402
from hornwork.store import open_store  # noqa: E402

FIELDS = ["sample_id", "cve_id", "comp_norm", "version", "cpe_prefix", "expected",
          "rule", "interval", "note"]


def _cpe_prefix(cpe23: str) -> str:
    parts = str(cpe23 or "").split(":")
    if len(parts) < 5:
        return ""
    return ":".join(parts[:5]) + ":"


def _comp_from_cpe(cpe23: str, store) -> str:
    """用 cve_component_map 反查 comp_norm；查不到时用 CPE 的 product 作为 comp_norm。"""
    try:
        rows = store.query(
            "SELECT comp_norm FROM cve_component_map WHERE cpe23=?", (_cpe_prefix(cpe23),)
        )
        if rows:
            return str(rows[0]["comp_norm"])
    except Exception:  # noqa: BLE001
        pass
    parts = str(cpe23 or "").split(":")
    return parts[4] if len(parts) > 4 else ""


def build(store, limit: int) -> list[dict]:
    """从 cve_cache 里挑有明确边界的行，生成正/负样本各一半。"""
    rows = store.query(
        "SELECT cve_id, cpe23, cpe_version, version_start_incl, version_start_excl,"
        " version_end_incl, version_end_excl FROM cve_cache"
        " WHERE (version_end_excl IS NOT NULL AND version_end_excl<>'')"
        "    OR (version_start_incl IS NOT NULL AND version_start_incl<>'')"
        "    OR (cpe_version IS NOT NULL AND cpe_version<>''"
        "        AND cpe_version NOT IN ('*','-'))"
        " ORDER BY cve_id DESC LIMIT 4000"
    )
    positives: list[dict] = []
    negatives: list[dict] = []
    seen: set[tuple] = set()
    for row in rows:
        cve = str(row["cve_id"])
        prefix = _cpe_prefix(row["cpe23"])
        comp = _comp_from_cpe(row["cpe23"], store)
        if not cve or not prefix or not comp:
            continue
        key = (cve, comp)
        if key in seen:
            continue
        start_incl = str(row["version_start_incl"] or "").strip()
        end_excl = str(row["version_end_excl"] or "").strip()
        end_incl = str(row["version_end_incl"] or "").strip()
        exact = str(row["cpe_version"] or "").strip()
        interval = {
            "start_incl": start_incl, "end_incl": end_incl, "end_excl": end_excl,
            "exact": exact,
        }
        if start_incl:
            positives.append({
                "cve_id": cve, "comp_norm": comp, "cpe_prefix": prefix,
                "version": start_incl, "expected": 1, "rule": "range",
                "interval": json.dumps(interval, ensure_ascii=False),
                "note": "取区间下界（含），应命中",
            })
            seen.add(key)
        elif exact:
            positives.append({
                "cve_id": cve, "comp_norm": comp, "cpe_prefix": prefix,
                "version": exact, "expected": 1, "rule": "exact",
                "interval": json.dumps(interval, ensure_ascii=False),
                "note": "CPE 精确版本，应命中",
            })
            seen.add(key)
        if end_excl:
            negatives.append({
                "cve_id": cve, "comp_norm": comp, "cpe_prefix": prefix,
                "version": end_excl, "expected": 0, "rule": "range-end-excl",
                "interval": json.dumps(interval, ensure_ascii=False),
                "note": "取区间上界（不含），不应命中",
            })
        elif end_incl and end_incl != start_incl:
            negatives.append({
                "cve_id": cve, "comp_norm": comp, "cpe_prefix": prefix,
                "version": end_incl, "expected": 1, "rule": "range-end-incl",
                "interval": json.dumps(interval, ensure_ascii=False),
                "note": "取区间上界（含），应命中",
            })
        if len(positives) + len(negatives) >= limit * 2:
            break

    half = max(1, limit // 2)
    samples = positives[:half] + negatives[: max(0, limit - half)]
    for index, item in enumerate(samples, start=1):
        item["sample_id"] = f"S{index:02d}"
    return samples


def evaluate(store, cfg: dict, labels: list[dict]) -> dict:
    confusion = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
    details: list[dict] = []
    for item in labels:
        fact = {
            "asset_id": "accuracy-probe",
            "comp_norm": item["comp_norm"],
            "version": item["version"],
            "cpe": (item.get("cpe_prefix") or "") + item["version"],
            "source": "nmap",
            "distro": None,
        }
        try:
            result = matcher.match_facts(store, cfg, [fact])
            hit_ids = {str(m.get("cve_id")) for m in (result.get("matched") or [])}
        except Exception as exc:  # noqa: BLE001
            hit_ids = set()
            details.append({"sample_id": item["sample_id"], "error": str(exc)})
            continue
        actual = 1 if item["cve_id"] in hit_ids else 0
        expected = int(item["expected"])
        if expected and actual:
            confusion["TP"] += 1
            verdict = "TP"
        elif expected and not actual:
            confusion["FN"] += 1
            verdict = "FN"
        elif not expected and actual:
            confusion["FP"] += 1
            verdict = "FP"
        else:
            confusion["TN"] += 1
            verdict = "TN"
        matched = [m for m in (result.get("matched") or []) if str(m.get("cve_id")) == item["cve_id"]]
        details.append({
            "sample_id": item["sample_id"], "cve_id": item["cve_id"],
            "comp_norm": item["comp_norm"], "version": item["version"],
            "expected": expected, "actual": actual, "verdict": verdict,
            "confidence": (matched[0].get("confidence") if matched else None),
            "rule": item.get("rule"), "interval": item.get("interval"),
            "note": item.get("note"),
        })
    total = sum(confusion.values())
    accuracy = round((confusion["TP"] + confusion["TN"]) / total, 4) if total else 0.0
    precision = round(confusion["TP"] / (confusion["TP"] + confusion["FP"]), 4) \
        if (confusion["TP"] + confusion["FP"]) else 0.0
    recall = round(confusion["TP"] / (confusion["TP"] + confusion["FN"]), 4) \
        if (confusion["TP"] + confusion["FN"]) else 0.0
    return {
        "samples": total, "confusion": confusion, "accuracy": accuracy,
        "precision": precision, "recall": recall, "details": details,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="扫描模块 CVE 匹配准确率评测")
    parser.add_argument("--build", action="store_true", help="生成标注样本 CSV")
    parser.add_argument("--eval", action="store_true", help="按标注样本评测")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--out", default="labels.csv")
    parser.add_argument("--labels", default="")
    parser.add_argument("--out-json", default="accuracy.json")
    parser.add_argument("--config", default="/opt/hornwork/config.toml")
    args = parser.parse_args(argv)
    cfg = load_config(args.config)
    store = open_store(cfg)
    init_schema(store)

    if args.build:
        samples = build(store, args.limit)
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=FIELDS)
            writer.writeheader()
            for item in samples:
                writer.writerow({key: item.get(key, "") for key in FIELDS})
        print(f"已生成 {len(samples)} 条标注样本：{out}")
        for item in samples:
            print(f"  {item['sample_id']} {item['cve_id']:<18} {item['comp_norm']:<12}"
                  f" v={item['version']:<14} expected={item['expected']} {item['note']}")
        return 0

    if args.eval:
        path = Path(args.labels or args.out)
        with path.open("r", encoding="utf-8", newline="") as fh:
            labels = list(csv.DictReader(fh))
        report = evaluate(store, cfg, labels)
        out = Path(args.out_json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps({k: report[k] for k in
                          ("samples", "confusion", "accuracy", "precision", "recall")},
                         ensure_ascii=False, indent=2))
        print(f"明细：{out}")
        for item in report["details"]:
            print(f"  {item.get('sample_id')} {item.get('cve_id')} expected={item.get('expected')}"
                  f" actual={item.get('actual')} -> {item.get('verdict')}"
                  f" conf={item.get('confidence')}")
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
