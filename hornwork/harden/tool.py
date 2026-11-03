"""密码学动作执行器（供 items.yaml 的 apply/verify 与命令行直接调用）。

用法示例：
  python -m hornwork.harden.tool pwhash --check
  python -m hornwork.harden.tool pki --ensure
  python -m hornwork.harden.tool sign --check
  python -m hornwork.harden.tool tls-render
  python -m hornwork.harden.tool tls-probe --protocols
"""

from __future__ import annotations

import argparse
import json
import sys

from . import crypto


def _dump(ok: bool, data: dict, verbose: bool) -> int:
    if verbose or not ok:
        print(json.dumps({"ok": ok, **data}, ensure_ascii=False, indent=2, default=str))
    else:
        print("ok" if ok else "fail")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    raw = list(argv if argv is not None else sys.argv[1:])
    # 允许 --verbose/--json 出现在子命令之后（items.yaml 里写成 `pwhash --check --verbose`）
    globals_first = [token for token in raw if token in ("--verbose", "--json")]
    rest = [token for token in raw if token not in ("--verbose", "--json")]
    argv = globals_first + rest
    parser = argparse.ArgumentParser(prog="hornwork.harden.tool")
    parser.add_argument("--json", action="store_true", default=True, help="JSON 输出（默认）")
    parser.add_argument("--verbose", action="store_true")
    sub = parser.add_subparsers(dest="action", required=True)

    p_pw = sub.add_parser("pwhash")
    p_pw.add_argument("--check", action="store_true")
    p_pw.add_argument("--migrate", action="store_true")

    p_pki = sub.add_parser("pki")
    p_pki.add_argument("--check", action="store_true")
    p_pki.add_argument("--ensure", action="store_true")
    p_pki.add_argument("--force", action="store_true")

    p_sign = sub.add_parser("sign")
    p_sign.add_argument("--check", action="store_true")
    p_sign.add_argument("--ensure", action="store_true")
    p_sign.add_argument("--tamper", action="store_true")

    sub.add_parser("tls-render")

    p_probe = sub.add_parser("tls-probe")
    p_probe.add_argument("--protocols", action="store_true")
    p_probe.add_argument("--ciphers", action="store_true")
    p_probe.add_argument("--hsts", action="store_true")

    p_cert = sub.add_parser("cert-check")

    p_luks = sub.add_parser("luks")
    p_luks.add_argument("--check", action="store_true")
    p_luks.add_argument("--ensure", action="store_true")

    args = parser.parse_args(argv)

    if args.action == "pwhash":
        if args.migrate:
            result = crypto.pwhash_migrate()
            ok = result["status"]["legacy_hashes_remaining"] == 0
            print(json.dumps({"ok": ok, **result}, ensure_ascii=False, indent=2, default=str))
            return 0 if ok else 1
        ok, status = crypto.pwhash_check()
        return _dump(ok, status, args.verbose or True)
    if args.action == "pki":
        if args.ensure:
            result = crypto.pki_ensure(force=args.force)
            ok = bool(result.get("server", {}).get("exists"))
            return _dump(ok, result, True)
        ok, info = crypto.pki_check()
        return _dump(ok, info, args.verbose)
    if args.action == "sign":
        if args.tamper:
            result = crypto.tamper_test()
            ok = result["before_tamper_verify"] and not result["after_tamper_verify"]
            return _dump(ok, result, True)
        if args.ensure:
            result = crypto.sign_ensure()
            ok = all(entry["ok"] for entry in result["signed"])
            return _dump(ok, result, True)
        ok, info = crypto.sign_check()
        return _dump(ok, info, args.verbose)
    if args.action == "tls-render":
        result = crypto.render_tls()
        return _dump(bool(result["nginx_test_ok"] and result["reload_ok"]), result, True)
    if args.action == "tls-probe":
        if args.ciphers:
            ok, info = crypto.tls_probe_ciphers()
        elif args.hsts:
            ok, info = crypto.tls_probe_hsts()
        else:
            ok, info = crypto.tls_probe_protocols()
        return _dump(ok, info, True)
    if args.action == "cert-check":
        ok, info = crypto.cert_check()
        return _dump(ok, info, args.verbose)
    if args.action == "luks":
        if args.ensure:
            result = crypto.luks_ensure()
            ok = crypto.luks_check()[0]
            return _dump(ok, result, True)
        ok, info = crypto.luks_check()
        return _dump(ok, info, args.verbose)
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
