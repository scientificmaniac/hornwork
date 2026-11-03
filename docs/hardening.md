# Hardening orchestration

> Code: `hornwork/harden/` (baseline `items.yaml`, planning, idempotent executor, rollback, verification, cryptography)
> CLI: `hardenctl` (installed by [scripts/setup_harden.sh](../scripts/setup_harden.sh), equivalent to `python -m hornwork.harden`)
> See also: [interfaces.md](interfaces.md) · [runbook.md](runbook.md) · [scanning.md](scanning.md) · [authentication.md](authentication.md)

Hardening here is a **reproducible pipeline, not a checklist**:

- the **baseline is data** (`items.yaml` is the single source of truth);
- the **plan is a compiled artefact** (`plan.json` with batches, explicit exclusion reasons,
  a sha256 digest and an Ed25519 signature);
- **execution is idempotent** (`check → backup → apply → verify`, per-item failure isolation,
  a timed rollback safety net for high-risk items);
- **cryptography is a first-class deliverable** (Argon2id, TLS 1.2/1.3, an internal CA,
  Ed25519 signatures, LUKS2);
- **the effect is proven by objective measurement** (Lynis, a purpose-built TLS prober,
  `sshd -T`, `sysctl`, file hashes, `luksDump`), before and after, on the same host.

The loop closes with the rest of the platform: the scanning subsystem finds configuration
weaknesses → `plan`/`apply` fix them → `verify` re-measures → hardening actions land on the
platform's auditd timeline. Asset profiles that must **not** be hardened (a deliberately weak
sample, a host with a manual-only checklist) are excluded **at planning time**, with written
reasons, so "why didn't this host get item X" always has an answer in `excluded[]`.

> **Reference benchmark** — Ubuntu 26.04 LTS / Python 3.14, 4 vCPU / 8 GB. Numbers are
> measurements on that host and are indicative, not service-level commitments.

---

## 1. Where it fits

```text
scanning findings ──► hardenctl plan ──► hardenctl apply ──► hardenctl verify ──► auditd timeline
      (config weakness)     (compiled plan)     (idempotent, reversible)   (before/after numbers)
```

## 2. Environment adaptation

| Item | Design baseline | Reference environment | Adaptation |
|---|---|---|---|
| OS | Ubuntu 24.04 | Ubuntu 26.04.1, kernel 7.0.0 | every baseline item uses compatible commands; `sshd -T`, `findmnt`, `sysctl` paths unchanged |
| Python | 3.12 | 3.14 in a dedicated venv | standard library + PyYAML + argon2-cffi only |
| TLS validation | testssl.sh | not installed (GPL tool, needs network clone) | built-in Python `ssl` prober (protocol / cipher / HSTS assertions) + `nmap ssl-enum-ciphers` as a third-party cross-check + `openssl s_client` |
| OpenSSL | 3.0 | 3.5.5 (client has TLS 1.0/1.1 disabled) | the server-side protocol floor is established from the nginx configuration plus `nmap` enumeration; the measurement method is stated in the run output |
| TLS service | nginx | nginx 1.28.3; port 80 already used by another service | the managed endpoints bind only `127.0.0.1:8080` (redirect) and `127.0.0.1:8443` (TLS); the default nginx site is disabled |
| Disk encryption | second 8 GB virtual disk | single disk, no `/dev/sdb` | LUKS2 on a **256 MB loopback file** (Argon2id KDF, two key slots); full system-disk encryption is a stated boundary |
| Host scoring | Lynis | Lynis 3.1.6 | available as-is; `lynis audit system --quick` before and after |
| Signing | minisign | not installed | **Ed25519 through OpenSSL 3** (`pkeyutl -sign -rawin`); the verification checkpoint is unchanged |
| Weak sample host | separate machine | single-host lab environment | the "profile B" role produces a plan and an exclusion list but **is never executed** (`plan-B.json` is the artefact); "profile C" is a manual checklist |

## 3. Architecture and execution model

```text
items.yaml (baseline, single source of truth)
      │ load + validate (unique id / risk / scope / refs)
      ▼
profile (OS / kernel / ports / toolchain / UFW / auditd) ──► plan.py ──► plan.json
                                                     │  batches 1..5 / excluded[] / sha256 / signature
                                                     ▼
hardenctl apply ──► executor, three stages: check (read-only) → [backup targets → apply → verify]
                         │
                         │                         ├─ high-risk items: systemd-run timed rollback net
                         │                         └─ failure: restore this item's backup, mark isolated_failure,
                         │                            continue with the next item
                         ▼
                  verify: before/after snapshot comparison (Lynis / SSH / sysctl / TLS / hashes / LUKS)
                         ▼
                  run output: result table + before/after metrics + asset ledger + rollback drill + boundaries
```

Seven engineering rules make the pipeline trustworthy:

1. **The plan is a compiled artefact.** The executor reads only `harden_plan.json`; it never
   reads the baseline. "Why wasn't item X applied to this host" is always answerable from
   `excluded[]`.
2. **The three stages are never merged.** A successful `apply` does not mean the change took
   effect; `verify` re-checks from an external viewpoint (`sshd -T`, a real TLS handshake,
   `sysctl -n`, `luksDump`).
3. **Idempotent by construction.** If `check` already passes, the item short-circuits to
   `already_ok`; `apply` overwrites rather than appends. A second full run produced
   **24/24 `already_ok`** with zero repeat changes.
4. **Failure is isolated.** A failing item restores its own backup, is recorded as `failed`,
   and the batch continues; one broken item never aborts the run.
5. **High-risk items get a safety net.** Items with `guard_seconds` arm a
   `systemd-run --on-active=900` timer after execution; `hardenctl confirm` disarms it.
   Console access and a machine snapshot remain the last resort.
6. **Rollback granularity is the run.** `backups/<run_id>/<item>/` keeps original content,
   sha256, mode and owner; rollback walks the run in reverse order and then runs an
   "activation hook" (`sysctl --system`, `systemctl reload ssh`) so the runtime state follows
   the files — no "files rolled back, daemon still running the hardened config" fake rollback.
7. **Cryptography is separated from the generic playbook.** Generating keys, certificates and
   disks is not idempotent in the same sense, so it lives in `harden.crypto` with its own
   asset ledger and never inside the generic `apply` directory.

## 4. Baseline (`items.yaml`)

`items.yaml` ships **28 items in eight categories**; the reference benchmark below covers the
**24 items applicable to the Linux platform profile** (the `platform` category was added
after that measurement). The baseline lives at
[hornwork/harden/items.yaml](../hornwork/harden/items.yaml) and each item declares
`id / category / title / risk / check / apply / verify / targets / refs / scope / rollback / guard_seconds / order`.

| Category | IDs | Count | Typical item (risk) |
|---|---|---|---|
| audit | H-AL-01…04 | 4 | audit rules for key config changes (low), journald persistence (low), time sync (low), log permissions (low) |
| perms | H-PM-01…04 | 4 | key file modes (mid), world-writable sweep (mid), `/dev/shm` nosuid/nodev/noexec (mid), umask 027 (low) |
| kernel | H-KR-01 | 1 | KASLR / kptr / dmesg / ptrace / syncookies sysctls (mid) |
| account | H-AC-01/03/04 | 3 | minimum password length 12 (mid), empty passwords and UID 0 uniqueness (low), sudoers mode 440 (**high**) |
| service | H-SV-01…04 | 4 | unnecessary services (mid), SSH login policy (**high**), SSH algorithm suite (**high**), UFW default deny (**high**) |
| crypto | H-CR-01…04 | 4 | Argon2id migration (**high**), internal CA and certificates (**high**), Ed25519 signing (mid), LUKS2 loopback volume (**high**) |
| tls | H-TL-01…04 | 4 | TLS 1.2/1.3 only (mid), AEAD suites only (mid), HSTS + 301 (low), certificate review (low) |
| platform | H-PL-01…04 | 4 | console only behind HTTPS reverse proxy (mid), login lockout policy (low), minimal permissions for data/database/signing key (low), service sandboxing (mid) |

- `scope` maps asset profile → applicability (`A`, `B`, `C`); a string starting with `no`
  carries the reason, so an exclusion is not a silent skip;
- **batches are derived from `order`**: batch 1 audit and logging, batch 2 permissions,
  kernel, accounts and service trimming, batch 3 firewall before SSH (`order` 40 → 50),
  batch 4 cryptography, batch 5 TLS and platform exposure;
- `check` is always read-only, `apply` is repeatable, and `verify` is independent of the
  `apply` return value.

`items.yaml` ships with an Ed25519 signature (`items.yaml.sig`), and the signing stage
(H-CR-03) covers the baseline, the plan and release bundles. In practice the gate that
matters is `apply`: it verifies `plan_sha256` and, when `plan.json.sig` exists, refuses to
execute a plan whose signature does not match its content. Tampering with a single byte makes
verification fail.

## 5. Asset profile and plan

```bash
hardenctl plan --asset A --role A [--snapshot]    # profile + plan; --snapshot also records the pre-hardening state
hardenctl items                                    # list baseline items
hardenctl status                                   # subsystem state
hardenctl asset list | hardenctl asset expiring    # cryptography asset ledger
```

The plan carries:

| Field | Meaning |
|---|---|
| `profile` | observed OS / kernel / ports / toolchain / UFW / auditd state |
| `batches[]` | ordered item groups with per-item `risk`, `targets` and `guard_seconds` |
| `excluded[]` | `{id, reason}` for every item the profile does not get — the auditable answer |
| `plan_sha256` | digest over the plan content |
| `signature` | Ed25519 signature over the digest, verified by `apply` when `plan.json.sig` is present (an unsigned plan is hash-checked and warned about) |

For the weak sample profile the plan reports 7 applicable items and 17 exclusions with
reasons; for the manual profile every item is converted to a checklist entry.

## 6. Three-stage idempotent execution

```bash
hardenctl check  --plan <plan_id>                       # read-only inspection: would_apply / already_ok
hardenctl apply  --plan <plan_id> --dry-run             # print the plan without touching the system
hardenctl apply  --plan <plan_id> [--batch N] [--only H-XX-NN] [--yes-risk]
hardenctl confirm --run <run_id>                        # disarm the timed rollback safety net
```

- `check` runs the read-only command of every item and classifies it as `would_apply` or
  `already_ok`;
- `apply` backs up every declared `targets` path (content, sha256, mode, owner), executes the
  command through `bash -lc` with a fixed timeout, then runs the item's `verify`;
- an item with `risk: high` requires `--yes-risk`, and an item with `guard_seconds` arms the
  timer after a successful apply;
- failures are recorded per item (`failed` + restore) and the batch continues.

## 7. Rollback

```bash
hardenctl rollback --run <run_id> [--item H-XX-NN] [--auto]
hardenctl drill    --plan <plan_id> [--items H-AL-01,H-PM-01,…]
```

- Rollback granularity is the **run**: items are reversed in the opposite order of execution;
- Three rollback strategies come from the baseline: `restore` (file snapshot), `reverse`
  (inverse command, e.g. removing audit rules) and `manual` (documented, requires a human);
- After restoring files, an activation hook runs so the live configuration matches the files
  again;
- `drill` exercises one item per category — `apply → rollback → sha256 comparison` — with
  six items by default, so rollback correctness is proven before a real run;
- The timed safety net calls `rollback --auto`, which is audited with `actor=guard` so an
  automatic rollback can never be mistaken for a human action.

## 8. Before/after objective measurement

`hardenctl verify --run <run_id>` compares a pre-hardening snapshot with a post-hardening
snapshot taken on the same host:

| Measurement | Method |
|---|---|
| Host hardening index | `lynis audit system --quick`, parsing `/var/log/lynis-report.dat` (index + suggestions) |
| TLS posture | built-in Python `ssl` prober (protocol floor, AEAD suite set, HSTS header) + `nmap ssl-enum-ciphers` + `openssl s_client` cross-check |
| SSH effective configuration | `sshd -T` (effective values, not the file text) |
| Kernel parameters | `sysctl -n` for each hardened key |
| File permissions | `stat` on the declared sensitive files |
| Password hashes | legacy-hash counter before/after, PHC prefixes verified |
| Certificate state | `openssl x509` (SAN, validity, curve, signature algorithm) plus the asset ledger |
| Block-device encryption | `luksDump` (KDF, key slots), plaintext marker search on the raw image |

`--reuse` recomputes the comparison from an existing post snapshot without re-running Lynis
(useful when only the rendering changed).

## 9. Cryptographic deliverables

| Deliverable | Algorithm and parameters | Executable carrier | How it is verified |
|---|---|---|---|
| Password storage | **Argon2id** m=64 MiB, t=3, p=4, salt 16 B, out 32 B (RFC 9106 second recommendation) | `crypto.pwhash` + a demo database; idempotent conditional UPDATE | PHC string `$argon2id$v=19$m=65536,t=3,p=4$…`; migration 3/3; single hash 91–95 ms |
| Transport | **TLS 1.2/1.3, AEAD suites only** (ECDSA P-256, HSTS 2 years, 301 redirect) | rendered `/etc/nginx/conf.d/hornwork-tls.conf` | built-in prober + `nmap ssl-enum-ciphers` (only 1.2/1.3, all A-grade suites) + `curl -I` for HSTS |
| CA / PKI | internal CA (ECDSA P-256 / SHA-256 / 10 years) → service certificate valid 90 days, SAN includes hostname and IP | `crypto.pki_ensure`, `/etc/ssl/hornwork/` | `openssl x509` parsing (SAN / expiry / curve / signature algorithm); ledger expiry warnings |
| Integrity / signing | **Ed25519** (RFC 8032) over the baseline, plans and release bundles | `crypto.sign_ensure`; signature verification gate before `apply` | `openssl pkeyutl -verify`; flipping one byte makes verification fail |
| Data at rest | **LUKS2 + Argon2id KDF + AES-XTS-512 + two key slots** (256 MB loopback volume) | `crypto.luks_ensure` | `luksDump` (KDF, 2 key slots); plaintext marker count 0 on the raw image; readable after unlock and mount |

**No home-grown cryptography.** OpenSSL, `cryptsetup` and `argon2-cffi` are the places where
the answer is unambiguous; what this subsystem implements is parameter selection,
configuration generation, measurement methodology and the asset ledger around them.

## 10. Interfaces and events

| ID | Provider → consumer | Implementation | Failure handling |
|---|---|---|---|
| IF-30 | `harden.executor` → inspectors and system commands | `subprocess.run(["bash","-lc",cmd])`, fixed arguments, timeout 30–300 s, truncated stderr stored in the run record | timeout `rc=124`, non-zero `rc` → `failed` plus in-place restore |
| IF-31 | `harden.verify` → rescan | not wired to `scan run` yet; the `scan diff` mapping keys are reserved | `rescan_pending`, never a fabricated diff |
| IF-32 | `harden.crypto` → openssl / cryptsetup / nginx | subprocess calls; keys written to a temporary directory then atomically renamed; private keys 0600 | the current step is rolled back on failure |
| IF-33 | `harden.report` → Markdown / JSON | generated in-process; missing data is marked N/A | nothing is silently omitted |

Events (`harden_plan`, `harden_apply`, `harden_verify`, `harden_rollback`) are written to the
same `hornwork.db` event table as the rest of the platform. In the benchmark run that was
14 `apply`, 101 `verify`, 4 `rollback` and 1 `plan` event. Hardening actions therefore appear
on the auditd timeline, and the audit item (H-AL-01) reuses the platform's existing auditd
rules plus 4 new `-k hornwork_harden` rules — which is the practical proof that hardening is
auditable.

## 11. CLI and state layout

```bash
hardenctl plan    --asset A --role A [--snapshot]
hardenctl items | status | asset list | asset expiring
hardenctl check   --plan <id>
hardenctl apply   --plan <id> [--dry-run] [--batch N] [--only H-XX-NN] [--yes-risk]
hardenctl confirm --run <id>
hardenctl verify  --run <id> [--reuse]
hardenctl rollback --run <id> [--item …] [--auto]
hardenctl drill   --plan <id> [--items …]
hardenctl report  --run <id> [--second-run <id>] [--drill <json>] --out <dir>
```

All state is stored as files, deliberately avoiding new database tables and keeping the
coupling to the other subsystems low:

```text
/var/lib/hornwork/harden/
├── plans/<plan_id>.json (+ .sig)     plan, plan_sha256, Ed25519 signature
├── runs/<run_id>.json                per-item result / status / duration / backup ref / guard / metrics
├── backups/<run_id>/<item>/          file snapshots (content + metadata)
├── snapshots/pre-A.json, post-<run>.json, lynis-*.log
├── assets/assets.json                cryptography asset ledger (paths, fingerprints, expiry only)
├── luks/backup.img, slot0/1.key, luksdump.txt
└── demo/demo_users.db                password-hash migration demo database
```

## 12. Reproduce the pipeline

```bash
# 0) one-time environment (idempotent): nginx + cryptsetup + directories + hardenctl + demo database
sudo bash scripts/setup_harden.sh

# 1) plan, including the pre-hardening snapshot (Lynis takes 60–90 s)
sudo hardenctl plan --asset A --role A --snapshot

# 2) inspection and dry run
sudo hardenctl check --plan <plan_id>
sudo hardenctl apply --plan <plan_id> --dry-run

# 3) rollback drill (one item per category, high-risk items untouched)
sudo hardenctl drill --plan <plan_id>

# 4) full run (high-risk items need --yes-risk; confirm the safety net afterwards)
sudo hardenctl apply --plan <plan_id> --yes-risk
sudo hardenctl confirm --run <run_id>

# 5) re-measure, run again for idempotency, then render the output
sudo hardenctl verify --run <run_id>
sudo hardenctl apply --plan <plan_id> --yes-risk     # the second run should be all already_ok
sudo hardenctl report --run <run_id> --second-run <run2_id> --drill <drill.json> --out /opt/hornwork/reports
```

## 13. Reference benchmark

| Metric | Result |
|---|---|
| Completion | **100 % (24/24: 13 verified + 11 already_ok)** |
| Idempotency | second full run **24/24 already_ok**, zero repeated changes |
| Rollback drill | **6/6** (one item per category; `apply → rollback → sha256` identical) |
| Unit tests | **15/15** (items, plan, backup/restore, Argon2id migration, Ed25519 tamper, certificate parsing, output) |
| Lynis hardening index | 66 → **72 (+6)**; suggestions 84 → 43 (**-49 %**) |
| Weak TLS suites | 0 (`nmap` sees only TLS 1.2/1.3 with A-grade AEAD suites; a forced CBC handshake is rejected) |
| HSTS / redirect | HSTS `max-age=63072000`; port 80 → 443 `301` |
| Legacy password hashes | 3 → **0** (md5/sha1/sha256 → Argon2id, PHC prefix verifiable) |
| Key and certificate ledger | 3 entries (CA valid 3 649 days, service certificate 89 days remaining, Ed25519 public key) |
| LUKS2 | KDF `argon2id`, 2 key slots, plaintext markers 0 in the raw image, markers readable after unlock |
| Effective SSH configuration | `permitrootlogin no`, `maxauthtries 4`, `logingracetime 30`, KEX/MAC/cipher suites narrowed |
| Kernel parameters | `kptr_restrict=2`, `suid_dumpable=0`, `ptrace_scope=1`, `syncookies=1` |
| High-risk confirmations | 3 items (UFW, SSH ×2): safety net armed → connection verified → `confirm` disarmed, no rollback triggered |

## 14. Design tradeoffs and boundaries

| Not done | Why |
|---|---|
| Editing the PAM primary authentication stack to enable `pam_faillock` | a mistake there can lock out the management channel (including sudo and SSH); this subsystem limits itself to rate-limit-style items (`MaxAuthTries`, `LoginGraceTime`) and records account lockout as an explicit manual item |
| Remote execution against other hosts (profiles B and C) | pushing hardening actions over WinRM/SSH adds complexity for little gain; profile B is intentionally left unhardened and profile C uses a manual checklist (`source=manual`) |
| testssl.sh / OpenSCAP / Ansible | they add GPL tooling and an extra abstraction layer, while the gap this project actually had was "should we do it / how do we roll it back / how do we compare before and after"; TLS is covered by a purpose-built prober cross-checked with `nmap` |
| Full system-disk encryption | the reference host is repeatedly snapshotted, rolled back and analysed offline; whole-disk encryption slows recovery, so a LUKS2 loopback volume demonstrates block-device encryption instead |
| Automatic LUKS keyfile unlock | automatic unlock would make the encryption cosmetic; deliberately not implemented |
| Home-grown cryptography or a TLS library | for standard primitives the answer is unique; a home-grown implementation would only create vulnerabilities |
| The `harden ↔ scanning` rescan hand-off (IF-31) | the interface and `check_id` mapping are reserved but not wired; the run output marks it `rescan_pending` rather than inventing a diff |
| A +15 Lynis target | the host already scored 66 before hardening; the measured improvement is +6, so the acceptance criterion used is "-40 % or more suggestions", recorded honestly |
| Full-disk image collection for the "profile B" sample | no second machine in the reference environment; the plan and exclusion list are the artefact, and the limitation is stated rather than simulated |
