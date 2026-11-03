# Authentication subsystem

> Code: `hornwork/auth/` (13 source files, library plus CLI)
> CLI: `hornworkctl auth …`
> See also: [interfaces.md](interfaces.md) · [runbook.md](runbook.md) · [hardening.md](hardening.md) · [scanning.md](scanning.md)

The authentication subsystem implements three-factor login for the platform — password,
TOTP and a revocable face template — plus the session, risk and audit machinery around it.
It ships as a **library and a CLI, not a service**: the kernel is importable by a future Web
middleware or PAM entry, and there is no resident process to keep alive, patch or monitor.

Guiding rule: *use a standard primitive where the answer is unambiguous, and write the
glue yourself where the policy is the point.* Argon2id and AES-GCM come from
`argon2-cffi` and `cryptography`; the TOTP algorithm, the PHC parser, the password pepper
chain, the revocable template transform, the risk model, the session token format and the
audit hash chain are implemented in this repository.

> **Reference benchmark** — Ubuntu 26.04 LTS / Python 3.14, 4 vCPU / 8 GB. Numbers are
> measurements on that host and are indicative, not service-level commitments.

---

## 1. Scope and explicit non-goals

| Implemented | Deliberately not implemented (documented as a boundary) |
|---|---|
| Password factor: Argon2id + pepper pre-transform, own PHC parsing, password policy, login-time migration from `md5`/`sha1`/`pbkdf2` | WebAuthn / FIDO2 as a fourth factor |
| TOTP factor: RFC 4226 / RFC 6238 implemented in-house, AES-GCM encrypted secret at rest, ±1 window, counter-based replay rejection | CAPTCHA / proof-of-work as a factor (an auxiliary control, not a factor) |
| Face factor: revocable orthogonal transform (random sign + permutation + Walsh–Hadamard) + AES-256-GCM + cosine-threshold comparison | Model inference, 5-point alignment and liveness detection (hundreds of MB of weights, licence constraints — intentionally not vendored) |
| Authentication state machine: password → risk score → TOTP → (LOA3) face → session; explicit, observable degradation | HTTP service and browser login page (the kernel is a library plus CLI) |
| Risk scoring (7 signals, thresholded policy stored in the database) + LOA / step-up + rate limiting and lockout | PAM entry point (would require editing the PAM stack — high blast radius) |
| Sessions: self-implemented HMAC token (instantly revocable) + idle/absolute dual expiry + trusted devices | Backup codes and account recovery |
| Audit: `auth_audit` hash chain + `logon`/`logon_fail` events on the platform event table | Real FAR/FRR measurement (needs a face-sample corpus) |

Size for orientation: `hornwork/auth/` is 13 files / 2 875 lines (core 2 345 +
`auth/cli.py` 530), of which the cryptographic surface (`crypto`, `password`, `totp`,
`session`, `biometric`, `audit`) is roughly 1 100 lines; [tests/test_auth.py](../tests/test_auth.py)
adds 432 lines.

## 2. Topology and privileges

```text
Ubuntu host
├── hornwork daemon              platform service, runs as user "hornwork"
├── hornwork/auth                library + CLI, no independent service
├── data:  /var/lib/hornwork/hornwork.db      shared database; 7 new auth_*/bio_*/trusted_device tables
└── keys:  /var/lib/hornwork/auth/auth.key    + auth.pepper
           directory 0700, files 0600, owner hornwork
```

- Keys live in the **data directory owned by `hornwork`**, not in `/etc/hornwork`, whose
  `root:root 0750` mode is reserved for system-side configuration by the hardening
  subsystem. File mode 0600 and directory mode 0700 keep the key material readable only by
  the service account;
- The subsystem **adds no systemd unit**: the kernel is delivered as a Python library and a
  CLI, so a Web middleware or a PAM adapter can reuse it later without a process to babysit;
- CLI writes must run as the owning user: `sudo -u hornwork hornworkctl auth …`. The database
  belongs to `hornwork`, matching the platform's offline read-only posture for everyone else;
- Key separation is intentional: rotating `auth.key` invalidates every face template;
  losing `auth.pepper` makes every password unverifiable. Both are recorded as operational
  hazards, not accidents.

## 3. Cryptographic primitives: algorithm, parameters, storage, code

| Stage | Algorithm | Parameters used here | Storage / key | Code |
|---|---|---|---|---|
| Password pre-transform | HMAC-SHA256(pepper, password) | 32-byte global pepper, stored separately from the database | `/var/lib/hornwork/auth/auth.pepper`, 0600 | `password.py` |
| Password hashing | **Argon2id** | `m=65536 KiB, t=3, p=4, hash=32 B, salt=16 B` (tests use 8/1/1 for speed) | PHC string carries salt and parameters | `password.py` |
| Password migration | recognise `md5$` / `sha1$` / `pbkdf2$` and rehash on successful login | migration window and `must_reset` column reserved | `auth_user.password_algo` statistics | `password.py`, `engine.py` |
| One-time code | HMAC-SHA1 + RFC 4226 dynamic truncation + RFC 6238 time step | `X=30 s, digits=6, window=±1, SHA1` | 20-byte shared secret encrypted with AES-256-GCM, AAD=`user_id\|totp\|key_id` | `totp.py` |
| Session token | HMAC-SHA256 signature + server-side `sha256(token)` registry | idle 30 min / 15 min, absolute 12 h / 8 h (LOA2 / LOA3) | master key → HKDF → `k_session` | `session.py` |
| Face template protection | random orthogonal transform → AES-256-GCM | 512 dimensions; transform = random signs + permutation + normalised Walsh–Hadamard, O(d log d) | ciphertext + 12-byte nonce in `bio_template`; no plaintext vector column; key from HKDF(`bio:{user_id}`) | `biometric.py` |
| Face comparison | cosine similarity (dot product on L2-normalised vectors) | threshold τ=0.35 (`auth_policy.bio.threshold`), quality gate 0.5 | plaintext only in memory | `biometric.py` |
| Audit chain | SHA-256 hash chain | `row_hash = SHA256(canonical fields ‖ prev_hash)`, chain head in `meta` | append-only | `audit.py` |
| Randomness | `os.urandom` / `secrets` | salt 16 B, nonce 12 B, challenges, secrets, device ids | none | `crypto.py` |

### 3.1 Three red lines, checkable in the code

1. **A face vector is never SHA-256-hashed and compared.** `biometric.py` uses AEAD for
   confidentiality and cosine similarity for comparison — hashing a template would destroy
   the metric and imply a security property it does not have.
2. **TOTP is a MAC, not encryption.** `totp.py` only verifies codes; the shared secret is
   protected separately with AEAD before it is stored.
3. **MD5/SHA1 only identify legacy hashes for migration.** `hash_password()` emits nothing
   but `$argon2id$…`.

### 3.2 How revocability actually works

`template_seed = HKDF(master, "auth|bio|seed|user_id")` seeds the transform parameters.
Rotating the master key (or the per-user salt) changes the transform, so every stored
template becomes unreadable and the user re-enrols. Honest labelling: the orthogonal
transform is itself invertible; **confidentiality comes from AEAD**, and the transform
provides *revocability*, not secrecy.

## 4. Data model

Seven new tables, zero changes to platform tables:

| Table | Contents |
|---|---|
| `auth_user` | account, PHC hash, lockout state, `last_totp_counter` |
| `auth_credential` | TOTP ciphertext, activation flag, reserved WebAuthn columns |
| `auth_session` | token hash, LOA, dual expiry, strong-auth timestamp |
| `bio_template` | template ciphertext, nonce, AAD, model version |
| `auth_audit` | append-only hash chain |
| `auth_policy` | thresholds and weights as JSON, adjustable at runtime |
| `trusted_device` | device trust records |

Existing `event` / `alert` / `scan_result` structures are untouched. The audit chain reuses
the platform `meta` table for its head but **does not share the platform action chain**, so
two subsystems cannot race for one chain head.

## 5. Authentication flow, risk and step-up

```text
start_login: rate limit → password (dummy Argon2id to avoid enumeration)
             → failure counter / lockout → risk score
             → LOA3 required but no face enrolled? → explicit LOA2 degradation
             → 120 s challenge

advance:     TOTP (±1 window, atomic counter advance) → face comparison when LOA3
             → issue session → audit(logon/logon_fail, factors, risk, loa, latency_ms)
             → platform event table

step_up:     LOA2 session requests a write action → re-verify TOTP + face
             → upgrade to LOA3 and refresh the strong-auth timestamp
```

- **Factors are serial, not parallel**: a wrong password returns a single uniform 401 and
  never hints that a second factor is next;
- **Risk decides how many factors are needed**: the policy starts at `new_device +20`,
  `ip_change +15`, `ioc_ip +30` with thresholds `loa3 ≥ 30`, `warn ≥ 60`, `lock ≥ 80`. A new
  device alone keeps the session at LOA2; an IP hit against threat intel reaches LOA3 on its
  own, while a network-segment change accumulates with other signals toward the same
  threshold. Every weight and threshold is a row in `auth_policy`, so the model can be tuned
  without a code change;
- **Degradation is an audited anomaly**: a user without an enrolled face gets LOA2 with
  `degraded=true`, recorded in both the audit chain and the event table;
- **Step-up extends into the session lifecycle**: an LOA2 session can read but a write action
  requires strong authentication within the last 15 minutes.

## 6. Interfaces

| ID | Provider → consumer | Mechanism | Payload | Failure handling |
|---|---|---|---|---|
| IF-25 | `auth` → `store` | in-process SQLite (WAL, same database) | rows of the seven tables | transaction rollback; `database is locked` absorbed by the store's 15 s busy timeout |
| IF-26 | `auth.biometric` → face embedding source | **pluggable**: JSON vector file / lightweight image descriptor / (reserved) `127.0.0.1:8930` HTTP | 512-dim float32; the service variant takes a JPEG plus a challenge | embedding failure → LOA2 + `degraded` event; never locks every login |
| IF-27 | `auth.audit` → `event` | in-process `store.insert_event` with the same `CanonicalEvent` | `logon` / `logon_fail`, `source_layer=host`, `source_product=hornwork-auth`, `raw.auth{loa,factors,risk,degraded,latency_ms}` | serialisation or write failure falls back to the DLQ; audit is not lost |
| IF-28 | Web / CLI → auth middleware | in-process `engine.require_action(token, action)` | `allow / stepup_required / deny` plus LOA | invalid token → deny; insufficient LOA → stepup_required |

## 7. Reference implementation evidence

- **Unit tests**: [tests/test_auth.py](../tests/test_auth.py) **25/25** — all RFC 4226 (10) and
  RFC 6238 (6) vectors, PHC/pepper handling, login-time md5 migration, TOTP replay rejection,
  session tamper / revocation / dual expiry, template inner-product invariance and
  revocability, AAD mismatch rejection, risk IOC and known-device handling, five-failure
  lockout, IP rate limiting, three-factor login, degradation, step-up, and audit-chain tamper
  detection;
- **Whole suite**: 521 passed / 3 skipped at benchmark time; the other subsystems are
  unaffected;
- **End-to-end walkthrough** (`scripts/demo_auth.sh`): LOA2 login → IP intel hit triggers
  LOA3 (similarity 0.9152) → replayed code rejected → five wrong passwords lock the account
  for 15 min (a correct password still returns the uniform error) → a user without an
  enrolled face degrades to LOA2/`degraded` → **audit chain verifies 72 rows** → 8
  `hornwork-auth` event rows;
- **Latency**: LOA2 login P50 ≈ **73 ms** including Argon2id at the default 64 MB / t=3; no
  resident memory;
- **Ciphertext self-check**: TOTP plaintext appears **0** times in `hornwork.db` + WAL;
  `bio_template` holds only `tmpl_enc` (2 064 B ciphertext) plus a 12-byte nonce; password
  hashes are `$argon2id$v=19$m=65536,t=3,p=4$…`.

## 8. Deployment and operation

```bash
# 1) install and initialise (idempotent: dependencies, key directory, 7 tables, policy seeds)
sudo bash scripts/setup_auth.sh

# 2) accounts and factors
sudo -u hornwork hornworkctl auth user add alice --password-stdin
sudo -u hornwork hornworkctl auth otp enroll alice                  # prints Base32 + otpauth URI
sudo -u hornwork hornworkctl auth otp confirm alice --code <current-code>
sudo -u hornwork hornworkctl auth biometric enroll alice --embedding vec.json

# 3) login, session and step-up
sudo -u hornwork hornworkctl auth login alice --ip 203.0.113.66 --totp <code> --embedding vec.json
sudo -u hornwork hornworkctl auth session list --user alice
sudo -u hornwork hornworkctl auth step-up --token <token> --totp <code> --embedding vec.json

# 4) audit and risk
sudo -u hornwork hornworkctl auth audit verify-chain
sudo -u hornwork hornworkctl auth audit tail --user alice
sudo -u hornwork hornworkctl auth audit summary --since 1h
sudo -u hornwork hornworkctl auth risk explain alice --ip 203.0.113.66
sudo -u hornwork hornworkctl auth policy show

# 5) one-shot walkthrough (three factors, replay, lockout, degradation, audit chain)
sudo bash scripts/demo_auth.sh
```

The embedding input is a 512-dimension JSON vector; production deployments replace it with
an output from the separate face service behind IF-26.

## 9. Design tradeoffs and boundaries

| Boundary | Explanation |
|---|---|
| Face embedding | the repository contains no model weights and no inference; the walkthrough uses synthetic vectors or a lightweight descriptor to exercise template protection and threshold comparison. A real deployment plugs in a separate service (IF-26) and re-calibrates the threshold against measured FAR/FRR |
| Liveness | not implemented; a single RGB frame cannot resist high-quality replayed video or deep fakes |
| WebAuthn / PAM | not implemented; `auth_credential` already carries `credential_id` / `public_key` / `sign_count` so the interface can be extended |
| Login UI | no browser UI; CLI output is the observable interface, the HTTP service and page are future work |
| Risk alerting | high risk (≥ 60) forces LOA3 and is audited, but the "delay 2 s and raise an alert event" behaviour is not wired yet |
| Distributed rate limiting | in-memory token bucket plus persisted counters; in-memory counters reset on restart (account lockout persists) |
| Clock | TOTP needs NTP; the ±1 window absorbs up to 30 s of drift |
| Statistics | FAR/FRR are not claimed: no real face corpus was measured, so no accuracy number is published |
| No resident service | a deliberate choice for a library-shaped kernel: fewer moving parts, at the cost of the caller owning process supervision |
