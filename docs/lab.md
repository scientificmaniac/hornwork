# Lab orchestration and vulnerability records

> Code: `hornwork/lab/`, `hornwork/vuln/`, `hornwork/tools/lab_repro.py`
> CLI: `hornworkctl lab …` (IF-17), `hornworkctl vuln …` (IF-18/IF-19)
> See also: [interfaces.md](interfaces.md) · [CONTRACT.md](CONTRACT.md) · [runbook.md](runbook.md) · [scanning.md](scanning.md) · [hardening.md](hardening.md)

This subsystem gives Hornwork a **reproducible vulnerability laboratory** plus the
**archive foundation** that the scanning subsystem builds on: a catalogue of Vulhub
environments, a lifecycle wrapper around Docker Compose, a typed vulnerability-record
model with a self-implemented CVSS 3.1 calculator, Debian/semver version-range matching,
and a reproduction pipeline that captures replayable evidence for every vulnerability
under test.

Design intent in one sentence: **a lab environment is cheap to start, hard to leak,
and every claim about a vulnerability is backed by a replayable command.**

> **Reference benchmark** — Ubuntu 26.04 LTS / Python 3.14, 4 vCPU / 8 GB. Every
> performance and count in this document was measured on that host and is reported as
> an indicative measurement, not as a committed service level.

---

## 1. Scope

| In scope | Out of scope (owned by another subsystem) |
|---|---|
| Docker + Vulhub environment, index `vulhub-index.json` | Scheduled scanning, asset ledger, scan plans ([scanning.md](scanning.md)) |
| `hornworkctl lab` up/down/status/logs/isolate, port allocation, resource gates, TTL | Hardening execution and rollback ([hardening.md](hardening.md)) |
| Vulnerability record model (21 fields), CVSS 3.1 calculator, version-range matching | Authentication and session handling ([authentication.md](authentication.md)) |
| Archive records and reproduction evidence for three server-side CVEs (Grafana / Spring Cloud Gateway / Redis) | Client-side software, 0-day work, weaponised chains, internet-facing targets |
| Reuse of the platform database, event table, audit hash chain, CLI and Web API | A second database, a message bus, or any new platform component |

A lab environment is **not** a target: no request ever leaves the loopback interface,
and the archive is a data model, not an exploitation framework.

## 2. Deployment topology

The reference deployment packs both roles onto one host. The design keeps the
two-host split available through the SSH execution backend, so the same code serves a
strictly separated topology.

```text
Ubuntu host (single-host dual role)
├── hornwork daemon          minimal-privilege systemd service, host process
├── hornworkctl lab / vuln   CLI, no long-running process of its own
└── Docker + Vulhub          containers published on 127.0.0.1:<port> only
```

| Control | Implementation |
|---|---|
| Loopback binding | every environment runs from a generated override copy of `docker-compose.yml` that rewrites each published port to `127.0.0.1:<host_port>:<container_port>`; the upstream Vulhub tree stays read-only |
| Port allocation | host ports are allocated from `[lab].port_range` (default `18000–18999`), skipping sockets already listening per `ss` |
| Target allow-list | the reproduction tool refuses any target that is not in `[lab].target_whitelist` (default `127.0.0.1`, `192.168.56.20`) |
| Execution backend | `[lab].backend = "local" \| "ssh"`; the `ssh` backend runs Compose on a remote lab host over `ssh -o BatchMode=yes` and never prompts for a password |
| Cleanup instead of snapshot | on a single host there is no independent lab-host snapshot, so `/opt/lab/S0-B.ok` documents the substitute: loopback binding + allow-list + `lab down -v` |
| TTL | every environment carries a lease (default 90 min); `cleanup_expired()` stops expired environments on the next command |

Config keys live in `[lab]` of [config.toml](../config.toml); the shared constants are
listed in §10.

## 3. Code map

```text
hornwork/lab/                 lab orchestration
├── index.py                  walk /opt/vulhub/*/*/docker-compose.yml → vulhub-index.json
├── runner.py                 local / ssh command backends (system ssh, BatchMode=yes)
├── compose.py                generate patched compose copies, then up/down/ps/logs
├── ports.py                  compose port parsing, occupancy probing, host-port allocation
├── guard.py                  concurrency / memory / disk gates, snapshot reminder, allow-list
├── store.py                  lab_env and lab_run tables (shared hornwork.db)
└── ctl.py                    LabCtl: index/list/up/down/status/logs/isolate/cleanup_expired/stats

hornwork/vuln/                vulnerability records
├── cvss.py                   self-implemented CVSS 3.1 (integer roundup, 8-vector cross-check)
├── version.py                Debian / semver / generic comparison and range matching
├── model.py                  21-field record model plus validation
├── store.py                  vuln_record table, YAML → SQLite synchronisation
├── match.py                  IF-18: (component, version) → matching records
└── report.py                 vulnerability card / remediation Markdown (IF-19)

data/
├── vulhub-index.json         generated at runtime
├── records/*.yaml            archive records (YAML is the source of truth)
├── templates/                record template
└── evidence/<VULN-ID>/<run>/ requests, responses, command output, sha256 manifest

scripts/setup_lab.sh      Docker + Vulhub + directories + index, idempotent
```

## 4. Lab environment lifecycle

### 4.1 Command surface

| Command | Action | Key response fields |
|---|---|---|
| `hornworkctl lab index [--force]` | scan the Vulhub tree and build the index | `{ok,count,path,elapsed_ms,errors}` |
| `hornworkctl lab list [--type] [--status]` | index merged with runtime state | environment list incl. ports and TTL |
| `hornworkctl lab up <env_id> [--ttl N] [--force]` | gates → override copy → pull/up → health check | `{ok,env_id,ports,containers,elapsed_ms,run_id}` |
| `hornworkctl lab down <env_id> [--keep-volume]` | `compose down -v` plus port release record | `{ok,env_id,freed_ports,cleanup_ok}` |
| `hornworkctl lab status [env_id]` | `compose ps` plus TCP probe | `down / starting / healthy / stopped / error` |
| `hornworkctl lab logs <env_id> [--tail]` | truncated `compose logs` | text or JSON |
| `hornworkctl lab isolate <env_id>` | stop the environment and record isolation | `{ok,mode}` |

### 4.2 Guard sequence for `up` (failure always cleans up)

```text
TTL cleanup → index hit → already-running check → snapshot reminder (--force skips)
→ concurrency / memory / disk gates → port allocation (skips listening sockets)
→ generate overrides/<env>.yml with 127.0.0.1 binding
→ compose pull (600 s, one retry) → compose up -d (180 s)
→ health check (TCP polling, 120 s) → persist lab_env / lab_run → event + audit → return

on any failure: collect `logs --tail 200` → `down -v` if anything started
                → lab_run(status=error) → return ok=false
```

### 4.3 Resource gates

| Gate | Default | Rationale |
|---|---|---|
| Concurrent environments | ≤ 2 | keeps the lab from starving the detection platform |
| `MemAvailable` | ≥ 800 MB | containers must not push the daemon into swap |
| Free disk | ≥ 5 GB | images plus data volumes |
| TTL | 90 min | `cleanup_expired()` stops overdue environments |
| Port range | 18000–18999 | avoids ports used by the platform and by system services |

Every gate is a config value in `[lab]`, so an operator can tighten them without code
changes.

### 4.4 State, events and audit

State lives in two new tables inside the shared `hornwork.db` — `lab_env` (one row per
environment, latest port allocation and TTL) and `lab_run` (one row per lifecycle
action, with result, elapsed time, container list and cleanup outcome). Each action also
emits a `CanonicalEvent` with `event_type=lab_action` and appends an audit row with
action `lab.up` / `lab.down` / `lab.isolate` / `lab.cleanup` to the platform's existing
`action_audit` hash chain. Nothing is written to a private database or log silo.

## 5. Vulnerability record model

A record describes **what a vulnerability is, where it applies, and how it was proven**.
YAML is the single source of truth (reviewable, diffable); the SQLite table
`vuln_record` is only a query index, rebuilt by `hornworkctl vuln record sync`.

- 21 fields in total, **18 required**; a record missing any required field is rejected;
- `references` must contain at least 2 entries (`[vuln].min_references`);
- `cvss_score` must equal `cvss.calculate(cvss_vector)` — the calculator is the only
  producer of scores;
- `status=verified` requires a non-empty `evidence` block whose sha256 manifest can be
  re-checked; records start as `draft` and are promoted after reproduction.

| Field group | Fields |
|---|---|
| Identity | `id`, `cve`, `cwe[]`, `title`, `type` |
| Affected surface | `component`, `vendor`, `ecosystem`, `affected_versions[]`, `fixed_version` |
| Scoring | `cvss_vector`, `cvss_score`, `severity` |
| Knowledge | `description`, `impact`, `attack_vector`, `remediation`, `references[]` |
| Provenance | `source[]`, `notes`, `status`, `evidence`, `created_at`/`updated_at` |

The template and the three reference records ship in the repository:
[data/templates/vuln-record.yaml](../data/templates/vuln-record.yaml),
[data/records/VULN-2026-0001.yaml](../data/records/VULN-2026-0001.yaml).

## 6. CVSS 3.1 calculator

`hornwork/vuln/cvss.py` implements the specification directly instead of pulling a
dependency: metric weights for AV/AC/PR/UI/S/C/I/A, the ISS / Impact / Exploitability
chain, the Scope-changed branch, and **integer roundup** arithmetic so that
floating-point drift cannot flip a score.

The implementation is cross-checked against eight canonical vectors from the public
specification — 9.8, 10.0, 9.9, 7.8, 7.5, 5.9, 6.1 and 0.0 — and matches all eight.
`explain()` returns the intermediate quantities, which is what the vulnerability card
uses to justify a severity instead of asserting it.

## 7. Version-range matching (IF-18)

The matcher answers exactly one question: *does this component version fall inside the
affected range?* It does not answer *is this instance exploitable* — that is the job of
reproduction and of the scanning subsystem's PoC engines.

```json
{
  "request":  {"component": "grafana", "version": "8.2.6", "distro": "ubuntu", "cpe": "cpe:2.3:a:grafana:grafana:8.2.6:*:*:*:*:*:*:*", "trace_id": "..."},
  "response": {"matched": [{"vuln_id": "VULN-2026-0001", "cve": "CVE-2021-43798",
                            "matched": true, "matched_rule": "introduced<=8.2.6<fixed",
                            "fixed_version": "8.3.0", "cvss_score": 7.5, "severity": "高",
                            "confidence": "range", "reason": "..."}],
               "unknown": [], "elapsed_ms": 3}
}
```

- Range semantics are **left-closed, right-open**: `introduced <= version < fixed`, with
  explicit `exclude` entries removed afterwards;
- Comparators: a Debian implementation (epoch, `~`, upstream and revision segments
  compared segment by segment), a standalone `semver` implementation, and a `generic`
  comparator that degrades to the Debian rules;
- The Debian comparator is cross-checked against `dpkg --compare-versions` on 56 version
  pairs and agrees on every one.

Callers consume the result through `hornworkctl vuln match --component … --version …`,
and the scanning subsystem reuses the same comparator rather than growing a second one.

## 8. Reproduction and evidence pipeline

`hornwork/tools/lab_repro.py` drives one vulnerability end to end: resolve the record,
start the environment, send the request, collect the response, hash the artefacts, stop
the environment, and fill the archive evidence block.

```bash
# full pipeline for one record (one command, one environment, one evidence directory)
sudo /opt/hornwork-venv/bin/python -m hornwork.tools.lab_repro --vuln VULN-2026-0001
```

Every run writes one directory `data/evidence/<VULN-ID>/<run>/`
(see [data/evidence/VULN-2026-0001](../data/evidence/VULN-2026-0001)):

```text
data/evidence/<VULN-ID>/<run-ts>/
├── meta.json        UTC time, env_id, lab_run_id, host port, image digest, operator
├── env.txt          docker compose ps / image digests / ss -ltn
├── request.txt      raw request line, response headers, response body (≤ 64 KB)
├── command.txt      triggering command, stdout/stderr, exit code, duration
├── sha256sum.txt    sha256 of every file in the directory
└── cleanup.txt      lab down time, freed ports, residual check
```

Three invariants make evidence trustworthy:

1. **Replayable** — one piece of evidence equals one command plus its expected result;
2. **Cleanable** — `lab down` records the released ports, and cleanup is part of the record;
3. **In bounds** — only allow-listed targets, no internet egress, no shared infrastructure.

## 9. Integration with the platform

The subsystem deliberately reuses platform machinery instead of introducing parallel
infrastructure.

| Integration point | Implementation | Observable |
|---|---|---|
| Storage | shared `hornwork.db` (WAL); adds `lab_env`, `lab_run`, `vuln_record` | `sqlite3 /var/lib/hornwork/hornwork.db .tables` |
| Events | `CanonicalEvent` with `event_type=lab_action`; `vuln_finding` is declared in the schema for archive state changes | `hornworkctl events --type lab_action` |
| Audit | platform hash chain; actions recorded as `lab.up/down/isolate/cleanup` | `hornworkctl audit verify` |
| CLI | `lab` and `vuln` subcommands of the same `hornworkctl` binary | `hornworkctl vuln --help` |
| Web | read-only `GET /api/lab/envs`, `GET /api/vuln/records`, bearer authentication inherited from the platform | `curl -H "Authorization: Bearer …" http://127.0.0.1:8787/api/lab/envs` |
| Export | the shared export framework renders vulnerability cards and remediation sheets to `reports/` | `hornworkctl vuln report --format md --out /opt/hornwork/reports` |
| Detection timeline | lab actions and reproduction traffic appear on the same event timeline as alerts, so a lab action can be correlated with a case | `hornworkctl events --since 1h` |

## 10. Configuration reference

| Key | Default | Meaning |
|---|---|---|
| `[lab].backend` | `local` | `local` (Docker on this host) or `ssh` (Compose on a remote lab host) |
| `[lab].vulhub_root` | `/opt/vulhub` | read-only Vulhub checkout |
| `[lab].overrides_dir` | `/opt/lab/overrides` | generated compose copies |
| `[lab].index_path` | `/opt/hornwork/data/vulhub-index.json` | index artefact |
| `[lab].host_bind` | `127.0.0.1` | bind address for published ports |
| `[lab].max_envs` | `2` | concurrency gate |
| `[lab].min_mem_mb` | `800` | memory gate |
| `[lab].min_disk_gb` | `5` | disk gate |
| `[lab].default_ttl_min` | `90` | default lease |
| `[lab].port_range` | `[18000, 18999]` | host-port pool |
| `[lab].target_whitelist` | `["127.0.0.1", "192.168.56.20"]` | targets reproduction may touch |
| `[lab].pull_timeout_sec` / `up_timeout_sec` / `healthy_timeout_sec` | `600` / `180` / `120` | stage timeouts |
| `[lab.ssh].*` | see config | remote backend addressing and key |
| `[vuln].min_references` | `2` | minimum reference count for a record |

## 11. Quick start

```bash
# 1) prepare Docker, Vulhub, directories and the index (idempotent)
sudo bash scripts/setup_lab.sh

# 2) build and inspect the environment index
sudo hornworkctl lab index
sudo hornworkctl lab list --type grafana --limit 10

# 3) run one environment and inspect it
sudo hornworkctl lab up grafana/CVE-2021-43798 --ttl 30
sudo hornworkctl lab status grafana/CVE-2021-43798
sudo hornworkctl lab logs grafana/CVE-2021-43798 --tail 50
sudo hornworkctl lab down grafana/CVE-2021-43798

# 4) archive: sync, list, show, match, export
sudo hornworkctl vuln record sync
sudo hornworkctl vuln list --severity 高
sudo hornworkctl vuln show VULN-2026-0001
sudo hornworkctl vuln match --component grafana --version 8.2.6
sudo hornworkctl vuln report --format md --out /opt/hornwork/reports

# 5) reproduce one CVE and capture evidence
sudo /opt/hornwork-venv/bin/python -m hornwork.tools.lab_repro --vuln VULN-2026-0001
```

The index step needs access to the Vulhub checkout; when the tree is already present,
set `SKIP_VULHUB_CLONE=1` for `scripts/setup_lab.sh` to work offline.

## 12. Reference benchmark

Measured on the reference host described at the top of this document.

| Item | Result |
|---|---|
| Environment index | **334 / 334** entries, matching the number of compose files; build time **294 ms** |
| Start / stop latency | `lab up` **2.3–3.3 s** (grafana 2949 ms, spring 3280 ms, redis 2300 ms); `lab down` **0.3–2.4 s**; `ss -ltn` shows only `127.0.0.1:18000` and `127.0.0.1:18001` |
| Reproduction | **3 / 3** server-side CVEs across three CWE classes: CVE-2021-43798 (CWE-22, reads `/etc/passwd`), CVE-2022-22947 (CWE-94, Actuator SpEL returns `uid=0`), CVE-2022-0543 (CWE-862, Lua escape returns `uid=0`) |
| Archive records | 3 records all `verified`; all 18 required fields present; 3–4 references each; `cvss_score` matches the calculator (7.5 / 10.0 / 10.0) |
| Calculator cross-check | CVSS **8 / 8** canonical vectors; Debian comparison **56 / 56** pairs agree with `dpkg --compare-versions` |
| Matching matrix | 8.2.6 hit / 8.2.7 miss; 3.1.0 hit / 3.1.1 miss; 5.0.7 hit / 6.0.16 miss |
| Integration | 12 `lab_action` events, audit chain 17 rows `ok=true`, `/api/lab/envs` and `/api/vuln/records` return 200 with a token and 401 without |
| Cleanup | `cleanup_ok` **100 % (12 / 12 runs)**; no residual ports, `docker ps` empty after the benchmark |
| Whole test suite | 343 passed / 3 skipped at benchmark time |

The lab, CVSS and version tests live in [tests/test_lab.py](../tests/test_lab.py),
[tests/test_cvss.py](../tests/test_cvss.py) and [tests/test_version.py](../tests/test_version.py).

## 13. Design tradeoffs and boundaries

| Decision / boundary | Rationale |
|---|---|
| Single-host dual role instead of a two-host split | one host is enough to demonstrate the full lifecycle; the `[lab].backend=ssh` path keeps the separated topology one config change away, and loopback binding + allow-list + `lab down -v` compensate for the missing physical isolation |
| No lab-host snapshot on a single host | `/opt/lab/S0-B.ok` records the substitute (loopback binding, allow-list, volume removal); a real two-host deployment should replace it with a genuine snapshot record |
| Ports published on loopback only | the lab must never be reachable from the office or the internet; a container listening on `0.0.0.0` would silently break that invariant |
| Allow-list checked before every reproduction | out-of-range targets are rejected with a logged reason rather than a "best effort" attempt |
| Version matching ≠ exploitability | interval matching is a triage signal; only reproduction and PoC evidence promote a finding to "exploitable" |
| Server-side software only | the archive covers the services the platform can actually exercise; client-side software is a separate, later work item |
| No 0-day or weaponised chains, no internet-facing targets | the tooling is for controlled lab environments and self-owned assets |
| Facts come from upstream | CVE data is taken from NVD, CWE and the upstream environment notes, and source links are kept in every record; no identifier is invented |
| Distribution fix versions are explicit | when the fix is a distribution backport (e.g. a Debian/Ubuntu security update), the record uses a `generic` range and states the source in `references`/`notes` |
| Container images are pulled through a mirror | each evidence `meta.json` records the concrete image digest, so a run can be reproduced even when the mirror changes |
| No daemon | lab and archive operations are short-lived CLI actions; a resident process would add failure modes for no benefit |
