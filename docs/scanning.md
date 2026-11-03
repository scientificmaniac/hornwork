# Periodic vulnerability scanning

> Code: `hornwork/scan/` (ledger, plans, gates, engines, matching, snapshots, coverage, output)
> CLI: `hornworkctl asset …`, `hornworkctl scan …`
> See also: [interfaces.md](interfaces.md) · [rules.md](rules.md) · [runbook.md](runbook.md) · [lab.md](lab.md) · [hardening.md](hardening.md)

The scanning subsystem turns "run a scanner every week" into an auditable, repeatable
process: an asset ledger, plans whose **period is data**, gates that decide whether a scan
may run at all, an adapter layer that reuses `nmap` for discovery, a three-layer CVE
matcher over NVD and Ubuntu OVAL data, frozen snapshots with a four-state diff, a weighted
coverage model, and a single-file HTML output that can be attached to a ticket.

Two design decisions define the subsystem:

1. **Reuse the expert tool, own the reasoning.** Port and service discovery is delegated
   to `nmap -sV` and its XML output. Everything that makes the result explainable —
   ledger, slots, gates, normalisation, CVE range matching, diff, coverage, output — is
   implemented in this repository.
2. **A timer is an alarm, not a schedule.** The period, profile, engines and window are
   rows in `scan_plan`. systemd timers only ring the bell; changing a cadence is a data
   change, never a code change.

> **Reference benchmark** — Ubuntu 26.04 LTS / Python 3.14, 4 vCPU / 8 GB, two ledger
> assets on the loopback interface. Numbers below are measurements on that host and are
> indicative, not service-level commitments.

---

## 1. Scope

| In scope | Out of scope (other subsystems) |
|---|---|
| Asset ledger (`asset`), plans/tasks/slots/gates/resume (`scan_plan`, `scan_task`) | Host intrusion detection, auditd/YARA/ClamAV ([architecture.md](architecture.md)) |
| `nmap` adapter: arguments, XML → internal result, port specs, timeout degradation | Lab orchestration and vulnerability archive ([lab.md](lab.md)) |
| Package facts (`dpkg-query`) and Ubuntu OVAL package-level matching | Hardening execution and rollback ([hardening.md](hardening.md)) |
| Three-layer CVE matching with confidence, exclusions and archive cross-reference | Authentication, sessions, face templates ([authentication.md](authentication.md)) |
| Normalisation/dedup/lifecycle, snapshot freeze, four-state diff, coverage, HTML output | A second database, message bus or platform component |
| Read-only Web API `/api/scan/*`, `hornworkctl scan/asset` CLI | Password spraying, credential policy |
| `scan_window` events and window-scoped rule downgrade on the detection side | Internet or campus-network scanning, OS fingerprinting, full UDP, IDS evasion |

## 2. Topology: two ledger assets on one IP

```text
Ubuntu host (single-host dual role)
├── hornwork daemon       host process; hosts ScanWindowGate background refresher (10 s)
├── hornworkctl scan      orchestration, systemd oneshot, exits when done
├── dpkg-query / nmap     engines, executed on this host
└── Docker + Vulhub       lab role; container ports on 127.0.0.1:18000-18002
```

Two assets share `127.0.0.1` but differ in role, which is what makes coverage and
applicability meaningful:

| Asset | IP | Role | Criticality | Declared ports | Applicable domains |
|---|---|---|---|---|---|
| `ast-self` | `127.0.0.1` | `self` | 5 | `22,80,443,631,8787` | all six |
| `ast-lab` | `127.0.0.1` | `lab` | 2 | `18000,18001,18002` | D1 / D3 / D6 |

- **Legality boundary**: `[scan].allow_cidrs` defaults to `127.0.0.1/32` and the host's own
  address. The gate evaluates `allow_cidrs` first and returns `ok=false` for anything else,
  with the rejection reason written to `action_audit`;
- **Remote package facts**: `[scan.pkgs].backend = "local" | "ssh"`; the `ssh` backend reads
  package lists from a remote host with `BatchMode=yes` (no password login), which is how a
  separate lab host is supported without changing the engine;
- **Trade-off**: scanner and lab share a host, so a scan can see lab containers. The ledger
  roles keep their domains separate, and the window governance in §11 keeps the
  scanner's own traffic from being misread as an attack.

## 3. Code map and data model

```text
hornwork/scan/
├── store.py       11 tables + 1 view (DDL); ledger/plan/task/finding/snapshot persistence
├── assets.py      ledger operations: IP validation, declared ports, TLS ports, web targets
├── scheduler.py   slot_of, in_window, allow_cidrs, profile expansion, gate_check, next_run
├── task.py        task state machine, checkpoint, retry/cancel/recover_stale/summary
├── runner.py      gate → task → engines → matching → normalise → snapshot → diff → coverage → output
├── normalize.py   raw result → finding (fact vs issue), dedup keys, lifecycle, checkpoint
├── diff.py        four-state diff over frozen snapshot items, trend, window comparison
├── coverage.py    asset × domain matrix, weighted coverage, uncovered list
├── report.py      single-file HTML / JSON output (5 tables)
├── api.py         read-only Web API query layer
├── window.py      ScanWindowGate: active-window cache and hit suppression
├── engines/       base protocol + nmap / dpkg-query / lynis / testssl / nuclei adapters
└── cve/           feed import, version wrapper, CPE mapping, three-layer matcher
```

| # | Table | Responsibility |
|---|---|---|
| 1 | `asset` | ledger; PK `asset_id`; `facts_json` holds `declared_ports` / `open_ports` / `services` |
| 2 | `scan_plan` | plan (period is data): `kind/profile/selector_json/engines_json/window_*/params_json` |
| 3 | `scan_task` | task: `run_id/plan_id/asset_id/slot`, **UNIQUE(plan_id, asset_id, slot)**, `checkpoint` |
| 4 | `scan_finding` | current finding state: `kind/check_id/severity/cvss/cvss_source/confidence/status`, **UNIQUE(asset_id, finding_key)**, `miss_count` |
| 5 | `cve_cache` | NVD affected-range rows: `cpe23/vulnerable/cpe_version/four bounds/cvss/severity` |
| 6 | `cve_component_map` | local component ↔ CPE prefix (imported from `comp_map.csv`) |
| 7 | `scan_oval_fix` | Ubuntu OVAL: `(release, package, cve_id, fixed_version)` |
| 8 | `scan_cve_exclude` | exclusions: `(cve_id, comp_norm, version, reason)`; empty `version` means all versions |
| 9 | `scan_snapshot` | snapshot metadata: `plan_id/run_id/ts/kind/is_base/task_count/finding_count/stats_json` |
| 10 | `scan_snapshot_item` | **frozen items**: `(snapshot_id, asset_id, finding_key, kind/check_id/severity/status/cvss)` |
| 11 | `scan_diff_stat` | four-state history: `(cur, prev, new/fixed/persisting/regressed, ts)` |
| — | `v_scan_finding_open` | view: `status IN ('new','observed','confirmed','reopened')` |

DDL is idempotent (`CREATE TABLE IF NOT EXISTS`) and adds missing columns on upgrade
(`ALTER TABLE … ADD COLUMN miss_count`). No existing platform table is altered.

## 4. Asset ledger, plans and slots

A plan is a row, and a task is one `(plan, asset, slot)` triple. The unique constraint on
`(plan_id, asset_id, slot)` is what makes a period idempotent: if a timer fires twice, the
second run sees the existing slot instead of duplicating work.

| Concept | Implementation |
|---|---|
| Period | `slot_of(plan, when)` maps a timestamp to a period key (day / week / quarter / manual) |
| Plan profiles | `quick` (top-200 ports), `weekly` (top-1000), `full` (all ports), `targeted` (CVE-driven), `verify-fix` (re-scan after hardening) |
| Engines per plan | `engines_json`, e.g. `nmap,pkgs,lynis`; a plan can disable an engine on purpose |
| Window per plan | `window_start` / `window_end` override the global `[scan.gates]` window |
| Timer | [deploy/hornwork-scan@.service](../deploy/hornwork-scan@.service) (oneshot, `User=root`) + [deploy/hornwork-scan@.timer](../deploy/hornwork-scan@.timer); installation writes one drop-in per plan with its own `OnCalendar` |
| Resume | `checkpoint` records completed engines/domains, so a partial task can be retried without redoing finished work |
| Recovery | `recover_stale()` marks tasks left running by a crash; `retry` re-queues failed or partial tasks; `cancel` stops a run |

Shipped plans: `daily-quick`, `weekly-linux`, `quarterly-full`, `l4-cve-targeted`,
`verify-fix`. Only the first three get timers by default; a targeted plan is normally
triggered by a CVE announcement.

## 5. Scan gates

`gate_check()` runs before any task is created. A rejection produces no task, no engine
call, and an audit row.

| Gate | Source | Default | Rejection effect |
|---|---|---|---|
| Allow-list | `[scan].allow_cidrs` | loopback + own address | `ok=false`, reason recorded, no task created |
| Time window | `[scan.gates].window_start/window_end` | `02:00–05:00` | rejected unless `--force-window` |
| Host concurrency | `[scan.gates].max_hosts` | 4 | rejected |
| Rate limit | `[scan.gates].pps` / plan `rate` | 500 | passed to the engine |
| Free disk | `[scan.gates].min_disk_gb` | 1 GB | rejected |
| Engine availability | adapter `available()` | per engine | engine recorded `not_selected` / `engine_unavailable` |

Loopback targets are always in the allow-list, and a rejected target is a first-class
outcome: `hornworkctl scan run --ip 8.8.8.8` returns `ok=false`, creates nothing, and
leaves an `action_audit` row with the reason.

## 6. The `nmap` adapter

### 6.1 Arguments

```text
nmap -oX - [-sV --version-intensity 7] -T4 --host-timeout <timeout>s \
     --max-retries 2 [--max-rate <rate>] <port spec> <asset.ip>
```

| Option | Value | Note |
|---|---|---|
| `-oX -` | fixed | XML on stdout; the full command is stored in `host_summary.evidence.cmd` |
| `-sV` / `--version-intensity` | `True` / 7 | service detection in the same pass, matching `[scan.nmap].version_intensity` |
| `-T4`, `--max-retries` | fixed, 2 | appropriate for loopback and local networks |
| `--host-timeout` | `ctx.timeout_sec` | profiles: quick 120 s, targeted/verify-fix 300 s, weekly 900 s, full 1800 s |
| `--max-rate` | `ctx.rate_limit` | only passed when set |

> **Scan type.** The adapter does not hard-code `-sS` or `-sT`. When the oneshot unit runs
> as `User=root`, `nmap` performs a SYN half-open scan; under a non-root user it degrades to
> a connect scan automatically. The XML output is identical either way, so parsing and
> matching are unaffected. A SYN scan is visible to the detection side as scanning
> behaviour, which is exactly the self-interference problem that §11 solves. Deployments
> that require strict connect semantics can run the unit as a non-root user.

### 6.2 XML → internal result

| XML node/attribute | Internal field |
|---|---|
| `nmaprun@version` | `host_summary.evidence.nmap_version` |
| `host/address[@addrtype=ipv4]` | `target` (IPv4 preferred) |
| `port@portid,@protocol` | `check_id="PORT-<portid>/<proto>"`, `kind=port` |
| `port/state@state,@reason` | `evidence.state/reason`; only `open` becomes an item, `closed/filtered` are counted |
| `service@name,@product,@version,@extrainfo,@tunnel,@method,@conf` | `evidence.*`; `conf` keeps nmap's own confidence (0–10) |
| `service/cpe` | `evidence.cpe` (prefer `part=a`) / `evidence.cpes` / top-level `cpe` |
| `host/status@state`, `ports/extraports@state,@count` | `host_summary.up`, `closed`, `filtered` |
| `scaninfo@numservices`, `host@starttime,@endtime` | `host_summary.scanned`, `elapsed_ms` |

Component normalisation: the application CPE `product` is lower-cased; without a CPE the
product name is lower-cased and spaces/underscores become `-`. `host_summary` never becomes
a finding — it feeds the checkpoint and the output only, because "how many ports were
scanned" is not "how much was covered".

### 6.3 Port specifications

| `ctx.ports` | Argument | Profile |
|---|---|---|
| `top:200` / `top` / empty | `--top-ports 200` | `quick` |
| `top:1000` | `--top-ports 1000` | `weekly` |
| `1-65535` | `-p 1-65535` | `full` |
| `declared` | `-p <ledger declared_ports>` (falls back to `--top-ports 200`) | `targeted` / `verify-fix` |
| `22,80,18000` | `-p 22,80,18000` | manual / `--check PORT-18000/tcp` |

### 6.4 Timeouts and degradation

| Situation | Behaviour | Task status |
|---|---|---|
| `available()=False` or `rc=127` | `log.warn`, return `[]` | engine `engine_unavailable` → task `partial` |
| Process timeout | `run_capture` returns `rc=-1` with captured stdout, **and the partial XML is still parsed** | engine `error` → task `partial` |
| Non-zero exit | log and continue parsing; results are ingested when present | depends on parse result |
| Malformed / truncated / empty XML | `ET.ParseError` → `[]` + `log.warn` | no exception, the whole scan is not aborted |

### 6.5 Process isolation and licensing

`nmap` is only ever invoked as a separate process: no linking, no source changes, no
copying of its rule database, and only the `-oX -` XML stream is read. `available()` merely
checks whether `[scan.nmap].bin` is executable and never runs a real scan, so unit tests on
a non-Linux developer machine do not spawn a scanner. Licensing follows the distribution
package (`/usr/share/doc/nmap/copyright`); `nmap` is installed by the system package
manager and is not distributed with this project.

## 7. CVE data and three-layer matching

### 7.1 Data sources

| Data | Command | Table | Note |
|---|---|---|---|
| NVD JSON 2.0 (`.json.gz`, records from 2015 onward) | `scan cve import --source nvd --dir <DIR>` or `--file` (repeatable) | `cve_cache` | streaming parse with periodic flush; import result includes `peak_kb` from `tracemalloc` |
| Ubuntu OVAL (`.xml`, `.xml.gz`, `.xml.bz2`) | `scan cve import --source oval --file <OVAL> --release noble` | `scan_oval_fix` | `ET.iterparse` over `dpkg` definitions/states; release from `--release` or inferred |
| Component mapping / exclusions | `scan cve map --file rules/scan/comp_map.csv`; `scan cve exclude --file rules/scan/cve_exclude.csv` | `cve_component_map` / `scan_cve_exclude` | component → CPE prefix maintained by hand; exclusions seed from the repository CSV |

### 7.2 The three layers

1. **Package level (OVAL).** When the fact source is a package manager
   (`dpkg`, `dpkg-query`, `apt`, …) and a release is known, look up `scan_oval_fix` and
   compare `detected < fixed_version` using Debian ordering → `confidence=range`.
   **OVAL data is authoritative when present and never falls back to CPE**, which avoids
   flagging a patched package because its banner still reports the upstream version.
2. **CPE prefix pre-filter.** The `nmap` CPE (or a prefix mapped from `comp_map`) narrows
   `cve_cache.cpe23 LIKE 'prefix%'` with escaped, bound parameters. SQL only narrows the
   candidate set; it never decides a range.
3. **Debian range decision.** Four bounds, left-closed/right-open, using the archive's
   comparator (no second implementation). With no bounds, the layer degrades to a
   `cpe_version` equality check where `*`, `-` and empty are wildcards.

### 7.3 Confidence, exclusions and archive override

| Confidence | Condition | Handling |
|---|---|---|
| `range` | inside an explicit range (CPE bounds or OVAL `detected < fixed`) | becomes a finding with status `new` |
| `exact` | equal to the CPE version, or equal after truncating the detected version to the CPE version length | becomes a finding with status `new` |
| `cpe_only` | only vendor:product matched, no comparable version | recorded as `observed`, never alerts; capped by `[scan.cve].max_cpe_only` (default 100) per fact |

- When several rows match the same CVE, the highest confidence wins (`range > exact >
  cpe_only`); the reason (range text, prefix, candidate count) is stored in `evidence_json`;
- Exclusions match either `(cve_id, comp_norm, normalised_version)` exactly or
  `(cve_id, comp_norm)` for all versions; hits increment `stats.excluded`;
- **Archive override.** `runner._archive_map()` loads `{cve: {id, cvss_score, severity, fix, title}}`
  from the vulnerability archive. A match makes the archive authoritative for CVSS, severity,
  title and remediation (`cvss_source='vuln'`, `vuln_ref` set); otherwise the NVD score is used
  (`cvss_source='nvd'`, marked "record pending"). OVAL hits without CVSS borrow the highest
  score for that CVE from `cve_cache`.

## 8. Snapshot freeze and four-state diff

A snapshot is a frozen copy of `scan_snapshot_item` rows. `scan_finding` means *current*;
using it to compare against history would project today's state onto yesterday's world.
That semantic conflict is why the frozen table exists.

```text
_classify(prev, cur):
  prev missing                      → new
  cur missing                       → fixed
  cur.status = reopened or
    prev.status = fixed             → regressed
  otherwise                         → persisting
```

- Output: `{cur, prev, ts, items[], stats{new,fixed,persisting,regressed,total}, by_severity{5 levels}}`;
  `stats` is persisted to `scan_diff_stat` (idempotent overwrite for the same pair; the read-only
  Web query passes `write_stat=False` and writes nothing);
- Ordering: `regressed → new → persisting → fixed`, then by severity, then by CVSS descending;
- Three uses: single-step (vs previous), phase (before vs after hardening), trend (three to six
  consecutive snapshots from `scan_diff_stat`).

Useful commands:

```bash
sudo hornworkctl scan snapshot list
sudo hornworkctl scan snapshot base --id <snapshot_id>   # freeze a baseline
sudo hornworkctl scan diff --from <older_snapshot> --to <newer_snapshot>
```

## 9. Weighted coverage (D1–D6)

```text
cell covered = 1.0  checkpoint.domains[D].status == done
             = 0.5  partial (engine unavailable / partial failure / empty CVE database)
             = 0    skipped / error / missing

coverage = Σ_asset Σ_domain (w_D × covered) / Σ_asset Σ_domain (w_D × applicable)
```

| Domain | Name | Primary engine |
|---|---|---|
| D1 | ports and services | nmap |
| D2 | operating-system patch CVEs | dpkg-query + OVAL/NVD |
| D3 | application-component CVEs | nmap CPE + CPE mapping |
| D4 | host configuration baseline | Lynis |
| D5 | TLS configuration | testssl adapter (optional) |
| D6 | web PoC | nuclei adapter (optional) |

| Item | Default |
|---|---|
| Domain weights | D1 0.15 / D2 0.30 / D3 0.20 / D4 0.15 / D5 0.10 / D6 0.10, overridable via `[scan.coverage.weights]` |
| Role → domains | `self/server/linux` = D1–D6; `lab` = D1/D3/D6; `web` = D1/D3/D5/D6; `workstation/windows` = D1/D3/D5; `network` = D1; others = D1/D3, overridable via `[scan.coverage.role_domains]` |
| Denominator | ledger assets with `enabled=1`; an asset not included in this run counts as 0 with the reason "asset not included in this run" |
| Uncovered list | every cell with `covered < 1`, with the checkpoint reason (`cve_cache_empty`, engine unavailable, …) |

The function returns `coverage` (0–1), `by_domain`, `matrix` (per asset, per domain, plus
`score`), `uncovered` and `weights`. A missing snapshot returns `coverage=0` with a full
uncovered list and an `error` field — it does not raise.

## 10. Self-contained HTML output

`hornworkctl scan report --snapshot <id> --format html` renders a **single file** with five
tables: assets, findings, diff, coverage, and per-engine contribution. Styles and data are
inlined, so the file opens without a server, without JavaScript, and without network access;
JSON output is available for automation. The output is meant to be attached to a ticket and
read by a human, and it carries the evidence needed to explain every number in it.

## 11. Scan-window self-interference governance

A scanner is supposed to look like an attacker; the detection side is supposed to alert on
attackers. Instead of disabling rules, the subsystem publishes a window and the detection
side downgrades **only** the scanner's own traffic inside it.

| Step | Implementation |
|---|---|
| Publish | `runner._emit_window("start"/"end")` → `event_type=scan_window` with `phase/run_id/plan_id/start/end/src_ips/dst_ips/window_sec/profile/port_spec/engines`; `src_ips` covers loopback, `[scan].local_ips` and local interface addresses |
| Cache | the daemon starts `ScanWindowGate` and refreshes it from the last two hours (max 500 window events) every `[scan.gates].window_refresh_sec` (10 s) |
| Decide | after `netrules.evaluate` produces a `Hit`, `scan_gate.suppress(rule_id, src_ip, dst_ip)` skips it when the rule is in `[scan].window_suppress_rules` **and** the destination is in the window's `dst_ips` **and** the source is in `src_ips` or `dst_ips`; the skip increments `scan_window_suppressed` |
| Bounds | the `end` event is a hard boundary (`start-5 ≤ now ≤ end`); a lone `start` falls back to `window_sec` (600 s); outside the window the same IP alerts as usual |
| Evidence | `netrules.stats()["scan_window_suppressed"]`, window start/end in the `event` table, and `scan.gate` / `scan.run` audit rows |

Principle: **downgrade, never disable**. If window governance fails, the gate object is
`None` and detection proceeds unchanged.

## 12. Deployment and verification

```bash
# 0) prerequisites: venv and hornworkctl installed (scripts/setup.sh)
# 1) nmap is required
sudo apt update && sudo apt install -y nmap && nmap --version | head -1

# 2) idempotent preparation: directories, ledger, plans, timers
sudo bash scripts/setup_scan.sh --no-timer
sudo bash scripts/setup_scan.sh              # add --with-lynis for the host baseline engine

# 3) CVE data (offline; NVD from 2015 onward)
sudo hornworkctl scan cve import --source nvd --dir /var/lib/hornwork/feed
sudo hornworkctl scan cve import --source oval --file /var/lib/hornwork/feed/oval/com.ubuntu.noble.cve.oval.xml.bz2 --release noble
sudo hornworkctl scan cve map --file rules/scan/comp_map.csv
sudo hornworkctl scan cve stats

# 4) ledger and plans
sudo hornworkctl asset list
sudo hornworkctl scan plan list

# 5) manual run through the same entry point the timer uses
sudo hornworkctl scan run --plan weekly-linux --label "baseline"
sudo hornworkctl scan status
sudo hornworkctl scan findings --severity 高
sudo hornworkctl scan coverage --snapshot <snapshot_id>
sudo hornworkctl scan report --snapshot <snapshot_id> --format html --out /opt/hornwork/reports/scan

# 6) a second run to exercise diff and trend
sudo hornworkctl scan run --plan weekly-linux
sudo hornworkctl scan diff

# 7) timers and window-governance evidence
systemctl list-timers 'hornwork-scan*' --no-pager
journalctl -u 'hornwork-scan@*' -n 50 --no-pager
sudo hornworkctl events --type scan_window --limit 10
```

## 13. Reference benchmark

| # | Criterion | Result |
|---|---|---|
| 1 | CVE matching accuracy ≥ 90 % on 20 hand-labelled samples | **100 %**: TP=10, TN=10, FP=0, FN=0 (10 positive + 10 negative boundary samples, [tools/scan_accuracy.py](../tools/scan_accuracy.py)) |
| 2 | False-positive rate ≤ 10 % with reason categories | confidence tiers keep `cpe_only` in `observed` and never alert; of 556 CVE rows in the baseline snapshot, 127 were `exact`/`range` (confirmable) and 471 were CPE-only pending review; manual sampling found 0 false positives |
| 3 | Four-state diff usable across three scans | **yes**: S1→S2 new 0 / fixed 36 / persisting 167; S2→S3 new 5 / persisting 167; S3→S4 new 36 / fixed 1 / persisting 166 / **regressed 5** (Grafana came back after two rounds offline, caught as `reopened`) |
| 4 | Timer fires unattended | **yes**: 3 timers registered (02:30 daily, Sunday 03:00, quarterly); `systemctl start hornwork-scan@daily-quick.service` uses the same `ExecStart`; journal shows completion at 13 480 ms with peak RSS 85.4 MB |
| 5 | Coverage computable, uncovered list available | **89.7 %** overall (D1–D4 = 100 %, D5/D6 = 50 % because those engines were unavailable); 3 uncovered cells: lab D6, self D5, self D6 |
| 6 | Scanning does not trigger false alerts | **governance works**: in an A/B comparison the same scan produced `N-0101` **+52** with suppression off and **+0** with it on (`scan_window_suppressed` +183); `N-0101` increments were 0 in all four weekly rounds |
| 7 | Out-of-range target rejected and audited | `8.8.8.8` is outside `allow_cidrs` → `ok=false`, no task, `action_audit` row with the reason |
| 8 | Any engine can be disabled without crashing | **pass**: plan-level nmap disable (`--engines pkgs`) → nmap `not_selected`, D1 `skipped`, D2 still produced 72 package-level CVEs (54 confirmable), task `done`, 1.5 s, coverage 44.8 %; unavailable testssl/nuclei leave the task `partial` instead of crashing |

Additional measurements on the same host:

- **Toolchain**: nmap 7.98 for discovery, `dpkg-query` for package facts, Lynis 3.1.6 for
  the host baseline; testssl.sh and nuclei were unavailable (no network access to fetch
  them), so their adapters reported `engine_unavailable` rather than pretending to run;
- **Scan throughput**: a weekly round produced **214** findings (ports 8 / components 21 /
  CVEs 147) in **329 s**, with Lynis host baseline accounting for roughly 300 s; a quick
  round took **8.1 s**;
- **CVE data**: NVD 2.0 **33,098** CVEs / **272,680** affected-range rows (full years
  2015–2017 plus targeted components), `cve_component_map` **66** rows; import 14.3 s with
  57 MB peak RSS; OVAL **44,851** package→fix-version rows, from a 220 MB XML file in 10.5 s
  at 136 MB peak;
- **Memory**: steady-state increment under 50 MB (process peak RSS 80 MB; 169 MB in the
  Lynis scenario);
- **Unit tests**: **156** cases (`test_scan_engines.py` 68, `test_scan_flow.py` 15,
  `test_scan_report.py` 36, `test_scan_cve.py` 37), with external programs mocked; the same
  suite is green on Python 3.14 on the reference host.

## 14. Design tradeoffs and boundaries

| # | Decision / boundary | Rationale |
|---|---|---|
| 1 | Single-host dual role | `ast-self` and `ast-lab` share `127.0.0.1` and are separated by `asset_id`/`role`; switching `[scan.pkgs].backend` to `ssh` recovers the two-host topology |
| 2 | `nmap` is a hard dependency | one new external program (`apt install nmap`); offline sites must pre-stage the package; on non-Linux developer machines `available()` is always `False`, so only mocked tests run |
| 3 | testssl / nuclei are optional and not installed by default | they report `engine_unavailable`, the task becomes `partial`, and coverage counts the cell as 0.5 — the system does not pretend the domain was covered |
| 4 | Two finding tables | `scan_finding` (current state) plus `scan_snapshot_item` (frozen items) removes the "one row is both live state and history" conflict |
| 5 | CVE import starts at 2015 | bounds import time and index size; an older CVE that shows up in results is handled as `unknown` (no candidates) and is documented as such |
| 6 | Two event types only | `scan_task` and `scan_window` are emitted; `scan_finding` is deliberately not an event because finding changes are expressed by snapshots and diffs |
| 7 | Container package lists are not collected | the lab asset's D2 is 0 (would need `docker exec dpkg-query`); the uncovered list says so, and this is a candidate enhancement |
| 8 | Root runs produce SYN scans | the oneshot unit needs root for `dpkg`/`lynis`; window governance absorbs the self-traffic (`N-0101` increment 0), and running as a non-root user pins connect semantics |
| 9 | Diff direction is explicit | `--from` is the older baseline and `--to` the newer snapshot, matching intuition; the CLI help says so |
| 10 | Coverage percentages depend on the deployment | the reported 89.7 % reflects the engines installed and the CVE data imported on that host; a different host will produce a different number by design |
| 11 | Rule downgrade is scoped and reversible | only scanning rules listed in `window_suppress_rules`, only inside the window, only for this scanner's source addresses; detection is never disabled |
