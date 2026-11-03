"""认证库：7 张新表的 DDL、策略表读写、与检测模块 共库（同一个 hornwork.db）。

对检测模块 零侵入：全部新表 + 复用 `meta` 存审计链头；不改 `event` / `alert` 结构。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..store import Store, now_utc

AUTH_SCHEMA_VERSION = "1"

DDL: list[str] = [
    """CREATE TABLE IF NOT EXISTS auth_user (
      id                INTEGER PRIMARY KEY AUTOINCREMENT,
      username          TEXT NOT NULL UNIQUE,
      display_name      TEXT,
      password_hash     TEXT NOT NULL,              -- PHC 串，参数随串走
      password_algo     TEXT NOT NULL,              -- argon2id | pbkdf2 | sha1 | md5
      password_ts       TEXT NOT NULL,
      status            TEXT NOT NULL DEFAULT 'active',
      loa_max           INTEGER NOT NULL DEFAULT 3,
      failed_count      INTEGER NOT NULL DEFAULT 0,
      locked_until      TEXT,
      last_totp_counter INTEGER NOT NULL DEFAULT 0, -- 防重放：单调递增
      mfa_enabled       INTEGER NOT NULL DEFAULT 0,
      must_reset        INTEGER NOT NULL DEFAULT 0,
      created_ts        TEXT NOT NULL,
      last_login_ts     TEXT
    )""",
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_auth_user_name ON auth_user(username)",

    """CREATE TABLE IF NOT EXISTS auth_credential (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id       INTEGER NOT NULL REFERENCES auth_user(id) ON DELETE CASCADE,
      kind          TEXT NOT NULL,                  -- totp | webauthn | recovery_code
      label         TEXT,
      secret_enc    BLOB,                           -- AEAD 密文
      nonce         BLOB,
      key_id        INTEGER NOT NULL DEFAULT 1,
      credential_id BLOB,
      public_key    BLOB,
      sign_count    INTEGER NOT NULL DEFAULT 0,
      aaguid        TEXT,
      transports    TEXT,
      active        INTEGER NOT NULL DEFAULT 0,     -- 注册后需输入一次当前码才激活
      created_ts    TEXT NOT NULL,
      last_used_ts  TEXT,
      revoked_ts    TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS ix_auth_cred_user ON auth_credential(user_id, kind)",

    """CREATE TABLE IF NOT EXISTS auth_session (
      session_id      TEXT PRIMARY KEY,
      user_id         INTEGER NOT NULL REFERENCES auth_user(id) ON DELETE CASCADE,
      token_hash      TEXT NOT NULL UNIQUE,          -- sha256(完整令牌)，吊销只需删/改标记
      loa             INTEGER NOT NULL,
      device_id       TEXT,
      ip              TEXT,
      ua_hash         TEXT,
      created_ts      TEXT NOT NULL,
      last_seen_ts    TEXT NOT NULL,
      idle_expires_ts TEXT NOT NULL,
      expires_ts      TEXT NOT NULL,
      strong_auth_ts  TEXT,
      revoked         INTEGER NOT NULL DEFAULT 0,
      revoke_reason   TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS ix_auth_sess_user ON auth_session(user_id, revoked)",
    "CREATE INDEX IF NOT EXISTS ix_auth_sess_exp ON auth_session(expires_ts)",

    """CREATE TABLE IF NOT EXISTS bio_template (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id     INTEGER NOT NULL REFERENCES auth_user(id) ON DELETE CASCADE,
      algo        TEXT NOT NULL,
      model_ver   TEXT NOT NULL,                    -- 换模型必须重标定阈值
      dim         INTEGER NOT NULL DEFAULT 512,
      tmpl_enc    BLOB NOT NULL,                    -- AES-256-GCM(R·e)
      nonce       BLOB NOT NULL,
      key_id      INTEGER NOT NULL DEFAULT 1,
      aad         TEXT NOT NULL,
      quality     REAL,
      created_ts  TEXT NOT NULL,
      revoked_ts  TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS ix_bio_user ON bio_template(user_id) WHERE revoked_ts IS NULL",

    """CREATE TABLE IF NOT EXISTS auth_audit (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      ts          TEXT NOT NULL,
      username    TEXT,
      user_id     INTEGER,
      event       TEXT NOT NULL,                    -- logon | logon_fail | totp_enroll | ...
      factor      TEXT,                             -- pw | totp | bio | captcha | recovery
      result      TEXT NOT NULL,                    -- ok | fail | degraded
      loa         INTEGER,
      risk_score  INTEGER,
      risk_why    TEXT,
      ip          TEXT,
      device_id   TEXT,
      latency_ms  INTEGER,
      detail      TEXT,
      prev_hash   TEXT,
      row_hash    TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS ix_auth_audit_ts ON auth_audit(ts)",
    "CREATE INDEX IF NOT EXISTS ix_auth_audit_user ON auth_audit(username, ts)",
    "CREATE INDEX IF NOT EXISTS ix_auth_audit_event ON auth_audit(event, ts)",

    """CREATE TABLE IF NOT EXISTS auth_policy (
      policy_key TEXT PRIMARY KEY,
      value_json TEXT NOT NULL,
      updated_ts TEXT NOT NULL,
      updated_by TEXT
    )""",

    """CREATE TABLE IF NOT EXISTS trusted_device (
      device_id   TEXT PRIMARY KEY,
      user_id     INTEGER NOT NULL REFERENCES auth_user(id) ON DELETE CASCADE,
      label       TEXT,
      issued_ts   TEXT NOT NULL,
      expires_ts  TEXT NOT NULL,
      revoked     INTEGER NOT NULL DEFAULT 0
    )""",
    "CREATE INDEX IF NOT EXISTS ix_auth_dev_user ON trusted_device(user_id, revoked)",
]


# ---------------------------------------------------------------------------
# 策略默认值：全部落库、可改不硬编码（"改权重做对比测试"的抓手）
# ---------------------------------------------------------------------------
POLICY_DEFAULTS: dict[str, Any] = {
    "argon2.params": {"m": 65536, "t": 3, "p": 4, "hash_len": 32, "salt_len": 16},
    "password.policy": {"min_len": 12, "admin_min_len": 16, "max_len": 128,
                        "blacklist_size": 60},
    "totp": {"step": 30, "digits": 6, "window": 1, "secret_len": 20,
             "issuer": "Hornwork"},
    "session.ttl": {
        "loa2": {"idle": 1800, "absolute": 43200},
        "loa3": {"idle": 900, "absolute": 28800},
    },
    "lockout": {"account_fail": 5, "account_window": 300, "lock_seconds": 900,
                "totp_fail": 5, "totp_window": 300, "totp_lock": 900,
                "ip_rate": 20, "ip_window": 60, "global_rate": 50,
                "global_window": 60},
    "risk.weights": {"new_device": 20, "ip_change": 15, "ioc_ip": 30,
                     "fail_each": 10, "fail_cap": 30, "unusual_time": 10,
                     "totp_fail": 15, "known_device": -20,
                     "session_ip_drift": 25},
    "risk.thresholds": {"loa3": 30, "warn": 60, "lock": 80},
    "bio": {"threshold": 0.35, "quality_min": 0.5, "dim": 512,
            "model_ver": "arcface-r50/dev", "algo": "revocable-orth"},
}

CHAIN_HEAD_KEY = "auth.audit_head"


def resolve_db_path(cfg: dict) -> Path:
    from ..config import cfg_get

    explicit = cfg_get(cfg, "auth.db_path", "")
    if explicit:
        return Path(str(explicit)).expanduser()
    return Path(str(cfg_get(cfg, "general.data_dir", "/var/lib/hornwork"))) / "hornwork.db"


def open_auth_store(cfg: dict, db_path: str | Path | None = None) -> Store:
    """打开共库并幂等建表（auth_* / bio_* / trusted_device）。"""
    store = Store(Path(db_path) if db_path else resolve_db_path(cfg))
    init_schema(store)
    seed_policy(store)
    return store


def init_schema(store: Store) -> None:
    for stmt in DDL:
        store.execute(stmt)
    store.set_meta("auth.schema_version", AUTH_SCHEMA_VERSION)


# ---------------------------------------------------------------------------
# 策略表
# ---------------------------------------------------------------------------
def seed_policy(store: Store) -> None:
    ts = now_utc()
    for key, value in POLICY_DEFAULTS.items():
        store.execute(
            "INSERT OR IGNORE INTO auth_policy(policy_key, value_json, updated_ts, updated_by)"
            " VALUES(?,?,?,?)",
            (key, json.dumps(value, ensure_ascii=False, sort_keys=True), ts, "default"),
        )


def get_policy(store: Store, key: str, default: Any = None) -> Any:
    if key in POLICY_DEFAULTS:
        default = json.loads(json.dumps(POLICY_DEFAULTS[key]))
    row = store.query_one("SELECT value_json FROM auth_policy WHERE policy_key=?", (key,))
    if not row:
        return default
    try:
        return json.loads(row["value_json"])
    except (TypeError, json.JSONDecodeError):
        return default


def set_policy(store: Store, key: str, value: Any, by: str = "cli") -> None:
    store.execute(
        "INSERT INTO auth_policy(policy_key, value_json, updated_ts, updated_by)"
        " VALUES(?,?,?,?) ON CONFLICT(policy_key) DO UPDATE SET"
        " value_json=excluded.value_json, updated_ts=excluded.updated_ts,"
        " updated_by=excluded.updated_by",
        (key, json.dumps(value, ensure_ascii=False, sort_keys=True), now_utc(), by),
    )


def all_policy(store: Store) -> dict[str, Any]:
    rows = store.query("SELECT policy_key, value_json FROM auth_policy ORDER BY policy_key")
    out: dict[str, Any] = {}
    for row in rows:
        try:
            out[row["policy_key"]] = json.loads(row["value_json"])
        except (TypeError, json.JSONDecodeError):
            out[row["policy_key"]] = row["value_json"]
    return out


def policy_section(store: Store, key: str) -> dict:
    val = get_policy(store, key, {})
    return val if isinstance(val, dict) else {}
