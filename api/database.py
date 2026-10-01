import datetime
import glob
import logging
import os
import sqlite3
from contextlib import contextmanager

from config import settings

# Prompt source of truth + versioning (see agent_prompts.py)
from agent_prompts import (
    DEFAULT_TRIAGE_PROMPT,
    PROMPT_VERSION,
    LEGACY_DEFAULT_PROMPTS,
)

log = logging.getLogger("db")
DB_PATH = os.path.join(settings.data_dir, "system.db")


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


@contextmanager
def db():
    conn = get_db()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _column_exists(conn, table, column):
    cols = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(row[1] == column for row in cols)


def _index_exists(conn, name):
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='index' AND name=?", (name,)
    ).fetchone() is not None


def backup_db(keep=None):
    """Hot-copy the database via VACUUM INTO; rotate old backups.

    Uses a raw connection: VACUUM cannot run inside a transaction.
    Backups land in DATA_DIR/backups (host: ./data/backups).
    """
    if keep is None:
        keep = settings.backup_keep
    backups_dir = os.path.join(settings.data_dir, "backups")
    os.makedirs(backups_dir, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    path = os.path.join(backups_dir, f"system-{stamp}.db")

    raw = sqlite3.connect(DB_PATH, timeout=30)
    try:
        raw.execute("VACUUM INTO ?", (path,))
    finally:
        raw.close()

    if keep > 0:
        files = sorted(glob.glob(os.path.join(backups_dir, "system-*.db")))
        for old in files[:-keep]:
            try:
                os.remove(old)
            except OSError:
                pass
    return path


def _upgrade_default_prompt(conn):
    """Upgrade the stored AI triage prompt to the current default.

    Replaces the prompt ONLY when it still equals a known legacy
    default (i.e., the user never customized it). Custom prompts are
    never touched. Tracked via settings key 'ai_triage_prompt_ver'.
    """
    row = conn.execute("SELECT value FROM settings WHERE key='ai_triage_prompt'").fetchone()
    ver_row = conn.execute("SELECT value FROM settings WHERE key='ai_triage_prompt_ver'").fetchone()
    try:
        current_ver = int(ver_row["value"]) if ver_row else 0
    except (TypeError, ValueError):
        current_ver = 0

    if current_ver >= PROMPT_VERSION:
        return

    if not row or not (row["value"] or "").strip():
        conn.execute(
            "INSERT OR REPLACE INTO settings (key,value) VALUES ('ai_triage_prompt',?)",
            (DEFAULT_TRIAGE_PROMPT,))
    elif row["value"] == DEFAULT_TRIAGE_PROMPT:
        pass  # already the current default
    elif row["value"] in LEGACY_DEFAULT_PROMPTS:
        conn.execute(
            "UPDATE settings SET value=? WHERE key='ai_triage_prompt'",
            (DEFAULT_TRIAGE_PROMPT,))
        log.info("Upgraded default AI triage prompt to v%d", PROMPT_VERSION)
    else:
        log.info("AI triage prompt is customized; kept unchanged (default v%d not applied)",
                 PROMPT_VERSION)

    conn.execute(
        "INSERT OR REPLACE INTO settings (key,value) VALUES ('ai_triage_prompt_ver',?)",
        (str(PROMPT_VERSION),))


def init_db():
    os.makedirs(settings.data_dir, exist_ok=True)
    conn = get_db()
    try:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS datasources (
                id TEXT PRIMARY KEY,
                name TEXT,
                api_url TEXT,
                auth_header TEXT,
                payload_json TEXT
            );
            CREATE TABLE IF NOT EXISTS correlation_rules (
                id TEXT PRIMARY KEY,
                name TEXT,
                description TEXT,
                prompt TEXT,
                depth TEXT DEFAULT 'standard',
                window_hours INTEGER DEFAULT 24
            );
            CREATE TABLE IF NOT EXISTS vpn_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT DEFAULT '',
                timestamp TEXT DEFAULT '',
                username TEXT DEFAULT '',
                src_ip TEXT DEFAULT 'N/A',
                private_ip TEXT DEFAULT 'N/A',
                action TEXT DEFAULT '',
                raw_event TEXT DEFAULT '',
                risk_score INTEGER DEFAULT 0,
                verdict TEXT DEFAULT 'benign',
                reason TEXT DEFAULT 'normal',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS ad_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT DEFAULT '',
                timestamp TEXT DEFAULT '',
                username TEXT DEFAULT '',
                domain TEXT DEFAULT '',
                src_ip TEXT DEFAULT 'N/A',
                hostname TEXT DEFAULT 'N/A',
                action TEXT DEFAULT '',
                raw_event TEXT DEFAULT '',
                risk_score INTEGER DEFAULT 0,
                verdict TEXT DEFAULT 'benign',
                reason TEXT DEFAULT 'normal',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            );
            CREATE TABLE IF NOT EXISTS geo_cache (
                ip TEXT PRIMARY KEY,
                geo TEXT,
                timezone TEXT DEFAULT '',
                fetched_at TEXT
            );
            CREATE TABLE IF NOT EXISTS incident_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                verdict TEXT,
                reason TEXT,
                created_at TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS auth_sessions (
                token TEXT PRIMARY KEY,
                username TEXT,
                display_name TEXT DEFAULT '',
                is_admin INTEGER DEFAULT 0,
                created_at TEXT DEFAULT '',
                expires_at TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT DEFAULT '',
                details TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS alert_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                alert_key TEXT UNIQUE NOT NULL,
                severity TEXT DEFAULT '',
                sent_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS playbook_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT NOT NULL,
                rule_name TEXT DEFAULT '',
                depth TEXT DEFAULT '',
                status TEXT DEFAULT 'running',
                started_at TEXT DEFAULT '',
                finished_at TEXT DEFAULT '',
                total INTEGER DEFAULT 0,
                analyzed INTEGER DEFAULT 0,
                error TEXT DEFAULT '',
                results_json TEXT DEFAULT '[]'
            );
        ''')

        if not _column_exists(conn, "correlation_rules", "depth"):
            conn.execute("ALTER TABLE correlation_rules ADD COLUMN depth TEXT DEFAULT 'standard'")
        if not _column_exists(conn, "correlation_rules", "window_hours"):
            conn.execute("ALTER TABLE correlation_rules ADD COLUMN window_hours INTEGER DEFAULT 24")
        for table, cols in (
            ("vpn_events", [("risk_score", "INTEGER DEFAULT 0"), ("verdict", "TEXT DEFAULT 'benign'"),
                            ("reason", "TEXT DEFAULT 'normal'"), ("private_ip", "TEXT DEFAULT 'N/A'")]),
            ("ad_events", [("hostname", "TEXT DEFAULT 'N/A'"), ("risk_score", "INTEGER DEFAULT 0"),
                           ("verdict", "TEXT DEFAULT 'benign'"), ("reason", "TEXT DEFAULT 'normal'")]),
        ):
            for col, ddl in cols:
                if not _column_exists(conn, table, col):
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")

        if not _column_exists(conn, "geo_cache", "timezone"):
            conn.execute("ALTER TABLE geo_cache ADD COLUMN timezone TEXT DEFAULT ''")

        # P1-4: one-time normalization of legacy ISO ('T'-separated) timestamps.
        for table in ("vpn_events", "ad_events"):
            cur = conn.execute(
                f"UPDATE OR IGNORE {table} "
                f"SET timestamp = REPLACE(SUBSTR(timestamp, 1, 19), 'T', ' ') "
                f"WHERE timestamp LIKE '____-__-__T%'")
            if cur.rowcount:
                log.info("Migrated %d ISO timestamps in %s", cur.rowcount, table)

        # Dedup is a ONE-TIME migration: once the unique indexes exist,
        # INSERT OR IGNORE makes duplicates impossible. The DELETE below
        # scans the whole table and made every startup slow on large
        # event tables - skip it when indexes are already in place.
        need_dedup = not (_index_exists(conn, "uq_vpn_events")
                          and _index_exists(conn, "uq_ad_events"))
        if need_dedup:
            log.info("Unique indexes missing: running one-time dedup migration")
            for table in ("vpn_events", "ad_events"):
                key = "COALESCE(rule_id,''), COALESCE(timestamp,''), COALESCE(username,''), COALESCE(src_ip,''), COALESCE(action,'')"
                cur = conn.execute(f"DELETE FROM {table} WHERE id NOT IN (SELECT MIN(id) FROM {table} GROUP BY {key})")
                if cur.rowcount:
                    log.info("Dedup: removed %d from %s", cur.rowcount, table)

        conn.executescript('''
            CREATE UNIQUE INDEX IF NOT EXISTS uq_vpn_events
                ON vpn_events(rule_id, timestamp, username, src_ip, action);
            CREATE UNIQUE INDEX IF NOT EXISTS uq_ad_events
                ON ad_events(rule_id, timestamp, username, src_ip, action);
            CREATE INDEX IF NOT EXISTS idx_vpn_ts ON vpn_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_vpn_user_ts ON vpn_events(username, timestamp);
            CREATE INDEX IF NOT EXISTS idx_vpn_action ON vpn_events(action);
            CREATE INDEX IF NOT EXISTS idx_ad_ts ON ad_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_ad_user_ts ON ad_events(username, timestamp);
            CREATE INDEX IF NOT EXISTS idx_ad_action ON ad_events(action);
            CREATE INDEX IF NOT EXISTS idx_alert_log_user ON alert_log(username, sent_at);
            CREATE INDEX IF NOT EXISTS idx_playbook_runs_rule ON playbook_runs(rule_id, id);
        ''')

        _upgrade_default_prompt(conn)
        conn.commit()
    finally:
        conn.close()