import os
import sqlite3
import hmac
import hashlib
import datetime as dt

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.environ.get("DATALEAK_DB", os.path.join(ROOT, "logs", "dataleak.db"))
_KEY = os.environ.get("DATALEAK_HASH_KEY", "change-me-in-production").encode()

SCHEMA = """CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    session_id TEXT,
    category TEXT,
    risk_score INTEGER,
    risk_level TEXT,
    action TEXT,
    ml_label TEXT,
    ml_confidence REAL,
    entity_types TEXT,
    prompt_hash TEXT,
    prompt_length INTEGER,
    redacted_text TEXT
)"""


def _conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with _conn() as c:
        c.execute(SCHEMA)


def hash_prompt(prompt: str) -> str:
    return hmac.new(_KEY, prompt.encode("utf-8"), hashlib.sha256).hexdigest()


def log_event(prompt: str, result: dict, session_id: str = "anon") -> int:
    """Store metadata only. The raw prompt is never written."""
    init_db()
    risk = result["risk"]
    with _conn() as c:
        cur = c.execute(
            """INSERT INTO events (ts, session_id, category, risk_score, risk_level, action,
                                   ml_label, ml_confidence, entity_types, prompt_hash,
                                   prompt_length, redacted_text)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), session_id,
             risk["category"], risk["score"], risk["level"], result["action"],
             risk["ml_label"], round(risk["ml_confidence"], 4), ",".join(risk["entity_types"]),
             hash_prompt(prompt), len(prompt), result.get("sanitized_prompt")))
        return cur.lastrowid


def events_df(limit: int = None):
    import pandas as pd
    init_db()
    q = "SELECT * FROM events ORDER BY id DESC" + (f" LIMIT {int(limit)}" if limit else "")
    with _conn() as c:
        return pd.read_sql_query(q, c)


def summary() -> dict:
    init_db()
    out = {"total": 0, "ALLOW": 0, "WARN": 0, "REDACT": 0, "BLOCK": 0}
    with _conn() as c:
        for row in c.execute("SELECT action, COUNT(*) n FROM events GROUP BY action"):
            out[row["action"]] = row["n"]
            out["total"] += row["n"]
    return out


def reset_db():
    init_db()
    with _conn() as c:
        c.execute("DELETE FROM events")
