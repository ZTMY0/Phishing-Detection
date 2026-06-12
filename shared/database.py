from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = ROOT / "data" / "phishguard.db"


def _path(custom: str | None) -> Path:
    if not custom:
        return DEFAULT_DB
    p = Path(custom)
    return p if p.is_absolute() else ROOT / p


def get_connection(path: str | None = None) -> sqlite3.Connection:
    p = _path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(p, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS reports (
            id TEXT PRIMARY KEY,
            declared_sender TEXT NOT NULL,
            subject TEXT NOT NULL,
            body_excerpt TEXT NOT NULL,
            urls TEXT NOT NULL DEFAULT '[]',
            has_attachments INTEGER NOT NULL DEFAULT 0,
            submitted_by TEXT NOT NULL,
            submitted_at TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            score INTEGER NOT NULL,
            reasons TEXT NOT NULL DEFAULT '[]',
            flags TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY (submitted_by) REFERENCES users(id)
        );
        CREATE INDEX IF NOT EXISTS idx_reports_submitted_by ON reports(submitted_by);
        CREATE INDEX IF NOT EXISTS idx_reports_risk ON reports(risk_level);
        CREATE INDEX IF NOT EXISTS idx_reports_sender ON reports(declared_sender);
    """)
    conn.commit()


def create_user(conn, email, password_hash, role="user", user_id=None) -> str:
    uid = user_id or str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (id, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
        (uid, email.strip().lower(), password_hash, role, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    return uid


def get_user_by_email(conn, email):
    return conn.execute(
        "SELECT * FROM users WHERE email = ? COLLATE NOCASE", (email.strip().lower(),)
    ).fetchone()


def get_user_by_id(conn, user_id):
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def update_user_role(conn, user_id, role):
    conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
    conn.commit()


def insert_report(conn, record: dict[str, Any]):
    conn.execute(
        """INSERT INTO reports (
            id, declared_sender, subject, body_excerpt, urls, has_attachments,
            submitted_by, submitted_at, risk_level, score, reasons, flags
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            record["id"], record["declared_sender"], record["subject"], record["body_excerpt"],
            json.dumps(record.get("urls", [])),
            1 if record.get("has_attachments") else 0,
            record["submitted_by"], record["submitted_at"],
            record["risk_level"], record["score"],
            json.dumps(record.get("reasons", [])),
            json.dumps(record.get("flags", {})),
        ),
    )
    conn.commit()


def _row(row, full=False):
    data = {
        "id": row["id"],
        "declared_sender": row["declared_sender"],
        "subject": row["subject"],
        "submitted_at": row["submitted_at"],
        "risk_level": row["risk_level"],
        "score": row["score"],
        "submitted_by": row["submitted_by"],
    }
    if full:
        data.update(
            body_excerpt=row["body_excerpt"],
            urls=json.loads(row["urls"]),
            has_attachments=bool(row["has_attachments"]),
            reasons=json.loads(row["reasons"]),
            flags=json.loads(row["flags"]),
        )
    return data


def get_report(conn, report_id):
    row = conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    return _row(row, full=True) if row else None


def list_reports(conn, *, uid=None, sender=None, risk=None, keyword=None, limit=50):
    clauses, params = [], []
    if uid:
        clauses.append("submitted_by = ?")
        params.append(uid)
    if risk in ("low", "medium", "high"):
        clauses.append("risk_level = ?")
        params.append(risk)
    if sender:
        clauses.append("declared_sender = ?")
        params.append(sender)
    if keyword:
        kw = f"%{keyword.lower()}%"
        clauses.append("(LOWER(subject) LIKE ? OR LOWER(body_excerpt) LIKE ?)")
        params.extend([kw, kw])

    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(limit)
    return [_row(r) for r in conn.execute(
        f"SELECT * FROM reports{where} ORDER BY submitted_at DESC LIMIT ?", params
    ).fetchall()]


def report_stats(conn):
    stats = {"total": 0, "low": 0, "medium": 0, "high": 0}
    for row in conn.execute("SELECT risk_level, COUNT(*) AS n FROM reports GROUP BY risk_level"):
        stats[row["risk_level"]] = row["n"]
        stats["total"] += row["n"]
    return stats
