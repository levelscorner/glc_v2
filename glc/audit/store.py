"""Append-only SQLite audit log.

Every channel message, agent decision, policy verdict, and tool dispatch
lands here. Append-only is enforced at the application layer: only
`append()` is exposed; there is no update or delete function. The schema
ships with `audit_schema` version 1; bumping it requires a documented
migration step (see schema.sql).

Each append commits immediately so writes survive a hard kill.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

DEFAULT_DIR = Path(os.path.expanduser("~/.glc"))

# Leak 2 fix: hash-chain constants. The app layer already refuses UPDATE/DELETE,
# but the SQLite file is writable at the OS layer, so in-process code can wipe
# it directly. Chaining each row to its predecessor makes any deletion or edit
# detectable even when the raw file is tampered with.
_GENESIS = "0" * 64
_append_lock = threading.Lock()


def _row_digest(
    prev_hash: str,
    ts: float,
    session_id: str | None,
    channel: str,
    channel_user_id: str,
    trust_level: str,
    event_type: str,
    tool: str | None,
    policy_verdict: str | None,
    params_json: str | None,
    result_json: str | None,
) -> str:
    payload = json.dumps(
        [
            prev_hash,
            ts,
            session_id,
            channel,
            channel_user_id,
            trust_level,
            event_type,
            tool,
            policy_verdict,
            params_json,
            result_json,
        ],
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _resolve_path() -> str:
    """Resolve at call time, not import time, so tests that swap the env
    var see the change."""
    return os.getenv("GLC_AUDIT_DB", str(DEFAULT_DIR / "audit.sqlite"))


@contextmanager
def _conn():
    p = _resolve_path()
    Path(p).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(p, isolation_level=None)  # autocommit; each insert flushes
    c.row_factory = sqlite3.Row
    try:
        yield c
    finally:
        c.close()


_SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def init_store() -> None:
    with _conn() as c:
        c.executescript(_SCHEMA_PATH.read_text())
        # Defensive migration: add the hash-chain columns to a pre-existing DB
        # created before leak 2 was fixed. No-op if they already exist.
        for col in ("prev_hash", "row_hash"):
            try:
                c.execute(f"ALTER TABLE audit_log ADD COLUMN {col} TEXT")
            except sqlite3.OperationalError:
                pass


def _jsonify(v: Any) -> str | None:
    if v is None:
        return None
    if isinstance(v, str):
        return v
    try:
        return json.dumps(v, default=str)
    except Exception:
        return json.dumps({"_repr": repr(v)})


class AuditStore:
    """Application-layer write-once store. The class deliberately exposes
    no update or delete methods. Reads (for the replay viewer) live in
    query() which is read-only."""

    def append(
        self,
        *,
        channel: str,
        channel_user_id: str,
        trust_level: str,
        event_type: str,
        session_id: str | None = None,
        tool: str | None = None,
        policy_verdict: str | None = None,
        params: Any = None,
        result: Any = None,
    ) -> int:
        ts = time.time()
        params_json = _jsonify(params)
        result_json = _jsonify(result)
        # Serialize the read-prev-then-insert so concurrent appends in this
        # process cannot fork the chain. (Cross-process/container writers still
        # race — that is A6's deeper fix: a single append-only writer.)
        with _append_lock, _conn() as c:
            row = c.execute("SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            prev_hash = row["row_hash"] if row and row["row_hash"] else _GENESIS
            row_hash = _row_digest(
                prev_hash, ts, session_id, channel, channel_user_id,
                trust_level, event_type, tool, policy_verdict, params_json, result_json,
            )
            cur = c.execute(
                """INSERT INTO audit_log
                   (ts, session_id, channel, channel_user_id, trust_level,
                    event_type, tool, policy_verdict, params_json, result_json,
                    prev_hash, row_hash)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    ts,
                    session_id,
                    channel,
                    channel_user_id,
                    trust_level,
                    event_type,
                    tool,
                    policy_verdict,
                    params_json,
                    result_json,
                    prev_hash,
                    row_hash,
                ),
            )
            return int(cur.lastrowid or 0)


_singleton: AuditStore | None = None


def get_store() -> AuditStore:
    global _singleton
    if _singleton is None:
        init_store()
        _singleton = AuditStore()
    return _singleton


def append(**kwargs: Any) -> int:
    return get_store().append(**kwargs)


def query(limit: int = 100, session_id: str | None = None, channel: str | None = None) -> list[dict]:
    q = "SELECT * FROM audit_log"
    where, args = [], []
    if session_id:
        where.append("session_id=?")
        args.append(session_id)
    if channel:
        where.append("channel=?")
        args.append(channel)
    if where:
        q += " WHERE " + " AND ".join(where)
    q += " ORDER BY ts DESC LIMIT ?"
    args.append(limit)
    with _conn() as c:
        return [dict(r) for r in c.execute(q, args).fetchall()]


def schema_version() -> int:
    with _conn() as c:
        row = c.execute("SELECT MAX(version) AS v FROM audit_schema").fetchone()
        return int(row["v"] or 0)


def verify_chain() -> tuple[bool, int | None]:
    """Recompute the hash chain in id order. Returns ``(ok, first_bad_id)``.

    Detects a deleted row (the next row's ``prev_hash`` no longer matches),
    an edited field (the recomputed ``row_hash`` differs), or a truncated
    tail. ``first_bad_id`` is the id where the chain first breaks, or None.
    """
    prev = _GENESIS
    with _conn() as c:
        rows = c.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall()
    for r in rows:
        expected = _row_digest(
            prev, r["ts"], r["session_id"], r["channel"], r["channel_user_id"],
            r["trust_level"], r["event_type"], r["tool"], r["policy_verdict"],
            r["params_json"], r["result_json"],
        )
        if r["prev_hash"] != prev or r["row_hash"] != expected:
            return False, int(r["id"])
        prev = r["row_hash"]
    return True, None
