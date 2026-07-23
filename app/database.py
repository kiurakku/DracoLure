"""Resilient persistence helpers for the honeypot.

Connections are opened per-write and every failure is swallowed with a log
line, mirroring the Go service: a honeypot that crashes because Postgres
blinked is a honeypot that stops watching. If the database is unreachable the
event is still emitted to stdout, so nothing is ever lost silently.
"""

from __future__ import annotations

import logging
import os
from typing import Optional, Sequence

import psycopg2

log = logging.getLogger("honeypot.db")


def get_db_connection():
    return psycopg2.connect(
        host=os.environ.get("POSTGRES_HOST", "db"),
        port=int(os.environ.get("POSTGRES_PORT", "5432")),
        database=os.environ.get("POSTGRES_DB", "honeypot"),
        user=os.environ.get("POSTGRES_USER", "honeypot"),
        password=os.environ.get("POSTGRES_PASSWORD", "honeypot_secret"),
        connect_timeout=int(os.environ.get("POSTGRES_TIMEOUT", "3")),
    )


def ping() -> bool:
    try:
        conn = get_db_connection()
        conn.close()
        return True
    except Exception:  # noqa: BLE001 - health probe must never raise
        return False


def _execute(sql: str, params: Sequence) -> bool:
    try:
        conn = get_db_connection()
        try:
            with conn, conn.cursor() as cur:
                cur.execute(sql, params)
            return True
        finally:
            conn.close()
    except Exception as exc:  # noqa: BLE001 - persistence must not crash serving
        log.warning("db write failed (continuing): %s", exc)
        return False


def record_attack(attack_type: str, source_ip: str) -> bool:
    """Backward-compatible insert for the legacy ``/attack`` endpoint."""
    return _execute(
        "INSERT INTO attacks (attack_type, source_ip, timestamp) "
        "VALUES (%s, %s, NOW())",
        (attack_type, source_ip),
    )


def record_event(
    source_ip: str,
    method: str,
    path: str,
    query: str,
    user_agent: str,
    categories: Sequence[str],
    threat_score: int,
    severity: str,
    payload: str,
    blocked: bool,
) -> bool:
    """Persist one classified honeypot interaction."""
    return _execute(
        "INSERT INTO honeypot_events "
        "(source_ip, method, path, query, user_agent, categories, "
        " threat_score, severity, payload, blocked, timestamp) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, NOW())",
        (
            source_ip, method, path[:2048], query[:2048], user_agent[:512],
            list(categories), threat_score, severity, payload[:2048], blocked,
        ),
    )
