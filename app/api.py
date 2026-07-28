"""DracoLure integration API (``/api/v1``).

This is the surface other systems bind to. A thin agent injected into any app
(see ``integrations/``) forwards request metadata to ``/api/v1/ingest``; the
detection engine classifies it centrally and returns the verdict, so the
calling app can decide whether to block on its own edge. The desktop console
reads ``/stats`` and ``/events`` and drives ``/block`` / ``/unblock``.

Auth is an optional shared key (``DRACOLURE_API_KEY``). When set, every
``/api/v1`` route requires the ``X-API-Key`` header. When unset (dev default),
the API is open — intended for isolated lab networks only.
"""

from __future__ import annotations

from functools import wraps
from typing import Callable, Optional

from flask import Blueprint, jsonify, request

import database as db

api_bp = Blueprint("api", __name__, url_prefix="/api/v1")

_tracker = None
_ingest: Optional[Callable] = None
_api_key: Optional[str] = None


def init_api(tracker, ingest: Callable, api_key: Optional[str] = None) -> None:
    """Wire the blueprint to the running app's tracker and ingest callback."""
    global _tracker, _ingest, _api_key
    _tracker = tracker
    _ingest = ingest
    _api_key = api_key or None


def _require_key(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if _api_key and request.headers.get("X-API-Key") != _api_key:
            return jsonify({"error": "unauthorized"}), 401
        return fn(*args, **kwargs)

    return wrapper


@api_bp.get("/health")
@_require_key
def api_health():
    return jsonify({"status": "ok", "db": db.ping()}), 200


@api_bp.get("/stats")
@_require_key
def api_stats():
    return jsonify(_tracker.snapshot()), 200


@api_bp.get("/events")
@_require_key
def api_events():
    limit = request.args.get("limit", default=100, type=int)
    min_score = request.args.get("min_score", default=0, type=int)
    return jsonify({"events": db.fetch_events(limit=limit, min_score=min_score)}), 200


@api_bp.post("/ingest")
@_require_key
def api_ingest():
    """Classify a request reported by an external/injected agent.

    Body: {method, path, query, body, user_agent, source_ip}
    Returns the verdict so the caller can enforce on its own edge.
    """
    data = request.get_json(force=True, silent=True) or {}
    source_ip = str(data.get("source_ip") or request.remote_addr or "0.0.0.0")
    detection, state = _ingest(
        ip=source_ip,
        method=str(data.get("method", "GET")),
        path=str(data.get("path", "/")),
        query=str(data.get("query", "")),
        body=str(data.get("body", "")),
        user_agent=str(data.get("user_agent", "")),
    )
    # A source can already be quarantined even when *this* request looks benign
    # (e.g. it earned the block a moment ago). The verdict must reflect that so
    # an injected agent in block mode denies known-hostile sources.
    blocked = bool((state and state.blocked) or _tracker.is_blocked(source_ip))
    return jsonify({
        "source_ip": source_ip,
        "malicious": detection.is_malicious,
        "score": detection.score,
        "severity": detection.severity,
        "categories": detection.categories,
        "matches": detection.matches,
        "blocked": blocked,
        "recommendation": "block" if blocked else (
            "monitor" if detection.is_malicious else "allow"),
    }), 200


@api_bp.post("/block")
@_require_key
def api_block():
    data = request.get_json(force=True, silent=True) or {}
    ip = str(data.get("ip", "")).strip()
    if not ip:
        return jsonify({"error": "ip is required"}), 400
    ttl = data.get("ttl_seconds")
    _tracker.block(ip, ttl_seconds=int(ttl) if ttl is not None else None)
    return jsonify({"ip": ip, "blocked": True}), 200


@api_bp.post("/unblock")
@_require_key
def api_unblock():
    data = request.get_json(force=True, silent=True) or {}
    ip = str(data.get("ip", "")).strip()
    if not ip:
        return jsonify({"error": "ip is required"}), 400
    was_blocked = _tracker.unblock(ip)
    return jsonify({"ip": ip, "blocked": False, "was_blocked": was_blocked}), 200
