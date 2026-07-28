"""Honeypot Flask surface.

Every inbound request is analysed the instant it arrives, classified against
the signature engine, scored, persisted, and — if the source crosses the
threat threshold — quarantined. The service presents deceptive bait so it
looks like a real, vulnerable target while capturing everything an attacker
does. All behaviour is defensive and confined to this process: it observes,
records, and slows hostile sources against its own surface only.
"""

import logging
import os
import time

from flask import Flask, Response, jsonify, request
from prometheus_client import Counter, Histogram, Summary, start_http_server

import database as db
from api import api_bp, init_api
from version import __version__
from decoys import decoy_for
from detection import analyze
from threat import ThreatTracker

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("honeypot")

app = Flask(__name__)

# Endpoints used by orchestration/monitoring — never analysed or quarantined.
_SAFE_PATHS = {"/health", "/metrics", "/favicon.ico"}

tracker = ThreatTracker(
    block_threshold=int(os.environ.get("HONEYPOT_BLOCK_THRESHOLD", "100")),
    window_seconds=int(os.environ.get("HONEYPOT_WINDOW_SECONDS", "300")),
    block_ttl_seconds=int(os.environ.get("HONEYPOT_BLOCK_TTL", "600")),
)
# Tarpit delay (seconds) applied to already-quarantined sources.
_TARPIT_SECONDS = float(os.environ.get("HONEYPOT_TARPIT_SECONDS", "1.5"))

REQUEST_TIME = Summary("request_processing_seconds", "Time spent processing request")
EVENTS = Counter(
    "honeypot_events_total", "Classified honeypot interactions",
    ["category", "severity"],
)
BLOCKS = Counter("honeypot_blocks_total", "Sources placed under quarantine")
TARPITS = Counter("honeypot_tarpit_total", "Requests answered from quarantine")
THREAT_SCORE = Histogram(
    "honeypot_threat_score", "Threat score per interaction",
    buckets=(0, 10, 25, 50, 80, 100),
)


def _client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"


def process_request(ip, method, path, query, body, user_agent):
    """Classify, score, persist, and count one interaction.

    Shared by the live ``before_request`` sentinel and the ``/api/v1/ingest``
    endpoint so on-surface traffic and reports from injected agents are scored
    identically. Returns ``(detection, state)`` — ``state`` is ``None`` for
    benign traffic. Side effects only (metrics, DB, tracker); no HTTP concern.
    """
    # analyze() decode-normalises internally, so encoded payloads
    # (e.g. %27%20OR%201=1) are matched alongside their raw form.
    detection = analyze(
        method=method, path=path, query=query, body=body, user_agent=user_agent,
    )
    if not detection.is_malicious:
        return detection, None

    state = tracker.record(ip, detection.score)
    THREAT_SCORE.observe(detection.score)
    for category in detection.categories:
        EVENTS.labels(category=category, severity=detection.severity).inc()

    db.record_event(
        source_ip=ip, method=method, path=path, query=query, user_agent=user_agent,
        categories=detection.categories, threat_score=detection.score,
        severity=detection.severity, payload=body[:2048], blocked=state.blocked,
    )
    log.warning(
        "intrusion ip=%s score=%s severity=%s categories=%s path=%s%s",
        ip, detection.score, detection.severity,
        ",".join(detection.categories), path,
        " [QUARANTINED]" if state.newly_blocked else "",
    )
    if state.newly_blocked:
        BLOCKS.inc()
    return detection, state


@app.before_request
def sentinel():
    """Analyse, score, persist, and quarantine — before any route runs."""
    path = request.path
    if path in _SAFE_PATHS or path.startswith("/api/v1"):
        return None

    ip = _client_ip()

    # Already quarantined: tarpit the source instead of feeding it more bait.
    if tracker.is_blocked(ip):
        TARPITS.inc()
        time.sleep(_TARPIT_SECONDS)
        return Response("Forbidden", status=403, mimetype="text/plain")

    body = request.get_data(as_text=True, cache=True) or ""
    query = request.query_string.decode("utf-8", "replace")
    ua = request.headers.get("User-Agent", "")

    _, state = process_request(ip, request.method, path, query, body, ua)

    if state and state.newly_blocked:
        TARPITS.inc()
        time.sleep(_TARPIT_SECONDS)
        return Response("Forbidden", status=403, mimetype="text/plain")

    return None


@app.route("/health")
def health():
    return jsonify({
        "status": "ok" if db.ping() else "degraded",
        "name": "DracoLure",
        "version": __version__,
    }), 200


@app.route("/attack", methods=["POST"])
@REQUEST_TIME.time()
def log_attack():
    """Legacy manual-logging endpoint, kept for backward compatibility."""
    data = request.get_json(force=True, silent=True) or {}
    attack_type = data.get("attack_type", "unknown")
    source_ip = data.get("source_ip", _client_ip())
    db.record_attack(attack_type, source_ip)
    return jsonify({"message": "Attack logged successfully"}), 200


@app.route("/honeypot/stats")
def stats():
    """Operator-only aggregate view of live threat activity."""
    return jsonify(tracker.snapshot()), 200


# Wire the /api/v1 integration surface (ingest, stats, events, block/unblock).
def _ingest(ip, method, path, query, body, user_agent):
    return process_request(ip, method, path, query, body, user_agent)


init_api(
    tracker=tracker,
    ingest=_ingest,
    api_key=os.environ.get("DRACOLURE_API_KEY"),
)
app.register_blueprint(api_bp)


@app.route("/", defaults={"path": ""},
           methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
@app.route("/<path:path>",
           methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
def catch_all(path):
    """Serve deceptive bait for anything else; every hit was already logged."""
    bait = decoy_for("/" + path)
    if bait is not None:
        body, content_type, status = bait
        return Response(body, status=status, mimetype=content_type)
    return Response("Not Found", status=404, mimetype="text/plain")


if __name__ == "__main__":
    start_http_server(8000)
    log.info("Honeypot metrics on :8000, surface on :5000")
    app.run(host="0.0.0.0", port=5000)
