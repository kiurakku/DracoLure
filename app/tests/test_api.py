"""Tests for the /api/v1 integration surface (via Flask test client)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("POSTGRES_HOST", "127.0.0.1")
os.environ.setdefault("POSTGRES_PORT", "1")
os.environ.setdefault("POSTGRES_TIMEOUT", "1")

import pytest  # noqa: E402

import api as api_module  # noqa: E402
import main  # noqa: E402


@pytest.fixture
def client():
    return main.app.test_client()


def test_ingest_classifies_sqli(client):
    r = client.post("/api/v1/ingest", json={
        "method": "GET", "path": "/x", "query": "id=1' OR 1=1--",
        "source_ip": "203.0.113.5"})
    d = r.get_json()
    assert d["malicious"] is True
    assert "sql-injection" in d["categories"]
    assert d["recommendation"] in ("monitor", "block")


def test_benign_ingest_allows(client):
    r = client.post("/api/v1/ingest", json={
        "method": "GET", "path": "/home", "source_ip": "203.0.113.6"})
    assert r.get_json()["recommendation"] == "allow"


def test_block_then_ingest_recommends_block(client):
    ip = "203.0.113.9"
    client.post("/api/v1/block", json={"ip": ip})
    d = client.post("/api/v1/ingest", json={
        "method": "GET", "path": "/", "source_ip": ip}).get_json()
    assert d["blocked"] is True
    assert d["recommendation"] == "block"
    client.post("/api/v1/unblock", json={"ip": ip})


def test_unblock_reports_prior_state(client):
    ip = "203.0.113.11"
    client.post("/api/v1/block", json={"ip": ip})
    assert client.post("/api/v1/unblock", json={"ip": ip}).get_json()["was_blocked"] is True


def test_block_requires_ip(client):
    assert client.post("/api/v1/block", json={}).status_code == 400


def test_stats_shape(client):
    d = client.get("/api/v1/stats").get_json()
    assert "tracked_sources" in d and "top_sources" in d


def test_api_key_gating(client, monkeypatch):
    monkeypatch.setattr(api_module, "_api_key", "sekret")
    assert client.get("/api/v1/stats").status_code == 401
    assert client.get(
        "/api/v1/stats", headers={"X-API-Key": "sekret"}).status_code == 200
