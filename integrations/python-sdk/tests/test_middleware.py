"""Pure unit tests for the injectable middleware (no network)."""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dracolure import DracoLureMiddleware, Verdict  # noqa: E402
from dracolure.client import DracoLureError  # noqa: E402


class StubClient:
    def __init__(self, verdict=None, raise_err=False):
        self.verdict = verdict
        self.raise_err = raise_err
        self.calls = []

    def ingest(self, **kw):
        self.calls.append(kw)
        if self.raise_err:
            raise DracoLureError("server down")
        return self.verdict


def _dummy_app(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"ok"]


def _run(mw, env):
    captured = {}
    body = b"".join(mw(env, lambda status, headers: captured.__setitem__("s", status)))
    return captured["s"], body


_ENV = {"REQUEST_METHOD": "GET", "PATH_INFO": "/", "QUERY_STRING": "",
        "REMOTE_ADDR": "1.2.3.4", "HTTP_USER_AGENT": "x"}


def _verdict(**kw):
    base = dict(malicious=False, score=0, severity="none", categories=[],
                recommendation="allow", blocked=False, source_ip="1.2.3.4")
    base.update(kw)
    return Verdict(**base)


def test_block_mode_denies_quarantined_source():
    c = StubClient(verdict=_verdict(blocked=True, recommendation="block"))
    status, _ = _run(DracoLureMiddleware(_dummy_app, c, mode="block"), _ENV)
    assert status.startswith("403")


def test_block_mode_allows_clean_source():
    c = StubClient(verdict=_verdict())
    status, body = _run(DracoLureMiddleware(_dummy_app, c, mode="block"), _ENV)
    assert status.startswith("200") and body == b"ok"


def test_block_mode_fail_open_when_server_down():
    c = StubClient(raise_err=True)
    status, _ = _run(DracoLureMiddleware(_dummy_app, c, mode="block", fail_open=True), _ENV)
    assert status.startswith("200")


def test_block_mode_fail_closed_when_server_down():
    c = StubClient(raise_err=True)
    status, _ = _run(DracoLureMiddleware(_dummy_app, c, mode="block", fail_open=False), _ENV)
    assert status.startswith("403")


def test_monitor_mode_reports_and_passes_through():
    c = StubClient(verdict=_verdict())
    status, body = _run(DracoLureMiddleware(_dummy_app, c, mode="monitor"), _ENV)
    assert status.startswith("200") and body == b"ok"
    time.sleep(0.25)  # monitor reports on a background thread
    assert len(c.calls) == 1


def test_extract_prefers_x_forwarded_for():
    c = StubClient(verdict=_verdict(blocked=True, recommendation="block"))
    env = dict(_ENV, HTTP_X_FORWARDED_FOR="9.9.9.9, 1.1.1.1")
    _run(DracoLureMiddleware(_dummy_app, c, mode="block"), env)
    assert c.calls[-1]["source_ip"] == "9.9.9.9"
