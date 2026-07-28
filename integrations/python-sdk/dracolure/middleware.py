"""Injectable WSGI middleware — add DracoLure to any WSGI app in one line.

Wrap your existing Flask / Django / Pyramid / Bottle app and every request is
reported to a DracoLure server for classification. In ``monitor`` mode the
report is fire-and-forget (zero added latency); in ``block`` mode the
middleware waits for the verdict and returns 403 for sources DracoLure has
quarantined.

    from dracolure import DracoLureClient, DracoLureMiddleware
    app.wsgi_app = DracoLureMiddleware(app.wsgi_app,
                                       DracoLureClient("http://dracolure:5000"))

Design guarantees:
- **Fail-open**: if DracoLure is down, the host app keeps serving (configurable).
- **Non-invasive**: the request body stream is never consumed, so it can't
  break downstream handlers. Detection runs on method, path, query, and UA —
  where the overwhelming majority of web attacks live.
"""

from __future__ import annotations

import threading
from typing import Callable, Iterable

from .client import DracoLureClient, DracoLureError

_FORBIDDEN = b"Forbidden"


class DracoLureMiddleware:
    def __init__(
        self,
        app: Callable,
        client: DracoLureClient,
        mode: str = "monitor",   # "monitor" (async report) | "block" (sync)
        fail_open: bool = True,
    ) -> None:
        self.app = app
        self.client = client
        self.mode = mode
        self.fail_open = fail_open

    def _extract(self, environ) -> dict:
        forwarded = environ.get("HTTP_X_FORWARDED_FOR", "")
        source_ip = (forwarded.split(",")[0].strip()
                     if forwarded else environ.get("REMOTE_ADDR", "0.0.0.0"))
        return {
            "method": environ.get("REQUEST_METHOD", "GET"),
            "path": environ.get("PATH_INFO", "/"),
            "query": environ.get("QUERY_STRING", ""),
            "user_agent": environ.get("HTTP_USER_AGENT", ""),
            "source_ip": source_ip,
        }

    def _deny(self, start_response) -> Iterable[bytes]:
        start_response("403 Forbidden", [
            ("Content-Type", "text/plain"),
            ("Content-Length", str(len(_FORBIDDEN))),
        ])
        return [_FORBIDDEN]

    def __call__(self, environ, start_response):
        fields = self._extract(environ)

        if self.mode == "block":
            try:
                verdict = self.client.ingest(**fields)
                if verdict.blocked or verdict.recommendation == "block":
                    return self._deny(start_response)
            except DracoLureError:
                if not self.fail_open:
                    return self._deny(start_response)
        else:
            # monitor: report in the background so the host app isn't slowed.
            threading.Thread(
                target=self._report_quietly, args=(fields,), daemon=True
            ).start()

        return self.app(environ, start_response)

    def _report_quietly(self, fields: dict) -> None:
        try:
            self.client.ingest(**fields)
        except DracoLureError:
            pass  # fail-open: monitoring must never disturb the host app
