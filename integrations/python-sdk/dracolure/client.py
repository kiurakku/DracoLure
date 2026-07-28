"""Dependency-free HTTP client for the DracoLure API.

Uses only the standard library (``urllib``) so it can be dropped into any
Python service without adding dependencies. Every call fails soft: network or
server errors raise :class:`DracoLureError`, and callers (e.g. the middleware)
decide whether to fail open.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


class DracoLureError(Exception):
    """Raised when the DracoLure API is unreachable or returns an error."""


@dataclass
class Verdict:
    malicious: bool
    score: int
    severity: str
    categories: List[str]
    recommendation: str  # "allow" | "monitor" | "block"
    blocked: bool
    source_ip: str

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Verdict":
        return cls(
            malicious=bool(d.get("malicious")),
            score=int(d.get("score", 0)),
            severity=str(d.get("severity", "none")),
            categories=list(d.get("categories", [])),
            recommendation=str(d.get("recommendation", "allow")),
            blocked=bool(d.get("blocked")),
            source_ip=str(d.get("source_ip", "")),
        )


class DracoLureClient:
    def __init__(
        self,
        base_url: str = "http://localhost:5000",
        api_key: Optional[str] = None,
        timeout: float = 2.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    # -- low-level ---------------------------------------------------------
    def _request(self, method: str, path: str, payload: Optional[dict] = None) -> dict:
        url = f"{self.base_url}/api/v1{path}"
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8") or "{}"
                return json.loads(body)
        except urllib.error.HTTPError as exc:
            raise DracoLureError(f"{exc.code} {exc.reason}") from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise DracoLureError(str(exc)) from exc

    # -- high-level --------------------------------------------------------
    def ingest(
        self,
        method: str = "GET",
        path: str = "/",
        query: str = "",
        body: str = "",
        user_agent: str = "",
        source_ip: str = "",
    ) -> Verdict:
        """Report a request for central classification; returns the verdict."""
        return Verdict.from_dict(self._request("POST", "/ingest", {
            "method": method, "path": path, "query": query, "body": body,
            "user_agent": user_agent, "source_ip": source_ip,
        }))

    def stats(self) -> dict:
        return self._request("GET", "/stats")

    def events(self, limit: int = 100, min_score: int = 0) -> List[dict]:
        return self._request(
            "GET", f"/events?limit={int(limit)}&min_score={int(min_score)}"
        ).get("events", [])

    def block(self, ip: str, ttl_seconds: Optional[int] = None) -> dict:
        payload = {"ip": ip}
        if ttl_seconds is not None:
            payload["ttl_seconds"] = ttl_seconds
        return self._request("POST", "/block", payload)

    def unblock(self, ip: str) -> dict:
        return self._request("POST", "/unblock", {"ip": ip})

    def health(self) -> dict:
        return self._request("GET", "/health")
