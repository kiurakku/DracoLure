"""In-memory threat tracking and self-contained quarantine.

Keeps a rolling per-source-IP threat score. When a source crosses the block
threshold it is quarantined for a fixed TTL — meaning the honeypot answers
*that* source with a tarpit/403 instead of a decoy. This is purely defensive
and local: nothing is sent to the attacker's host and no other system is
touched. It only changes how this honeypot responds to its own traffic.

Thread-safe so it can back Flask's threaded dev/gunicorn workers.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class _Source:
    hits: int = 0
    events: List = field(default_factory=list)  # (timestamp, score) within window
    blocked_until: float = 0.0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)


class ThreatTracker:
    def __init__(
        self,
        block_threshold: int = 100,
        window_seconds: int = 300,
        block_ttl_seconds: int = 600,
    ) -> None:
        self.block_threshold = block_threshold
        self.window_seconds = window_seconds
        self.block_ttl_seconds = block_ttl_seconds
        self._sources: Dict[str, _Source] = {}
        self._lock = threading.Lock()
        self._blocks_total = 0

    def record(self, ip: str, score: int) -> "SourceState":
        """Add ``score`` for ``ip`` and auto-quarantine past the threshold."""
        now = time.time()
        with self._lock:
            src = self._sources.setdefault(ip, _Source())
            src.hits += 1
            src.last_seen = now
            src.events.append((now, score))
            # Drop events that fell out of the rolling window, then re-sum:
            # the score reflects only recent activity, so quiet sources cool off.
            cutoff = now - self.window_seconds
            src.events = [(t, s) for t, s in src.events if t >= cutoff]
            window_score = sum(s for _, s in src.events)
            newly_blocked = False
            if score > 0 and window_score >= self.block_threshold:
                if src.blocked_until <= now:
                    newly_blocked = True
                    self._blocks_total += 1
                src.blocked_until = now + self.block_ttl_seconds
            return SourceState(
                ip=ip,
                score=window_score,
                hits=src.hits,
                blocked=src.blocked_until > now,
                newly_blocked=newly_blocked,
            )

    def is_blocked(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            src = self._sources.get(ip)
            return bool(src and src.blocked_until > now)

    def block(self, ip: str, ttl_seconds: int = None) -> None:
        """Manually quarantine ``ip`` (operator action from API/console)."""
        ttl = self.block_ttl_seconds if ttl_seconds is None else ttl_seconds
        now = time.time()
        with self._lock:
            src = self._sources.setdefault(ip, _Source())
            if src.blocked_until <= now:
                self._blocks_total += 1
            src.blocked_until = now + ttl

    def unblock(self, ip: str) -> bool:
        """Manually release ``ip`` from quarantine. Returns True if it was blocked."""
        now = time.time()
        with self._lock:
            src = self._sources.get(ip)
            was_blocked = bool(src and src.blocked_until > now)
            if src:
                src.blocked_until = 0.0
            return was_blocked

    def snapshot(self) -> Dict[str, object]:
        """Aggregate view for the operator stats endpoint."""
        now = time.time()
        cutoff = now - self.window_seconds
        with self._lock:
            def window_score(src: _Source) -> int:
                return sum(s for t, s in src.events if t >= cutoff)

            blocked = [ip for ip, s in self._sources.items() if s.blocked_until > now]
            top = sorted(
                self._sources.items(), key=lambda kv: window_score(kv[1]), reverse=True
            )[:10]
            return {
                "tracked_sources": len(self._sources),
                "blocked_now": len(blocked),
                "blocks_total": self._blocks_total,
                "block_threshold": self.block_threshold,
                "top_sources": [
                    {
                        "ip": ip,
                        "score": window_score(s),
                        "hits": s.hits,
                        "blocked": s.blocked_until > now,
                    }
                    for ip, s in top
                ],
            }


@dataclass
class SourceState:
    ip: str
    score: int
    hits: int
    blocked: bool
    newly_blocked: bool
