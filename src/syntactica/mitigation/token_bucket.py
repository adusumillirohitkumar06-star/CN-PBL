"""The Token Bucket algorithm (Unit IV: QoS / congestion control).

A textbook token bucket: tokens accrue at ``refill_rate`` per second up to
``capacity``; a request of ``cost`` tokens is admitted only if enough tokens are
available, otherwise it is dropped (or, for a shaper, delayed). This is the
exact algorithm the Computer Networks course covers for traffic policing, used
here as the *response* half of a detect-and-throttle pipeline.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class TokenBucket:
    capacity: float
    refill_rate: float  # tokens per second
    tokens: float = None  # type: ignore[assignment]
    last_time: float = 0.0

    def __post_init__(self) -> None:
        if self.tokens is None:
            self.tokens = self.capacity

    def _refill(self, now: float) -> None:
        if now > self.last_time:
            gained = (now - self.last_time) * self.refill_rate
            self.tokens = min(self.capacity, self.tokens + gained)
            self.last_time = now

    def allow(self, now: float, cost: float = 1.0) -> bool:
        """Admit a request of ``cost`` tokens at time ``now``; True if admitted."""
        self._refill(now)
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False

    def level(self, now: float) -> float:
        """Current token level (after refilling to ``now``), for inspection/plots."""
        self._refill(now)
        return self.tokens
