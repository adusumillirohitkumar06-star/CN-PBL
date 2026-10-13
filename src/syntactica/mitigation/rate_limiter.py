"""Detector-driven adaptive rate limiting.

This is the *response* layer that turns Syntactica from a detector into a
closed-loop defence. Each source (e.g. client IP) gets its own token bucket
(Unit IV). The twist: a query's **token cost scales with its grammar
surprisal**. Benign-looking queries cost ~1 token; queries the detector flags as
grammar violations cost many tokens.

The effect is exactly what a defender wants:

* a legitimate client sending ordinary queries almost never exhausts its bucket,
  so its goodput is preserved even under attack;
* a source flooding high-surprisal tunnelling/exfil queries drains its bucket
  almost immediately and is throttled — without any global rate cap that would
  punish everyone.

Because the penalty is graded (not a hard block), the occasional false positive
on a legitimate query is absorbed by the bucket rather than dropping the client.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict

from .token_bucket import TokenBucket


@dataclass
class LimiterConfig:
    capacity: float = 20.0
    refill_rate: float = 6.0     # tokens/sec per source
    base_cost: float = 1.0       # cost of a clearly-benign query
    penalty: float = 12.0        # extra cost applied to a flagged (violating) query


@dataclass
class AdaptiveRateLimiter:
    """Per-source token buckets whose admission cost is driven by the detector."""

    config: LimiterConfig = field(default_factory=LimiterConfig)
    buckets: Dict[str, TokenBucket] = field(default_factory=dict)

    def _bucket(self, source: str) -> TokenBucket:
        b = self.buckets.get(source)
        if b is None:
            b = TokenBucket(self.config.capacity, self.config.refill_rate)
            self.buckets[source] = b
        return b

    def cost_for(self, is_violation: bool) -> float:
        return self.config.base_cost + (self.config.penalty if is_violation else 0.0)

    def admit(self, source: str, now: float, is_violation: bool) -> bool:
        """Return True if a query from ``source`` at ``now`` is admitted."""
        return self._bucket(source).allow(now, cost=self.cost_for(is_violation))


@dataclass
class GlobalRateLimiter:
    """A naive single-bucket limiter — the baseline the adaptive one is compared to.

    It polices aggregate traffic with one bucket and no notion of *who* or
    *what*, so it drops legitimate and malicious queries indiscriminately once
    the aggregate rate is exceeded.
    """

    capacity: float = 40.0
    refill_rate: float = 30.0
    bucket: TokenBucket = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.bucket is None:
            self.bucket = TokenBucket(self.capacity, self.refill_rate)

    def admit(self, source: str, now: float, is_violation: bool) -> bool:
        return self.bucket.allow(now, cost=1.0)
