"""Closed-loop detect-and-throttle simulation.

Generates a timeline of DNS traffic from many legitimate clients plus a
high-rate tunnelling/exfil source, runs every query through the detector and a
rate limiter, and measures the two numbers that actually matter for a defender:

* **legitimate goodput** — the fraction of benign queries that still get through;
* **attack blocked** — the fraction of exfil queries that are throttled.

Three policies are compared: no mitigation, a naive global token bucket, and the
detector-driven adaptive limiter. The adaptive policy should preserve legitimate
goodput *and* block the attack, which a global cap cannot do.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable, Dict, List

from ..conformance import ConformanceScorer
from ..data.schema import DnsMessage
from ..data.synth import gen_benign, gen_tunnel
from .rate_limiter import AdaptiveRateLimiter, GlobalRateLimiter, LimiterConfig


@dataclass
class SimEvent:
    time: float
    source: str
    msg: DnsMessage
    is_attack: bool


def generate_timeline(
    duration: float = 20.0,
    n_legit_sources: int = 12,
    legit_rate: float = 1.5,       # queries/sec per legitimate client
    exfil_rate: float = 25.0,      # queries/sec from the exfil channel
    seed: int = 0,
) -> List[SimEvent]:
    """Build a deterministic event timeline of benign clients + one exfil source."""
    rng = random.Random(seed)
    benign_pool = gen_benign(4000, seed=seed + 1)
    tunnel_pool = gen_tunnel(2000, seed=seed + 2)
    bi = ti = 0
    events: List[SimEvent] = []

    # Legitimate clients: independent Poisson-ish arrivals.
    for s in range(n_legit_sources):
        src = f"10.0.0.{s + 10}"
        t = rng.expovariate(legit_rate)
        while t < duration:
            events.append(SimEvent(t, src, benign_pool[bi % len(benign_pool)], False))
            bi += 1
            t += rng.expovariate(legit_rate)

    # Exfil source: one busy client tunnelling data out.
    exfil_src = "10.0.6.66"
    t = rng.expovariate(exfil_rate)
    while t < duration:
        events.append(SimEvent(t, exfil_src, tunnel_pool[ti % len(tunnel_pool)], True))
        ti += 1
        t += rng.expovariate(exfil_rate)

    events.sort(key=lambda e: e.time)
    return events


def _run(scorer: ConformanceScorer, timeline: List[SimEvent], limiter) -> Dict:
    legit_total = legit_ok = attack_total = attack_ok = 0
    for ev in timeline:
        is_violation = scorer.decide(ev.msg).is_violation
        admitted = limiter.admit(ev.source, ev.time, is_violation)
        if ev.is_attack:
            attack_total += 1
            attack_ok += int(admitted)
        else:
            legit_total += 1
            legit_ok += int(admitted)
    return {
        "legit_goodput": round(legit_ok / legit_total, 4) if legit_total else 0.0,
        "attack_blocked": round(1 - attack_ok / attack_total, 4) if attack_total else 0.0,
        "legit_total": legit_total,
        "attack_total": attack_total,
    }


def _timeseries(scorer: ConformanceScorer, timeline: List[SimEvent], bins: int = 40) -> Dict:
    """Adaptive-policy admission over time, binned for plotting."""
    limiter = AdaptiveRateLimiter()
    duration = timeline[-1].time if timeline else 1.0
    width = duration / bins
    series = {k: [0] * bins for k in ("legit_ok", "legit_drop", "attack_ok", "attack_drop")}
    for ev in timeline:
        admitted = limiter.admit(ev.source, ev.time, scorer.decide(ev.msg).is_violation)
        b = min(bins - 1, int(ev.time / width))
        if ev.is_attack:
            series["attack_ok" if admitted else "attack_drop"][b] += 1
        else:
            series["legit_ok" if admitted else "legit_drop"][b] += 1
    return {"bin_width_sec": round(width, 3), **series}


def run_comparison(scorer: ConformanceScorer, seed: int = 0) -> Dict:
    """Compare no-mitigation vs global vs adaptive limiting on one timeline."""
    timeline = generate_timeline(seed=seed)

    class _AdmitAll:
        def admit(self, *a, **k):
            return True

    policies: Dict[str, Callable[[], object]] = {
        "none": _AdmitAll,
        "global": GlobalRateLimiter,
        "adaptive": lambda: AdaptiveRateLimiter(LimiterConfig()),
    }
    results = {name: _run(scorer, timeline, factory()) for name, factory in policies.items()}
    return {
        "policies": results,
        "timeseries": _timeseries(scorer, timeline),
        "scenario": {
            "duration_sec": 20.0,
            "legit_sources": 12,
            "exfil_sources": 1,
            "events": len(timeline),
        },
    }
