"""Online, self-learning DNS anomaly detection.

The batch detector learns a grammar once. Real networks drift: new internal
services appear, traffic mixes change. A frozen model slowly goes stale and
starts false-alarming on perfectly benign novelty.

``OnlineDetector`` keeps learning from the live stream. For each query it:

1. scores conformance against the current grammar;
2. flags it if the score exceeds the current (rolling) threshold;
3. **self-trains** — learns from the query *only if it is not an extreme
   outlier* (a gate that keeps an attack flood from poisoning the model);
4. periodically **decays** old counts so the grammar tracks recent traffic; and
5. recalibrates the threshold on a sliding window of recent scores.

This is genuine continual, unsupervised self-learning: no labels, and the model
is the self-updating **Knowledge** component of the MAPE-K loop.
"""
from __future__ import annotations

from collections import Counter, deque
from typing import List

import numpy as np

from .conformance import Decision
from .data.schema import DnsMessage, DnsQuestion, labels_of
from .models.ngram import NGramGrammar
from .tokenizer import tokenize


class OnlineDetector:
    def __init__(
        self,
        order: int = 3,
        window: int = 1500,
        warmup: int = 400,
        quantile: float = 0.99,
        decay_factor: float = 0.997,
        decay_every: int = 400,
        repeat_k: int = 5,
    ):
        self.model = NGramGrammar(order)
        self.window: deque = deque(maxlen=window)
        self.warmup = warmup
        self.quantile = quantile
        self.decay_factor = decay_factor
        self.decay_every = decay_every
        self.repeat_k = repeat_k
        self.threshold = float("inf")
        self.n = 0
        # Rolling count of recently-seen second-level domains, to tell a
        # repeating new *service* (benign drift) from unique high-entropy
        # attack queries (which never recur).
        self._sld_hist: deque = deque(maxlen=window)
        self._sld_counts: Counter = Counter()

    def _recalibrate(self) -> None:
        if len(self.window) >= 30:
            self.threshold = float(np.quantile(self.window, self.quantile))

    @staticmethod
    def _sld(msg: DnsMessage) -> str:
        labels = labels_of(msg.primary_qname)
        return ".".join(labels[-2:]) if len(labels) >= 2 else (labels[0] if labels else "")

    def _track_sld(self, sld: str) -> int:
        if len(self._sld_hist) == self._sld_hist.maxlen:
            old = self._sld_hist[0]
            self._sld_counts[old] -= 1
            if self._sld_counts[old] <= 0:
                del self._sld_counts[old]
        self._sld_hist.append(sld)
        self._sld_counts[sld] += 1
        return self._sld_counts[sld]

    def process(self, msg: DnsMessage) -> Decision:
        """Score one message, adapt, and return the decision.

        Learning and calibration are deliberately decoupled:

        * **Calibration** (the threshold) only ever sees *conforming* scores, so a
          transient spike or an attack never inflates it.
        * **Learning** absorbs conforming traffic and *recurring* domains (benign
          drift), but never *extreme* outliers, so an attack flood — whose
          queries are unique and high-entropy — can neither be learned nor raise
          the bar for detecting itself.
        """
        tokens = tokenize(msg)
        self.n += 1
        have_threshold = len(self.window) >= 30
        score = self.model.sequence_nll(tokens) if self.model._vocab else 0.0
        is_violation = have_threshold and score >= self.threshold

        recurs = self._track_sld(self._sld(msg))
        bootstrapping = self.n <= self.warmup and not have_threshold
        conforming = (not have_threshold) or score < self.threshold
        extreme = have_threshold and score > 3.0 * self.threshold

        # Learn: conforming traffic, or a recurring new service — but never an
        # extreme outlier.
        if (bootstrapping or conforming or recurs >= self.repeat_k) and not extreme:
            self.model.observe(tokens)

        # Calibrate: only clearly-benign (conforming, non-extreme) scores.
        if (bootstrapping or conforming) and not extreme:
            self.window.append(score)
            self._recalibrate()

        if self.n % self.decay_every == 0:
            self.model.decay(self.decay_factor)

        return Decision(
            score=score, threshold=self.threshold, is_violation=is_violation, label=msg.label
        )

    def process_stream(self, messages: List[DnsMessage]) -> List[Decision]:
        return [self.process(m) for m in messages]


# --------------------------------------------------------------------------- #
# A reproducible drift scenario for the report/dashboard
# --------------------------------------------------------------------------- #
def _drift_stream(seed: int = 0, warmup: int = 400):
    """Warm-up + generic benign, then a *new internal service* dominates, with
    tunnelling/DGA attacks sprinkled after the (clean) warm-up."""
    import random

    from .data.synth import gen_benign, gen_dga, gen_tunnel

    rng = random.Random(seed)
    benign1 = gen_benign(1500, seed=seed)
    subs = ["dashboard", "api", "login", "assets", "vpn", "mail", "sso", "reports", "cache", "edge"]
    envs = ["prod", "stage", "eu-west", "us-east", "internal"]
    phase2 = [
        DnsMessage(
            questions=[DnsQuestion(
                f"{rng.choice(subs)}.newportal-{rng.choice(envs)}.acmecorp.example", 1, 1
            )],
            label="benign",
        )
        for _ in range(1500)
    ]
    stream = list(benign1) + phase2
    drift_at = len(benign1)
    for a in gen_tunnel(90, seed=seed + 1) + gen_dga(90, seed=seed + 2):
        stream.insert(rng.randint(warmup + 50, len(stream)), a)
    return stream, drift_at


def stream_adaptation_demo(seed: int = 0, warmup: int = 400, bins: int = 40) -> dict:
    """Compare a frozen (static) detector with the online detector under drift.

    Returns headline metrics plus a binned false-alarm time series, showing the
    static model's false alarms spike when benign traffic shifts while the
    online model absorbs the change — and both keep catching attacks.
    """
    from .conformance import ConformanceScorer
    from .models.ngram import NGramGrammar

    stream, drift_at = _drift_stream(seed, warmup)

    static_model = NGramGrammar(order=3).fit([tokenize(m) for m in stream[:warmup]])
    static = ConformanceScorer(static_model, mode="ngram")
    static.calibrate([m for m in stream[:warmup]], quantile=0.99)
    online = OnlineDetector(warmup=warmup)

    width = len(stream) / bins
    s_fa = [[0, 0] for _ in range(bins)]
    o_fa = [[0, 0] for _ in range(bins)]
    thr_series = [0.0] * bins
    agg = {"static": {"drift_fa": [0, 0], "atk": [0, 0]},
           "online": {"drift_fa": [0, 0], "tun": [0, 0], "dga": [0, 0]}}
    for i, m in enumerate(stream):
        ds = static.decide(m)
        do = online.process(m)
        b = min(bins - 1, int(i / width))
        thr_series[b] = round(online.threshold, 3) if online.threshold != float("inf") else 0.0
        if m.label == "benign":
            s_fa[b][1] += 1
            s_fa[b][0] += ds.is_violation
            o_fa[b][1] += 1
            o_fa[b][0] += do.is_violation
            if i >= drift_at:
                agg["static"]["drift_fa"][1] += 1
                agg["static"]["drift_fa"][0] += ds.is_violation
                agg["online"]["drift_fa"][1] += 1
                agg["online"]["drift_fa"][0] += do.is_violation
        else:
            agg["static"]["atk"][1] += 1
            agg["static"]["atk"][0] += ds.is_violation
            if m.label == "tunnel":
                agg["online"]["tun"][1] += 1
                agg["online"]["tun"][0] += do.is_violation
            if m.label == "dga":
                agg["online"]["dga"][1] += 1
                agg["online"]["dga"][0] += do.is_violation

    def rate(a):
        return round(a[0] / a[1], 4) if a[1] else 0.0

    def series(rows):
        return [round(r[0] / r[1], 4) if r[1] else 0.0 for r in rows]

    online_atk = agg["online"]["tun"][0] + agg["online"]["dga"][0]
    online_atk_n = agg["online"]["tun"][1] + agg["online"]["dga"][1]
    return {
        "scenario": {"events": len(stream), "drift_bin": int(drift_at / width), "warmup": warmup},
        "static": {"drift_false_alarm": rate(agg["static"]["drift_fa"]),
                   "attack_recall": rate(agg["static"]["atk"])},
        "online": {"drift_false_alarm": rate(agg["online"]["drift_fa"]),
                   "attack_recall": round(online_atk / max(online_atk_n, 1), 4),
                   "tunnel_recall": rate(agg["online"]["tun"]),
                   "dga_recall": rate(agg["online"]["dga"])},
        "timeseries": {
            "static_fa": series(s_fa), "online_fa": series(o_fa), "threshold": thr_series,
        },
    }
