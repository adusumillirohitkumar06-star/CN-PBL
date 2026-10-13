"""Token-bucket rate limiting (Unit IV) and the closed-loop mitigation."""
from syntactica.conformance import ConformanceScorer
from syntactica.data.synth import build_corpus
from syntactica.mitigation import (
    AdaptiveRateLimiter,
    TokenBucket,
    generate_timeline,
    run_comparison,
)
from syntactica.mitigation.rate_limiter import LimiterConfig
from syntactica.models.ngram import NGramGrammar
from syntactica.tokenizer import tokenize


def test_token_bucket_basic():
    b = TokenBucket(capacity=5, refill_rate=1.0)
    # 5 immediate requests fit in the initial capacity, the 6th does not.
    assert sum(b.allow(now=0.0) for _ in range(6)) == 5
    # after 3 seconds, 3 more tokens have refilled
    assert sum(b.allow(now=3.0) for _ in range(4)) == 3


def test_token_bucket_never_exceeds_capacity():
    b = TokenBucket(capacity=10, refill_rate=100.0)
    assert b.level(now=1000.0) == 10  # long idle does not overfill


def test_adaptive_costs_more_for_violations():
    lim = AdaptiveRateLimiter(LimiterConfig(base_cost=1, penalty=10))
    assert lim.cost_for(False) == 1
    assert lim.cost_for(True) == 11


def test_closed_loop_adaptive_beats_global():
    train, _ = build_corpus(6000, 1, seed=0)
    model = NGramGrammar(order=3).fit([tokenize(m) for m in train])
    scorer = ConformanceScorer(model, mode="ngram")
    scorer.calibrate(train, quantile=0.99)

    res = run_comparison(scorer, seed=0)
    none = res["policies"]["none"]
    glob = res["policies"]["global"]
    adap = res["policies"]["adaptive"]

    # No mitigation lets everything through; adaptive blocks most of the attack
    # while keeping legitimate goodput high — and strictly beats the global cap
    # on both axes.
    assert none["attack_blocked"] == 0.0
    assert adap["attack_blocked"] > 0.8
    assert adap["legit_goodput"] > 0.95
    assert adap["legit_goodput"] > glob["legit_goodput"]
    assert adap["attack_blocked"] > glob["attack_blocked"]


def test_timeline_is_deterministic():
    a = [(e.time, e.source, e.is_attack) for e in generate_timeline(seed=0)]
    b = [(e.time, e.source, e.is_attack) for e in generate_timeline(seed=0)]
    assert a == b
