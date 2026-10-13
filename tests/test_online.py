"""Online, self-learning detection: incremental grammar + drift adaptation."""
from syntactica.data.synth import gen_benign
from syntactica.models.ngram import NGramGrammar
from syntactica.online import OnlineDetector, stream_adaptation_demo
from syntactica.tokenizer import tokenize


def test_incremental_observe_matches_batch_fit():
    seqs = [tokenize(m) for m in gen_benign(200, seed=0)]
    batch = NGramGrammar(3).fit(seqs)
    online = NGramGrammar(3)
    for s in seqs:
        online.observe(s)
    probe = tokenize(gen_benign(1, seed=99)[0])
    # Same counts observed => same score (both are exact count models).
    assert abs(batch.sequence_nll(probe) - online.sequence_nll(probe)) < 1e-9


def test_decay_shrinks_counts_and_prunes():
    g = NGramGrammar(3).fit([tokenize(m) for m in gen_benign(300, seed=0)])
    before = sum(sum(t.values()) for t in g.counts[1].values())
    g.decay(factor=0.5, floor=0.4)
    after = sum(sum(t.values()) for t in g.counts[1].values())
    assert after < before


def test_online_detector_runs_and_flags_nothing_on_pure_benign():
    det = OnlineDetector(warmup=200)
    decisions = det.process_stream(gen_benign(1500, seed=1))
    flagged = sum(d.is_violation for d in decisions)
    # A stationary benign stream should produce very few false alarms.
    assert flagged / len(decisions) < 0.05


def test_online_beats_static_under_drift():
    res = stream_adaptation_demo(seed=0)
    # Static model false-alarms heavily once benign traffic shifts...
    assert res["static"]["drift_false_alarm"] > 0.5
    # ...while the online model adapts and keeps false alarms low,
    # yet still catches the great majority of attacks.
    assert res["online"]["drift_false_alarm"] < 0.05
    assert res["online"]["attack_recall"] > 0.85
    assert res["online"]["tunnel_recall"] == 1.0
