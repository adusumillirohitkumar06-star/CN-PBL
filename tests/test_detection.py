"""The core claim: a grammar learned on benign traffic flags attacks it never saw."""
import numpy as np
from sklearn.metrics import roc_auc_score

from syntactica.conformance import ConformanceScorer
from syntactica.data.schema import DnsMessage, DnsQuestion
from syntactica.data.synth import build_corpus
from syntactica.models.ngram import NGramGrammar
from syntactica.tokenizer import tokenize


def _fit_scorer(seed=0):
    # 5k benign is enough for the diverse (pronounceable) benign grammar to be
    # well estimated; the held-out false-positive rate then reflects the regime
    # reported in the README rather than a small-sample artefact.
    train, test = build_corpus(5000, 300, seed=seed)
    model = NGramGrammar(order=3).fit([tokenize(m) for m in train])
    scorer = ConformanceScorer(model, mode="ngram")
    scorer.calibrate(train, quantile=0.99)
    return scorer, test


def test_benign_scores_below_attacks():
    scorer, test = _fit_scorer()
    scores = scorer.score_many(test)
    y = np.array([0 if m.label == "benign" else 1 for m in test])
    assert roc_auc_score(y, scores) > 0.95


def test_obvious_cases():
    scorer, _ = _fit_scorer()
    benign = DnsMessage(questions=[DnsQuestion("www.google.com", 1, 1)])
    tunnel = DnsMessage(questions=[DnsQuestion(
        "mfrggzdfmztwq2lknnwg23tpobyxe43uov3ho6dz.tunnel.example.com", 16, 1)])
    assert not scorer.decide(benign).is_violation
    assert scorer.decide(tunnel).is_violation
    assert scorer.score_message(tunnel) > scorer.score_message(benign)


def test_threshold_controls_false_positives():
    scorer, test = _fit_scorer()
    benign = [m for m in test if m.label == "benign"]
    flagged = sum(scorer.decide(m).is_violation for m in benign)
    # Calibrated at the 99th percentile of *train* benign; on held-out benign the
    # false-positive rate stays in the low single digits.
    assert flagged / len(benign) < 0.08


def test_explanation_points_at_hotspot():
    from syntactica.grammar import field_profile, hotspot

    scorer, _ = _fit_scorer()
    tunnel = DnsMessage(questions=[DnsQuestion(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.tunnel.example.com", 16, 1)])
    hs = hotspot(field_profile(tunnel, scorer))
    assert hs is not None and hs.surprisal > 0
