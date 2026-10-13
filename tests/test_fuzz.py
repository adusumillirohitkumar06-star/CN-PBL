import pytest

from syntactica.data.synth import build_corpus
from syntactica.fuzz import FuzzHarness, GrammarFuzzer, MockResolver
from syntactica.models.ngram import NGramGrammar
from syntactica.tokenizer import tokenize


def _fuzzer(seed=0):
    train, _ = build_corpus(1500, 1, seed=seed)
    model = NGramGrammar(order=3).fit([tokenize(m) for m in train])
    return GrammarFuzzer(model, seed=seed)


def test_harness_refuses_external_target():
    with pytest.raises(PermissionError):
        FuzzHarness(("8.8.8.8", 53))


def test_harness_allows_loopback():
    FuzzHarness(("127.0.0.1", 5353))  # should not raise


def test_grammar_samples_are_wire_valid():
    from syntactica.data.codec import decode, encode

    fz = _fuzzer()
    for _ in range(25):
        msg = fz.sample_message(temperature=1.0)
        # A pure grammar sample must survive a codec round-trip.
        assert decode(encode(msg)).primary_qname


def test_end_to_end_loop():
    fz = _fuzzer()
    with MockResolver() as resolver:
        harness = FuzzHarness(("127.0.0.1", resolver.port))
        report = harness.run(fz.batch(60, temperature=1.0, mutate_frac=0.3))
    assert report.total == 60
    assert report.outcomes.get("OK", 0) > 0
    assert 0.0 <= report.validity_rate <= 1.0
