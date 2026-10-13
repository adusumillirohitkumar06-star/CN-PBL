"""The synthetic corpus must be reproducible: same seed => identical bytes.

This guards against the classic footgun of seeding with the builtin ``hash`` of a
string, which is salted per process (PYTHONHASHSEED) and silently makes results
non-reproducible from run to run.
"""
from syntactica.data.synth import build_corpus, gen_dga, gen_malformed, gen_tunnel


def _qnames(messages):
    return [m.primary_qname for m in messages]


def test_corpus_is_deterministic():
    a_train, a_test = build_corpus(1000, 100, seed=0)
    b_train, b_test = build_corpus(1000, 100, seed=0)
    assert _qnames(a_train) == _qnames(b_train)
    assert _qnames(a_test) == _qnames(b_test)
    assert [m.label for m in a_test] == [m.label for m in b_test]


def test_different_seeds_differ():
    _, a = build_corpus(1000, 100, seed=0)
    _, b = build_corpus(1000, 100, seed=1)
    assert _qnames(a) != _qnames(b)


def test_attack_generators_are_seeded():
    assert _qnames(gen_tunnel(50, seed=1)) == _qnames(gen_tunnel(50, seed=1))
    assert _qnames(gen_dga(50, seed=2)) == _qnames(gen_dga(50, seed=2))
    assert _qnames(gen_malformed(50, seed=3)) == _qnames(gen_malformed(50, seed=3))


def test_labels_present():
    _, test = build_corpus(1000, 100, seed=0)
    labels = {m.label for m in test}
    assert "benign" in labels
    assert {"tunnel", "dga", "malformed"} <= labels


def test_training_set_is_benign_only():
    train, _ = build_corpus(1000, 100, seed=0)
    assert all(m.label == "benign" for m in train)
