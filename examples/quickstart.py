"""Quickstart: learn a DNS grammar and score traffic in ~20 lines.

Run with:  python examples/quickstart.py
"""
from syntactica.conformance import ConformanceScorer
from syntactica.data.schema import DnsMessage, DnsQuestion
from syntactica.data.synth import build_corpus
from syntactica.models.ngram import NGramGrammar
from syntactica.tokenizer import tokenize

# 1. Build a corpus (benign for training; benign + attacks for testing).
train_benign, test = build_corpus(n_benign=6000, n_attack_each=400, seed=0)

# 2. Learn the grammar of *benign* traffic.
grammar = NGramGrammar(order=3).fit([tokenize(m) for m in train_benign])

# 3. Calibrate a conformance threshold on benign surprisal (no attack labels).
scorer = ConformanceScorer(grammar, mode="ngram")
scorer.calibrate(train_benign, quantile=0.99)
print(f"threshold = {scorer.threshold:.3f} nats/token\n")

# 4. Score a few domains.
probes = [
    ("www.wikipedia.org", 1),
    ("cdn.assets.example.net", 28),
    ("t7f3kd9s0a1m2z4x.tunnel.example.com", 16),  # tunnelling
    ("qzxkvbnmwrtplahs.com", 1),                   # DGA
]
for name, qtype in probes:
    msg = DnsMessage(questions=[DnsQuestion(name, qtype, 1)])
    d = scorer.decide(msg)
    verdict = "VIOLATION" if d.is_violation else "conforms  "
    print(f"{verdict}  score={d.score:5.3f}  {name}")
