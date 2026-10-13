"""Syntactica — neural protocol grammar for DNS.

Learn the grammar of benign traffic, score conformance to catch anomalies
(tunnelling, DGA, malformed packets), extract an interpretable automaton, and
turn the same grammar around to fuzz a resolver.
"""
from .conformance import ConformanceScorer, Decision
from .data import DnsMessage, build_corpus
from .grammar import LabelLengthAutomaton
from .models import NGramGrammar
from .tokenizer import Vocab, build_vocab, tokenize

__version__ = "0.1.0"

__all__ = [
    "ConformanceScorer",
    "Decision",
    "DnsMessage",
    "LabelLengthAutomaton",
    "NGramGrammar",
    "Vocab",
    "__version__",
    "build_corpus",
    "build_vocab",
    "tokenize",
]
