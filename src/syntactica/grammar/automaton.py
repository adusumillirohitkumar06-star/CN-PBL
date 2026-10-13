"""Extract an interpretable automaton from the learned grammar.

A neural (or n-gram) language model is a black box; a state machine is not.
This module recovers a *human-readable* stochastic automaton over the shape of
domain names — the sequence of label-length buckets — directly from traffic.

Why label-length shape? Because it is where the three attack families separate
cleanly and legibly:

* benign names walk short, dictionary-length buckets (``m -> l -> s``),
* DGA collapses to one long random label (``xl -> END``),
* tunnelling explodes into a run of ``xxl`` labels.

The automaton is a first-order Markov chain with ``START``/``END`` states. It
serialises to JSON that the dashboard renders as a labelled state diagram, and
it provides an independent, fully transparent anomaly signal to corroborate the
language model.
"""
from __future__ import annotations

import json
import math
from collections import defaultdict
from typing import Dict, List

from ..data.schema import DnsMessage, labels_of
from ..tokenizer import length_bucket

START, END = "START", "END"


class LabelLengthAutomaton:
    def __init__(self):
        self.transitions: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.states: set = {START, END}

    def _path(self, msg: DnsMessage) -> List[str]:
        if not msg.questions:
            return [START, END]
        buckets = [length_bucket(len(lbl)) for lbl in labels_of(msg.questions[0].qname)]
        return [START] + buckets + [END]

    def fit(self, messages: List[DnsMessage]) -> "LabelLengthAutomaton":
        for msg in messages:
            path = self._path(msg)
            for a, b in zip(path, path[1:]):
                self.transitions[a][b] += 1
                self.states.update((a, b))
        return self

    # ------------------------------------------------------------------ #
    def transition_prob(self, a: str, b: str) -> float:
        table = self.transitions.get(a)
        if not table:
            return 0.0
        total = sum(table.values())
        return table.get(b, 0) / total if total else 0.0

    def path_nll(self, msg: DnsMessage, floor: float = 1e-4) -> float:
        """Mean negative log-probability of a message's name-shape path."""
        path = self._path(msg)
        total, count = 0.0, 0
        for a, b in zip(path, path[1:]):
            p = self.transition_prob(a, b)
            total += -math.log(max(p, floor))
            count += 1
        return total / max(count, 1)

    # ------------------------------------------------------------------ #
    def to_dict(self) -> dict:
        """Serialise as nodes + probability-weighted edges for visualisation."""
        edges = []
        for a, table in self.transitions.items():
            total = sum(table.values())
            for b, c in table.items():
                edges.append({"from": a, "to": b, "prob": round(c / total, 4), "count": c})
        order = [START, "LEN=s", "LEN=m", "LEN=l", "LEN=xl", "LEN=xxl", "LEN=ILLEGAL", "LEN=0", END]
        nodes = sorted(self.states, key=lambda s: order.index(s) if s in order else 99)
        return {"nodes": nodes, "edges": edges}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)
