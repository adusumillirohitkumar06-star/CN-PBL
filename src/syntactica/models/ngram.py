"""An interpolated n-gram language model — the transparent grammar baseline.

This model exists for three reasons:

1. **It always runs.** No PyTorch, no GPU, no training loop — just counting.
   The whole pipeline (and the paper's headline numbers) reproduces on any
   machine in seconds.
2. **It is honest about what a "grammar" is.** An interpolated n-gram model is
   literally a smoothed stochastic regular grammar over the token stream. Its
   per-token surprisal is a principled conformance score.
3. **It is portable.** The fitted model serialises to a small JSON blob and is
   re-implemented verbatim in the dashboard, so a visitor can type a domain and
   get the *same* score the Python pipeline produced.

Smoothing is Jelinek–Mercer interpolation across orders ``1..k`` with a small
uniform floor, which keeps unseen-but-legal tokens finite and unseen-illegal
tokens (``<oovc>``, ``LEN=ILLEGAL``) appropriately surprising.
"""
from __future__ import annotations

import json
import math
from collections import defaultdict
from typing import Dict, List, Sequence, Tuple

# Separator used to serialise a multi-token context to a single JSON string key.
_CTX_SEP = "\u001f"  # ASCII unit separator; never appears inside a token


class NGramGrammar:
    def __init__(self, order: int = 3, lambdas: Sequence[float] | None = None, floor: float = 1e-6):
        self.order = order
        # Interpolation weights for orders k, k-1, ..., 1 (must sum to <= 1).
        self.lambdas = list(lambdas) if lambdas else self._default_lambdas(order)
        self.floor = floor
        self.vocab_size = 0
        # counts[n] maps a context tuple (length n-1) -> {token: count}.
        self.counts: List[Dict[Tuple[str, ...], Dict[str, int]]] = [
            defaultdict(lambda: defaultdict(int)) for _ in range(order + 1)
        ]
        # totals[n] caches sum(counts[n][ctx].values()) so scoring never re-sums.
        self._totals: List[Dict[Tuple[str, ...], int]] = [{} for _ in range(order + 1)]
        # distinct real tokens seen (for the smoothing floor); kept live for online use.
        self._vocab: set = set()

    @staticmethod
    def _default_lambdas(order: int) -> List[float]:
        # Favour the highest order but keep meaningful mass on backoffs.
        base = [0.6, 0.25, 0.1, 0.04, 0.01]
        w = base[:order]
        s = sum(w)
        return [x / s * 0.999 for x in w]

    # ------------------------------------------------------------------ #
    def fit(self, sequences: List[List[str]]) -> "NGramGrammar":
        for seq in sequences:
            self._add(seq, 1.0)
        self.vocab_size = max(len(self._vocab), 1)
        self._recompute_totals()
        return self

    def _add(self, sequence: List[str], weight: float) -> None:
        """Add one token sequence's n-gram counts with a given weight."""
        padded = ["<bos>"] * (self.order - 1) + sequence
        self._vocab.update(sequence)
        for n in range(1, self.order + 1):
            for i in range(len(padded) - n + 1):
                gram = padded[i : i + n]
                self.counts[n][tuple(gram[:-1])][gram[-1]] += weight

    def observe(self, sequence: List[str], weight: float = 1.0) -> "NGramGrammar":
        """Incrementally learn from one sequence (online/streaming updates).

        Keeps the cached totals and vocabulary consistent so the model can be
        scored immediately after — the basis of the online self-learning
        detector, where the grammar adapts to a live traffic stream.
        """
        padded = ["<bos>"] * (self.order - 1) + sequence
        for n in range(1, self.order + 1):
            tn = self._totals[n]
            for i in range(len(padded) - n + 1):
                gram = padded[i : i + n]
                ctx, tok = tuple(gram[:-1]), gram[-1]
                self.counts[n][ctx][tok] += weight
                tn[ctx] = tn.get(ctx, 0) + weight
        self._vocab.update(sequence)
        self.vocab_size = max(len(self._vocab), 1)
        return self

    def decay(self, factor: float = 0.99, floor: float = 0.4) -> None:
        """Exponentially forget old counts (concept-drift adaptation).

        Every count is scaled by ``factor``; counts falling below ``floor`` are
        pruned to bound memory. This lets an online model track a slowly
        changing traffic distribution instead of averaging over all history.
        """
        for n in range(1, self.order + 1):
            for ctx in list(self.counts[n].keys()):
                table = self.counts[n][ctx]
                for tok in list(table.keys()):
                    table[tok] *= factor
                    if table[tok] < floor:
                        del table[tok]
                if not table:
                    del self.counts[n][ctx]
        self._recompute_totals()

    def _recompute_totals(self) -> None:
        """(Re)build the per-context count totals used by scoring."""
        self._totals = [{} for _ in range(self.order + 1)]
        for n in range(1, self.order + 1):
            tn = self._totals[n]
            for ctx, table in self.counts[n].items():
                tn[ctx] = sum(table.values())

    # ------------------------------------------------------------------ #
    def _order_prob(self, n: int, ctx: Tuple[str, ...], tok: str) -> float:
        table = self.counts[n].get(ctx)
        if not table:
            return 0.0
        total = self._totals[n].get(ctx)
        if total is None:  # cache miss (e.g. counts mutated post-fit): compute + store
            total = sum(table.values())
            self._totals[n][ctx] = total
        return table.get(tok, 0) / total if total else 0.0

    def token_logprob(self, history: List[str], tok: str) -> float:
        """Interpolated log-probability of ``tok`` given preceding ``history``."""
        prob = self.floor / self.vocab_size  # uniform floor
        for idx, n in enumerate(range(self.order, 0, -1)):
            lam = self.lambdas[idx] if idx < len(self.lambdas) else 0.0
            if lam == 0.0:
                continue
            ctx = tuple(history[-(n - 1):]) if n > 1 else tuple()
            prob += lam * self._order_prob(n, ctx, tok)
        return math.log(max(prob, 1e-12))

    def sequence_nll(self, seq: List[str]) -> float:
        """Mean negative log-likelihood per token (natural log). Higher = stranger."""
        padded = ["<bos>"] * (self.order - 1) + seq
        total, count = 0.0, 0
        span = self.order - 1  # token_logprob only needs the last (order-1) tokens
        for i in range(self.order - 1, len(padded)):
            history = padded[i - span:i]  # bounded slice, not a growing prefix copy
            total += -self.token_logprob(history, padded[i])
            count += 1
        return total / max(count, 1)

    def perplexity(self, seq: List[str]) -> float:
        return math.exp(self.sequence_nll(seq))

    # ------------------------------------------------------------------ #
    def to_json(self, prune_below: int = 1) -> str:
        """Serialise to a compact JSON blob (pruning rare grams for browser use).

        Contexts are stored as explicit token lists so the format is unambiguous
        and trivially re-parsed in JavaScript.
        """
        payload = {
            "order": self.order,
            "lambdas": self.lambdas,
            "floor": self.floor,
            "vocab_size": self.vocab_size,
            "counts": [],
        }
        for n in range(1, self.order + 1):
            entries = []
            for ctx, table in self.counts[n].items():
                pruned = {t: c for t, c in table.items() if c > prune_below or n == 1}
                if pruned:
                    entries.append([_CTX_SEP.join(ctx), pruned])
            payload["counts"].append(entries)
        return json.dumps(payload, ensure_ascii=False)

    @classmethod
    def from_json(cls, text: str) -> "NGramGrammar":
        d = json.loads(text)
        m = cls(order=d["order"], lambdas=d["lambdas"], floor=d["floor"])
        m.vocab_size = d["vocab_size"]
        for n, entries in enumerate(d["counts"], start=1):
            for ctx_str, table in entries:
                ctx = tuple(ctx_str.split(_CTX_SEP)) if ctx_str else tuple()
                m.counts[n][ctx] = defaultdict(int, table)
        m._recompute_totals()
        return m
