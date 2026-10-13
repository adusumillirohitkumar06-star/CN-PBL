"""Grammar-conformance scoring and thresholding.

A conformance score is simply the model's mean per-token surprisal for a
message. The detector is unsupervised: we calibrate a single threshold on
*benign* traffic (a high quantile of benign surprisal) and flag anything above
it. No attack labels are used to fit the detector, which is what lets it catch
families it has never seen.

For the n-gram grammar we can go one better than a scalar: ``explain`` returns
the surprisal of every token, so the UI can point at the exact byte that broke
the grammar — the long ``LEN=xxl`` label of a tunnel, or the ``<oovc>`` control
character of a malformed packet.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import List, Optional, Tuple

import numpy as np

from .data.schema import DnsMessage
from .models.ngram import NGramGrammar
from .tokenizer import Vocab, tokenize


@dataclass
class Decision:
    score: float
    threshold: float
    is_violation: bool
    label: Optional[str] = None


class ConformanceScorer:
    def __init__(self, model, vocab: Optional[Vocab] = None, mode: str = "ngram"):
        if mode not in ("ngram", "transformer"):
            raise ValueError("mode must be 'ngram' or 'transformer'")
        self.model = model
        self.vocab = vocab
        self.mode = mode
        self.threshold: float = float("inf")

    # ------------------------------------------------------------------ #
    def score_message(self, msg: DnsMessage) -> float:
        tokens = tokenize(msg)
        if self.mode == "ngram":
            return self.model.sequence_nll(tokens)
        if self.vocab is None:
            raise ValueError("transformer mode requires a vocab")
        return self.model.sequence_nll(self.vocab.encode(tokens))

    def score_many(self, messages: List[DnsMessage]) -> np.ndarray:
        # Fast path: batched scoring for the Transformer grammar.
        if self.mode == "transformer" and hasattr(self.model, "sequence_nll_batch"):
            seqs = [self.vocab.encode(tokenize(m)) for m in messages]
            return np.array(self.model.sequence_nll_batch(seqs), dtype=float)
        return np.array([self.score_message(m) for m in messages], dtype=float)

    # ------------------------------------------------------------------ #
    def calibrate(self, benign: List[DnsMessage], quantile: float = 0.99) -> float:
        """Set the decision threshold to a high quantile of benign surprisal."""
        scores = self.score_many(benign)
        self.threshold = float(np.quantile(scores, quantile))
        return self.threshold

    def calibrate_conformal(self, calib_benign: List[DnsMessage], alpha: float = 0.01) -> float:
        """Split-conformal calibration with a finite-sample false-positive guarantee.

        Given calibration scores from benign traffic that is *exchangeable* with
        future benign traffic (i.e. a held-out set the model was not fit on), the
        threshold is placed at rank ``ceil((n+1)(1-alpha))`` of the sorted scores.
        Under exchangeability this guarantees the probability a genuinely benign
        query is flagged is at most ``alpha`` — a distribution-free guarantee, no
        Gaussian assumption required (Vovk et al.; Angelopoulos & Bates, 2021).

        Use a calibration set disjoint from the grammar's training data for the
        guarantee to hold.
        """
        scores = np.sort(self.score_many(calib_benign))
        n = len(scores)
        k = min(n, math.ceil((n + 1) * (1 - alpha)))
        self.threshold = float(scores[k - 1])
        return self.threshold

    def decide(self, msg: DnsMessage) -> Decision:
        s = self.score_message(msg)
        return Decision(
            score=s,
            threshold=self.threshold,
            is_violation=s >= self.threshold,
            label=msg.label,
        )

    # ------------------------------------------------------------------ #
    def explain(self, msg: DnsMessage) -> List[Tuple[str, float]]:
        """Per-token surprisal (nats). Only meaningful for the n-gram grammar."""
        if self.mode != "ngram" or not isinstance(self.model, NGramGrammar):
            raise NotImplementedError("token-level explanation is available for the n-gram grammar")
        tokens = tokenize(msg)
        order = self.model.order
        padded = ["<bos>"] * (order - 1) + tokens
        out: List[Tuple[str, float]] = []
        for i in range(order - 1, len(padded)):
            history = padded[:i]
            surprisal = -self.model.token_logprob(history, padded[i])
            out.append((padded[i], surprisal))
        return out
