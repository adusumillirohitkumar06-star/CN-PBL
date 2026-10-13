"""Grammar-guided test-case generation.

The same grammar that detects anomalies can *generate* them. Sampling from the
learned n-gram model at a temperature ``T`` reproduces the Learn&Fuzz tradeoff
(Godefroid et al., ASE'17): low ``T`` yields highly valid, in-distribution
queries that exercise the parser's happy path; high ``T`` yields novel,
boundary-pushing queries more likely to trip it up. Reporting *validity vs
temperature* is the honest fuzzing result — not a vanity crash count.

Three generation strategies are provided:

* ``sample`` — walk the n-gram grammar with temperature ``T``;
* ``mutate_message`` — structural mutations (illegal qtype, over-long label,
  query-with-answers) that violate grammar invariants on purpose;
* ``mutate_bytes`` — wire-level corruption (truncation, length-field tampering,
  bit flips) to stress the *parser* rather than the grammar.
"""
from __future__ import annotations

import random
from typing import List, Union

from ..data.schema import DnsMessage, DnsQuestion, DnsRecord
from ..models.ngram import NGramGrammar
from ..tokenizer import ROOT, SEP

TestCase = Union[DnsMessage, bytes]


class GrammarFuzzer:
    def __init__(self, model: NGramGrammar, seed: int = 0):
        self.model = model
        self.rng = random.Random(seed)
        # Candidate next-tokens = everything the unigram model has ever seen.
        self.vocab: List[str] = sorted(
            {tok for table in model.counts[1].values() for tok in table}
        )

    # ------------------------------------------------------------------ #
    def _sample_next(self, history: List[str], temperature: float) -> str:
        weights = []
        for tok in self.vocab:
            lp = self.model.token_logprob(history, tok) / max(temperature, 1e-3)
            weights.append(lp)
        # softmax over log-probs (numerically stabilised)
        m = max(weights)
        exps = [pow(2.718281828, w - m) for w in weights]
        return self.rng.choices(self.vocab, weights=exps, k=1)[0]

    def sample_tokens(self, temperature: float = 1.0, max_len: int = 80) -> List[str]:
        history = ["<bos>"]
        out = ["<bos>"]
        for _ in range(max_len):
            tok = self._sample_next(history, temperature)
            out.append(tok)
            history.append(tok)
            if tok == "<eos>":
                break
        return out

    @staticmethod
    def _qname_from_tokens(tokens: List[str]) -> str:
        labels, cur = [], []
        for t in tokens:
            if t == SEP:
                if cur:
                    labels.append("".join(cur))
                cur = []
            elif t == ROOT or t == "<eos>":
                if cur:
                    labels.append("".join(cur))
                break
            elif len(t) == 1 and t.isprintable():
                cur.append(t)
            # structural tokens (QR=, LEN=, ...) are skipped for name reconstruction
        return ".".join(x for x in labels if x) or "example.com"

    def sample_message(self, temperature: float = 1.0) -> DnsMessage:
        toks = self.sample_tokens(temperature)
        qtype = 1
        for t in toks:
            if t.startswith("QT="):
                name = t[3:]
                from ..data.schema import QTYPE_CODES

                qtype = QTYPE_CODES.get(name, 1)
                break
        qname = self._qname_from_tokens(toks)
        return DnsMessage(
            txn_id=self.rng.randint(0, 0xFFFF),
            qr=0,
            opcode=0,
            rd=1,
            questions=[DnsQuestion(qname, qtype, 1)],
        )

    # ------------------------------------------------------------------ #
    def mutate_message(self, msg: DnsMessage) -> DnsMessage:
        m = DnsMessage(
            txn_id=msg.txn_id,
            qr=msg.qr,
            opcode=msg.opcode,
            rd=msg.rd,
            questions=list(msg.questions),
        )
        choice = self.rng.randint(0, 3)
        q = m.questions[0]
        if choice == 0:
            m.questions[0] = DnsQuestion(q.qname, self.rng.choice([0, 65535, 41]), q.qclass)
        elif choice == 1:
            over = "".join(self.rng.choice("abcdef") for _ in range(self.rng.randint(64, 130)))
            m.questions[0] = DnsQuestion(over + "." + q.qname, q.qtype, q.qclass)
        elif choice == 2:
            m.answers = [DnsRecord(q.qname, 1, 1, 0, b"\x00\x00\x00\x00")]  # query with answers
        else:
            m.opcode = self.rng.choice([3, 6, 7, 14])  # reserved opcodes
        return m

    def mutate_bytes(self, raw: bytes) -> bytes:
        data = bytearray(raw)
        if not data:
            return bytes(data)
        strategy = self.rng.randint(0, 2)
        if strategy == 0 and len(data) > 12:  # truncate mid-message
            return bytes(data[: self.rng.randint(12, len(data) - 1)])
        if strategy == 1 and len(data) > 5:  # flip a random bit
            i = self.rng.randrange(len(data))
            data[i] ^= 1 << self.rng.randint(0, 7)
            return bytes(data)
        # tamper with the qdcount field to desync the parser
        if len(data) >= 6:
            data[4], data[5] = 0xFF, 0xFF
        return bytes(data)

    # ------------------------------------------------------------------ #
    def batch(self, n: int, temperature: float = 1.0, mutate_frac: float = 0.3) -> List[TestCase]:
        from ..data.codec import encode

        cases: List[TestCase] = []
        for _ in range(n):
            msg = self.sample_message(temperature)
            r = self.rng.random()
            if r < mutate_frac / 2:
                cases.append(self.mutate_message(msg))
            elif r < mutate_frac:
                cases.append(self.mutate_bytes(encode(msg)))
            else:
                cases.append(msg)
        return cases
