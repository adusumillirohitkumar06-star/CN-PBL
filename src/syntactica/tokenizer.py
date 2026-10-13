"""Protocol-aware tokenizer: DNS message -> token stream.

The tokenizer *is* the front half of the grammar. Rather than feeding raw
bytes to the model (ET-BERT style), we expose the structure a network engineer
would recognise from a Forouzan header diagram:

    <bos> QR=0 OP=QUERY QT=A QC=IN
          LEN=m  w w w        <sep>
          LEN=l  e x a m p l e <sep>
          LEN=s  c o m          <sep>
    <root> <eos>

Two design choices carry the project:

* **Label-length buckets** (``LEN=…``) make the *shape* of a name a first-class
  token. Benign names have a characteristic length rhythm; tunnelling blows the
  buckets out to ``xxl`` and DGA collapses them to a single ``l``/``xl``. This
  is exactly the signal the extracted automaton reads.
* **A fixed, DNS-legal character alphabet.** Any octet outside ``[a-z0-9-_]`` is
  mapped to ``<oovc>``. Malformed messages with control bytes therefore emit a
  token the grammar has *never* seen in training, so their perplexity spikes for
  a principled reason rather than a memorised blocklist.

The scheme is deliberately simple enough to re-implement in the browser (the
dashboard scores domains client-side against the exported n-gram model).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List

from .data.schema import DnsMessage, labels_of

# Special tokens (ids 0..n are reserved and stable across runs).
PAD, BOS, EOS, UNK = "<pad>", "<bos>", "<eos>", "<unk>"
SEP, ROOT, OOVC = "<sep>", "<root>", "<oovc>"
SPECIALS = [PAD, BOS, EOS, UNK, SEP, ROOT, OOVC]

# DNS-legal hostname characters (RFC 1035 preferred name syntax + common '_').
ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789-_"


def length_bucket(n: int) -> str:
    """Map a DNS label length to a coarse, grammar-relevant bucket."""
    if n <= 0:
        return "LEN=0"
    if n <= 2:
        return "LEN=s"
    if n <= 6:
        return "LEN=m"
    if n <= 15:
        return "LEN=l"
    if n <= 31:
        return "LEN=xl"
    if n <= 63:
        return "LEN=xxl"
    return "LEN=ILLEGAL"  # > 63 octets is not a legal DNS label


def _char_token(ch: str) -> str:
    return ch if ch in ALPHABET else OOVC


def tokenize(msg: DnsMessage) -> List[str]:
    """Turn one DNS message into a flat token stream."""
    q = msg.questions[0] if msg.questions else None
    toks: List[str] = [BOS, f"QR={msg.qr}", f"OP={msg.opcode_name}"]
    if q is not None:
        toks.append(f"QT={q.qtype_name}")
        toks.append(f"QC={q.qclass}")
        # A query that carries answers is itself a structural anomaly; surface it.
        if msg.answers:
            toks.append("HAS_ANSWERS")
        for label in labels_of(q.qname):
            toks.append(length_bucket(len(label)))
            toks.extend(_char_token(c) for c in label.lower())
            toks.append(SEP)
        toks.append(ROOT)
    toks.append(EOS)
    return toks


@dataclass
class Vocab:
    """Bidirectional token<->id map with reserved special ids."""

    stoi: Dict[str, int] = field(default_factory=dict)
    itos: List[str] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.itos)

    def add(self, tok: str) -> int:
        if tok not in self.stoi:
            self.stoi[tok] = len(self.itos)
            self.itos.append(tok)
        return self.stoi[tok]

    def encode(self, tokens: List[str]) -> List[int]:
        unk = self.stoi[UNK]
        return [self.stoi.get(t, unk) for t in tokens]

    def decode(self, ids: List[int]) -> List[str]:
        return [self.itos[i] for i in ids]

    # -- persistence ------------------------------------------------------- #
    def to_json(self) -> str:
        return json.dumps({"itos": self.itos}, ensure_ascii=False)

    @classmethod
    def from_json(cls, text: str) -> "Vocab":
        itos = json.loads(text)["itos"]
        v = cls(stoi={t: i for i, t in enumerate(itos)}, itos=list(itos))
        return v


def build_vocab(messages: List[DnsMessage]) -> Vocab:
    """Construct a vocabulary: specials + alphabet + every structural token seen."""
    v = Vocab()
    for s in SPECIALS:
        v.add(s)
    for c in ALPHABET:
        v.add(c)
    for msg in messages:
        for tok in tokenize(msg):
            v.add(tok)
    return v
