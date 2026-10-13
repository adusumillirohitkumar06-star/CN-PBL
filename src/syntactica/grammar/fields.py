"""Localise *where* in a message the grammar was violated.

A scalar anomaly score tells you *that* a packet is strange; a per-token
surprisal profile tells you *where* — which is what an analyst actually needs.
This module turns the n-gram scorer's per-token surprisal into a segmented
profile: each token is tagged with its structural role (header field, label
length, payload character, separator) and its surprisal in nats.

The dashboard renders this as a heatmap over the packet, so a tunnel lights up
along its ``xxl`` payload run and a malformed packet lights up on its ``<oovc>``
control byte — an explanation grounded in the protocol, not a saliency map.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

from ..conformance import ConformanceScorer
from ..data.schema import DnsMessage
from ..tokenizer import OOVC, ROOT, SEP


def _role(token: str) -> str:
    if token.startswith(("QR=", "OP=", "QT=", "QC=")) or token == "HAS_ANSWERS":
        return "header"
    if token.startswith("LEN="):
        return "length"
    if token in (SEP, ROOT):
        return "delimiter"
    if token in ("<bos>", "<eos>"):
        return "frame"
    if token == OOVC:
        return "illegal"
    return "payload"


@dataclass
class FieldCell:
    token: str
    role: str
    surprisal: float


def field_profile(msg: DnsMessage, scorer: ConformanceScorer) -> List[FieldCell]:
    """Return the per-token surprisal profile with structural role tags."""
    pairs = scorer.explain(msg)
    return [FieldCell(token=t, role=_role(t), surprisal=round(s, 4)) for t, s in pairs]


def hotspot(profile: List[FieldCell]) -> FieldCell | None:
    """The single most surprising token — the grammar's 'smoking gun'."""
    payload = [c for c in profile if c.role not in ("frame",)]
    return max(payload, key=lambda c: c.surprisal) if payload else None
