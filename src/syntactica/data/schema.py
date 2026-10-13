"""Typed representations of DNS messages.

These dataclasses are the boundary between raw bytes (``codec``) and the
learning pipeline (``tokenizer``). They intentionally model only the fields the
grammar cares about, keeping the surface small and well understood.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

# DNS record / query types we care about (RFC 1035 and common extensions).
QTYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}
QTYPE_CODES = {v: k for k, v in QTYPE_NAMES.items()}

QCLASS_NAMES = {1: "IN", 3: "CH", 4: "HS", 255: "ANY"}

# Opcodes and response codes (subset used by the tokenizer).
OPCODE_NAMES = {0: "QUERY", 1: "IQUERY", 2: "STATUS", 4: "NOTIFY", 5: "UPDATE"}
RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}


@dataclass(frozen=True)
class DnsQuestion:
    qname: str
    qtype: int
    qclass: int = 1

    @property
    def qtype_name(self) -> str:
        return QTYPE_NAMES.get(self.qtype, f"TYPE{self.qtype}")


@dataclass(frozen=True)
class DnsRecord:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes = b""

    @property
    def rtype_name(self) -> str:
        return QTYPE_NAMES.get(self.rtype, f"TYPE{self.rtype}")


@dataclass
class DnsMessage:
    """A single DNS message (query or response)."""

    txn_id: int = 0
    qr: int = 0  # 0 = query, 1 = response
    opcode: int = 0
    aa: int = 0
    tc: int = 0
    rd: int = 1
    ra: int = 0
    rcode: int = 0
    questions: List[DnsQuestion] = field(default_factory=list)
    answers: List[DnsRecord] = field(default_factory=list)
    authorities: List[DnsRecord] = field(default_factory=list)
    additionals: List[DnsRecord] = field(default_factory=list)
    label: Optional[str] = None  # ground-truth class for supervised eval, if known

    @property
    def is_query(self) -> bool:
        return self.qr == 0

    @property
    def primary_qname(self) -> str:
        return self.questions[0].qname if self.questions else ""

    @property
    def opcode_name(self) -> str:
        return OPCODE_NAMES.get(self.opcode, f"OP{self.opcode}")

    @property
    def rcode_name(self) -> str:
        return RCODE_NAMES.get(self.rcode, f"RCODE{self.rcode}")


def labels_of(qname: str) -> List[str]:
    """Split a domain name into its labels, dropping the empty root."""
    return [lbl for lbl in qname.rstrip(".").split(".") if lbl]
