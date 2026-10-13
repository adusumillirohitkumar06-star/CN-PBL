"""A dependency-free DNS wire-format codec (RFC 1035).

Why hand-roll this instead of pulling in ``dnspython`` or ``scapy``? Two
reasons that matter for this project:

1. **Provenance.** The whole thesis of Syntactica is that a protocol *is* a
   grammar. Implementing the encoder/decoder ourselves keeps the byte-level
   grammar visible and auditable rather than hidden behind a dependency.
2. **Zero runtime dependencies.** The core pipeline runs anywhere Python runs.

The decoder handles message compression pointers so it can read real captures;
the encoder emits uncompressed names, which every resolver accepts and which
keeps the grammar-guided fuzzer's output easy to reason about.
"""
from __future__ import annotations

import struct
from typing import List, Tuple

from .schema import DnsMessage, DnsQuestion, DnsRecord


class DnsDecodeError(ValueError):
    """Raised when a byte string is not a well-formed DNS message.

    The fuzzer and pcap loader both rely on this being *specific*: a malformed
    message is a signal, not a crash.
    """


# --------------------------------------------------------------------------- #
# Encoding
# --------------------------------------------------------------------------- #
def _encode_name(name: str) -> bytes:
    """Serialise a domain name to length-prefixed labels.

    Encoding is *total*: it never raises. Non-ASCII input (which on the wire
    would already be punycode) is coerced to ASCII with replacement, and
    over-long labels are truncated to the 63-octet limit. This matters because
    the fuzzer and mock resolver must round-trip adversarial names without the
    codec itself becoming the crash.
    """
    out = bytearray()
    for label in name.rstrip(".").split("."):
        if label == "":
            continue
        raw = label.encode("ascii", "replace")
        if len(raw) > 63:
            raw = raw[:63]
        out.append(len(raw))
        out.extend(raw)
    out.append(0)  # root
    return bytes(out)


def _encode_question(q: DnsQuestion) -> bytes:
    return _encode_name(q.qname) + struct.pack("!HH", q.qtype, q.qclass)


def _encode_record(r: DnsRecord) -> bytes:
    return (
        _encode_name(r.name)
        + struct.pack("!HHIH", r.rtype, r.rclass, r.ttl & 0xFFFFFFFF, len(r.rdata))
        + r.rdata
    )


def encode(msg: DnsMessage) -> bytes:
    """Serialise a :class:`DnsMessage` to DNS wire format."""
    flags = (
        (msg.qr & 1) << 15
        | (msg.opcode & 0xF) << 11
        | (msg.aa & 1) << 10
        | (msg.tc & 1) << 9
        | (msg.rd & 1) << 8
        | (msg.ra & 1) << 7
        | (msg.rcode & 0xF)
    )
    header = struct.pack(
        "!HHHHHH",
        msg.txn_id & 0xFFFF,
        flags,
        len(msg.questions),
        len(msg.answers),
        len(msg.authorities),
        len(msg.additionals),
    )
    body = bytearray()
    for q in msg.questions:
        body.extend(_encode_question(q))
    for section in (msg.answers, msg.authorities, msg.additionals):
        for r in section:
            body.extend(_encode_record(r))
    return header + bytes(body)


# --------------------------------------------------------------------------- #
# Decoding
# --------------------------------------------------------------------------- #
def _read_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Read a (possibly compressed) domain name. Returns (name, next_offset)."""
    labels: List[str] = []
    jumped = False
    next_offset = offset
    hops = 0
    while True:
        if offset >= len(data):
            raise DnsDecodeError("name runs past end of message")
        length = data[offset]
        if length & 0xC0 == 0xC0:  # compression pointer
            if offset + 1 >= len(data):
                raise DnsDecodeError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                next_offset = offset + 2
            offset = pointer
            jumped = True
            hops += 1
            if hops > 128:
                raise DnsDecodeError("compression pointer loop")
            continue
        if length == 0:
            offset += 1
            if not jumped:
                next_offset = offset
            break
        offset += 1
        if offset + length > len(data):
            raise DnsDecodeError("label runs past end of message")
        labels.append(data[offset : offset + length].decode("ascii", "replace"))
        offset += length
    return (".".join(labels), next_offset)


def _read_question(data: bytes, offset: int) -> Tuple[DnsQuestion, int]:
    name, offset = _read_name(data, offset)
    if offset + 4 > len(data):
        raise DnsDecodeError("truncated question")
    qtype, qclass = struct.unpack_from("!HH", data, offset)
    return DnsQuestion(name, qtype, qclass), offset + 4


def _read_record(data: bytes, offset: int) -> Tuple[DnsRecord, int]:
    name, offset = _read_name(data, offset)
    if offset + 10 > len(data):
        raise DnsDecodeError("truncated resource record header")
    rtype, rclass, ttl, rdlen = struct.unpack_from("!HHIH", data, offset)
    offset += 10
    if offset + rdlen > len(data):
        raise DnsDecodeError("resource record rdata runs past end of message")
    rdata = data[offset : offset + rdlen]
    return DnsRecord(name, rtype, rclass, ttl, rdata), offset + rdlen


def decode(data: bytes) -> DnsMessage:
    """Parse DNS wire format into a :class:`DnsMessage`.

    Raises :class:`DnsDecodeError` on malformed input.
    """
    if len(data) < 12:
        raise DnsDecodeError("message shorter than 12-byte header")
    txn_id, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", data, 0)
    msg = DnsMessage(
        txn_id=txn_id,
        qr=(flags >> 15) & 1,
        opcode=(flags >> 11) & 0xF,
        aa=(flags >> 10) & 1,
        tc=(flags >> 9) & 1,
        rd=(flags >> 8) & 1,
        ra=(flags >> 7) & 1,
        rcode=flags & 0xF,
    )
    offset = 12
    for _ in range(qd):
        q, offset = _read_question(data, offset)
        msg.questions.append(q)
    for _ in range(an):
        r, offset = _read_record(data, offset)
        msg.answers.append(r)
    for _ in range(ns):
        r, offset = _read_record(data, offset)
        msg.authorities.append(r)
    for _ in range(ar):
        r, offset = _read_record(data, offset)
        msg.additionals.append(r)
    return msg
