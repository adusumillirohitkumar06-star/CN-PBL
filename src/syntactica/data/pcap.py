"""Minimal, dependency-free reader for libpcap ``.pcap`` files.

Enough of the format to pull DNS messages out of a Wireshark/``tshark``
capture: global header, per-packet records, Ethernet -> IPv4/IPv6 -> UDP,
port 53. This lets the project consume *your own* captures — the difference
between a Kaggle-download project and a real one — without adding a dependency.

Only UDP/53 is handled (the overwhelming majority of DNS). TCP/53 and the
handful of exotic link types are skipped rather than mis-parsed; a capture is
data, and we would rather drop a packet than invent one.
"""
from __future__ import annotations

import struct
from typing import Iterator, List, Tuple

from .codec import DnsDecodeError, decode
from .schema import DnsMessage

# Classic pcap magics: microsecond and nanosecond timestamp variants, both endians.
_PCAP_MAGICS = {0xA1B2C3D4, 0xD4C3B2A1, 0xA1B23C4D, 0x4D3CB2A1}
_PCAPNG_SHB = 0x0A0D0D0A  # pcapng Section Header Block type (Wireshark's default format)
_LINKTYPE_ETHERNET = 1
_LINKTYPE_RAW = 101
_LINKTYPE_LINUX_SLL = 113


def _iter_records(blob: bytes):
    """Dispatch on file magic: classic pcap or pcapng (Wireshark's default)."""
    if len(blob) < 24:
        raise ValueError("file too short to be a capture")
    (magic,) = struct.unpack_from("<I", blob, 0)
    if magic in _PCAP_MAGICS:
        yield from _iter_records_classic(blob)
    elif magic == _PCAPNG_SHB:
        yield from _iter_records_pcapng(blob)
    else:
        raise ValueError(
            "unrecognised capture format (not classic pcap or pcapng). "
            "If it came from Wireshark, convert with: editcap -F pcap in.pcapng out.pcap"
        )


def _iter_records_classic(blob: bytes):
    (magic,) = struct.unpack_from("<I", blob, 0)
    endian = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
    (_, _, _, _, _, linktype) = struct.unpack_from(endian + "HHiIII", blob, 4)
    offset = 24
    while offset + 16 <= len(blob):
        _ts_sec, _ts_usec, caplen, _origlen = struct.unpack_from(endian + "IIII", blob, offset)
        offset += 16
        if offset + caplen > len(blob):
            break
        yield linktype, blob[offset : offset + caplen]
        offset += caplen


def _iter_records_pcapng(blob: bytes):
    """Walk pcapng blocks, yielding (linktype, packet_bytes) for packet blocks."""
    # Endianness comes from the Section Header Block's byte-order magic at offset 8.
    endian = "<" if struct.unpack_from("<I", blob, 8)[0] == 0x1A2B3C4D else ">"
    linktype = _LINKTYPE_ETHERNET
    offset, n = 0, len(blob)
    while offset + 12 <= n:
        btype = struct.unpack_from(endian + "I", blob, offset)[0]
        blen = struct.unpack_from(endian + "I", blob, offset + 4)[0]
        if blen < 12 or offset + blen > n:
            break
        body = offset + 8
        if btype == 0x00000001:  # Interface Description Block -> linktype
            linktype = struct.unpack_from(endian + "H", blob, body)[0]
        elif btype == 0x00000006:  # Enhanced Packet Block
            caplen = struct.unpack_from(endian + "I", blob, body + 12)[0]
            if body + 20 + caplen <= n:
                yield linktype, blob[body + 20 : body + 20 + caplen]
        elif btype == 0x00000003:  # Simple Packet Block
            origlen = struct.unpack_from(endian + "I", blob, body)[0]
            if body + 4 + origlen <= n:
                yield linktype, blob[body + 4 : body + 4 + origlen]
        offset += blen


def _l3_from_link(linktype: int, frame: bytes):
    """Return (ethertype, l3_payload) or (None, None)."""
    if linktype == _LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None, None
        ethertype = struct.unpack_from("!H", frame, 12)[0]
        return ethertype, frame[14:]
    if linktype == _LINKTYPE_LINUX_SLL:
        if len(frame) < 16:
            return None, None
        ethertype = struct.unpack_from("!H", frame, 14)[0]
        return ethertype, frame[16:]
    if linktype == _LINKTYPE_RAW:
        if not frame:
            return None, None
        version = frame[0] >> 4
        return (0x0800 if version == 4 else 0x86DD), frame
    return None, None


def _udp_datagram(ethertype: int, l3: bytes):
    """Return ``(dns_payload, src_ip, dst_ip, udp_segment)`` for a DNS/UDP packet.

    ``src_ip``/``dst_ip`` are 4 bytes for IPv4 and ``None`` for IPv6 (the UDP
    checksum verifier only supports IPv4 pseudo-headers here).
    """
    if ethertype == 0x0800:  # IPv4
        if len(l3) < 20:
            return None
        ihl = (l3[0] & 0x0F) * 4
        proto = l3[9]
        if proto != 17 or len(l3) < ihl + 8:
            return None
        src_ip, dst_ip = l3[12:16], l3[16:20]
        udp = l3[ihl:]
    elif ethertype == 0x86DD:  # IPv6 (no extension-header chasing; good enough)
        if len(l3) < 40 or l3[6] != 17:
            return None
        src_ip, dst_ip = None, None
        udp = l3[40:]
    else:
        return None
    if len(udp) < 8:
        return None
    src_port, dst_port = struct.unpack_from("!HH", udp, 0)
    if 53 not in (src_port, dst_port):
        return None
    return udp[8:], src_ip, dst_ip, udp


def iter_dns_from_pcap(path: str) -> Iterator[DnsMessage]:
    with open(path, "rb") as fh:
        blob = fh.read()
    for linktype, frame in _iter_records(blob):
        ethertype, l3 = _l3_from_link(linktype, frame)
        if l3 is None:
            continue
        dgram = _udp_datagram(ethertype, l3)
        if not dgram:
            continue
        try:
            yield decode(dgram[0])
        except DnsDecodeError:
            # A capture full of real-world garbage is expected; skip, don't crash.
            continue


def iter_dns_with_integrity(path: str) -> Iterator[Tuple[DnsMessage, bool]]:
    """Yield ``(message, checksum_ok)`` for each DNS packet in a capture.

    The UDP checksum is verified against the IPv4 pseudo-header (Unit II error
    detection). IPv6 packets and UDP datagrams with a zero checksum are reported
    as ``True`` (valid-by-omission).
    """
    from ..net.checksum import verify_udp_checksum

    with open(path, "rb") as fh:
        blob = fh.read()
    for linktype, frame in _iter_records(blob):
        ethertype, l3 = _l3_from_link(linktype, frame)
        if l3 is None:
            continue
        dgram = _udp_datagram(ethertype, l3)
        if not dgram:
            continue
        payload, src_ip, dst_ip, udp_segment = dgram
        try:
            msg = decode(payload)
        except DnsDecodeError:
            continue
        ok = True if src_ip is None else verify_udp_checksum(src_ip, dst_ip, udp_segment)
        yield msg, ok


def load_pcap(path: str) -> List[DnsMessage]:
    """Eagerly load every DNS message from a pcap file."""
    return list(iter_dns_from_pcap(path))
