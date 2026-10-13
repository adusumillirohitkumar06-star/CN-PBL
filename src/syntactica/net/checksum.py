"""Error-detection primitives: CRC-32 and the Internet (one's-complement) checksum.

This module is a direct, hand-rolled realisation of the **Unit II** error-detection
topics (Block coding, CRC) and the checksum used across the TCP/IP stack:

* :func:`crc32` — the IEEE 802.3 CRC-32 (polynomial ``0xEDB88320``), built from a
  256-entry lookup table generated at import time. This is the same CRC used by
  Ethernet frame check sequences; implementing it here (rather than calling
  ``zlib``) makes the mechanism inspectable and is verified against ``zlib`` in
  the tests.
* :func:`internet_checksum` — the 16-bit one's-complement sum of RFC 1071, used
  by IPv4, ICMP, UDP and TCP.
* :func:`udp_checksum` / :func:`verify_udp_checksum` — the UDP checksum over the
  IPv4 pseudo-header, so integrity of a captured DNS datagram can be checked.

A single bit flip anywhere in a protected payload changes the CRC and (with
overwhelming probability) the checksum, which is exactly the error-detection
guarantee the course covers.
"""
from __future__ import annotations

import struct

# --------------------------------------------------------------------------- #
# CRC-32 (IEEE 802.3), table-driven
# --------------------------------------------------------------------------- #
_CRC32_POLY = 0xEDB88320


def _build_crc32_table() -> list[int]:
    table = []
    for byte in range(256):
        crc = byte
        for _ in range(8):
            crc = (crc >> 1) ^ (_CRC32_POLY if (crc & 1) else 0)
        table.append(crc)
    return table


_CRC32_TABLE = _build_crc32_table()


def crc32(data: bytes) -> int:
    """Compute the IEEE 802.3 CRC-32 of ``data`` (matches ``zlib.crc32``)."""
    crc = 0xFFFFFFFF
    for b in data:
        crc = (crc >> 8) ^ _CRC32_TABLE[(crc ^ b) & 0xFF]
    return crc ^ 0xFFFFFFFF


# --------------------------------------------------------------------------- #
# Internet checksum (RFC 1071)
# --------------------------------------------------------------------------- #
def internet_checksum(data: bytes) -> int:
    """16-bit one's-complement checksum used by IP/ICMP/UDP/TCP (RFC 1071)."""
    if len(data) % 2:
        data = data + b"\x00"  # pad to a 16-bit boundary
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    # fold the carries back in
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


# --------------------------------------------------------------------------- #
# UDP checksum over the IPv4 pseudo-header
# --------------------------------------------------------------------------- #
def _ipv4_pseudo_header(src_ip: bytes, dst_ip: bytes, udp_len: int) -> bytes:
    # src(4) + dst(4) + zero(1) + proto=17(1) + udp length(2)
    return src_ip + dst_ip + struct.pack("!BBH", 0, 17, udp_len)


def udp_checksum(src_ip: bytes, dst_ip: bytes, udp_segment: bytes) -> int:
    """Compute the UDP checksum for an IPv4 datagram.

    ``udp_segment`` is the full UDP header + payload; the checksum field within
    it is treated as zero for the computation.
    """
    if len(src_ip) != 4 or len(dst_ip) != 4:
        raise ValueError("IPv4 addresses must be 4 bytes")
    seg = bytearray(udp_segment)
    if len(seg) >= 8:
        seg[6] = 0  # zero the existing checksum field before recomputing
        seg[7] = 0
    pseudo = _ipv4_pseudo_header(src_ip, dst_ip, len(seg))
    return internet_checksum(pseudo + bytes(seg))


def verify_udp_checksum(src_ip: bytes, dst_ip: bytes, udp_segment: bytes) -> bool:
    """Return ``True`` if the UDP datagram's checksum is valid.

    A UDP checksum of 0 means "not computed" (permitted over IPv4), which we
    treat as valid-by-omission.
    """
    if len(udp_segment) < 8:
        return False
    stored = (udp_segment[6] << 8) | udp_segment[7]
    if stored == 0:
        return True
    return udp_checksum(src_ip, dst_ip, udp_segment) == stored
