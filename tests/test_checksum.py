"""Error-detection primitives (Unit II): CRC-32 and the Internet/UDP checksum."""
import struct
import zlib

from syntactica.net.checksum import (
    crc32,
    internet_checksum,
    udp_checksum,
    verify_udp_checksum,
)


def test_crc32_matches_zlib():
    for data in [b"", b"a", b"hello world", bytes(range(256)), b"\x00" * 100]:
        assert crc32(data) == (zlib.crc32(data) & 0xFFFFFFFF)


def test_crc32_detects_single_bit_flip():
    data = bytearray(b"the quick brown fox jumps over the lazy dog")
    before = crc32(bytes(data))
    data[10] ^= 0x01
    assert crc32(bytes(data)) != before


def test_internet_checksum_padding_and_range():
    c = internet_checksum(b"\x01\x02\x03")  # odd length -> padded
    assert 0 <= c <= 0xFFFF


def _build_udp(src_ip, dst_ip, payload):
    udp_len = 8 + len(payload)
    udp = struct.pack("!HHHH", 5353, 53, udp_len, 0) + payload
    ck = udp_checksum(src_ip, dst_ip, udp)
    return udp[:6] + struct.pack("!H", ck) + udp[8:]


def test_udp_checksum_roundtrip_and_corruption():
    src, dst = bytes([192, 168, 0, 2]), bytes([1, 1, 1, 1])
    payload = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x00\x00\x01\x00\x01"
    good = _build_udp(src, dst, payload)
    assert verify_udp_checksum(src, dst, good)
    bad = bytearray(good)
    bad[-1] ^= 0x80
    assert not verify_udp_checksum(src, dst, bytes(bad))


def test_zero_checksum_is_valid_by_omission():
    src, dst = bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])
    udp = struct.pack("!HHHH", 53, 5353, 12, 0) + b"\x00\x00\x00\x00"
    assert verify_udp_checksum(src, dst, udp)
