"""The pcap reader must ingest both classic .pcap and pcapng (Wireshark default)."""
import struct

import pytest

from syntactica.data.codec import encode
from syntactica.data.pcap import iter_dns_with_integrity, load_pcap
from syntactica.data.schema import DnsMessage, DnsQuestion
from syntactica.net.checksum import internet_checksum, udp_checksum


def _eth_ipv4_udp(src, dst, payload):
    udp = struct.pack("!HHHH", 5353, 53, 8 + len(payload), 0) + payload
    ck = udp_checksum(src, dst, udp)
    udp = udp[:6] + struct.pack("!H", ck) + udp[8:]
    tl = 20 + len(udp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, tl, 0, 0x4000, 64, 17, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", internet_checksum(ip)) + ip[12:]
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb" + struct.pack("!H", 0x0800)
    return eth + ip + udp


def _messages(n=30):
    return [
        DnsMessage(txn_id=i, questions=[DnsQuestion(f"host{i}.example.com", 1, 1)])
        for i in range(n)
    ]


def _classic_pcap(frames):
    gh = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    recs = b"".join(struct.pack("<IIII", 0, 0, len(f), len(f)) + f for f in frames)
    return gh + recs


def _pcapng(frames):
    def blk(btype, body):
        pad = body + b"\x00" * ((-len(body)) % 4)
        total = 12 + len(pad)
        return struct.pack("<II", btype, total) + pad + struct.pack("<I", total)

    shb = blk(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = blk(0x00000001, struct.pack("<HHI", 1, 0, 65535))
    epbs = b"".join(
        blk(0x00000006, struct.pack("<IIIII", 0, 0, 0, len(f), len(f)) + f) for f in frames
    )
    return shb + idb + epbs


@pytest.fixture
def frames():
    src, dst = bytes([10, 0, 0, 5]), bytes([8, 8, 8, 8])
    return [_eth_ipv4_udp(src, dst, encode(m)) for m in _messages()]


def test_classic_pcap_roundtrip(tmp_path, frames):
    p = tmp_path / "c.pcap"
    p.write_bytes(_classic_pcap(frames))
    assert len(load_pcap(str(p))) == 30


def test_pcapng_roundtrip(tmp_path, frames):
    p = tmp_path / "c.pcapng"
    p.write_bytes(_pcapng(frames))
    msgs = load_pcap(str(p))
    assert len(msgs) == 30
    assert msgs[0].primary_qname == "host0.example.com"


def test_pcapng_integrity_all_valid(tmp_path, frames):
    p = tmp_path / "c.pcapng"
    p.write_bytes(_pcapng(frames))
    pairs = list(iter_dns_with_integrity(str(p)))
    assert len(pairs) == 30
    assert all(ok for _, ok in pairs)  # we built valid checksums


def test_unknown_format_rejected(tmp_path):
    p = tmp_path / "bad.bin"
    p.write_bytes(b"\x00" * 64)
    with pytest.raises(ValueError):
        load_pcap(str(p))
