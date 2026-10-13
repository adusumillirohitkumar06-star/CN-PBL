"""The DNS codec is the project's ground truth; it must round-trip exactly."""
import pytest

from syntactica.data.codec import DnsDecodeError, decode, encode
from syntactica.data.schema import DnsMessage, DnsQuestion, DnsRecord


def test_query_roundtrip():
    msg = DnsMessage(txn_id=0x1337, rd=1, questions=[DnsQuestion("www.example.com", 1, 1)])
    back = decode(encode(msg))
    assert back.txn_id == 0x1337
    assert back.primary_qname == "www.example.com"
    assert back.questions[0].qtype == 1
    assert back.is_query


def test_response_with_answer_roundtrip():
    msg = DnsMessage(
        txn_id=42,
        qr=1,
        ra=1,
        questions=[DnsQuestion("example.com", 1, 1)],
        answers=[DnsRecord("example.com", 1, 1, 300, b"\x5d\xb8\xd8\x22")],
    )
    back = decode(encode(msg))
    assert back.qr == 1
    assert back.answers[0].rdata == b"\x5d\xb8\xd8\x22"
    assert back.answers[0].ttl == 300


def test_multi_label_name():
    msg = DnsMessage(questions=[DnsQuestion("a.b.c.d.example.co.uk", 28, 1)])
    assert decode(encode(msg)).primary_qname == "a.b.c.d.example.co.uk"


def test_short_message_rejected():
    with pytest.raises(DnsDecodeError):
        decode(b"\x00\x01\x02")


def test_truncated_question_rejected():
    # Valid header claiming one question, but no question body.
    header = encode(DnsMessage(questions=[DnsQuestion("x.com", 1, 1)]))[:12]
    with pytest.raises(DnsDecodeError):
        decode(header[:12] + b"\x03abc")  # dangling label, no qtype/qclass


def test_compression_pointer_loop_is_caught():
    # 12-byte header (qd=1) then a name that is a pointer to itself -> loop.
    data = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\xc0\x0c"
    with pytest.raises(DnsDecodeError):
        decode(data)
