from syntactica.data.schema import DnsMessage, DnsQuestion
from syntactica.tokenizer import (
    BOS,
    EOS,
    OOVC,
    ROOT,
    SEP,
    build_vocab,
    length_bucket,
    tokenize,
)


def test_length_buckets():
    assert length_bucket(1) == "LEN=s"
    assert length_bucket(5) == "LEN=m"
    assert length_bucket(12) == "LEN=l"
    assert length_bucket(20) == "LEN=xl"
    assert length_bucket(50) == "LEN=xxl"
    assert length_bucket(80) == "LEN=ILLEGAL"


def test_tokenize_structure():
    msg = DnsMessage(questions=[DnsQuestion("www.example.com", 1, 1)])
    toks = tokenize(msg)
    assert toks[0] == BOS and toks[-1] == EOS
    assert "QR=0" in toks and "QT=A" in toks
    assert toks.count(SEP) == 3  # three labels
    assert ROOT in toks


def test_control_chars_become_oovc():
    msg = DnsMessage(questions=[DnsQuestion("a\x01b.com", 1, 1)])
    assert OOVC in tokenize(msg)


def test_query_with_answers_flagged():
    from syntactica.data.schema import DnsRecord

    msg = DnsMessage(
        questions=[DnsQuestion("x.com", 1, 1)],
        answers=[DnsRecord("x.com", 1, 1, 0, b"\x00\x00\x00\x00")],
    )
    assert "HAS_ANSWERS" in tokenize(msg)


def test_vocab_roundtrip():
    msgs = [DnsMessage(questions=[DnsQuestion("a.b.com", 1, 1)])]
    v = build_vocab(msgs)
    toks = tokenize(msgs[0])
    assert v.decode(v.encode(toks)) == toks
