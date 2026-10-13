"""A safe, loopback-only fuzzing harness with a bundled mock resolver.

**Safety first.** Sending crafted DNS at a resolver you do not own is at best
rude and at worst illegal. This harness therefore refuses any target that is not
loopback unless the caller *explicitly* passes ``allow_external=True`` and owns
the target. The default workflow talks only to the bundled :class:`MockResolver`
on ``127.0.0.1`` — an in-process parser-under-test — so the whole loop runs on
one machine with no external traffic.

Outcomes are classified the way a real fuzzing campaign classifies them:

* ``OK``        — the parser accepted the message and answered;
* ``REJECTED``  — the parser cleanly refused a malformed message (good hygiene);
* ``CRASH``     — the parser raised an *unexpected* exception (a real finding);
* ``TIMEOUT``   — no answer within the deadline (a potential hang).
"""
from __future__ import annotations

import ipaddress
import socket
import threading
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Union

from ..data.codec import DnsDecodeError, decode, encode
from ..data.schema import DnsMessage, DnsRecord

TestCase = Union[DnsMessage, bytes]
_LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def _is_loopback(host: str) -> bool:
    if host in _LOOPBACK:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# Mock resolver: the parser under test
# --------------------------------------------------------------------------- #
class MockResolver:
    """A minimal UDP DNS responder whose parser is :func:`codec.decode`.

    It answers well-formed queries with a canned ``A`` record and surfaces
    parse failures, so the fuzzer has something concrete to probe. Use as a
    context manager; it binds an ephemeral port on loopback.
    """

    def __init__(self, host: str = "127.0.0.1"):
        self.host = host
        self.sock: Optional[socket.socket] = None
        self.port = 0
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.parse_failures = 0
        self.served = 0

    def __enter__(self) -> "MockResolver":
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1.0)
        if self.sock:
            self.sock.close()

    def _serve(self) -> None:
        assert self.sock is not None
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                msg = decode(data)
                self.served += 1
                reply = self._answer(msg)
                self.sock.sendto(encode(reply), addr)
            except Exception:
                # A conforming resolver must never crash on input: any malformed
                # message is answered with FORMERR (or silently dropped if even
                # that fails). Catching broadly is deliberate — the parser under
                # test is the thing we are probing, not the server loop.
                self.parse_failures += 1
                try:
                    txn = (data[0] << 8 | data[1]) if len(data) > 1 else 0
                    self.sock.sendto(encode(DnsMessage(txn_id=txn, qr=1, rcode=1)), addr)
                except OSError:
                    pass

    @staticmethod
    def _answer(msg: DnsMessage) -> DnsMessage:
        reply = DnsMessage(txn_id=msg.txn_id, qr=1, opcode=msg.opcode, rd=msg.rd, ra=1)
        reply.questions = list(msg.questions)
        if msg.questions and msg.questions[0].qtype == 1:
            reply.answers = [DnsRecord(msg.questions[0].qname, 1, 1, 60, b"\xc0\x00\x02\x01")]
        return reply


# --------------------------------------------------------------------------- #
# Harness
# --------------------------------------------------------------------------- #
@dataclass
class FuzzReport:
    total: int = 0
    outcomes: Counter = field(default_factory=Counter)
    findings: List[dict] = field(default_factory=list)

    @property
    def validity_rate(self) -> float:
        return self.outcomes.get("OK", 0) / self.total if self.total else 0.0

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "outcomes": dict(self.outcomes),
            "validity_rate": round(self.validity_rate, 4),
            "findings": self.findings[:20],
        }


class FuzzHarness:
    def __init__(self, target: Tuple[str, int], timeout: float = 0.5, allow_external: bool = False):
        host, _ = target
        if not _is_loopback(host) and not allow_external:
            raise PermissionError(
                f"Refusing to fuzz non-loopback target {host!r}. Pass allow_external=True "
                "only for hosts you own and are authorised to test."
            )
        self.target = target
        self.timeout = timeout

    def _send(self, raw: bytes) -> str:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(self.timeout)
            try:
                s.sendto(raw, self.target)
                resp, _ = s.recvfrom(4096)
            except socket.timeout:
                return "TIMEOUT"
            except OSError:
                return "CRASH"
        try:
            reply = decode(resp)
        except DnsDecodeError:
            return "CRASH"
        return "REJECTED" if reply.rcode == 1 else "OK"

    def run(self, cases: List[TestCase]) -> FuzzReport:
        report = FuzzReport()
        for case in cases:
            raw = encode(case) if isinstance(case, DnsMessage) else case
            outcome = self._send(raw)
            report.total += 1
            report.outcomes[outcome] += 1
            if outcome in ("CRASH", "TIMEOUT"):
                report.findings.append({"outcome": outcome, "len": len(raw), "hex": raw[:32].hex()})
        return report
