# 9. Hand-roll a zero-dependency DNS codec

- **Status:** Accepted
- **Date:** 2025-08-25

## Context

We need to encode and decode DNS wire format and read `.pcap` captures. The easy path is `dnspython` + `scapy` (or `dpkt`). They are excellent libraries, but pulling them in has costs: heavier installs, another moving part in the demo, and — more importantly — the byte-level grammar of DNS disappears behind an API at the exact moment the project is *about* that grammar.

## Decision

We implement the DNS codec and a minimal `.pcap` reader ourselves, in pure Python with **no runtime dependencies** beyond `numpy` (and optional `torch`/`scikit-learn`).

- `data/codec.py` encodes/decodes DNS messages, including compression pointers when reading real captures. Encoding is *total* — it never raises — so the fuzzer and mock resolver can round-trip adversarial names without the codec becoming the crash.
- `data/pcap.py` reads classic libpcap files, walks Ethernet/Linux-SLL/raw → IPv4/IPv6 → UDP/53, and yields DNS messages, skipping anything it cannot parse.

## Consequences

- The core pipeline installs and runs anywhere Python runs; consuming your own Wireshark capture is a one-liner with no extra packages.
- The byte-level protocol grammar is visible and auditable in the source, reinforcing the project's thesis and its value as a networks artefact.
- We own the maintenance of the codec. The scope (DNS over UDP) is small and fully covered by round-trip tests, so this cost is bounded.
- We do not handle every exotic case (TCP/53, EDNS options, all link types). That is acceptable for the project's scope and documented in the code.
