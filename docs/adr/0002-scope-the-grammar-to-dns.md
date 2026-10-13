# 2. Scope the grammar to DNS

- **Status:** Accepted
- **Date:** 2025-08-20

## Context

The thesis — "a protocol is a grammar you can learn and violate" — applies to any protocol: HTTP, TLS handshakes, Modbus, SMTP. The temptation is to build a general framework covering many protocols. In a single-semester project, breadth would mean a shallow, unconvincing result for every protocol and a demo that impresses no one.

We considered HTTP (rich but enormous grammar, heavy captures), TLS (mostly opaque/encrypted after the handshake), Modbus (tiny clean grammar, but a niche audience), and DNS.

## Decision

We scope the entire project to **DNS**.

DNS is the sweet spot: a compact, well-documented wire format; a name syntax with real structure to learn; and a genuinely rich attack surface (tunnelling, DGA, cache poisoning, malformed-packet exploits) that maps cleanly onto grammar violations. It is also the protocol a networks student can capture, read byte-by-byte, and reason about end to end.

## Consequences

- Every component — codec, tokenizer, attacks, automaton — is DNS-specific and therefore concrete and testable.
- The generalisation claim is made *by analogy and argument*, not by a half-working multi-protocol framework. Extending to a second protocol is future work, and the tokenizer/model boundary is designed to make that a contained change.
- We can capture our own data trivially, which is a differentiator (see [ADR-0009](0009-zero-dependency-dns-codec.md)).
