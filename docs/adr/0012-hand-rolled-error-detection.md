# 12. Hand-roll CRC-32 and the Internet checksum

- **Status:** Accepted
- **Date:** 2025-08-27

## Context

Reading real captures raises the question of packet integrity, which is exactly the **Unit II** error-detection topic (block coding, CRC). We could ignore integrity, or call a library, but neither teaches or demonstrates the mechanism.

## Decision

We implement, from scratch and with no dependencies, the two error-detection codes that matter here:

- **CRC-32** (IEEE 802.3, polynomial `0xEDB88320`) via a 256-entry lookup table generated at import — the same CRC used in Ethernet frame check sequences.
- The **Internet checksum** (RFC 1071 one's-complement sum) used by IPv4/UDP/TCP, plus a UDP-checksum verifier over the IPv4 pseudo-header.

The pcap reader exposes `iter_dns_with_integrity`, which yields each DNS message alongside whether its UDP checksum is valid, and `syntactica analyze` reports checksum failures on your own captures.

## Consequences

- The project has a concrete, testable Unit II artefact: `crc32` is verified bit-for-bit against `zlib`, and the UDP verifier detects single-bit corruption.
- Integrity verification on real captures is a one-liner, reinforcing that the DNS/TCP-IP stack is inspectable end to end.
- We handle IPv4 UDP checksums; IPv6 and TCP/53 integrity are out of scope and documented as such.
