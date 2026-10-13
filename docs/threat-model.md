# Threat model & responsible use

Syntactica is a **defensive** research tool with an offensive component (a fuzzer). This document states what it defends against, what it does not, and the guardrails on the offensive side.

## What Syntactica detects

A monitoring position that sees DNS queries (a recursive resolver, a network tap, a pcap) and wants to flag anomalous traffic **without a labelled attack set**:

| Threat | Grammar signal |
|---|---|
| **DNS tunnelling / exfiltration** | long, high-entropy label runs → `LEN=xl/xxl`, unusual character statistics |
| **DGA (C2 rendezvous)** | unpronounceable labels → low benign likelihood |
| **Malformed-packet / parser exploits** | control bytes → `<oovc>`; illegal qtypes; over-long labels → `LEN=ILLEGAL` |

Detection is unsupervised: the detector is calibrated on benign traffic and flags improbable messages, so **previously unseen families** are caught by the same mechanism.

## What it does not do

- **It is not a complete IDS.** It inspects DNS message structure, not payload semantics, TLS, or host telemetry. Use it as one signal among many.
- **It does not decrypt anything.** It reasons about DNS message structure only.
- **It makes no claim against an adaptive adversary** who shapes traffic to mimic the benign grammar (mimicry attacks). Constraining and evaluating such adversaries is future work.
- **Synthetic evaluation is optimistic.** Numbers on the bundled synthetic corpus are an upper bound; validate on real captures before trusting it operationally.

## Offensive component: guardrails

The grammar-guided fuzzer can generate malformed DNS. Sending such traffic to systems you do not own is unacceptable and often illegal. The design enforces:

1. **Loopback-only by default.** `FuzzHarness` raises `PermissionError` for any non-loopback target unless `allow_external=True` is passed explicitly.
2. **A bundled in-process mock resolver.** The default workflow generates *and* consumes traffic on `127.0.0.1`; nothing leaves the machine.
3. **Authorisation is the caller's responsibility.** `allow_external=True` exists only for hosts you own and are authorised to test (your own lab resolver). There is no “target the internet” mode.

This guard is covered by an automated test (`tests/test_fuzz.py::test_harness_refuses_external_target`).

## Data handling

- The synthetic corpus contains no real user data.
- If you ingest real captures: capturing other people's DNS traffic may be subject to law and policy. Obtain authorisation, anonymise client IPs, and treat captures as sensitive. Syntactica reads only the DNS message; it does not need or store client addresses.

## Responsible disclosure

If you use the fuzzer against software you are authorised to test and find a genuine parser defect, follow coordinated disclosure with the affected vendor before publishing details.
