# Course mapping — Computer Networks PBL (20CS3102)

This document maps Syntactica to the Computer Networks course outcomes, programme outcomes, and syllabus units, for the Project-Based-Learning evaluation.

> The course file itself lists, as a future skill students should acquire, *"network performance monitoring using Artificial Intelligence"* (Computer Networks course file, §8). Syntactica is a direct, hands-on realisation of that skill for the DNS protocol.

## Course Outcomes (COs)

| CO | Statement (abridged) | How Syntactica addresses it |
|---|---|---|
| **CO1** | Explain the layers of the OSI and TCP/IP model | `data/pcap.py` decodes a real capture layer by layer — Ethernet (L2) → IPv4/IPv6 (L3) → UDP (L4) → DNS (L7). The tokenizer surfaces the application-layer message structure explicitly. |
| **CO2** | Data-link layer & MAC sub-layer; **error detection (CRC)** | `net/checksum.py` implements **CRC-32** (the Ethernet FCS polynomial, from scratch) and the **Internet/UDP checksum** (RFC 1071); `analyze` verifies packet integrity on real captures. DNS names are length-prefixed **framing**, and over-long/illegal labels are detected (`LEN=ILLEGAL`). |
| **CO3** | **Congestion-control algorithms** | `mitigation/` implements the **Token Bucket** traffic-policing algorithm (named in Unit IV) as an adaptive, per-source rate limiter — a genuine congestion/QoS-control artefact, evaluated with a goodput-vs-attack study. |
| **CO4** | **Develop a program for TCP/IP and UDP using network programming** | The mock resolver and fuzz harness are UDP socket programs (`socket`, `sendto`/`recvfrom`) that speak DNS over UDP end to end — squarely CO4. |
| **CO5** | **Analyse application-layer protocols using open-source tools** | The workflow captures DNS with **Wireshark/`tshark`** (named in the syllabus) and analyses the DNS application-layer protocol. This is the project's centre of gravity. |

**All five COs are now touched by a concrete artefact** — CO2 and CO3 in particular via the hand-rolled CRC/checksum (Unit II error detection) and the token-bucket rate limiter (Unit IV congestion control).

## Programme Outcomes (POs) exercised

| PO | Evidence in the project |
|---|---|
| **PO1** Engineering knowledge | Applies networking + probability/ML fundamentals to a protocol problem. |
| **PO2** Problem analysis | Frames intrusion detection as language modelling; analyses why supervised IDS fail on zero-days. |
| **PO3/PO4** Design & investigation | Designs the pipeline; investigates with ROC/PR, per-family recall, and a fuzzing study. |
| **PO5** Modern tool usage | Wireshark/`tshark`, PyTorch, numpy, GitHub Pages, CI. |
| **PO6/PO8** Engineer & society, ethics | Explicit threat model and loopback-only fuzzing guardrails ([threat model](threat-model.md)). |
| **PO10** Communication | This documentation, ADRs, and an interactive dashboard. |
| **PO12** Life-long learning | Engages current research (ET-BERT, Learn&Fuzz, NetPlier). |
| **PSO1/PSO2** | Defines computing requirements under constraints and follows engineering best practice (tests, CI, ADRs). |

## Syllabus units touched (with a concrete artefact each)

- **Unit I** — OSI/TCP-IP layering → the layered pcap decode (`data/pcap.py`, L2→L7).
- **Unit II** — error detection / CRC → `net/checksum.py` (CRC-32 + Internet/UDP checksum); framing → length-prefixed DNS labels and `LEN=ILLEGAL` detection.
- **Unit IV** — transport & **network programming** → the UDP sockets code; **congestion control / traffic policing** → the **Token Bucket** rate limiter (`mitigation/`).
- **Unit V** — **DNS** (application layer) → the whole detector; the system acts as a next-gen firewall/monitor in the spirit of Unit V's firewalls & cryptography topics.

## Suggested PBL deliverables checklist

- [x] Problem statement & literature grounding — [README](../README.md#why-this-exists) + references.
- [x] Design rationale — [ADRs](adr/) (15 records).
- [x] Working implementation — `src/syntactica/`, 42 passing tests.
- [x] Error-detection artefact (CO2, Unit II) — hand-rolled CRC-32 + UDP checksum.
- [x] Congestion-control artefact (CO3, Unit IV) — token-bucket adaptive rate limiter with a goodput study.
- [x] Network programming artefact (CO4) — UDP mock resolver + harness.
- [x] Open-source tool analysis (CO5) — `scripts/capture.sh` (Wireshark/`tshark`) + `syntactica analyze`.
- [x] Results with honest evaluation — ROC/PR, per-family recall, conformal FPR guarantee, fuzzing + mitigation studies.
- [x] Interactive demonstration — [dashboard](https://cattolatte.github.io/syntactica/).
- [x] Threat model / ethics — [threat model](threat-model.md).

## Local vs. hosted (an examiner will ask)

The **GitHub Pages dashboard is the report** — a static results page whose live scorer is a client-side reimplementation of the model. The **networking system runs locally**: `scripts/capture.sh` sniffs real DNS off your interface, and `syntactica analyze mycapture.pcap` learns the grammar of *your* traffic and flags its anomalies + checksum failures. Nothing about the live system depends on the hosted page.

## Talking points for the viva

1. **Why is this a *networks* project, not just ML?** The features, the automaton, the checksum, the token bucket, and the fuzzer are all grounded in the DNS/TCP-IP wire format — the codec and CRC are hand-written and auditable.
2. **Which named syllabus algorithms did you implement?** The **Token Bucket** (Unit IV) and **CRC-32 / Internet checksum** (Unit II), both from scratch.
3. **Why unsupervised?** So it catches zero-day families, which supervised IDS cannot — and conformal calibration gives a *provable* false-positive bound.
4. **How do you know it isn't a black box?** The extracted automaton, per-token surprisal, and the Transformer embedding view explain and visualise each decision.
5. **Detection or defence?** Both — the token bucket closes the loop, preserving 100% legitimate goodput while blocking 98% of an exfil flood.
6. **Is the fuzzer safe/ethical?** Loopback-only by default, enforced in code and tested.
7. **Why no LLM/chatbot?** It would break the local, offline, reproducible design and add no networking value; autonomy is delivered as a MAPE-K control loop instead.
