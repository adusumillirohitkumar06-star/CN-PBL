# 8. Grammar-guided fuzzing, loopback-only by default

- **Status:** Accepted
- **Date:** 2025-08-25

## Context

The same grammar that detects anomalies can *generate* them — this is the offensive half of the project and the part that makes it more than a detector. Sampling the grammar at temperature `T` reproduces the validity/novelty tradeoff of Learn&Fuzz (Godefroid et al., ASE 2017). But a fuzzer that sends crafted DNS at arbitrary hosts is a liability: probing a resolver you do not own is at best antisocial and at worst illegal.

## Decision

- The fuzzer **generates** test cases three ways: grammar sampling at temperature, structural mutation (illegal qtype, over-long label, query-with-answers), and wire-level byte mutation (truncation, bit flips, length-field tampering).
- The harness **refuses any non-loopback target** unless the caller passes `allow_external=True` for a host they own and are authorised to test.
- The default workflow talks only to a bundled in-process `MockResolver` on `127.0.0.1`, whose parser is our own codec, so the whole loop runs on one machine with no external traffic.
- We report **validity vs temperature** and **grammar novelty vs temperature**, not a vanity crash count.

## Consequences

- The offensive capability is demonstrated end to end, safely, on any machine.
- The safety guard is enforced in code and covered by a test (`test_harness_refuses_external_target`).
- Because the bundled resolver's parser is intentionally robust, "validity" stays high; the informative signal is the rising *novelty* curve, which we surface explicitly.
