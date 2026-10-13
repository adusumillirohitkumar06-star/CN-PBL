# 5. Score conformance by per-token surprisal, calibrated on benign traffic

- **Status:** Accepted
- **Date:** 2025-08-22

## Context

Given a language model of benign traffic, we need a scalar "how anomalous is this message" and a decision rule. Options included: a fixed likelihood cutoff, a distance to nearest benign neighbour, a separate one-class SVM on embeddings, or the model's own likelihood.

## Decision

The conformance score is the model's **mean per-token negative log-likelihood** (equivalently, log-perplexity) for the message. The decision threshold is a **high quantile (99th percentile) of benign surprisal**, estimated on benign traffic alone.

## Consequences

- The score is principled and model-agnostic: both the n-gram and the Transformer expose `sequence_nll`, so the scorer treats them identically.
- The single knob (the quantile) has a clear operational meaning: it sets the benign false-positive budget. A team can dial it to their tolerance.
- Calibrating on the *training* benign split means the realised false-positive rate on held-out benign traffic can be somewhat higher than `1 − quantile`; we measure and report the realised rate rather than assuming it.
- Because scoring is per-token, we get token-level surprisal for free, which the explanation layer reuses.
