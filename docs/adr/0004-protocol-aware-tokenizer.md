# 4. Use a protocol-aware tokenizer, not raw bytes

- **Status:** Accepted
- **Date:** 2025-08-21

## Context

To feed DNS messages to a language model we must tokenize them. The obvious choice, following byte-level models like ET-BERT, is to treat the raw packet bytes as the token stream. That works, but it hides the protocol structure inside the model and makes every decision a black box.

## Decision

We tokenize with a **protocol-aware** scheme that exposes DNS structure as explicit tokens: message-level fields (`QR=`, `OP=`, `QT=`, `QC=`), a per-label **length bucket** (`LEN=s|m|l|xl|xxl|ILLEGAL`), the label characters over a fixed DNS-legal alphabet, and structural delimiters (`<sep>`, `<root>`). Any octet outside `[a-z0-9-_]` maps to a single out-of-vocabulary token `<oovc>`.

Two consequences of this scheme are load-bearing:

- **Label-length buckets** make the *shape* of a name first-class. The three attack families separate cleanly in this dimension.
- **A fixed legal alphabet** means malformed control bytes emit a token the grammar never saw in training, so their surprisal spikes for a principled reason rather than a memorised rule.

## Consequences

- Detections are explainable in protocol terms: we can point at `LEN=xxl` or `<oovc>` as the token that broke the grammar (see [ADR-0007](0007-extract-interpretable-automaton.md)).
- The scheme is simple enough to re-implement in the browser, which powers the client-side live scorer.
- We encode some domain knowledge into features rather than learning everything from bytes. This is a deliberate trade of raw generality for interpretability and data efficiency.
