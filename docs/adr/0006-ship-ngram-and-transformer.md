# 6. Ship both an n-gram grammar and a Transformer LM

- **Status:** Accepted
- **Date:** 2025-08-23

## Context

We could ship a single model. A pure Transformer would be the fashionable choice; a pure n-gram would be the humble one. Each has a failure mode for this project: a Transformer-only pipeline needs PyTorch (heavy, GPU-adjacent) and is a black box; an n-gram-only pipeline undersells the "deep learning" objective of the PBL.

## Decision

We ship **both**, with the n-gram grammar as the default and the Transformer as an optional, more powerful model behind the `[nn]` extra.

- The **interpolated n-gram grammar** (`numpy` only) is a smoothed stochastic regular grammar. It always runs, reproduces the headline numbers in seconds, serialises to a small JSON blob, and is re-implemented verbatim in the browser.
- The **causal Transformer LM** (`torch`) is the deep model. It learns longer-range structure and is the headline DL artefact.

Both implement the same `sequence_nll` interface, so `conformance.py`, `eval.py`, and `report.py` are model-agnostic.

## Consequences

- The project runs anywhere (n-gram) *and* demonstrates modern deep learning (Transformer). The dashboard reports both side by side.
- The n-gram is not a throwaway baseline — it is the portable, interpretable, browser-deployable model, and it happens to be competitive on this data.
- We maintain two models. The shared interface keeps the cost low, and the comparison is itself a result.
