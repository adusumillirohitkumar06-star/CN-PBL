# 1. Record architecture decisions

- **Status:** Accepted
- **Date:** 2025-08-20

## Context

This project makes several non-obvious design choices (framing detection as language modelling, shipping two models, hand-rolling a DNS codec). Reviewers, teammates, and our future selves need to know *why* each choice was made, not just *what* the code does. Reconstructing rationale from a diff is expensive and lossy.

## Decision

We record architecturally significant decisions as short Markdown files in `docs/adr/`, numbered sequentially, using a lightweight Context / Decision / Consequences structure (after Michael Nygard's ADR pattern). A decision is "significant" if it is costly to reverse, shapes the public API, or is likely to be questioned.

An ADR is immutable once accepted. If a later decision overturns it, we add a new ADR and mark the old one *Superseded by ADR-NNNN* rather than editing history.

## Consequences

- New contributors can read the ADR log and understand the shape of the system in ten minutes.
- Design debates are settled once and cited, not relitigated.
- There is a small ongoing cost to writing an ADR when a real decision is made; we accept it.
