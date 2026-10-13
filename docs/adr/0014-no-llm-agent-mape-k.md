# 14. No LLM agent; deliver autonomy as a MAPE-K loop

- **Status:** Accepted
- **Date:** 2025-08-28

## Context

"Agentic AI" is fashionable, and it is tempting to wrap the detector in a large-language-model agent that narrates findings or decides responses. We evaluated this and decided against it.

## Decision

We do **not** introduce any LLM or external-API agent. Instead, the system's autonomy is delivered as a classic **MAPE-K autonomic control loop** (Kephart & Chess, 2003):

- **Monitor** — ingest DNS (pcap or live);
- **Analyse** — score conformance with the grammar;
- **Plan / Execute** — throttle via the per-source token bucket;
- **Knowledge** — per-source bucket state / reputation.

## Consequences

- The system stays **local, offline, and reproducible** — essential for a networking tool that defends the very layer an external API would depend on, and for regenerating every figure from one seed.
- The autonomy is real and defensible (a self-adapting control loop), not a veneer. The hard contributions — protocol grammar, token-bucket response, conformal guarantee — owe nothing to an LLM.
- If a future variant wants natural-language reporting, it can consume `results.json` out-of-band without putting a non-deterministic model in the control path.

Superseding this decision would require a use case where an LLM genuinely improves the *networking* outcome, which we did not find.
