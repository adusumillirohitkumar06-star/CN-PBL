# 15. Add an online, self-learning detector

- **Status:** Accepted
- **Date:** 2025-08-29

## Context

The batch detector learns a grammar once and freezes it. Real networks drift: a new internal service appears, client mixes change. A frozen model slowly goes stale and starts false-alarming on perfectly benign novelty — in our drift scenario it flags ~97% of the new traffic. "Self-learning" is also the natural realisation of the **Knowledge** component of the MAPE-K loop ([ADR-0014](0014-no-llm-agent-mape-k.md)).

## Decision

Add `OnlineDetector`, which processes a live stream and continually adapts:

- **Incremental learning** — `NGramGrammar.observe` updates counts and cached totals in place (no refit).
- **Exponential forgetting** — `NGramGrammar.decay` scales and prunes old counts so the grammar tracks *recent* traffic.
- **A self-training gate** — it learns from conforming traffic *and* from domains that **recur** (a repeating new service is benign drift), but never from **extreme** outliers. Because DGA/tunnel queries are unique and high-entropy, an attack flood can neither be learned nor raise the bar for detecting itself.
- **Decoupled calibration** — only clearly-benign scores enter the rolling window that sets the threshold, so a transient spike never inflates it.

## Consequences

- Under drift, false alarms drop from ~97% (static) to ~0.1% (online) while attack recall stays high (tunnel 100%, DGA ~84%). This is genuine continual, unsupervised self-learning — no labels.
- The self-training gate trades some adaptation speed for poisoning resistance; a determined mimicry adversary that slowly, repeatedly issues near-benign queries is still a theoretical risk, noted as future work.
- Warm-up assumes the stream starts on mostly-benign traffic (the standard cold-start assumption for unsupervised baselines).
