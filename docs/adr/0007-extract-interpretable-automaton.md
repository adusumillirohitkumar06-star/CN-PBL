# 7. Extract an interpretable automaton from the learned grammar

- **Status:** Accepted
- **Date:** 2025-08-24

## Context

A language model is a black box. For a security tool, "the model says this is anomalous" is not good enough — an analyst needs to know *why*, and a reviewer needs to trust the mechanism. The research literature on extracting automata from RNNs (Weiss et al., ICML 2018) shows this is possible but heavyweight.

## Decision

We recover a **first-order stochastic automaton over label-length shape** — the sequence of `LEN=` buckets — directly from benign traffic, with `START`/`END` states. It is a transparent Markov chain: each transition is an observed probability. We render it as a transition matrix in the dashboard and use its path likelihood as an independent, fully-auditable anomaly signal.

Separately, the per-token surprisal profile localises *where* in a message the grammar broke, tagging each token with its structural role and highlighting the single most surprising token ("the smoking gun").

We deliberately do **not** attempt full neural CFG induction or RNN-to-DFA extraction; that is a research project in itself and a common way to sink a semester.

## Consequences

- The detector's decisions are explainable in protocol terms a networks student can defend in a viva.
- The automaton is a genuine artefact (`automaton.to_dict()`), not a diagram we drew by hand — it is extracted from data every run.
- It models name *shape*, not full protocol semantics; it corroborates the language model rather than replacing it.
