# 3. Frame detection as language modelling, not classification

- **Status:** Accepted
- **Date:** 2025-08-21

## Context

The default approach to ML-based intrusion detection is a supervised classifier: collect a labelled dataset of benign and attack flows, extract features, train a model to separate them. This is what almost every "IDS with machine learning" project does, and it has two structural weaknesses:

1. **It needs attack labels.** It can only recognise attack families present in the training set. Novel (zero-day) families are, by definition, unrepresented.
2. **It over-reports.** A single accuracy/F1 on one benchmark (often with known label leakage, e.g. CICIDS2017) invites over-fitting to that benchmark.

## Decision

We frame detection as **unsupervised language modelling of benign traffic**. A model learns the probability distribution of *normal* DNS token sequences. A message's conformance is its likelihood under that model; low likelihood ⇒ grammar violation ⇒ anomaly.

Attack labels are used only to *measure* the detector, never to *fit* it.

## Consequences

- The detector catches families it has never seen — including the three modelled here and, in principle, real zero-days — because "unlike normal" is a superset of "like a known attack".
- Calibration reduces to picking one threshold on benign surprisal (see [ADR-0005](0005-perplexity-as-conformance-score.md)).
- We cannot claim supervised-level precision on a *specific* known family; a supervised head could always squeeze out more on its training distribution. We accept this: generality and zero-day capability are the point.
- Evaluation must report separability and per-family recall, not one scalar (see `eval.py`).
