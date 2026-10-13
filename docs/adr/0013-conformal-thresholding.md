# 13. Offer conformal thresholds with a false-positive guarantee

- **Status:** Accepted
- **Date:** 2025-08-28

## Context

The quantile threshold ([ADR-0005](0005-perplexity-as-conformance-score.md)) is simple and works, but its false-positive rate is only *empirically* controlled — there is no formal statement, and calibrating on the training set biases it. For a security tool, a defensible bound on false alarms is worth having.

## Decision

We add **split-conformal calibration**: fit the grammar on one benign split, and set the threshold on a *disjoint* held-out benign calibration set at rank `ceil((n+1)(1-alpha))` of the sorted scores. Under exchangeability this guarantees the probability that a genuinely benign query is flagged is at most `alpha` — distribution-free, no Gaussian assumption. The report sweeps several `alpha` values and shows the realised FPR stays at or below each target.

This does not replace the quantile threshold; it is an additional, rigorously-calibrated operating mode (`ConformanceScorer.calibrate_conformal`).

## Consequences

- The operator can pick a false-positive budget with a finite-sample guarantee, and the dashboard shows the guarantee holding empirically (e.g. `alpha = 1%` → realised FPR ≈ 0.5%, recall ≈ 99%).
- The guarantee requires the calibration set to be disjoint from training and exchangeable with test traffic; the report enforces the split, and real deployments must use held-out benign traffic.
- It adds a small, well-understood piece of machinery rather than another model.
