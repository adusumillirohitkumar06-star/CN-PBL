# 11. Close the loop with token-bucket rate limiting

- **Status:** Accepted
- **Date:** 2025-08-27

## Context

Detection alone is only half of a defence. A detector that flags DNS tunnelling but does nothing about it leaves the operator to react manually. We wanted a *response* mechanism that (a) is grounded in the Computer Networks syllabus, (b) preserves service for legitimate users, and (c) does not require a global rate cap that punishes everyone.

## Decision

We add a **detector-driven adaptive rate limiter** built on the **token bucket** algorithm (Unit IV). Each source gets its own bucket; a query's token cost scales with its grammar surprisal (benign ≈ 1 token, flagged ≈ 13 tokens). A source flooding high-surprisal exfil queries drains its bucket and is throttled, while ordinary clients are unaffected. This turns Syntactica into a closed **detect → analyse → throttle** loop.

We compare three policies — none, a naive global token bucket, and the adaptive one — and report **legitimate goodput** and **attack blocked** for each.

## Consequences

- On the closed-loop scenario the adaptive policy preserves ~100% legitimate goodput *and* blocks ~98% of the attack, versus a global cap that drops ~28% of legitimate traffic and blocks only ~27% of the attack.
- Graded (cost-based) throttling makes the response robust to the occasional false positive: one flagged legitimate query is absorbed by the bucket rather than dropping the client.
- This is a genuine realisation of a named syllabus algorithm, and it elevates the project from a detector to a defence. See the closed-loop simulation in `mitigation/simulate.py`.
