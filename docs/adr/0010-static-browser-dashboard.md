# 10. Ship a self-contained static dashboard

- **Status:** Accepted
- **Date:** 2025-08-26

## Context

The results need a face — a way to explore separability, the extracted automaton, the fuzzing curve, and to *try* the detector. Options: a Jupyter notebook (great for authors, poor for a public audience), a Streamlit/Flask app (interactive but needs a running server, so no free hosting and a fragile demo), or a static site.

## Decision

We ship a **static, dependency-free dashboard** (`dashboard/`) that reads two JSON artefacts (`results.json`, `grammar.json`) emitted by `syntactica report`. It renders every figure as inline SVG and **re-implements the n-gram scorer in JavaScript** so a visitor can score any domain entirely client-side — the same model and math the Python pipeline uses (verified to match to four decimal places).

It is theme-aware (light/dark), responsive, and deploys to GitHub Pages with no build step.

## Consequences

- There is a live, zero-cost, always-on demo anyone can open — no server, no install.
- The client-side scorer is a faithful mirror of the Python model, which is both a nice interaction and a correctness cross-check.
- Regenerating the figures is one command (`syntactica report`); the dashboard has no separate build.
- The dashboard shows only what `report.py` chooses to export; deep/interactive exploration still belongs in Python.
