# Architecture

Syntactica is a small, layered pipeline. Each layer has one job and a narrow interface to the next, so the system is easy to test and to reason about. This document walks the data from a packet to a verdict.

## The one-sentence version

> Turn each DNS message into a structural token stream, learn the distribution of *benign* token streams with a language model, and flag any message whose surprisal under that model exceeds a benign-calibrated threshold — then reuse the same model to extract an automaton and to fuzz a resolver.

## Layers

```
        ┌───────────────────────────────────────────────────────────────┐
        │  data/                                                         │
        │  ┌────────────┐  ┌────────────┐  ┌──────────────┐             │
        │  │ synth.py   │  │ pcap.py    │  │ codec.py     │             │
        │  │ benign +   │  │ your own   │  │ DNS wire     │             │
        │  │ attacks    │  │ captures   │  │ encode/decode│             │
        │  └─────┬──────┘  └─────┬──────┘  └──────┬───────┘             │
        │        └──────── DnsMessage ────────────┘                     │
        └───────────────────────┬───────────────────────────────────────┘
                                │
                     ┌──────────▼───────────┐
                     │ tokenizer.py         │   protocol-aware tokens:
                     │ DnsMessage → tokens  │   QR=, QT=, LEN=, chars, <sep>
                     └──────────┬───────────┘
                     ┌──────────▼───────────┐
        models/      │ ngram.py │ transformer.py    both expose sequence_nll()
                     └──────────┬───────────┘
                     ┌──────────▼───────────┐
                     │ conformance.py       │   surprisal → threshold → Decision
                     └──────────┬───────────┘
         ┌───────────┬──────────┼───────────┬───────────────┐
   ┌─────▼─────┐ ┌───▼────┐ ┌───▼─────┐ ┌───▼────────┐ ┌────▼────────┐
   │ eval.py   │ │grammar/│ │ fuzz/   │ │ grammar/   │ │ report.py   │
   │ ROC, PR,  │ │automaton│ │generator│ │ fields.py  │ │ → dashboard │
   │ per-family│ │extraction│ │+ harness│ │ localisation│ │ artefacts   │
   └───────────┘ └────────┘ └─────────┘ └────────────┘ └─────────────┘
```

## Data layer (`data/`)

- **`schema.py`** — `DnsMessage`, `DnsQuestion`, `DnsRecord`. The typed boundary between bytes and learning.
- **`codec.py`** — pure-Python DNS wire encode/decode, compression-pointer aware, *total* encoding (never raises). See [ADR-0009](adr/0009-zero-dependency-dns-codec.md).
- **`synth.py`** — deterministic benign generator (dictionary labels, realistic qtype mix) plus three attack families. Training uses **benign only**.
- **`pcap.py`** — minimal libpcap reader to ingest your own `tshark`/Wireshark captures.

## Tokenizer (`tokenizer.py`)

Converts a `DnsMessage` into a flat token stream that exposes protocol structure: message fields, per-label length buckets, characters over a fixed DNS-legal alphabet, and delimiters. This is the front half of the grammar; see [ADR-0004](adr/0004-protocol-aware-tokenizer.md).

## Models (`models/`)

Two interchangeable grammars behind a common `sequence_nll` interface:

- **`ngram.py`** — interpolated n-gram (a smoothed stochastic regular grammar). Pure numpy, JSON-serialisable, browser-portable.
- **`transformer.py`** — a small causal Transformer LM (optional `torch`). Batched scoring keeps evaluation fast on CPU.

See [ADR-0006](adr/0006-ship-ngram-and-transformer.md).

## Conformance (`conformance.py`)

Wraps a model + tokenizer. Scores a message's mean per-token surprisal, calibrates a threshold on benign traffic, and (for the n-gram) explains per-token surprisal. See [ADR-0003](adr/0003-language-model-as-grammar.md), [ADR-0005](adr/0005-perplexity-as-conformance-score.md).

## Consumers

- **`eval.py`** — threshold-free separability (ROC/PR AUC) plus per-family recall and score distributions.
- **`grammar/automaton.py`** — extracts a label-length Markov automaton; **`grammar/fields.py`** localises the offending token. See [ADR-0007](adr/0007-extract-interpretable-automaton.md).
- **`net/checksum.py`** — CRC-32 + Internet/UDP checksum (Unit II error detection); consumed by `data/pcap.py`'s integrity iterator. See [ADR-0012](adr/0012-hand-rolled-error-detection.md).
- **`mitigation/`** — token bucket + adaptive rate limiter (Unit IV) and the closed-loop `simulate.py`; turns detection into defence. See [ADR-0011](adr/0011-closed-loop-token-bucket-mitigation.md).
- **`conformance.calibrate_conformal`** — distribution-free FPR-bounded thresholds. See [ADR-0013](adr/0013-conformal-thresholding.md).
- **`fuzz/`** — grammar-guided generator + safe loopback harness with a bundled mock resolver. See [ADR-0008](adr/0008-grammar-guided-fuzzing-loopback-only.md).
- **`report.py`** — runs everything from one seed and writes `dashboard/data/{results,grammar}.json`.

The end-to-end system reads as a **MAPE-K autonomic loop** — Monitor (`data`) → Analyse (`conformance`) → Plan/Execute (`mitigation`) → Knowledge (per-source buckets) — with no external services. See [ADR-0014](adr/0014-no-llm-agent-mape-k.md).

## Reproducibility

Everything is seeded. `syntactica report` regenerates every metric, figure, and dashboard artefact deterministically. The dashboard is a static consumer of those artefacts — no separate build. See [ADR-0010](adr/0010-static-browser-dashboard.md).
