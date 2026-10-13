# Architecture Decision Records

This log captures the significant, hard-to-reverse decisions behind Syntactica and the reasoning at the time each was made. See [ADR-0001](0001-record-architecture-decisions.md) for the format and rules.

| # | Decision | Status |
|---|---|---|
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | Accepted |
| [0002](0002-scope-the-grammar-to-dns.md) | Scope the grammar to DNS | Accepted |
| [0003](0003-language-model-as-grammar.md) | Frame detection as language modelling, not classification | Accepted |
| [0004](0004-protocol-aware-tokenizer.md) | Use a protocol-aware tokenizer, not raw bytes | Accepted |
| [0005](0005-perplexity-as-conformance-score.md) | Score conformance by per-token surprisal | Accepted |
| [0006](0006-ship-ngram-and-transformer.md) | Ship both an n-gram grammar and a Transformer LM | Accepted |
| [0007](0007-extract-interpretable-automaton.md) | Extract an interpretable automaton | Accepted |
| [0008](0008-grammar-guided-fuzzing-loopback-only.md) | Grammar-guided fuzzing, loopback-only by default | Accepted |
| [0009](0009-zero-dependency-dns-codec.md) | Hand-roll a zero-dependency DNS codec | Accepted |
| [0010](0010-static-browser-dashboard.md) | Ship a self-contained static dashboard | Accepted |
| [0011](0011-closed-loop-token-bucket-mitigation.md) | Close the loop with token-bucket rate limiting (Unit IV) | Accepted |
| [0012](0012-hand-rolled-error-detection.md) | Hand-roll CRC-32 and the Internet checksum (Unit II) | Accepted |
| [0013](0013-conformal-thresholding.md) | Conformal thresholds with a false-positive guarantee | Accepted |
| [0014](0014-no-llm-agent-mape-k.md) | No LLM agent; autonomy as a MAPE-K loop | Accepted |
| [0015](0015-online-self-learning.md) | Add an online, self-learning detector | Accepted |
