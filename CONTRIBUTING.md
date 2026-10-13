# Contributing

Thanks for your interest in Syntactica. This is a research/education project; contributions that improve clarity, correctness, or coverage are welcome.

## Development setup

```bash
pip install -e ".[nn,dev]"
pytest -q          # run the tests
ruff check src tests
```

## Ground rules

- **Tests must pass and lint must be clean** before a PR is merged (CI enforces this).
- **Keep the core dependency-free.** The data/codec/tokenizer/n-gram path must run with only `numpy` (+ `scikit-learn` for metrics). PyTorch stays behind the optional `[nn]` extra.
- **Record significant decisions as ADRs** (`docs/adr/`). If you change a design choice, add a new ADR rather than rewriting an old one.
- **Never weaken the fuzzing safety guard.** The loopback-only default in `fuzz/harness.py` is load-bearing; `test_harness_refuses_external_target` must stay green.

## Ideas that would genuinely extend the project

- A second protocol (HTTP or Modbus) behind the same tokenizer→model→scorer interface.
- Ingesting a public labelled corpus alongside the synthetic one for external validation.
- RNN→DFA extraction to recover a richer state machine than the label-length chain.
- A constrained adversarial-mimicry study against the detector.

## Commit style

Small, focused commits with imperative subject lines (e.g. "Add TCP/53 support to the pcap reader"). Reference an issue when one exists.
