"""End-to-end pipeline: build corpus, learn the grammar, evaluate, and emit
the artefacts the dashboard consumes.

Running ``build_report`` reproduces every number and figure in the project from
a single seed. It writes two files under ``dashboard/data/``:

* ``results.json`` — metrics, ROC curve, score histograms, the extracted
  automaton, worked explanations, and the fuzzing validity curve;
* ``grammar.json``  — the fitted n-gram grammar, so the dashboard can score
  domains typed by a visitor entirely client-side.
"""
from __future__ import annotations

import json
import os
import time
from typing import Dict, List

from .conformance import ConformanceScorer
from .data.synth import build_corpus
from .eval import evaluate
from .fuzz import FuzzHarness, GrammarFuzzer, MockResolver
from .grammar import LabelLengthAutomaton, field_profile, hotspot
from .models.ngram import NGramGrammar
from .tokenizer import build_vocab, tokenize


def _fuzz_curve(
    model: NGramGrammar, scorer: ConformanceScorer, temperatures, n_per: int = 150
) -> List[Dict]:
    """Characterise the grammar fuzzer across sampling temperatures.

    Two signals, together the validity/novelty tradeoff at the heart of
    grammar-guided fuzzing (Learn&Fuzz, ASE'17):

    * ``validity_rate`` — share of generated traffic the resolver accepts;
    * ``mean_novelty``  — mean conformance score of *pure* grammar samples under
      the detector. As temperature rises the sampler drifts away from the
      learned grammar, so novelty climbs — it is exploring the boundary.
    """
    curve = []
    with MockResolver() as resolver:
        harness = FuzzHarness(("127.0.0.1", resolver.port))
        for t in temperatures:
            fuzzer = GrammarFuzzer(model, seed=int(t * 100))
            cases = fuzzer.batch(n_per, temperature=t, mutate_frac=0.25)
            report = harness.run(cases)
            # Novelty: score pure (unmutated) grammar samples with the detector.
            novelty_fuzzer = GrammarFuzzer(model, seed=1000 + int(t * 100))
            samples = [novelty_fuzzer.sample_message(t) for _ in range(n_per)]
            novelty = float(scorer.score_many(samples).mean())
            curve.append(
                {
                    "temperature": t,
                    "validity_rate": round(report.validity_rate, 4),
                    "mean_novelty": round(novelty, 4),
                    "outcomes": dict(report.outcomes),
                }
            )
    return curve



def _embedding_block(tf, vocab, test, n: int = 700, seed: int = 0) -> Dict:
    """2D PCA projection of the Transformer's learned flow embeddings.

    Shows whether the model has organised traffic into meaningful regions. The
    projection is deterministic (PCA, fixed subsample) so the figure reproduces.
    """
    import random

    from sklearn.decomposition import PCA

    rng = random.Random(seed)
    sub = test if len(test) <= n else rng.sample(test, n)
    emb = tf.embed([vocab.encode(tokenize(m)) for m in sub])
    pca = PCA(n_components=2)
    xy = pca.fit_transform(emb)
    # normalise to a tidy range for plotting
    xy = (xy - xy.mean(axis=0)) / (xy.std(axis=0) + 1e-9)
    points = [
        {"x": round(float(px), 3), "y": round(float(py), 3), "f": m.label}
        for (px, py), m in zip(xy, sub)
    ]
    return {
        "explained_variance": [round(float(v), 3) for v in pca.explained_variance_ratio_],
        "points": points,
    }


def _conformal_block(train_benign, test, alphas=(0.005, 0.01, 0.02, 0.05)) -> Dict:
    """Distribution-free operating points via split-conformal calibration.

    The grammar is fit on 80% of benign traffic and the threshold is conformal-
    calibrated on the held-out 20% (disjoint, so the finite-sample guarantee is
    valid). For each target false-positive rate ``alpha`` we report the realised
    FPR on benign test traffic and the attack recall — showing the empirical FPR
    stays at or below the guarantee while recall stays high.
    """
    split = int(len(train_benign) * 0.8)
    fit_set, calib_set = train_benign[:split], train_benign[split:]
    g = NGramGrammar(order=3).fit([tokenize(m) for m in fit_set])
    sc = ConformanceScorer(g, mode="ngram")
    benign_test = [m for m in test if m.label == "benign"]
    attacks = [m for m in test if m.label != "benign"]
    points = []
    for alpha in alphas:
        thr = sc.calibrate_conformal(calib_set, alpha=alpha)
        fpr = sum(sc.decide(m).is_violation for m in benign_test) / max(len(benign_test), 1)
        rec = sum(sc.decide(m).is_violation for m in attacks) / max(len(attacks), 1)
        points.append(
            {
                "alpha": alpha,
                "threshold": round(thr, 4),
                "empirical_fpr": round(fpr, 4),
                "attack_recall": round(rec, 4),
            }
        )
    return {"n_calibration": len(calib_set), "points": points}


def _worked_examples(scorer: ConformanceScorer, test, per_family: int = 1) -> List[Dict]:
    seen = {}
    examples = []
    for m in test:
        fam = m.label
        if seen.get(fam, 0) >= per_family:
            continue
        seen[fam] = seen.get(fam, 0) + 1
        profile = field_profile(m, scorer)
        hs = hotspot(profile)
        examples.append(
            {
                "family": fam,
                "qname": m.primary_qname,
                "qtype": m.questions[0].qtype_name if m.questions else "",
                "score": round(scorer.score_message(m), 4),
                "is_violation": bool(scorer.decide(m).is_violation),
                "hotspot": (
                    {"token": hs.token, "role": hs.role, "surprisal": hs.surprisal} if hs else None
                ),
                "profile": [{"t": c.token, "r": c.role, "s": c.surprisal} for c in profile][:120],
            }
        )
        if len(seen) >= 4 and all(v >= per_family for v in seen.values()):
            break
    return examples


def build_report(
    out_dir: str = "dashboard/data",
    n_benign: int = 8000,
    n_attack_each: int = 600,
    seed: int = 0,
    use_transformer: bool = True,
    transformer_epochs: int = 6,
) -> Dict:
    t0 = time.time()
    os.makedirs(out_dir, exist_ok=True)

    # 1. Corpus ------------------------------------------------------------
    train_benign, test = build_corpus(n_benign, n_attack_each, seed=seed)
    vocab = build_vocab(train_benign + test)

    # 2. N-gram grammar ----------------------------------------------------
    ngram = NGramGrammar(order=3)
    ngram.fit([tokenize(m) for m in train_benign])
    ng_scorer = ConformanceScorer(ngram, mode="ngram")
    ng_scorer.calibrate(train_benign, quantile=0.99)
    ngram_metrics = evaluate(ng_scorer, test)

    models_block = {"ngram": ngram_metrics}
    embedding = None

    # 3. Transformer grammar (optional) -----------------------------------
    if use_transformer:
        try:
            from .models.transformer import TransformerGrammar

            tf = TransformerGrammar(vocab)
            tf.fit([vocab.encode(tokenize(m)) for m in train_benign], epochs=transformer_epochs)
            tf_scorer = ConformanceScorer(tf, vocab=vocab, mode="transformer")
            tf_scorer.calibrate(train_benign, quantile=0.99)
            models_block["transformer"] = evaluate(tf_scorer, test)
            embedding = _embedding_block(tf, vocab, test, seed=seed)
        except Exception as exc:  # torch missing or training failure
            models_block["transformer_error"] = str(exc)

    # 4. Extracted automaton ----------------------------------------------
    automaton = LabelLengthAutomaton().fit(train_benign).to_dict()

    # 5. Worked explanations ----------------------------------------------
    examples = _worked_examples(ng_scorer, test)

    # 6. Grammar-guided fuzzing curve -------------------------------------
    fuzz_curve = _fuzz_curve(ngram, ng_scorer, temperatures=[0.5, 0.8, 1.0, 1.3, 1.6, 2.0])

    # 7. Closed-loop mitigation (token-bucket rate limiting) --------------
    from .mitigation import run_comparison

    mitigation = run_comparison(ng_scorer, seed=seed)

    # 8. Conformal operating points (distribution-free FPR guarantee) -----
    conformal = _conformal_block(train_benign, test)

    # 9. Online self-learning under traffic drift -------------------------
    from .online import stream_adaptation_demo

    online = stream_adaptation_demo(seed=seed)

    results = {
        "meta": {
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "seed": seed,
            "elapsed_sec": round(time.time() - t0, 2),
            "dataset": {
                "train_benign": len(train_benign),
                "test_total": len(test),
                "test_attacks": sum(1 for m in test if m.label != "benign"),
                "attack_families": sorted({m.label for m in test if m.label != "benign"}),
            },
            "vocab_size": len(vocab),
        },
        "models": models_block,
        "automaton": automaton,
        "examples": examples,
        "fuzzing": fuzz_curve,
        "mitigation": mitigation,
        "conformal": conformal,
        "embedding": embedding,
        "online": online,
    }

    with open(os.path.join(out_dir, "results.json"), "w") as fh:
        json.dump(results, fh, indent=2)
    with open(os.path.join(out_dir, "grammar.json"), "w") as fh:
        fh.write(ngram.to_json(prune_below=1))

    return results
