"""Evaluation metrics for the conformance detector.

We deliberately avoid the headline "99% accuracy on one dataset" number that
makes intrusion-detection papers untrustworthy. Instead we report:

* **ROC-AUC / PR-AUC** — threshold-free separability of benign vs attack.
* **Per-family recall at a benign-calibrated threshold** — does the detector
  catch tunnelling *and* DGA *and* malformed traffic, or just one?
* **Score distributions** — so a reader can see the separation, not just trust
  a scalar.

The detector is calibrated on benign traffic only; attack labels are used for
*measurement*, never for fitting.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve

from .conformance import ConformanceScorer
from .data.schema import DnsMessage


def _binary_labels(messages: List[DnsMessage]) -> np.ndarray:
    return np.array([0 if m.label == "benign" else 1 for m in messages], dtype=int)


def evaluate(scorer: ConformanceScorer, test: List[DnsMessage]) -> Dict:
    scores = scorer.score_many(test)
    y = _binary_labels(test)
    thr = scorer.threshold

    roc_auc = float(roc_auc_score(y, scores))
    pr_auc = float(average_precision_score(y, scores))

    pred = (scores >= thr).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr_at_thr = fp / (fp + tn) if (fp + tn) else 0.0

    # Per-family recall.
    per_family: Dict[str, Dict] = {}
    fam_scores: Dict[str, List[float]] = defaultdict(list)
    for m, s, p in zip(test, scores, pred):
        fam = m.label or "unknown"
        fam_scores[fam].append(float(s))
        d = per_family.setdefault(fam, {"n": 0, "flagged": 0})
        d["n"] += 1
        d["flagged"] += int(p == 1)
    for fam, d in per_family.items():
        d["detection_rate"] = round(d["flagged"] / d["n"], 4) if d["n"] else 0.0

    # ROC curve (down-sampled for the dashboard, always keeping the final point
    # so the curve reaches (1, 1)).
    fpr, tpr, _ = roc_curve(y, scores)
    step = max(1, len(fpr) // 120)
    idx = list(range(0, len(fpr), step))
    if idx[-1] != len(fpr) - 1:
        idx.append(len(fpr) - 1)
    roc = {"fpr": fpr[idx].round(4).tolist(), "tpr": tpr[idx].round(4).tolist()}

    # Score histograms per family.
    hist = {}
    lo, hi = float(scores.min()), float(scores.max())
    bins = np.linspace(lo, hi, 31)
    for fam, vals in fam_scores.items():
        counts, _ = np.histogram(vals, bins=bins)
        hist[fam] = counts.tolist()

    return {
        "threshold": round(thr, 4),
        "roc_auc": round(roc_auc, 4),
        "pr_auc": round(pr_auc, 4),
        "operating_point": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "false_positive_rate": round(fpr_at_thr, 4),
            "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        },
        "per_family": per_family,
        "roc_curve": roc,
        "score_hist": {"bins": bins.round(4).tolist(), "counts": hist},
    }
