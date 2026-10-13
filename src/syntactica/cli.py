"""Command-line interface: ``syntactica <command>``.

Commands
--------
report   Run the full pipeline and (re)generate the dashboard artefacts.
score    Score one or more domain names against a freshly-learned grammar.
analyze  Analyse a real .pcap capture from your own network for DNS anomalies.
fuzz     Run the grammar-guided fuzzer against the bundled mock resolver.
demo     A fast, self-contained end-to-end smoke run.
"""
from __future__ import annotations

import argparse
import sys
from typing import List

from .conformance import ConformanceScorer
from .data.schema import DnsMessage, DnsQuestion
from .data.synth import build_corpus
from .fuzz import FuzzHarness, GrammarFuzzer, MockResolver
from .models.ngram import NGramGrammar
from .report import build_report
from .tokenizer import tokenize


def _train_ngram_scorer(n_benign: int = 6000, seed: int = 0) -> ConformanceScorer:
    train_benign, _ = build_corpus(n_benign, 1, seed=seed)
    model = NGramGrammar(order=3).fit([tokenize(m) for m in train_benign])
    scorer = ConformanceScorer(model, mode="ngram")
    scorer.calibrate(train_benign, quantile=0.99)
    return scorer


def cmd_report(args: argparse.Namespace) -> int:
    res = build_report(
        out_dir=args.out,
        n_benign=args.benign,
        n_attack_each=args.attacks,
        seed=args.seed,
        use_transformer=not args.no_transformer,
        transformer_epochs=args.epochs,
    )
    m = res["models"]["ngram"]
    print(f"n-gram   ROC-AUC={m['roc_auc']}  PR-AUC={m['pr_auc']}  "
          f"recall={m['operating_point']['recall']}  "
          f"FPR={m['operating_point']['false_positive_rate']}")
    if "transformer" in res["models"]:
        t = res["models"]["transformer"]
        print(f"transformer ROC-AUC={t['roc_auc']}  PR-AUC={t['pr_auc']}  "
              f"recall={t['operating_point']['recall']}")
    print(f"artefacts written to {args.out}/  ({res['meta']['elapsed_sec']}s)")
    return 0


def cmd_score(args: argparse.Namespace) -> int:
    scorer = _train_ngram_scorer(seed=args.seed)
    for name in args.domains:
        msg = DnsMessage(questions=[DnsQuestion(name, args.qtype, 1)])
        d = scorer.decide(msg)
        verdict = "VIOLATION" if d.is_violation else "conforming"
        print(f"{name:<45} score={d.score:6.3f}  thr={d.threshold:5.3f}  -> {verdict}")
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    """Analyse a real capture: fit the grammar on its own traffic, flag outliers.

    This is the deploy-on-your-own-network workflow. With no labels available,
    we treat the capture as mostly-benign background, learn its grammar, and
    surface the least-conforming queries plus any UDP-checksum failures.
    """
    from .data import iter_dns_with_integrity
    from .grammar import field_profile, hotspot

    try:
        pairs = list(iter_dns_with_integrity(args.pcap))
    except FileNotFoundError:
        print(f"error: no such file: {args.pcap}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    queries = [m for m, _ in pairs if m.is_query and m.questions]
    checksum_failures = sum(1 for _, ok in pairs if not ok)
    if len(queries) < 20:
        print(f"only {len(queries)} DNS queries found — need more traffic to learn a grammar.")
        return 1

    model = NGramGrammar(order=3).fit([tokenize(m) for m in queries])
    scorer = ConformanceScorer(model, mode="ngram")
    scorer.calibrate(queries, quantile=args.quantile)

    scored = sorted(queries, key=scorer.score_message, reverse=True)
    flagged = [m for m in queries if scorer.decide(m).is_violation]

    print(f"capture: {args.pcap}")
    print(f"  DNS messages: {len(pairs)}   queries analysed: {len(queries)}")
    print(f"  UDP checksum failures: {checksum_failures}")
    print(f"  conformance threshold: {scorer.threshold:.3f} nats/token")
    print(f"  flagged as anomalous: {len(flagged)} ({len(flagged) / len(queries) * 100:.1f}%)\n")
    print(f"  top {min(args.top, len(scored))} least-conforming queries:")
    for m in scored[: args.top]:
        hs = hotspot(field_profile(m, scorer))
        why = f"  [{hs.token}]" if hs else ""
        print(f"    {scorer.score_message(m):6.3f}  {m.primary_qname[:60]}{why}")
    return 0


def cmd_fuzz(args: argparse.Namespace) -> int:
    train_benign, _ = build_corpus(6000, 1, seed=args.seed)
    model = NGramGrammar(order=3).fit([tokenize(m) for m in train_benign])
    fuzzer = GrammarFuzzer(model, seed=args.seed)
    with MockResolver() as resolver:
        harness = FuzzHarness(("127.0.0.1", resolver.port))
        cases = fuzzer.batch(args.n, temperature=args.temperature, mutate_frac=args.mutate)
        report = harness.run(cases)
    print(f"sent={report.total}  validity={report.validity_rate:.3f}  "
          f"outcomes={dict(report.outcomes)}")
    for f in report.findings[:5]:
        print("  finding:", f)
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    print("Syntactica demo — learning DNS grammar on synthetic traffic...")
    res = build_report(out_dir=args.out, n_benign=3000, n_attack_each=300,
                       seed=0, use_transformer=False)
    m = res["models"]["ngram"]
    print(f"\n  ROC-AUC = {m['roc_auc']}   PR-AUC = {m['pr_auc']}")
    print("  per-family detection:")
    for fam, d in res["models"]["ngram"]["per_family"].items():
        print(f"    {fam:<10} {d['detection_rate']*100:5.1f}%  (n={d['n']})")
    print(f"\n  dashboard artefacts in {args.out}/")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="syntactica", description="Neural protocol grammar for DNS.")
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("report", help="run the full pipeline and emit dashboard artefacts")
    r.add_argument("--out", default="dashboard/data")
    r.add_argument("--benign", type=int, default=8000)
    r.add_argument("--attacks", type=int, default=600)
    r.add_argument("--epochs", type=int, default=6)
    r.add_argument("--seed", type=int, default=0)
    r.add_argument("--no-transformer", action="store_true", help="skip the PyTorch model")
    r.set_defaults(func=cmd_report)

    s = sub.add_parser("score", help="score domain names")
    s.add_argument("domains", nargs="+")
    s.add_argument("--qtype", type=int, default=1)
    s.add_argument("--seed", type=int, default=0)
    s.set_defaults(func=cmd_score)

    a = sub.add_parser("analyze", help="analyse a real .pcap capture for DNS anomalies")
    a.add_argument("pcap", help="path to a libpcap .pcap capture (see scripts/capture.sh)")
    a.add_argument("--quantile", type=float, default=0.99, help="benign calibration quantile")
    a.add_argument("--top", type=int, default=15, help="how many anomalies to list")
    a.set_defaults(func=cmd_analyze)

    f = sub.add_parser("fuzz", help="grammar-guided fuzzing against the mock resolver")
    f.add_argument("-n", type=int, default=500)
    f.add_argument("--temperature", type=float, default=1.0)
    f.add_argument("--mutate", type=float, default=0.3)
    f.add_argument("--seed", type=int, default=0)
    f.set_defaults(func=cmd_fuzz)

    d = sub.add_parser("demo", help="fast end-to-end smoke run")
    d.add_argument("--out", default="dashboard/data")
    d.set_defaults(func=cmd_demo)
    return p


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
