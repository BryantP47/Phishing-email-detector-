"""Command-line interface.

    python -m phishing_detector analyze message.eml [more.eml | dir/] [--json] [--model model.json]
    python -m phishing_detector train data.csv --out model.json
    python -m phishing_detector evaluate data.csv --model model.json
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import sys
from typing import List, Optional, Tuple

from .classifier import NaiveBayesClassifier, evaluate, normalize_label
from .detector import PhishingDetector
from .parser import parse_email_file

EMAIL_EXTENSIONS = (".eml", ".msg", ".txt")

_COLORS = {"phishing": "\033[91m", "suspicious": "\033[93m", "legitimate": "\033[92m"}
_RESET = "\033[0m"


def _expand_paths(paths: List[str]) -> List[str]:
    files = []
    for path in paths:
        if os.path.isdir(path):
            for root, _, names in os.walk(path):
                files.extend(os.path.join(root, n) for n in sorted(names) if n.lower().endswith(EMAIL_EXTENSIONS))
        else:
            files.append(path)
    return files


def load_dataset(path: str) -> Tuple[List[str], List[str]]:
    """Load (texts, labels) from a CSV or from a directory of labelled .eml files.

    CSV: needs a label column (``label``/``class``/``is_phishing``) and a text
    column (``text``/``body``/``email``), optionally ``subject``.
    Directory: sub-folders named ``phishing`` and ``legitimate`` (or ``ham``).
    """
    texts: List[str] = []
    labels: List[str] = []
    if os.path.isdir(path):
        for sub in sorted(os.listdir(path)):
            full = os.path.join(path, sub)
            if not os.path.isdir(full):
                continue
            try:
                label = normalize_label(sub)
            except ValueError:
                continue
            for file in _expand_paths([full]):
                texts.append(parse_email_file(file).full_text)
                labels.append(label)
        return texts, labels

    csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        fields = {f.lower().strip(): f for f in reader.fieldnames or []}
        label_col = next((fields[c] for c in ("label", "class", "is_phishing", "type") if c in fields), None)
        text_col = next((fields[c] for c in ("text", "body", "email", "message", "content") if c in fields), None)
        subject_col = fields.get("subject")
        if not label_col or not text_col:
            raise SystemExit(f"{path}: CSV needs a label column and a text column, got {reader.fieldnames}")
        for row in reader:
            text = row.get(text_col) or ""
            if subject_col:
                text = f"{row.get(subject_col) or ''}\n{text}"
            try:
                labels.append(normalize_label(row[label_col]))
            except ValueError:
                continue
            texts.append(text)
    return texts, labels


def _print_result(path: str, result, verbose: bool, color: bool) -> None:
    verdict = result.verdict.upper()
    if color:
        verdict = f"{_COLORS[result.verdict]}{verdict}{_RESET}"
    print(f"{path}: {verdict} (score {result.score:.0%})")
    if result.subject:
        print(f"  Subject: {result.subject}")
    if result.sender:
        print(f"  From:    {result.sender}")
    if result.model_score is not None:
        print(f"  Rules: {result.rule_score:.0%}  Model: {result.model_score:.0%}")
    shown = result.findings if verbose else result.findings[:8]
    for f in shown:
        print(f"  [{f.category:<10}] +{f.weight:<4} {f.description}")
    if len(shown) < len(result.findings):
        print(f"  ... {len(result.findings) - len(shown)} more (use -v)")
    print()


def cmd_analyze(args) -> int:
    detector = PhishingDetector.with_model_file(args.model, model_weight=args.model_weight) if args.model else PhishingDetector()
    files = _expand_paths(args.paths)
    if not files:
        print("no email files found", file=sys.stderr)
        return 2
    results = []
    exit_code = 0
    color = sys.stdout.isatty() and not args.no_color
    for path in files:
        try:
            result = detector.analyze_file(path)
        except OSError as exc:
            print(f"{path}: error: {exc}", file=sys.stderr)
            exit_code = 2
            continue
        if result.verdict == "phishing" and exit_code == 0:
            exit_code = 1
        if args.json:
            results.append({"file": path, **result.to_dict()})
        else:
            _print_result(path, result, args.verbose, color)
    if args.json:
        print(json.dumps(results if len(results) != 1 else results[0], indent=2))
    return exit_code


def cmd_train(args) -> int:
    texts, labels = load_dataset(args.data)
    if not texts:
        raise SystemExit("no training examples found")
    # Stratified split so both classes appear in train and test.
    rng = random.Random(args.seed)
    train, test = [], []
    for label in ("phishing", "legitimate"):
        group = [(t, l) for t, l in zip(texts, labels) if l == label]
        rng.shuffle(group)
        n_test = int(round(len(group) * args.test_split)) if args.test_split > 0 else 0
        test.extend(group[:n_test])
        train.extend(group[n_test:])
    clf = NaiveBayesClassifier(alpha=args.alpha).fit([t for t, _ in train], [l for _, l in train])
    if not clf.is_trained:
        raise SystemExit("training data must contain both phishing and legitimate examples")
    clf.save(args.out)
    print(f"Trained on {len(train)} emails ({clf.doc_counts['phishing']} phishing, "
          f"{clf.doc_counts['legitimate']} legitimate); model saved to {args.out}")
    if test:
        _print_metrics(evaluate(clf, [t for t, _ in test], [l for _, l in test]), len(test))
    return 0


def _print_metrics(metrics: dict, n: int) -> None:
    c = metrics["confusion"]
    print(f"Evaluation on {n} emails: accuracy {metrics['accuracy']:.3f}, precision {metrics['precision']:.3f}, "
          f"recall {metrics['recall']:.3f}, F1 {metrics['f1']:.3f}")
    print(f"  TP {c['tp']}  FP {c['fp']}  TN {c['tn']}  FN {c['fn']}")


def cmd_evaluate(args) -> int:
    texts, labels = load_dataset(args.data)
    clf = NaiveBayesClassifier.load(args.model)
    _print_metrics(evaluate(clf, texts, labels), len(texts))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phishing-detector", description="Detect phishing emails.")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("analyze", help="analyze .eml files or directories")
    p.add_argument("paths", nargs="+")
    p.add_argument("--model", help="trained model JSON to blend with the rules")
    p.add_argument("--model-weight", type=float, default=0.4, help="weight of the model score (0-1, default 0.4)")
    p.add_argument("--json", action="store_true", help="output JSON")
    p.add_argument("-v", "--verbose", action="store_true", help="show all findings")
    p.add_argument("--no-color", action="store_true")
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("train", help="train the Naive Bayes model")
    p.add_argument("data", help="CSV file or directory with phishing/ and legitimate/ sub-folders")
    p.add_argument("--out", default="model.json")
    p.add_argument("--alpha", type=float, default=1.0, help="Laplace smoothing")
    p.add_argument("--test-split", type=float, default=0.2, help="fraction held out for evaluation")
    p.add_argument("--seed", type=int, default=42)
    p.set_defaults(func=cmd_train)

    p = sub.add_parser("evaluate", help="evaluate a trained model on labelled data")
    p.add_argument("data")
    p.add_argument("--model", required=True)
    p.set_defaults(func=cmd_evaluate)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
