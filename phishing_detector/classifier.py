"""A small multinomial Naive Bayes text classifier with no third-party deps.

It complements the heuristic rules: train it on a labelled corpus of your own
mail (or a public dataset) and the detector blends its probability with the
rule score.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from typing import Dict, Iterable, List, Sequence, Tuple

TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9'$-]{1,30}")
URL_TOKEN_RE = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)

STOPWORDS = frozenset(
    "the and for you your are with this that have from not but all was our can will "
    "has his her its they them their what which when who were been has had would "
    "there here about into than then also any more some such only other".split()
)

LABELS = ("legitimate", "phishing")


def tokenize(text: str) -> List[str]:
    text = URL_TOKEN_RE.sub(" __url__ ", text)
    tokens = [t for t in TOKEN_RE.findall(text.lower()) if t not in STOPWORDS]
    bigrams = [f"{a}_{b}" for a, b in zip(tokens, tokens[1:])]
    return tokens + bigrams


class NaiveBayesClassifier:
    def __init__(self, alpha: float = 1.0) -> None:
        self.alpha = alpha
        self.doc_counts: Dict[str, int] = {label: 0 for label in LABELS}
        self.token_counts: Dict[str, Counter] = {label: Counter() for label in LABELS}
        self.total_tokens: Dict[str, int] = {label: 0 for label in LABELS}

    @property
    def vocabulary(self) -> set:
        vocab = set()
        for counts in self.token_counts.values():
            vocab.update(counts)
        return vocab

    @property
    def is_trained(self) -> bool:
        return all(self.doc_counts[label] > 0 for label in LABELS)

    def fit(self, texts: Sequence[str], labels: Sequence[str]) -> "NaiveBayesClassifier":
        if len(texts) != len(labels):
            raise ValueError("texts and labels must have the same length")
        for text, label in zip(texts, labels):
            label = normalize_label(label)
            tokens = tokenize(text)
            self.doc_counts[label] += 1
            self.token_counts[label].update(tokens)
            self.total_tokens[label] += len(tokens)
        return self

    def predict_proba(self, text: str) -> float:
        """Probability that ``text`` is phishing."""
        if not self.is_trained:
            raise RuntimeError("classifier has not been trained on both classes")
        tokens = tokenize(text)
        vocab_size = len(self.vocabulary) or 1
        total_docs = sum(self.doc_counts.values())
        log_scores = {}
        for label in LABELS:
            score = math.log(self.doc_counts[label] / total_docs)
            denom = self.total_tokens[label] + self.alpha * vocab_size
            counts = self.token_counts[label]
            for token in tokens:
                score += math.log((counts.get(token, 0) + self.alpha) / denom)
            log_scores[label] = score
        diff = log_scores["legitimate"] - log_scores["phishing"]
        if diff > 700:
            return 0.0
        return 1.0 / (1.0 + math.exp(diff))

    def predict(self, text: str, threshold: float = 0.5) -> str:
        return "phishing" if self.predict_proba(text) >= threshold else "legitimate"

    def top_tokens(self, n: int = 20) -> List[Tuple[str, float]]:
        """Tokens with the largest phishing-vs-legitimate log-likelihood ratio."""
        vocab = self.vocabulary
        v = len(vocab) or 1
        ratios = []
        for token in vocab:
            p = (self.token_counts["phishing"][token] + self.alpha) / (self.total_tokens["phishing"] + self.alpha * v)
            q = (self.token_counts["legitimate"][token] + self.alpha) / (self.total_tokens["legitimate"] + self.alpha * v)
            ratios.append((token, math.log(p / q)))
        ratios.sort(key=lambda kv: kv[1], reverse=True)
        return ratios[:n]

    def to_dict(self) -> dict:
        return {
            "alpha": self.alpha,
            "doc_counts": self.doc_counts,
            "token_counts": {label: dict(c) for label, c in self.token_counts.items()},
            "total_tokens": self.total_tokens,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "NaiveBayesClassifier":
        clf = cls(alpha=data.get("alpha", 1.0))
        clf.doc_counts = {label: int(data["doc_counts"][label]) for label in LABELS}
        clf.token_counts = {label: Counter(data["token_counts"][label]) for label in LABELS}
        clf.total_tokens = {label: int(data["total_tokens"][label]) for label in LABELS}
        return clf

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh)

    @classmethod
    def load(cls, path: str) -> "NaiveBayesClassifier":
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))


def normalize_label(label) -> str:
    value = str(label).strip().lower()
    if value in ("1", "phishing", "phish", "spam", "malicious", "true", "yes"):
        return "phishing"
    if value in ("0", "legitimate", "legit", "ham", "safe", "benign", "false", "no"):
        return "legitimate"
    raise ValueError(f"unrecognised label: {label!r}")


def evaluate(clf: NaiveBayesClassifier, texts: Iterable[str], labels: Iterable[str]) -> dict:
    tp = fp = tn = fn = 0
    for text, label in zip(texts, labels):
        actual = normalize_label(label) == "phishing"
        predicted = clf.predict(text) == "phishing"
        tp += actual and predicted
        fp += predicted and not actual
        tn += not actual and not predicted
        fn += actual and not predicted
    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "accuracy": (tp + tn) / total if total else 0.0,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
    }
