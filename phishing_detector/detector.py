"""Combine heuristic rules (and optionally a trained model) into a verdict."""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from typing import List, Optional

from .classifier import NaiveBayesClassifier
from .parser import ParsedEmail, parse_email, parse_email_file
from .rules import ALL_RULES, Finding, run_rules

# Logistic curve parameters: a total rule weight of RULE_MIDPOINT maps to 50%.
RULE_MIDPOINT = 4.0
RULE_STEEPNESS = 0.8

SUSPICIOUS_THRESHOLD = 0.4
PHISHING_THRESHOLD = 0.7


@dataclass
class DetectionResult:
    verdict: str  # "legitimate", "suspicious" or "phishing"
    score: float  # 0..1 combined phishing likelihood
    rule_score: float
    model_score: Optional[float]
    findings: List[Finding] = field(default_factory=list)
    subject: str = ""
    sender: str = ""

    @property
    def is_phishing(self) -> bool:
        return self.verdict == "phishing"

    def to_dict(self) -> dict:
        data = asdict(self)
        data["score"] = round(self.score, 4)
        data["rule_score"] = round(self.rule_score, 4)
        if self.model_score is not None:
            data["model_score"] = round(self.model_score, 4)
        return data


class PhishingDetector:
    def __init__(
        self,
        model: Optional[NaiveBayesClassifier] = None,
        model_weight: float = 0.4,
        rules=ALL_RULES,
        suspicious_threshold: float = SUSPICIOUS_THRESHOLD,
        phishing_threshold: float = PHISHING_THRESHOLD,
    ) -> None:
        if not 0.0 <= model_weight <= 1.0:
            raise ValueError("model_weight must be between 0 and 1")
        self.model = model
        self.model_weight = model_weight
        self.rules = rules
        self.suspicious_threshold = suspicious_threshold
        self.phishing_threshold = phishing_threshold

    @classmethod
    def with_model_file(cls, path: str, **kwargs) -> "PhishingDetector":
        return cls(model=NaiveBayesClassifier.load(path), **kwargs)

    @staticmethod
    def rule_probability(total_weight: float) -> float:
        if total_weight <= 0:
            return 0.0
        return 1.0 / (1.0 + math.exp(-RULE_STEEPNESS * (total_weight - RULE_MIDPOINT)))

    def analyze(self, email: ParsedEmail) -> DetectionResult:
        findings = run_rules(email, self.rules)
        findings.sort(key=lambda f: f.weight, reverse=True)
        rule_score = self.rule_probability(sum(f.weight for f in findings))

        model_score = None
        score = rule_score
        if self.model is not None and self.model.is_trained:
            model_score = self.model.predict_proba(email.full_text)
            score = (1 - self.model_weight) * rule_score + self.model_weight * model_score

        if score >= self.phishing_threshold:
            verdict = "phishing"
        elif score >= self.suspicious_threshold:
            verdict = "suspicious"
        else:
            verdict = "legitimate"
        return DetectionResult(
            verdict=verdict,
            score=score,
            rule_score=rule_score,
            model_score=model_score,
            findings=findings,
            subject=email.subject,
            sender=email.from_address,
        )

    def analyze_raw(self, raw: bytes | str) -> DetectionResult:
        return self.analyze(parse_email(raw))

    def analyze_file(self, path: str) -> DetectionResult:
        return self.analyze(parse_email_file(path))
