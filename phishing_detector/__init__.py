"""Phishing email detector: heuristic rules plus an optional Naive Bayes model."""

from .classifier import NaiveBayesClassifier
from .detector import DetectionResult, PhishingDetector
from .parser import ParsedEmail, parse_email, parse_email_file
from .rules import Finding

__all__ = [
    "DetectionResult",
    "Finding",
    "NaiveBayesClassifier",
    "ParsedEmail",
    "PhishingDetector",
    "parse_email",
    "parse_email_file",
]

__version__ = "0.1.0"
