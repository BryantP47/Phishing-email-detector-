# Phishing Email Detector

Analyzes raw emails (`.eml`) and flags phishing using **explainable heuristic rules**,
optionally blended with a **Naive Bayes text classifier** you train on your own data.
Pure Python 3.9+, no third-party dependencies.

## Quick start

```bash
python -m phishing_detector analyze samples/
python -m phishing_detector analyze suspicious.eml --json
```

```
samples/phishing/paypal_account_suspended.eml: PHISHING (score 100%)
  Subject: URGENT: Your account has been suspended
  From:    service@paypa1-secure.com
  [content   ] +3.5  Contains threat language: 'account has been suspended', ...
  [header    ] +3.0  Sender domain 'paypa1-secure.com' imitates 'paypal'
  [url       ] +3.0  Link text shows 'paypal.com' but points to '192.168.45.10'
  [header    ] +2.5  DMARC check result: fail
  ...
```

Each email gets a verdict — `legitimate` (< 40%), `suspicious` (40–70%) or `phishing` (≥ 70%) —
and a list of findings explaining why. The exit code is `1` if any email is
phishing, `2` on errors, otherwise `0`, so it can be used in scripts.

Install as a command with `pip install .` to get `phishing-detector`.

## Web version

`web/index.html` is a single page that runs the same rule checks in the browser:
open it, paste an email's original source (or drop an `.eml` file) and see the
verdict, the warning signs and where each link really goes. Nothing is uploaded.
It covers the rules only, not the trainable model. After changing
`web/template.html` or the samples, rebuild it with `python web/build.py`.

## What it checks

| Category | Indicators |
|---|---|
| Headers | SPF / DKIM / DMARC failures, Reply-To and Return-Path domain mismatch, display-name spoofing (brand name or address in the display name), lookalike sender domains (`paypa1.com`, `rnicrosoft.com`), high-risk sender TLDs |
| Links | Link text showing one domain but pointing to another, raw IP addresses, punycode domains, URL shorteners, `user@host` tricks, high-risk TLDs, excessive subdomains, lookalike brand domains, `data:`/`javascript:` links, plain-HTTP login links, embedded HTML forms, brand mentioned with off-brand links |
| Content | Urgency, threats (account suspension), credential requests, financial lures (prizes, gift cards, wire transfers), generic greetings, all-caps subjects, fake `RE:` replies |
| Attachments | Executable / script-capable types, double extensions (`invoice.pdf.exe`), archives |

Rule weights are summed and mapped to a 0–1 score with a logistic curve
(see `phishing_detector/detector.py`).

## Training the model

The rules work out of the box. To add a statistical model, train on labelled data:

```bash
# CSV with a text column (text/body/email/message), a label column
# (label/class/is_phishing: phishing|legitimate, 1|0, spam|ham), optional subject
python -m phishing_detector train samples/training_data.csv --out model.json

# ...or a directory containing phishing/ and legitimate/ (or ham/) folders of .eml files
python -m phishing_detector train path/to/corpus --out model.json

python -m phishing_detector analyze inbox/ --model model.json --model-weight 0.4
python -m phishing_detector evaluate test.csv --model model.json
```

`samples/training_data.csv` is a tiny synthetic demo set; for real use, train on
a larger corpus such as a public phishing/ham email dataset or your own labelled mail.

## Python API

```python
from phishing_detector import PhishingDetector

detector = PhishingDetector()            # or PhishingDetector.with_model_file("model.json")
result = detector.analyze_file("message.eml")
print(result.verdict, result.score)
for finding in result.findings:
    print(finding.weight, finding.description)
```

## Tests

```bash
python -m unittest discover -s tests -t .
```

## Limitations

Heuristics are signals, not proof: legitimate bulk mail can trip some rules, and
targeted phishing from compromised legitimate accounts may pass them. Domain
handling uses a simplified eTLD+1 approximation rather than the full Public
Suffix List, and links are analyzed statically (no URLs are fetched).
