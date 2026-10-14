"""Build web/index.html from web/template.html, embedding the sample emails.

    python web/build.py
"""

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES_DIR = os.path.join(os.path.dirname(HERE), "samples")

LABELS = {
    "paypal_account_suspended.eml": "PayPal account suspended",
    "microsoft_password_expiry.eml": "Microsoft password form",
    "invoice_malware.eml": "Overdue invoice with attachment",
    "prize_winner.eml": "Lottery prize",
    "amazon_order.eml": "Amazon shipping notice",
    "github_notification.eml": "GitHub notification",
    "team_meeting.eml": "Meeting notes from a colleague",
}


def main() -> None:
    samples = []
    for group in ("phishing", "legitimate"):
        folder = os.path.join(SAMPLES_DIR, group)
        for name in sorted(os.listdir(folder), key=lambda n: list(LABELS).index(n) if n in LABELS else 99):
            with open(os.path.join(folder, name), encoding="utf-8") as fh:
                samples.append({"group": group, "label": LABELS.get(name, name), "raw": fh.read()})
    with open(os.path.join(HERE, "template.html"), encoding="utf-8") as fh:
        template = fh.read()
    # Escape "</" so sample text can never close the <script> element.
    data = json.dumps(samples, ensure_ascii=False).replace("</", "<\\/")
    html = template.replace("/*SAMPLES*/[]", data)
    with open(os.path.join(HERE, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"Wrote web/index.html with {len(samples)} samples")


if __name__ == "__main__":
    main()
