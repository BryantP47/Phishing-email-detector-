import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

from phishing_detector import NaiveBayesClassifier, PhishingDetector, parse_email, parse_email_file
from phishing_detector.cli import load_dataset, main
from phishing_detector.rules import is_ip, lookalike_brand, registrable_domain

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(ROOT, "samples")


def make_email(body="Hello", subject="Hi", sender="Alice <alice@example.org>", headers="", html=False):
    ctype = "text/html" if html else "text/plain"
    return (
        f"From: {sender}\nTo: bob@example.org\nSubject: {subject}\n{headers}"
        f"MIME-Version: 1.0\nContent-Type: {ctype}; charset=utf-8\n\n{body}\n"
    )


def rules_hit(raw):
    return {f.rule for f in PhishingDetector().analyze_raw(raw).findings}


class ParserTests(unittest.TestCase):
    def test_extracts_headers_and_links(self):
        raw = make_email(
            '<p>Hi</p><a href="https://evil.example/x">Click</a><form action="https://evil.example/post"></form>',
            sender='"Bank" <info@bank.com>',
            headers="Reply-To: other@elsewhere.net\n",
            html=True,
        )
        email = parse_email(raw)
        self.assertEqual(email.from_address, "info@bank.com")
        self.assertEqual(email.from_name, "Bank")
        self.assertEqual(email.reply_to, ["other@elsewhere.net"])
        self.assertEqual([l.url for l in email.links], ["https://evil.example/x", "https://evil.example/post"])
        self.assertEqual(email.links[0].text, "Click")
        self.assertTrue(email.has_forms)
        self.assertIn("Hi", email.body)

    def test_plain_text_urls(self):
        email = parse_email(make_email("See https://example.org/page, and www.test.com."))
        self.assertEqual([l.url for l in email.links], ["https://example.org/page", "www.test.com"])

    def test_attachments(self):
        email = parse_email_file(os.path.join(SAMPLES, "phishing", "invoice_malware.eml"))
        self.assertEqual(email.attachments, ["Invoice_10293.pdf.exe"])


class HelperTests(unittest.TestCase):
    def test_registrable_domain(self):
        self.assertEqual(registrable_domain("mail.google.com"), "google.com")
        self.assertEqual(registrable_domain("www.amazon.co.uk"), "amazon.co.uk")
        self.assertEqual(registrable_domain("10.0.0.1"), "10.0.0.1")

    def test_is_ip(self):
        self.assertTrue(is_ip("192.168.1.1"))
        self.assertTrue(is_ip("::1"))
        self.assertFalse(is_ip("example.com"))

    def test_lookalikes(self):
        for domain, brand in [
            ("paypa1.com", "paypal"),
            ("secure-paypal-login.net", "paypal"),
            ("micros0ft.com", "microsoft"),
            ("rnicrosoft.com", "microsoft"),
            ("app1e.com", "apple"),
            ("amazon-support.help", "amazon"),
        ]:
            self.assertEqual(lookalike_brand(domain), brand, domain)

    def test_lookalike_false_positives(self):
        for domain in ["paypal.com", "mail.google.com", "pineapple.com", "purchase.com", "apply.com", "github.com"]:
            self.assertIsNone(lookalike_brand(domain), domain)


class RuleTests(unittest.TestCase):
    def test_reply_to_mismatch(self):
        self.assertIn("reply_to_mismatch", rules_hit(make_email(headers="Reply-To: x@other.net\n")))
        self.assertNotIn("reply_to_mismatch", rules_hit(make_email(headers="Reply-To: x@mail.example.org\n")))

    def test_auth_failures(self):
        hits = rules_hit(make_email(headers="Authentication-Results: mx; spf=fail; dkim=pass; dmarc=fail\n"))
        self.assertTrue({"spf_fail", "dmarc_fail"} <= hits)
        self.assertNotIn("dkim_fail", hits)
        self.assertIn("spf_softfail", rules_hit(make_email(headers="Received-SPF: softfail (domain)\n")))

    def test_display_name_spoof(self):
        hits = rules_hit(make_email(sender='"PayPal Support" <paypal.help@gmail.com>'))
        self.assertIn("brand_impersonation_sender", hits)
        hits = rules_hit(make_email(sender='"ceo@company.com" <someone@random.net>'))
        self.assertIn("display_name_address", hits)

    def test_link_text_mismatch(self):
        raw = make_email('<a href="https://evil.example.net/login">https://www.mybank.com</a>', html=True)
        self.assertIn("link_text_mismatch", rules_hit(raw))
        raw = make_email('<a href="https://www.mybank.com/login">www.mybank.com</a>', html=True)
        self.assertNotIn("link_text_mismatch", rules_hit(raw))

    def test_url_rules(self):
        hits = rules_hit(make_email(
            "Go to http://10.1.2.3/a and http://bit.ly/x and https://xn--pple-43d.com "
            "and https://user@evil.top/ and https://a.b.c.d.example.com/"
        ))
        self.assertTrue({"ip_address_url", "url_shortener", "punycode_domain", "userinfo_in_url",
                         "suspicious_tld", "excessive_subdomains"} <= hits, hits)

    def test_content_rules(self):
        hits = rules_hit(make_email(
            "Dear Customer,\nYour account has been suspended. Verify your account immediately. You have won a prize!",
            subject="RE: URGENT ACCOUNT NOTICE",
        ))
        self.assertTrue({"generic_greeting", "threat_language", "credential_request", "urgency_language",
                         "financial_lure", "fake_reply", "shouting_subject"} <= hits, hits)

    def test_fake_reply_needs_prefix(self):
        self.assertNotIn("fake_reply", rules_hit(make_email(subject="Your credit score: updated")))
        self.assertIn("fake_reply", rules_hit(make_email(subject="Fwd: invoice")))

    def test_attachments(self):
        raw = (
            "From: a@example.org\nSubject: docs\nMIME-Version: 1.0\n"
            'Content-Type: multipart/mixed; boundary="B"\n\n'
            "--B\nContent-Type: text/plain\n\nsee attached\n"
            '--B\nContent-Type: application/octet-stream\nContent-Disposition: attachment; filename="run.js"\n\nx\n'
            '--B\nContent-Type: application/zip\nContent-Disposition: attachment; filename="files.zip"\n\nx\n'
            "--B--\n"
        )
        self.assertTrue({"dangerous_attachment", "archive_attachment"} <= rules_hit(raw))


class DetectorTests(unittest.TestCase):
    def test_samples(self):
        detector = PhishingDetector()
        for label in ("phishing", "legitimate"):
            folder = os.path.join(SAMPLES, label)
            for name in os.listdir(folder):
                result = detector.analyze_file(os.path.join(folder, name))
                self.assertEqual(result.verdict, label, f"{name}: {result.score:.2f} {result.findings}")

    def test_clean_email_scores_zero(self):
        result = PhishingDetector().analyze_raw(make_email("See you at lunch tomorrow."))
        self.assertEqual(result.verdict, "legitimate")
        self.assertEqual(result.score, 0.0)

    def test_model_blending(self):
        clf = NaiveBayesClassifier().fit(
            ["verify your account password now", "lunch tomorrow with the team"],
            ["phishing", "legitimate"],
        )
        detector = PhishingDetector(model=clf, model_weight=0.5)
        result = detector.analyze_raw(make_email("lunch tomorrow with the team"))
        self.assertIsNotNone(result.model_score)
        self.assertAlmostEqual(result.score, 0.5 * result.rule_score + 0.5 * result.model_score)

    def test_invalid_model_weight(self):
        with self.assertRaises(ValueError):
            PhishingDetector(model_weight=1.5)


class ClassifierTests(unittest.TestCase):
    def setUp(self):
        self.texts, self.labels = load_dataset(os.path.join(SAMPLES, "training_data.csv"))

    def test_training_and_prediction(self):
        clf = NaiveBayesClassifier().fit(self.texts, self.labels)
        self.assertEqual(clf.predict("Urgent: verify your account password or it will be suspended"), "phishing")
        self.assertEqual(clf.predict("Notes from the team meeting and lunch plans for Friday"), "legitimate")

    def test_save_and_load_roundtrip(self):
        clf = NaiveBayesClassifier().fit(self.texts, self.labels)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "model.json")
            clf.save(path)
            loaded = NaiveBayesClassifier.load(path)
        text = "Confirm your billing details immediately"
        self.assertAlmostEqual(clf.predict_proba(text), loaded.predict_proba(text))

    def test_untrained_raises(self):
        with self.assertRaises(RuntimeError):
            NaiveBayesClassifier().predict_proba("hello")

    def test_bad_label(self):
        with self.assertRaises(ValueError):
            NaiveBayesClassifier().fit(["x"], ["maybe"])

    def test_load_dataset_from_directory(self):
        texts, labels = load_dataset(SAMPLES)
        self.assertEqual(labels.count("phishing"), 4)
        self.assertEqual(labels.count("legitimate"), 3)


class CLITests(unittest.TestCase):
    def run_cli(self, *argv):
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(list(argv))
        return code, out.getvalue()

    def test_analyze_json(self):
        code, out = self.run_cli("analyze", os.path.join(SAMPLES, "phishing", "prize_winner.eml"), "--json")
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(data["verdict"], "phishing")
        self.assertTrue(data["findings"])

    def test_analyze_legitimate_exit_code(self):
        code, out = self.run_cli("analyze", os.path.join(SAMPLES, "legitimate"), "--no-color")
        self.assertEqual(code, 0)
        self.assertIn("LEGITIMATE", out)

    def test_train_then_analyze_with_model(self):
        with tempfile.TemporaryDirectory() as tmp:
            model = os.path.join(tmp, "model.json")
            code, out = self.run_cli("train", os.path.join(SAMPLES, "training_data.csv"), "--out", model)
            self.assertEqual(code, 0)
            self.assertIn("accuracy", out)
            code, out = self.run_cli(
                "analyze", os.path.join(SAMPLES, "legitimate", "team_meeting.eml"), "--model", model, "--json"
            )
            self.assertIsNotNone(json.loads(out)["model_score"])


if __name__ == "__main__":
    unittest.main()
