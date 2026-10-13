"""Heuristic rules that flag phishing indicators in a parsed email.

Each rule takes a ``ParsedEmail`` and returns a list of ``Finding`` objects.
Weights are additive evidence points; ``detector.py`` turns the total into a
probability-like score.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional
from urllib.parse import urlsplit

from .parser import ParsedEmail, domain_of


@dataclass
class Finding:
    rule: str
    weight: float
    description: str
    category: str


Rule = Callable[[ParsedEmail], List[Finding]]

# --------------------------------------------------------------------------- #
# Reference data
# --------------------------------------------------------------------------- #

# Brand name -> legitimate registrable domains.
BRANDS = {
    "paypal": ["paypal.com"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com", "office365.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "amazonses.com"],
    "google": ["google.com", "gmail.com", "youtube.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "facebookmail.com", "meta.com"],
    "instagram": ["instagram.com"],
    "linkedin": ["linkedin.com"],
    "dropbox": ["dropbox.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "usps": ["usps.com"],
    "irs": ["irs.gov"],
    "coinbase": ["coinbase.com"],
}

# Multi-word brands, so "Wells Fargo" in text matches the "wellsfargo" key.
_BRAND_WORDS = {
    "wellsfargo": ["wells", "fargo"],
    "bankofamerica": ["bank", "of", "america"],
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id", "t.ly",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click",
    "link", "country", "kim", "loan", "men", "review", "date", "racing",
    "download", "stream", "gdn", "rest", "fit", "cam", "icu", "sbs", "cfd",
}

FREE_MAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "mail.com", "gmx.com", "protonmail.com", "proton.me", "yandex.com", "icloud.com",
}

DANGEROUS_EXTENSIONS = {
    "exe", "scr", "bat", "cmd", "com", "pif", "js", "jse", "vbs", "vbe", "wsf",
    "hta", "msi", "jar", "ps1", "lnk", "iso", "img", "vhd", "reg", "cpl",
    "docm", "xlsm", "pptm", "html", "htm", "svg", "one",
}
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "gz", "tar", "ace", "cab"}

URGENCY_PATTERNS = [
    r"\burgent(ly)?\b", r"\bimmediate(ly)?\b", r"\bact now\b", r"\bwithin (24|48|72) hours\b",
    r"\bas soon as possible\b", r"\bfinal (notice|warning|reminder)\b", r"\bexpires? (today|soon)\b",
    r"\blast chance\b", r"\btime[- ]sensitive\b", r"\bdeadline\b",
]
THREAT_PATTERNS = [
    r"\b(account|access) (has been |will be )?(suspended|locked|disabled|terminated|closed|restricted)\b",
    r"\bunusual (sign[- ]in|login|activity)\b", r"\bsuspicious activity\b",
    r"\bunauthori[sz]ed (access|transaction|login)\b", r"\bpermanently (deleted|closed|suspended)\b",
    r"\blegal action\b", r"\bfailure to (comply|verify|respond)\b",
]
CREDENTIAL_PATTERNS = [
    r"\bverify your (account|identity|information|details|email)\b",
    r"\bconfirm your (account|identity|password|details|information|billing)\b",
    r"\b(update|validate|re-?enter) your (payment|billing|account|credit card|password|details)\b",
    r"\b(password|passcode|pin|social security|ssn|credit card number|cvv|login credentials)\b",
    r"\blog ?in (here|below|now)\b", r"\bsign ?in to (restore|verify|unlock)\b",
]
FINANCIAL_PATTERNS = [
    r"\byou('ve| have)? won\b", r"\bprize\b", r"\blottery\b", r"\binheritance\b",
    r"\bwire transfer\b", r"\bgift ?cards?\b", r"\bbitcoin\b", r"\bcrypto(currency)?\b",
    r"\brefund\b", r"\binvoice (attached|overdue)\b", r"\bunclaimed\b", r"\bbeneficiary\b",
]
GENERIC_GREETINGS = [
    r"^\s*dear (customer|user|client|member|account holder|valued customer|sir|madam|sir/madam)\b",
    r"^\s*hello (customer|user)\b",
]

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

_COMMON_SECOND_LEVEL = {"co", "com", "net", "org", "gov", "ac", "edu"}


def registrable_domain(host: str) -> str:
    """Approximate the registrable domain (eTLD+1) without a public suffix list."""
    host = (host or "").lower().strip(".")
    if is_ip(host):
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if len(parts[-1]) == 2 and parts[-2] in _COMMON_SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def url_host(url: str) -> str:
    if url.lower().startswith("www."):
        url = "http://" + url
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        return ""
    return host.lower()


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        pass
    # Decimal / hex encoded IPv4 (e.g. http://3232235777/)
    return bool(re.fullmatch(r"(0x[0-9a-f]+|\d{8,10})", host))


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"})


def lookalike_brand(domain: str) -> Optional[str]:
    """Return the brand a domain imitates, if it looks like one but isn't legitimate.

    Matches brand names used as a hostname token (``paypal-secure.com``),
    embedded in a token for longer brands (``securepaypal.net``), homoglyph
    substitutions (``paypa1.com``) and near-miss typos (``micros0ft.com``).
    """
    reg = registrable_domain(domain)
    if not reg or is_ip(reg):
        return None
    if any(reg in legit for legit in BRANDS.values()):
        return None
    tokens = [t for t in re.split(r"[.\-]", domain.lower()) if t]
    normalized = [t.translate(_HOMOGLYPHS).replace("rn", "m").replace("vv", "w") for t in tokens]
    for brand in BRANDS:
        for token in set(tokens + normalized):
            if token == brand:
                return brand
            # Short brands as substrings cause false positives (apple/pineapple, chase/purchase).
            if len(brand) >= 6 and brand in token:
                return brand
            if len(brand) >= 6 and abs(len(token) - len(brand)) <= 1 and levenshtein(token, brand) == 1:
                return brand
    return None


def _find_patterns(text: str, patterns: Iterable[str]) -> List[str]:
    hits = []
    for pattern in patterns:
        m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if m:
            hits.append(m.group(0).strip())
    return hits


_BRAND_MENTION_RE = {
    brand: re.compile(r"\b" + r"\s?".join(_BRAND_WORDS.get(brand, [brand])) + r"\b", re.IGNORECASE)
    for brand in BRANDS
}


def _brands_mentioned(text: str) -> List[str]:
    return [brand for brand, pattern in _BRAND_MENTION_RE.items() if pattern.search(text)]


# --------------------------------------------------------------------------- #
# Header rules
# --------------------------------------------------------------------------- #

def rule_reply_to_mismatch(email: ParsedEmail) -> List[Finding]:
    from_reg = registrable_domain(email.from_domain)
    for addr in email.reply_to:
        rt_reg = registrable_domain(domain_of(addr))
        if from_reg and rt_reg and rt_reg != from_reg:
            return [Finding("reply_to_mismatch", 2.0,
                            f"Reply-To domain '{rt_reg}' differs from From domain '{from_reg}'", "header")]
    return []


def rule_return_path_mismatch(email: ParsedEmail) -> List[Finding]:
    from_reg = registrable_domain(email.from_domain)
    rp_reg = registrable_domain(domain_of(email.return_path))
    if from_reg and rp_reg and rp_reg != from_reg:
        return [Finding("return_path_mismatch", 0.75,
                        f"Return-Path domain '{rp_reg}' differs from From domain '{from_reg}'", "header")]
    return []


def rule_authentication_results(email: ParsedEmail) -> List[Finding]:
    findings = []
    results = " ".join(email.header("Authentication-Results")).lower()
    # Received-SPF puts the verdict first ("fail (...)"); normalise to "spf=fail".
    for spf in email.header("Received-SPF"):
        results += " spf=" + spf.strip().split(" ", 1)[0].lower()
    weights = {"spf": 1.5, "dkim": 1.5, "dmarc": 2.5}
    for mech, weight in weights.items():
        m = re.search(rf"\b{mech}=(fail|softfail|permerror|none)\b", results)
        if m:
            w = weight if m.group(1) in ("fail", "permerror") else weight / 2
            findings.append(Finding(f"{mech}_{m.group(1)}", w,
                                    f"{mech.upper()} check result: {m.group(1)}", "header"))
    return findings


def rule_display_name_spoof(email: ParsedEmail) -> List[Finding]:
    findings = []
    name = email.from_name or ""
    from_domain = email.from_domain
    embedded = re.search(r"[\w.+-]+@([\w-]+\.[\w.-]+)", name)
    if embedded and registrable_domain(embedded.group(1)) != registrable_domain(from_domain):
        findings.append(Finding("display_name_address", 2.0,
                                f"Display name contains a different address ('{embedded.group(0)}')", "header"))
    for brand in _brands_mentioned(name):
        legit = BRANDS[brand]
        if registrable_domain(from_domain) not in legit:
            weight = 2.5 if from_domain in FREE_MAIL_DOMAINS else 2.0
            findings.append(Finding("brand_impersonation_sender", weight,
                                    f"Sender name claims '{brand}' but address is '{email.from_address}'", "header"))
            break
    return findings


def rule_lookalike_sender(email: ParsedEmail) -> List[Finding]:
    findings = []
    brand = lookalike_brand(email.from_domain)
    if brand:
        findings.append(Finding("lookalike_sender_domain", 3.0,
                                f"Sender domain '{email.from_domain}' imitates '{brand}'", "header"))
    if email.from_domain.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        findings.append(Finding("suspicious_sender_tld", 1.0,
                                f"Sender uses a high-risk TLD ({email.from_domain})", "header"))
    return findings


# --------------------------------------------------------------------------- #
# URL rules
# --------------------------------------------------------------------------- #

def rule_urls(email: ParsedEmail) -> List[Finding]:
    findings: List[Finding] = []
    flagged = set()

    def add(rule: str, weight: float, desc: str) -> None:
        # Count each rule once per email to avoid one noisy message dominating.
        if rule not in flagged:
            flagged.add(rule)
            findings.append(Finding(rule, weight, desc, "url"))

    from_reg = registrable_domain(email.from_domain)
    for link in email.links:
        url = link.url
        lowered = url.lower()
        if lowered.startswith(("mailto:", "tel:", "#", "cid:")):
            continue
        if lowered.startswith("data:"):
            add("data_uri_link", 2.5, "Link uses a data: URI")
            continue
        if lowered.startswith("javascript:"):
            add("javascript_link", 2.5, "Link executes JavaScript")
            continue
        host = url_host(url)
        if not host:
            continue
        reg = registrable_domain(host)

        if is_ip(host):
            add("ip_address_url", 2.5, f"Link points to a raw IP address ({host})")
        if host.startswith("xn--") or ".xn--" in host:
            add("punycode_domain", 2.0, f"Link uses an internationalized (punycode) domain ({host})")
        if reg in URL_SHORTENERS:
            add("url_shortener", 1.0, f"Link uses a URL shortener ({reg})")
        if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            add("suspicious_tld", 1.0, f"Link uses a high-risk TLD ({host})")
        if "@" in (urlsplit(url).netloc if "://" in url else ""):
            add("userinfo_in_url", 2.0, f"Link hides its real destination using '@' ({url[:80]})")
        if host.count(".") >= 4:
            add("excessive_subdomains", 1.0, f"Link has many subdomains ({host})")
        if len(url) > 150:
            add("long_url", 0.5, "Link is unusually long")
        brand = lookalike_brand(host)
        if brand:
            add("lookalike_link_domain", 3.0, f"Link domain '{host}' imitates '{brand}'")
        if lowered.startswith("http://") and re.search(r"(login|signin|verify|account|secure|update|password)", lowered):
            add("insecure_login_link", 1.0, "Credential-related link does not use HTTPS")

        # Anchor text shows one domain but href goes elsewhere.
        text = link.text.strip()
        shown = re.search(r"((?:https?://)?(?:[\w-]+\.)+[a-z]{2,})(?:/\S*)?", text, re.IGNORECASE)
        if shown and "." in text and " " not in text.strip():
            shown_reg = registrable_domain(url_host(shown.group(1) if "://" in shown.group(1) else "http://" + shown.group(1)))
            if shown_reg and shown_reg != reg:
                add("link_text_mismatch", 3.0, f"Link text shows '{shown_reg}' but points to '{reg}'")

    external = {registrable_domain(url_host(l.url)) for l in email.links if url_host(l.url)}
    external.discard(from_reg)
    if from_reg and email.links and len(external) >= 1:
        brands = _brands_mentioned(email.full_text)
        for brand in brands:
            if from_reg not in BRANDS[brand] and not any(d in BRANDS[brand] for d in external):
                add("brand_content_offsite_links", 1.0,
                    f"Mentions '{brand}' but neither the sender nor links belong to {brand}")
                break
    if email.has_forms:
        add("html_form", 2.0, "Email contains an embedded HTML form")
    return findings


# --------------------------------------------------------------------------- #
# Content rules
# --------------------------------------------------------------------------- #

def rule_content(email: ParsedEmail) -> List[Finding]:
    text = email.full_text
    findings = []
    groups = [
        ("urgency_language", URGENCY_PATTERNS, 1.0, 0.5),
        ("threat_language", THREAT_PATTERNS, 1.5, 0.5),
        ("credential_request", CREDENTIAL_PATTERNS, 1.5, 0.75),
        ("financial_lure", FINANCIAL_PATTERNS, 1.0, 0.5),
    ]
    for rule, patterns, base, per_extra in groups:
        hits = _find_patterns(text, patterns)
        if hits:
            weight = min(base + per_extra * (len(hits) - 1), base * 2.5)
            sample = ", ".join(f"'{h}'" for h in hits[:3])
            findings.append(Finding(rule, weight, f"Contains {rule.replace('_', ' ')}: {sample}", "content"))
    if _find_patterns(email.body, GENERIC_GREETINGS):
        findings.append(Finding("generic_greeting", 0.75, "Uses a generic greeting instead of your name", "content"))
    subject = email.subject
    letters = [c for c in subject if c.isalpha()]
    if len(letters) >= 10 and sum(c.isupper() for c in letters) / len(letters) > 0.7:
        findings.append(Finding("shouting_subject", 0.5, "Subject is mostly upper case", "content"))
    if re.search(r"(re|fwd?):", subject, re.IGNORECASE) and not email.header("In-Reply-To") and not email.header("References"):
        findings.append(Finding("fake_reply", 0.75, "Subject looks like a reply but there is no thread history", "content"))
    return findings


# --------------------------------------------------------------------------- #
# Attachment rules
# --------------------------------------------------------------------------- #

def rule_attachments(email: ParsedEmail) -> List[Finding]:
    findings = []
    for name in email.attachments:
        lowered = name.lower().strip()
        parts = lowered.rsplit(".", 2)
        ext = parts[-1] if len(parts) > 1 else ""
        if len(parts) == 3 and ext in DANGEROUS_EXTENSIONS and len(parts[1]) <= 4:
            findings.append(Finding("double_extension", 3.0,
                                    f"Attachment '{name}' disguises its type with a double extension", "attachment"))
        elif ext in DANGEROUS_EXTENSIONS:
            findings.append(Finding("dangerous_attachment", 2.5,
                                    f"Attachment '{name}' is an executable/script-capable file type", "attachment"))
        elif ext in ARCHIVE_EXTENSIONS:
            findings.append(Finding("archive_attachment", 1.0, f"Attachment '{name}' is an archive", "attachment"))
    return findings


ALL_RULES: List[Rule] = [
    rule_reply_to_mismatch,
    rule_return_path_mismatch,
    rule_authentication_results,
    rule_display_name_spoof,
    rule_lookalike_sender,
    rule_urls,
    rule_content,
    rule_attachments,
]


def run_rules(email: ParsedEmail, rules: Iterable[Rule] = ALL_RULES) -> List[Finding]:
    findings: List[Finding] = []
    for rule in rules:
        findings.extend(rule(email))
    return findings
