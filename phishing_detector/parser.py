"""Parse raw RFC 822 email messages into a structure the detector can inspect."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from typing import List, Optional, Tuple

URL_RE = re.compile(r"""(?i)\b((?:https?://|www\.)[^\s<>"'()\[\]]+)""")


@dataclass
class Link:
    """A hyperlink found in the message body."""

    url: str
    text: str = ""  # visible anchor text, empty for bare URLs in plain text


@dataclass
class ParsedEmail:
    subject: str = ""
    from_name: str = ""
    from_address: str = ""
    reply_to: List[str] = field(default_factory=list)
    return_path: str = ""
    to: List[str] = field(default_factory=list)
    headers: List[Tuple[str, str]] = field(default_factory=list)
    text_body: str = ""
    html_body: str = ""
    links: List[Link] = field(default_factory=list)
    attachments: List[str] = field(default_factory=list)
    has_forms: bool = False

    @property
    def from_domain(self) -> str:
        return domain_of(self.from_address)

    def header(self, name: str) -> List[str]:
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]

    @property
    def body(self) -> str:
        """Best-effort plain text of the message (text part, else stripped HTML)."""
        if self.text_body.strip():
            return self.text_body
        return html_to_text(self.html_body)

    @property
    def full_text(self) -> str:
        return f"{self.subject}\n{self.body}"


def domain_of(address: str) -> str:
    address = (address or "").strip().strip("<>")
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].lower().rstrip(".")


class _HTMLExtractor(HTMLParser):
    """Collects visible text, anchors and form presence from HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text_parts: List[str] = []
        self.links: List[Link] = []
        self.has_forms = False
        self._href: Optional[str] = None
        self._anchor_text: List[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ("script", "style"):
            self._skip_depth += 1
        elif tag == "a" and attrs.get("href"):
            self._href = attrs["href"].strip()
            self._anchor_text = []
        elif tag == "form":
            self.has_forms = True
            if attrs.get("action"):
                self.links.append(Link(attrs["action"].strip(), ""))
        elif tag in ("br", "p", "div", "tr", "li"):
            self.text_parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip_depth:
            self._skip_depth -= 1
        elif tag == "a" and self._href is not None:
            self.links.append(Link(self._href, " ".join("".join(self._anchor_text).split())))
            self._href = None

    def handle_data(self, data):
        if self._skip_depth:
            return
        self.text_parts.append(data)
        if self._href is not None:
            self._anchor_text.append(data)


def html_to_text(html: str) -> str:
    if not html:
        return ""
    extractor = _HTMLExtractor()
    extractor.feed(html)
    return "".join(extractor.text_parts)


def _decode_part(part: EmailMessage) -> str:
    try:
        content = part.get_content()
    except (LookupError, ValueError, AssertionError):
        payload = part.get_payload(decode=True) or b""
        content = payload.decode("utf-8", errors="replace")
    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="replace")
    return content


def parse_email(raw: bytes | str) -> ParsedEmail:
    """Parse a raw email message (bytes or str)."""
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="replace")
    msg = BytesParser(policy=policy.default).parsebytes(raw)

    parsed = ParsedEmail()
    parsed.headers = [(k, str(v)) for k, v in msg.items()]
    parsed.subject = str(msg.get("Subject", "") or "")
    parsed.from_name, parsed.from_address = parseaddr(str(msg.get("From", "") or ""))
    parsed.from_address = parsed.from_address.lower()
    parsed.reply_to = [a.lower() for _, a in getaddresses(msg.get_all("Reply-To", []) or []) if a]
    parsed.to = [a.lower() for _, a in getaddresses(msg.get_all("To", []) or []) if a]
    parsed.return_path = parseaddr(str(msg.get("Return-Path", "") or ""))[1].lower()

    text_parts: List[str] = []
    html_parts: List[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        if filename or disposition == "attachment":
            parsed.attachments.append(filename or "(unnamed)")
            continue
        ctype = part.get_content_type()
        if ctype == "text/plain":
            text_parts.append(_decode_part(part))
        elif ctype == "text/html":
            html_parts.append(_decode_part(part))

    parsed.text_body = "\n".join(text_parts)
    parsed.html_body = "\n".join(html_parts)

    seen = set()
    if parsed.html_body:
        extractor = _HTMLExtractor()
        extractor.feed(parsed.html_body)
        parsed.has_forms = extractor.has_forms
        for link in extractor.links:
            if link.url not in seen:
                seen.add(link.url)
                parsed.links.append(link)
    for match in URL_RE.finditer(parsed.text_body):
        url = match.group(1).rstrip(".,;:!?")
        if url not in seen:
            seen.add(url)
            parsed.links.append(Link(url))
    return parsed


def parse_email_file(path: str) -> ParsedEmail:
    with open(path, "rb") as fh:
        return parse_email(fh.read())
