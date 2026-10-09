"""Turn the free-text notes of a CISA KEV entry into a short list of references (no GUI dependencies).

The notes come from a downloaded file, so they are untrusted. A reference is only offered as a clickable link when it
is a plain https address with an ordinary host name; anything else is kept as readable text and is never opened.
"""
import ipaddress
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass

MAX_REFERENCES = 12
MAX_TEXT_CHARS = 300
MAX_URL_CHARS = 2000
URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)
SPLIT_RE = re.compile(r"\s*;\s+|\s*;\s*$")
HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


@dataclass(frozen=True)
class Reference:
    """One item from the notes: a label, an optional safe https link, and any other text that went with it."""

    label: str = ""
    url: str = ""
    text: str = ""

    @property
    def host(self):
        """Return the host name of the link, or an empty string when this item is not a link."""
        return (urllib.parse.urlsplit(self.url).hostname or "") if self.url else ""

    @property
    def is_link(self):
        """True when the item has a link that is safe to offer."""
        return bool(self.url)


def clean(text):
    """Remove control, invisible, private-use and unassigned characters and collapse white space."""
    kept = "".join(" " if ch.isspace() else ch for ch in text
                   if unicodedata.category(ch) not in ("Cc", "Cf", "Cs", "Co", "Cn"))
    return " ".join(kept.split())


def safe_https_url(candidate):
    """Return the address if it is a plain, ordinary https link, otherwise an empty string."""
    if len(candidate) > MAX_URL_CHARS or not candidate.isascii() or not candidate.isprintable() or "\\" in candidate:
        return ""
    try:
        parts = urllib.parse.urlsplit(candidate)
        port = parts.port
    except ValueError:
        return ""
    host = parts.hostname or ""
    if parts.scheme != "https" or "@" in parts.netloc or not HOST_RE.match(host) or port not in (None, 443):
        return ""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return candidate
    return ""


def parse_references(notes):
    """Split KEV notes (items separated by semicolons) into references, at most MAX_REFERENCES of them."""
    found, seen = [], set()
    for part in SPLIT_RE.split(clean(notes) if isinstance(notes, str) else ""):
        part = part.strip()
        if not part:
            continue
        match = URL_RE.search(part)
        if match is None:
            item = Reference(text=part[:MAX_TEXT_CHARS])
        else:
            url = safe_https_url(match.group().rstrip(".,"))
            label = part[:match.start()].strip().rstrip(":").strip()[:MAX_TEXT_CHARS]
            if url:
                item = Reference(label, url, part[match.end():].strip()[:MAX_TEXT_CHARS])
            else:
                item = Reference(text=part[:MAX_TEXT_CHARS])
        key = item.url or item.text
        if key in seen:
            continue
        seen.add(key)
        found.append(item)
        if len(found) == MAX_REFERENCES:
            break
    return tuple(found)


def describe(reference):
    """Return one line of plain text for a reference, always showing the real address."""
    if reference.is_link:
        label = f"{reference.label}: " if reference.label else ""
        return f"{label}{reference.url}"
    return reference.text


def markdown_item(reference):
    """Return one Markdown list item for a reference, with characters that could change the layout escaped."""
    if not reference.is_link:
        return "- " + re.sub(r"([\\`*_{}\[\]()<>#+!|~])", r"\\\1", reference.text)
    label = re.sub(r"([\\`*_{}\[\]()<>#+!|~])", r"\\\1", reference.label or reference.host)
    address = reference.url.translate({ord("("): "%28", ord(")"): "%29", ord("<"): "%3C", ord(">"): "%3E"})
    return f"- [{label}]({address})"
