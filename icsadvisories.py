"""CISA ICS advisories: which published advisories name a CVE (no GUI).

CISA publishes every ICS (OT) advisory as a machine-readable CSAF file in its public GitHub repository. The tool
downloads that repository as one archive, reads only the OT advisory files inside it (nothing is ever unpacked to
disk), keeps a small index of advisory -> CVEs, and stores only that index. The advisory files are untrusted input like
every other downloaded file: sizes, counts and nesting are limited, one unreadable advisory is skipped and counted
(never guessed at), and links are built from the validated advisory number, never copied from the file.
"""
import dataclasses
import gzip
import hashlib
import io
import json
import re
import tarfile
import unicodedata
import zlib
from dataclasses import dataclass, field
from pathlib import Path

import references
import threatdata
import versions as vers
from threatdata import CVE_RE, MB, FetchError, SourceResult, ThreatDataError

ICS_URL = "https://codeload.github.com/cisagov/CSAF/tar.gz/refs/heads/develop"
ICS_HOSTS = frozenset({"codeload.github.com"})
ICS_MAX_COMPRESSED = 60 * MB
ICS_MAX_STREAM = 600 * MB          # all the bytes read out of the archive, whatever the entries claim
ICS_MAX_MEMBERS = 100_000
ICS_MAX_ADVISORY_BYTES = 8 * MB
ICS_MAX_ADVISORIES = 20_000
ICS_MAX_CVES = 2_000               # per advisory
ICS_MAX_INDEX_BYTES = 60 * MB
MAX_TITLE_CHARS = 200
MAX_VENDOR_CHARS = 80
MAX_VENDORS = 10
MAX_PRODUCTS = 30                  # product names kept per advisory, for matching an asset's vendor and product
MAX_PRODUCT_CHARS = 120
MAX_NAME_TOKENS = 12               # words of a vendor or product name that are used for matching
MAX_TOKEN_CHARS = 40
MAX_MATCH_CACHE = 5_000
LEGAL_WORDS = frozenset({"inc", "llc", "ltd", "limited", "corp", "corporation", "co", "company", "gmbh", "ag", "sa",
                         "plc", "bv", "nv", "kg", "oy", "ab", "as", "srl", "spa", "pty", "lp", "the"})
MAX_TREE_NODES = 20_000
MAX_TREE_DEPTH = 12
MAX_SKIPPED = 10                   # unreadable advisories tolerated, or 5% of them if that is more
SKIPPED_SHARE = 0.05
MAX_LISTED = 5                     # advisories shown for one CVE

# What an advisory says about fixing one CVE, reduced to one letter (CSAF remediation categories vendor_fix,
# mitigation, workaround, none_available and no_fix_planned). The words are shown to the person.
REMEDIATION_WORDS = {"F": "vendor fix available",
                     "P": "vendor fix for some products, none for others",
                     "N": "no fix available yet",
                     "X": "no fix planned",
                     "M": "mitigation or workaround only"}
REMEDIATION_CHIPS = {"F": "Vendor fix (CISA)", "P": "Partial fix (CISA)", "N": "No fix yet (CISA)",
                     "X": "No fix planned (CISA)", "M": "Mitigation only (CISA)"}
# The vendor's own words about each fix or mitigation: one Step per CSAF remediation entry. The letters are the
# step kinds; the words are shown to the person.
STEP_KINDS = {"vendor_fix": "F", "mitigation": "M", "workaround": "W", "none_available": "N", "no_fix_planned": "X"}
STEP_WORDS = {"F": "Fix", "M": "Mitigation", "W": "Workaround", "N": "No fix available", "X": "No fix planned"}
MAX_STEP_CHARS = 400               # text of one step (longer text is cut and ends with an ellipsis)
MAX_STEP_URL_CHARS = 500           # a longer address is left out; the text is kept
MAX_STEPS = 25                     # steps kept for one CVE of one advisory
MAX_STEP_TABLE = 100               # different steps kept for one advisory
ELLIPSIS = "\u2026"
MAX_AFFECTED_IDS = 10_000         # product ids read from one vulnerability's known_affected list
MAX_AFFECTED = 40                  # listed affected product and version pairs kept per advisory
MAX_VERSION_CHARS = 80             # one listed version or version range, as the advisory words it
MAX_RANGES_SHOWN = 3               # listed ranges named in a version note
MAX_VERSION_NOTE_CHARS = 200
VERSION_CATEGORIES = ("product_version", "product_version_range")
# What comparing an asset's version with an advisory's listed versions found (VersionCheck.status)
VERSION_WORDS = {"A": "lists your version as affected", "O": "lists other versions only",
                 "U": "could not be compared with your version"}
INDEX_VERSION = 5

ICS_FILE, ICS_META_FILE = "ics_advisories.json", "ics_meta.json"
ID_RE = re.compile(r"^ICS(?:A|MA)-\d{2}-\d{3}-\d{2}[A-Z]?$")
MEMBER_RE = re.compile(r"^[^/]{1,100}/csaf_files/OT/white/\d{4}/(icsm?a-\d{2}-\d{3}-\d{2}[a-z]?)\.json$")
DATE_RE = threatdata.DATE_RE


@dataclass(frozen=True)
class Step:
    """One thing a vendor says to do about a CVE: a kind (a key of STEP_WORDS), the vendor's text, maybe a link."""

    kind: str
    text: str
    url: str = ""               # a plain https address (references.safe_https_url), or empty

    @property
    def kind_text(self):
        """The kind in words."""
        return STEP_WORDS.get(self.kind, "")

    @property
    def line(self):
        """One readable line: the kind and the text."""
        return f"{self.kind_text}: {self.text}"


@dataclass(frozen=True)
class Affected:
    """One product and the version (or range of versions) an advisory lists as affected, in the advisory's words."""

    product: str
    versions: str = ""


@dataclass(frozen=True)
class VersionCheck:
    """What comparing one asset's version with one advisory's listed affected versions found.

    status is "A" (inside a listed range), "O" (outside every listed range) or "U" (cannot be said); ranges holds
    the listed texts that decided it (at most MAX_RANGES_SHOWN).
    """

    status: str
    ranges: tuple = ()

    def note(self, version):
        """One sentence for the person, naming the version that was checked. It never says the asset is safe."""
        listed = "; ".join(self.ranges)
        shown = version if len(version) <= 40 else version[:39] + "\u2026"
        if self.status == "A":
            text = f"your version {shown} is inside a listed affected range ({listed})"
        elif self.status == "O":
            text = f"your version {shown} is outside the listed affected versions ({listed}); read the advisory anyway"
        else:
            text = f"your version {shown} could not be compared with the listed versions" + (
                f" ({listed})" if listed else "")
        return text[:MAX_VERSION_NOTE_CHARS]


@dataclass(frozen=True)
class VersionSummary:
    """The advisories that may apply to an asset, checked against its version (see IcsData.check)."""

    advisories: tuple           # at most MAX_LISTED, those listing the version as affected first; each has version_note
    total: int                  # how many advisories match the vendor and product
    vendor_known: bool
    readable: bool = True       # False when the version cannot be read as a number, so nothing was compared
    affected: int = 0           # how many list the version as affected
    outside: int = 0            # how many list other versions only
    unknown: int = 0            # how many could not be compared
    newest: str = ""            # the id of the newest advisory that matches (listed first when the order is by date)


@dataclass(frozen=True)
class IcsAdvisory:
    """One CISA ICS advisory: what it is called, when it was published and updated, and whose products it covers."""

    id: str
    title: str
    published: str
    updated: str
    vendors: tuple = ()
    products: tuple = ()        # product names the advisory lists (for matching an asset's vendor and product)
    fix: str = ""               # what this advisory says about fixing the looked-up CVE: a key of REMEDIATION_WORDS
    steps: tuple = ()           # the vendor's fixes and mitigations for the looked-up CVE (Step objects)
    affected: tuple = ()        # the products and versions the advisory lists as affected (Affected objects)
    version_note: str = ""      # what comparing the asset's version with them found, in words (set by check)

    @property
    def fix_text(self):
        """The remediation status in words, or an empty string when the advisory does not say."""
        return REMEDIATION_WORDS.get(self.fix, "")

    @property
    def url(self):
        """The advisory's page on cisa.gov, built from the validated advisory number."""
        kind = "ics-medical-advisories" if self.id.startswith("ICSMA") else "ics-advisories"
        return f"https://www.cisa.gov/news-events/{kind}/{self.id.lower()}"

    @property
    def line(self):
        """One readable line: the advisory number and its title."""
        return f"{self.id}: {self.title}"


def name_tokens(text, drop_legal=False):
    """The words of a vendor or product name, lower case, ignoring punctuation and accents (at most a dozen)."""
    decomposed = unicodedata.normalize("NFKD", str(text))
    plain = "".join(c for c in decomposed if not unicodedata.combining(c)).casefold()
    words = [w[:MAX_TOKEN_CHARS] for w in re.findall(r"[a-z0-9]+", plain)]
    if drop_legal:
        words = [w for w in words if w not in LEGAL_WORDS]
    return tuple(words[:MAX_NAME_TOKENS])


@dataclass(frozen=True)
class IcsData:
    """A validated set of advisories and the CVEs each one names."""

    feed_date: str
    advisories: dict            # advisory id -> IcsAdvisory
    by_cve: dict                # CVE id -> tuple of advisory ids, newest first
    fixes: dict = field(default_factory=dict)    # advisory id -> {CVE id: remediation letter}
    steps: dict = field(default_factory=dict)    # advisory id -> {CVE id: tuple of Step}
    _cache: dict = field(default_factory=dict, repr=False, compare=False)    # work done by match(), kept for reuse

    def lookup(self, cve):
        """Return the advisories that name this CVE, newest first (at most MAX_LISTED) and how many there are.

        Each advisory carries what it says about fixing this CVE in its fix and steps fields.
        """
        cve = threatdata.normalize_cve(cve)
        ids = self.by_cve.get(cve, ())
        return tuple(dataclasses.replace(self.advisories[i], fix=self.fixes.get(i, {}).get(cve, ""),
                                         steps=self.steps.get(i, {}).get(cve, ()))
                     for i in ids[:MAX_LISTED]), len(ids)

    def _postings(self):
        """Which advisories each vendor word and each product word appears in (built once, on first use)."""
        if "postings" not in self._cache:
            vendor_words, product_words = {}, {}
            for ident, advisory in self.advisories.items():
                for name in advisory.vendors:
                    for word in name_tokens(name, drop_legal=True):
                        vendor_words.setdefault(word, set()).add(ident)
                for name in (*advisory.products, advisory.title):
                    for word in name_tokens(name):
                        product_words.setdefault(word, set()).add(ident)
            self._cache["postings"] = (vendor_words, product_words)
        return self._cache["postings"]

    def match(self, vendor, product):
        """Find the advisories that may apply to an asset made by this vendor and called this product.

        An advisory matches when every word of the vendor appears in one of its vendor names and every word of the
        product appears in one of its product names or its title. This is a pointer, not proof: it does not know
        the asset's version. Returns (advisories newest first, at most MAX_LISTED; how many match in all; whether
        any advisory names this vendor at all). Needs a vendor and a product word of at least three characters.
        """
        ids, vendor_known = self._matching_ids(vendor, product)
        return tuple(self.advisories[i] for i in ids[:MAX_LISTED]), len(ids), vendor_known

    def _matching_ids(self, vendor, product):
        """The ids of the advisories that match a vendor and product (newest first) and whether the vendor is known."""
        vendor_words, product_words = name_tokens(vendor, drop_legal=True), name_tokens(product)
        if not vendor_words or not any(len(w) >= 3 for w in product_words):
            return (), False
        key = (vendor_words, product_words)
        found = self._cache.get(key)
        if found is None:
            found = self._find(vendor_words, product_words)
            if len(self._cache) > MAX_MATCH_CACHE:
                self._cache.clear()
            self._cache[key] = found
        return found

    def check_advisory(self, ident, vendor, product, version):
        """Compare an asset's version with the versions one advisory lists as affected; a VersionCheck, or None.

        None means there is nothing to say: the version cannot be read, the advisory does not name this vendor, or
        none of the products it lists is this product. Otherwise the answer is "inside a listed range" if any
        listed range for the product holds the version, "outside" only if every one is understood and none does, and
        "cannot be said" if some text was not understood. It is a pointer for the person to read, not a verdict.
        """
        advisory, wanted = self.advisories.get(ident), vers.parse_version(version)
        vendor_words, product_words = set(name_tokens(vendor, drop_legal=True)), set(name_tokens(product))
        if advisory is None or wanted is None or not vendor_words or not product_words:
            return None
        if not any(vendor_words <= set(name_tokens(v, drop_legal=True)) for v in advisory.vendors):
            return None
        inside, unclear, outside = [], [], []
        for entry in advisory.affected:
            if not product_words <= set(name_tokens(entry.product)):
                continue
            answer = vers.in_range(wanted, vers.parse_range(entry.versions))
            label = vers.describe_range(entry.versions) or "no version given"
            (inside if answer is True else outside if answer is False else unclear).append(label)
        if not (inside or unclear or outside):
            return None
        status, listed = ("A", inside) if inside else ("U", unclear) if unclear else ("O", outside)
        return VersionCheck(status, tuple(dict.fromkeys(listed))[:MAX_RANGES_SHOWN])

    def check(self, vendor, product, version):
        """Find the advisories that may apply to an asset (see match) and compare its version with each one.

        The advisories listing the version as affected come first, then those that could not be compared, then those
        listing other versions only; within each, newest first. At most MAX_LISTED are returned, each with a
        version_note, and the counts cover all of them.
        """
        ids, vendor_known = self._matching_ids(vendor, product)
        if vers.parse_version(version) is None:
            return VersionSummary(tuple(self.advisories[i] for i in ids[:MAX_LISTED]), len(ids), vendor_known, False,
                                  0, 0, len(ids), ids[0] if ids else "")
        rank, order = {"A": 0, "U": 1, "O": 2}, []
        counts = {"A": 0, "O": 0, "U": 0}
        checks = {}
        for position, ident in enumerate(ids):
            checks[ident] = self.check_advisory(ident, vendor, product, version)
            status = checks[ident].status if checks[ident] else "U"
            counts[status] += 1
            order.append((rank[status], position, ident))
        shown = []
        for _rank, _position, ident in sorted(order)[:MAX_LISTED]:
            check = checks[ident]
            shown.append(dataclasses.replace(self.advisories[ident], version_note=check.note(version) if check else ""))
        return VersionSummary(tuple(shown), len(ids), vendor_known, True, counts["A"], counts["O"], counts["U"],
                              ids[0] if ids else "")

    def _find(self, vendor_words, product_words):
        vendors, products = self._postings()
        by_vendor = None
        for word in vendor_words:
            posting = vendors.get(word, frozenset())
            by_vendor = posting if by_vendor is None else by_vendor & posting
        vendor_known = bool(by_vendor)
        ids = set(by_vendor or ())
        for word in product_words:
            if not ids:
                break
            ids &= products.get(word, frozenset())
        ordered = sorted(ids, key=lambda i: (self.advisories[i].updated, i), reverse=True)
        return tuple(ordered), vendor_known


def _date(text, where):
    if not isinstance(text, str) or not DATE_RE.fullmatch(text[:10]) or not threatdata._valid_date(text[:10]):
        raise ValueError(f"{where} is not a valid date")
    return text[:10]


def _clean(text, limit):
    """Clean text and cut it to a limit, without leaving a space at the cut (stored text must be exactly clean)."""
    return references.clean(text)[:limit].rstrip()


def _products(tree):
    """Return the product names found in a CSAF product tree (bounded in depth and size)."""
    found, stack, seen = [], [(tree, 0)], 0
    while stack:
        node, depth = stack.pop()
        seen += 1
        if seen > MAX_TREE_NODES or depth > MAX_TREE_DEPTH:
            raise ValueError("the product tree is too large or too deeply nested")
        if not isinstance(node, dict):
            continue
        if node.get("category") in ("product_name", "product_family") and isinstance(node.get("name"), str):
            name = _clean(node["name"], MAX_PRODUCT_CHARS)
            if name and name not in found and len(found) < MAX_PRODUCTS:
                found.append(name)
        children = node.get("branches")
        if isinstance(children, list):
            stack.extend((child, depth + 1) for child in reversed(children))
    return tuple(found)


def _affected(tree, listed_ids):
    """Return the products and versions a CSAF product tree lists as known affected (bounded in depth and size).

    listed_ids is the set of product ids that the advisory's vulnerabilities list as known_affected. Each is paired
    with the nearest product name above it and the text of the version branch it hangs on.
    """
    found, stack, seen = [], [(tree, 0, "")], 0
    while stack:
        node, depth, context = stack.pop()
        seen += 1
        if seen > MAX_TREE_NODES or depth > MAX_TREE_DEPTH:
            raise ValueError("the product tree is too large or too deeply nested")
        if not isinstance(node, dict):
            continue
        name, category = node.get("name"), node.get("category")
        if category in ("product_name", "product_family") and isinstance(name, str):
            context = _clean(name, MAX_PRODUCT_CHARS) or context
        product = node.get("product")
        if isinstance(product, dict) and isinstance(product.get("product_id"), str) \
                and product["product_id"] in listed_ids:
            text = _clean(name, MAX_VERSION_CHARS) if category in VERSION_CATEGORIES and isinstance(name, str) else ""
            label = context or (_clean(product["name"], MAX_PRODUCT_CHARS) if isinstance(product.get("name"), str)
                                else "")
            entry = Affected(label, text)
            if label and entry not in found and len(found) < MAX_AFFECTED:
                found.append(entry)
        children = node.get("branches")
        if isinstance(children, list):
            stack.extend((child, depth + 1, context) for child in reversed(children))
    return tuple(found)


def _listed_affected(items):
    """The product ids the vulnerabilities list as known_affected (a set of at most a few thousand strings)."""
    ids = set()
    for item in items:
        status = item.get("product_status") if isinstance(item, dict) else None
        listed = status.get("known_affected") if isinstance(status, dict) else None
        if isinstance(listed, list):
            ids.update(p for p in listed[:MAX_AFFECTED_IDS] if isinstance(p, str))
    return ids


def _vendors(tree):
    """Return the vendor names found in a CSAF product tree, bounded in depth and size."""
    found, stack, seen = [], [(tree, 0)], 0
    while stack:
        node, depth = stack.pop()
        seen += 1
        if seen > MAX_TREE_NODES or depth > MAX_TREE_DEPTH:
            raise ValueError("the product tree is too large or too deeply nested")
        if not isinstance(node, dict):
            continue
        if node.get("category") == "vendor" and isinstance(node.get("name"), str):
            name = _clean(node["name"], MAX_VENDOR_CHARS)
            if name and name not in found:
                found.append(name)
        children = node.get("branches")
        if isinstance(children, list):
            stack.extend((child, depth + 1) for child in reversed(children))
    return tuple(found[:MAX_VENDORS])


def _remediation(item):
    """Reduce one vulnerability's CSAF remediations to a letter of REMEDIATION_WORDS, or "" when it says nothing."""
    found = item.get("remediations")
    if not isinstance(found, list):
        return ""
    categories = {r.get("category") for r in found if isinstance(r, dict) and isinstance(r.get("category"), str)}
    has_fix = "vendor_fix" in categories
    if has_fix and categories & {"none_available", "no_fix_planned"}:
        return "P"
    if has_fix:
        return "F"
    if "no_fix_planned" in categories:
        return "X"
    if "none_available" in categories:
        return "N"
    return "M" if categories & {"mitigation", "workaround"} else ""


def _step_text(text):
    """The vendor's text for one step, cleaned and cut to MAX_STEP_CHARS (an ellipsis shows that it was cut)."""
    text = references.clean(text)
    if len(text) <= MAX_STEP_CHARS:
        return text
    return text[:MAX_STEP_CHARS].rstrip() + ELLIPSIS


def _steps(item):
    """The vendor's steps for one vulnerability, in the order the advisory gives them: at most MAX_STEPS different ones.

    Only remediation entries of a known category with some text are kept. A link is kept only when it is a plain
    https address of reasonable length; otherwise the text is kept without it.
    """
    found = item.get("remediations")
    steps = []
    for entry in found if isinstance(found, list) else ():
        if not isinstance(entry, dict) or not isinstance(entry.get("category"), str):
            continue
        kind, details = STEP_KINDS.get(entry["category"]), entry.get("details")
        if kind is None or not isinstance(details, str) or not references.clean(details):
            continue
        url = entry.get("url")
        url = url if isinstance(url, str) and len(url) <= MAX_STEP_URL_CHARS and references.safe_https_url(url) else ""
        step = Step(kind, _step_text(details), url)
        if step not in steps:
            steps.append(step)
            if len(steps) == MAX_STEPS:
                break
    return tuple(steps)


def _read_advisory(raw, stem):
    """Return (IcsAdvisory, cves, fixes, steps) from one CSAF advisory file; raise ValueError if it is not trusted.

    fixes maps a CVE id to its remediation letter, and leaves out CVEs the advisory does not say anything about.
    steps maps a CVE id to the vendor's steps (a tuple of Step), and leaves out CVEs that have none.
    """
    try:
        doc = json.loads(raw.decode("utf-8"), parse_constant=threatdata._reject_constant,
                         object_pairs_hook=threatdata._reject_duplicates)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise ValueError("not valid JSON") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("document"), dict):
        raise ValueError("no document section")
    head = doc["document"]
    tracking = head.get("tracking")
    if not isinstance(tracking, dict):
        raise ValueError("no tracking section")
    ident = tracking.get("id")
    if not isinstance(ident, str) or not ID_RE.fullmatch(ident.upper()) or ident.lower() != stem:
        raise ValueError("its id does not match its file name")
    title = head.get("title")
    if not isinstance(title, str) or not _clean(title, MAX_TITLE_CHARS):
        raise ValueError("no title")
    published = _date(tracking.get("initial_release_date"), "initial_release_date")
    updated = _date(tracking.get("current_release_date"), "current_release_date")
    items = doc.get("vulnerabilities", [])
    if not isinstance(items, list):
        raise ValueError("vulnerabilities is not a list")
    cves, fixes, steps, table = [], {}, {}, set()
    for item in items:
        cve = item.get("cve") if isinstance(item, dict) else None
        if isinstance(cve, str) and CVE_RE.fullmatch(cve) and cve not in cves:
            cves.append(cve)
            if len(cves) > ICS_MAX_CVES:
                raise ValueError(f"it names more than {ICS_MAX_CVES:,} CVEs")
            if _remediation(item):
                fixes[cve] = _remediation(item)
            found = []
            for step in _steps(item):
                # Only so many different steps are kept for one advisory; a step that would go over that is left out
                if step in table or len(table) < MAX_STEP_TABLE:
                    table.add(step)
                    found.append(step)
            if found:
                steps[cve] = tuple(found)
    tree = doc.get("product_tree")
    vendors = _vendors(tree) if isinstance(tree, dict) else ()
    products = _products(tree) if isinstance(tree, dict) else ()
    affected = _affected(tree, _listed_affected(items)) if isinstance(tree, dict) else ()
    advisory = IcsAdvisory(ident.upper(), _clean(title, MAX_TITLE_CHARS), published, updated, vendors, products,
                           affected=affected)
    return advisory, cves, fixes, steps


def _assemble(quads):
    """Build an IcsData from (IcsAdvisory, cves, fixes, steps) tuples."""
    advisories, links, all_fixes, all_steps = {}, {}, {}, {}
    for advisory, cves, fixes, steps in quads:
        if advisory.id in advisories:
            raise ThreatDataError(f"advisory {advisory.id} is listed twice")
        advisories[advisory.id] = advisory
        if fixes:
            all_fixes[advisory.id] = fixes
        if steps:
            all_steps[advisory.id] = steps
        for cve in cves:
            links.setdefault(cve, []).append(advisory.id)
    by_cve = {cve: tuple(sorted(ids, key=lambda i: (advisories[i].updated, i), reverse=True))
              for cve, ids in links.items()}
    feed_date = max(a.updated for a in advisories.values())
    return IcsData(feed_date, advisories, by_cve, all_fixes, all_steps)


class _Counting(io.RawIOBase):
    """Reads from a stream and refuses to go on once more than a limit has come out of it."""

    def __init__(self, stream, limit):
        self.stream, self.limit, self.count = stream, limit, 0

    def readable(self):
        return True

    def readinto(self, buffer):
        data = self.stream.read(len(buffer))
        self.count += len(data)
        if self.count > self.limit:
            raise ThreatDataError(f"the ICS advisories archive expands to more than {self.limit // MB} MB")
        buffer[:len(data)] = data
        return len(data)


def parse_archive(data):
    """Read the OT advisories out of the CISA CSAF repository archive (tar.gz bytes) and return an IcsData."""
    if len(data) > ICS_MAX_COMPRESSED:
        raise ThreatDataError(f"the ICS advisories download is larger than {ICS_MAX_COMPRESSED // MB} MB")
    if data[:2] != b"\x1f\x8b":
        raise ThreatDataError("the ICS advisories file is not a gzip archive")
    pairs, candidates, skipped, members = [], 0, 0, 0
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz, \
                tarfile.open(fileobj=io.BufferedReader(_Counting(gz, ICS_MAX_STREAM)), mode="r|") as archive:
            for member in archive:
                members += 1
                if members > ICS_MAX_MEMBERS:
                    raise ThreatDataError(f"the ICS advisories archive has more than {ICS_MAX_MEMBERS:,} entries")
                match = MEMBER_RE.fullmatch(member.name) if member.isfile() else None
                if not match:
                    continue
                candidates += 1
                if candidates > ICS_MAX_ADVISORIES:
                    raise ThreatDataError(f"the ICS advisories archive has more than {ICS_MAX_ADVISORIES:,} advisories")
                if member.size > ICS_MAX_ADVISORY_BYTES:
                    skipped += 1
                    continue
                try:
                    pairs.append(_read_advisory(archive.extractfile(member).read(), match.group(1)))
                except ValueError:
                    skipped += 1
    except (OSError, EOFError, zlib.error, tarfile.TarError) as error:
        raise ThreatDataError(f"the ICS advisories file could not be read ({type(error).__name__})") from None
    if not pairs:
        raise ThreatDataError("the ICS advisories file has no readable OT advisories")
    if skipped > max(MAX_SKIPPED, int(candidates * SKIPPED_SHARE)):
        raise ThreatDataError(f"{skipped} of {candidates} advisories could not be read (has the format changed?)")
    # An advisory that names no CVE stays out of the index: there is nothing to look up
    return _assemble([(a, c, f, s) for a, c, f, s in pairs if c])


def to_index(data):
    """Serialize an IcsData as the small index file the tool stores."""
    names = {}
    for cve, ids in data.by_cve.items():
        for ident in ids:
            names.setdefault(ident, []).append(cve)
    rows = []
    for a in sorted(data.advisories.values(), key=lambda a: a.id):
        table, position, applies = [], {}, {}      # an advisory repeats the same steps for most of its CVEs
        for cve, steps in sorted(data.steps.get(a.id, {}).items()):
            for step in steps:
                if step not in position:
                    position[step] = len(table)
                    table.append([step.kind, step.text, step.url])
            applies[cve] = [position[step] for step in steps]
        rows.append({"id": a.id, "title": a.title, "published": a.published, "updated": a.updated,
                     "vendors": list(a.vendors), "products": list(a.products), "cves": sorted(names.get(a.id, ())),
                     "fixes": dict(sorted(data.fixes.get(a.id, {}).items())), "steps": table, "applies": applies,
                     "affected": [[e.product, e.versions] for e in a.affected]})
    return json.dumps({"version": INDEX_VERSION, "feed_date": data.feed_date, "count": len(rows), "advisories": rows},
                      separators=(",", ":")).encode("utf-8")


def parse_index(raw):
    """Validate a stored index and return an IcsData."""
    if len(raw) > ICS_MAX_INDEX_BYTES:
        raise ThreatDataError(f"the stored ICS index is larger than {ICS_MAX_INDEX_BYTES // MB} MB")
    try:
        doc = json.loads(raw.decode("utf-8"), parse_constant=threatdata._reject_constant,
                         object_pairs_hook=threatdata._reject_duplicates)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise ThreatDataError("the stored ICS index is not valid JSON") from None
    if not isinstance(doc, dict) or doc.get("version") != INDEX_VERSION:
        raise ThreatDataError("the stored ICS index has an unknown version")
    rows = doc.get("advisories")
    if not isinstance(rows, list) or not rows or len(rows) > ICS_MAX_ADVISORIES or doc.get("count") != len(rows):
        raise ThreatDataError("the stored ICS index is incomplete")
    pairs = []
    for row in rows:
        try:
            pairs.append(_index_row(row))
        except (ValueError, TypeError, KeyError) as error:
            raise ThreatDataError(f"the stored ICS index has an invalid advisory ({str(error)[:80]})") from None
    return _assemble(pairs)


def _index_row(row):
    if not isinstance(row, dict) or set(row) != {"id", "title", "published", "updated", "vendors", "products",
                                                 "cves", "fixes", "steps", "applies", "affected"}:
        raise ValueError("unexpected fields")
    ident, title, vendors, cves, fixes = row["id"], row["title"], row["vendors"], row["cves"], row["fixes"]
    products = row["products"]
    if not isinstance(products, list) or len(products) > MAX_PRODUCTS or not all(
            isinstance(p, str) and 0 < len(p) <= MAX_PRODUCT_CHARS and p == references.clean(p) for p in products):
        raise ValueError("bad products")
    if not isinstance(ident, str) or not ID_RE.fullmatch(ident):
        raise ValueError("bad id")
    if not isinstance(title, str) or not title or len(title) > MAX_TITLE_CHARS or title != references.clean(title):
        raise ValueError("bad title")
    if not isinstance(vendors, list) or len(vendors) > MAX_VENDORS or not all(
            isinstance(v, str) and 0 < len(v) <= MAX_VENDOR_CHARS and v == references.clean(v) for v in vendors):
        raise ValueError("bad vendors")
    if not isinstance(cves, list) or not cves or len(cves) > ICS_MAX_CVES or not all(
            isinstance(c, str) and CVE_RE.fullmatch(c) for c in cves) or len(set(cves)) != len(cves):
        raise ValueError("bad CVE list")
    if not isinstance(fixes, dict) or not all(k in cves and v in REMEDIATION_WORDS for k, v in fixes.items()):
        raise ValueError("bad remediation list")
    steps = _index_steps(row["steps"], row["applies"], cves)
    affected = _index_affected(row["affected"])
    return IcsAdvisory(ident, title, _date(row["published"], "published"), _date(row["updated"], "updated"),
                       tuple(vendors), tuple(products), affected=affected), cves, fixes, steps


def _index_affected(rows):
    """Validate the stored affected products and versions of one advisory; return a tuple of Affected."""
    if not isinstance(rows, list) or len(rows) > MAX_AFFECTED:
        raise ValueError("bad affected list")
    found = []
    for entry in rows:
        if not isinstance(entry, list) or len(entry) != 2 or not all(isinstance(x, str) for x in entry):
            raise ValueError("bad affected entry")
        product, text = entry
        if (not 0 < len(product) <= MAX_PRODUCT_CHARS or len(text) > MAX_VERSION_CHARS
                or product != references.clean(product) or text != references.clean(text)):
            raise ValueError("bad affected text")
        found.append(Affected(product, text))
    if len(set(found)) != len(found):
        raise ValueError("repeated affected entry")
    return tuple(found)


def _index_steps(table, applies, cves):
    """Validate the stored steps of one advisory; return {CVE id: tuple of Step}."""
    if not isinstance(table, list) or len(table) > MAX_STEP_TABLE:
        raise ValueError("bad steps")
    found = []
    for entry in table:
        if not isinstance(entry, list) or len(entry) != 3 or not all(isinstance(x, str) for x in entry):
            raise ValueError("bad step")
        kind, text, url = entry
        if (kind not in STEP_WORDS or not text or len(text) > MAX_STEP_CHARS + len(ELLIPSIS)
                or text != references.clean(text)):
            raise ValueError("bad step text")
        if url and (len(url) > MAX_STEP_URL_CHARS or references.safe_https_url(url) != url):
            raise ValueError("bad step link")
        found.append(Step(kind, text, url))
    if not isinstance(applies, dict) or not all(k in cves for k in applies):
        raise ValueError("bad step list")
    steps = {}
    for cve, positions in applies.items():
        if (not isinstance(positions, list) or not positions or len(positions) > MAX_STEPS
                or len(set(positions)) != len(positions)
                or not all(type(p) is int and 0 <= p < len(found) for p in positions)):
            raise ValueError("bad step positions")
        steps[cve] = tuple(found[p] for p in positions)
    return steps


# ---- storage, update and import ---------------------------------------------

def _meta(data_dir):
    path = Path(data_dir) / ICS_META_FILE
    try:
        meta = json.loads(threatdata._read_capped(path, threatdata.META_MAX_BYTES).decode("utf-8"))
    except (OSError, ValueError, ThreatDataError, RecursionError):
        return {}
    if not isinstance(meta, dict):
        return {}
    return {k: threatdata._label(meta.get(k, "")) for k in ("source", "retrieved_at", "sha256", "count")}


def _install(raw, source, data_dir, now):
    data = parse_archive(raw)
    index = to_index(data)
    parse_index(index)  # what is stored must read back exactly as it will be used
    data_dir = Path(data_dir)
    threatdata._write_atomic(data_dir / ICS_FILE, index)
    meta = {"source": threatdata._label(source), "retrieved_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "sha256": hashlib.sha256(index).hexdigest(), "count": str(len(data.advisories))}
    threatdata._write_atomic(data_dir / ICS_META_FILE, json.dumps({"version": 1, **meta}, indent=2).encode("utf-8"))
    return len(data.advisories), len(data.by_cve)


def _run(produce, source, data_dir, now):
    try:
        advisories, cves = _install(produce(), source, data_dir, now)
    except ThreatDataError as error:
        return SourceResult("ics", False, f"ICS advisories not updated: {error}. The previous copy was kept.")
    except OSError as error:
        return SourceResult("ics", False, f"ICS advisories not updated: file error ({error.strerror or error}). "
                                          "The previous copy was kept.")
    return SourceResult("ics", True, f"ICS advisories updated: {advisories:,} advisories naming {cves:,} CVEs.")


def update_from_network(data_dir=None, fetcher=None, now=None, cancel=None, progress=None):
    """Download the CISA advisories archive and replace the stored index only if the new data validates.

    fetcher defaults to threatdata.fetch, looked up when called (so a test can replace it).
    """
    fetcher = fetcher or threatdata.fetch
    data_dir = data_dir or threatdata.default_data_dir()
    now = now or threatdata._now()
    if cancel is not None and cancel.is_set():
        return SourceResult("ics", False, "ICS advisories not updated: cancelled. The previous copy was kept.")
    if progress:
        progress("Downloading ICS advisories...")
    try:
        kwargs = {} if cancel is None else {"cancel": cancel}
        raw = fetcher(ICS_URL, ICS_MAX_COMPRESSED, ICS_HOSTS, **kwargs)
    except FetchError as error:
        return SourceResult("ics", False, f"ICS advisories not updated: {error}. The previous copy was kept.")
    return _run(lambda: raw, ICS_URL, data_dir, now)


def import_from_file(path, data_dir=None, now=None):
    """Import the advisories archive (the .tar.gz that GitHub offers for the repository) from a file."""
    data_dir = data_dir or threatdata.default_data_dir()
    path = Path(path)
    return _run(lambda: threatdata._read_capped(path, ICS_MAX_COMPRESSED), f"file import: {path.name}", data_dir,
                now or threatdata._now())


def load(data_dir=None):
    """Return (IcsData or None, warnings): unusable stored data becomes a warning, never an exception."""
    data_dir = Path(data_dir or threatdata.default_data_dir())
    path = data_dir / ICS_FILE
    if not path.exists():
        return None, []
    try:
        return parse_index(threatdata._read_capped(path, ICS_MAX_INDEX_BYTES)), []
    except (OSError, ThreatDataError) as error:
        return None, [f"Stored ICS advisories could not be used ({error}). Update or import them again."]


def status(data_dir=None):
    """Return a threatdata.SourceStatus for the stored advisories."""
    data, warnings = load(data_dir)
    name, label = "ics", "ICS advisories"
    if warnings:
        return threatdata.SourceStatus(name, label, problem=warnings[0][:200])
    if data is None:
        return threatdata.SourceStatus(name, label)
    meta = _meta(data_dir or threatdata.default_data_dir())
    return threatdata.SourceStatus(name, label, True, "", data.feed_date, len(data.advisories),
                                   meta.get("retrieved_at", ""))


def versions(data):
    """A short description of the advisories in use, for summaries and exports."""
    return f"ICS advisories {data.feed_date}" if data is not None else "ICS advisories not loaded"

