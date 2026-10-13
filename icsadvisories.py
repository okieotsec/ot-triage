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
import zlib
from dataclasses import dataclass, field
from pathlib import Path

import references
import threatdata
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
MAX_VENDORS = 5
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
INDEX_VERSION = 2

ICS_FILE, ICS_META_FILE = "ics_advisories.json", "ics_meta.json"
ID_RE = re.compile(r"^ICS(?:A|MA)-\d{2}-\d{3}-\d{2}[A-Z]?$")
MEMBER_RE = re.compile(r"^[^/]{1,100}/csaf_files/OT/white/\d{4}/(icsm?a-\d{2}-\d{3}-\d{2}[a-z]?)\.json$")
DATE_RE = threatdata.DATE_RE


@dataclass(frozen=True)
class IcsAdvisory:
    """One CISA ICS advisory: what it is called, when it was published and updated, and whose products it covers."""

    id: str
    title: str
    published: str
    updated: str
    vendors: tuple = ()
    fix: str = ""               # what this advisory says about fixing the looked-up CVE: a key of REMEDIATION_WORDS

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


@dataclass(frozen=True)
class IcsData:
    """A validated set of advisories and the CVEs each one names."""

    feed_date: str
    advisories: dict            # advisory id -> IcsAdvisory
    by_cve: dict                # CVE id -> tuple of advisory ids, newest first
    fixes: dict = field(default_factory=dict)    # advisory id -> {CVE id: remediation letter}

    def lookup(self, cve):
        """Return the advisories that name this CVE, newest first (at most MAX_LISTED) and how many there are.

        Each advisory carries what it says about fixing this CVE in its fix field.
        """
        cve = threatdata.normalize_cve(cve)
        ids = self.by_cve.get(cve, ())
        return tuple(dataclasses.replace(self.advisories[i], fix=self.fixes.get(i, {}).get(cve, ""))
                     for i in ids[:MAX_LISTED]), len(ids)


def _date(text, where):
    if not isinstance(text, str) or not DATE_RE.fullmatch(text[:10]) or not threatdata._valid_date(text[:10]):
        raise ValueError(f"{where} is not a valid date")
    return text[:10]


def _clean(text, limit):
    return references.clean(text)[:limit]


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


def _read_advisory(raw, stem):
    """Return (IcsAdvisory, cves, fixes) from one CSAF advisory file, or raise ValueError if it cannot be trusted.

    fixes maps a CVE id to its remediation letter, and leaves out CVEs the advisory does not say anything about.
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
    cves, fixes = [], {}
    for item in items:
        cve = item.get("cve") if isinstance(item, dict) else None
        if isinstance(cve, str) and CVE_RE.fullmatch(cve) and cve not in cves:
            cves.append(cve)
            if len(cves) > ICS_MAX_CVES:
                raise ValueError(f"it names more than {ICS_MAX_CVES:,} CVEs")
            if _remediation(item):
                fixes[cve] = _remediation(item)
    tree = doc.get("product_tree")
    vendors = _vendors(tree) if isinstance(tree, dict) else ()
    return IcsAdvisory(ident.upper(), _clean(title, MAX_TITLE_CHARS), published, updated, vendors), cves, fixes


def _assemble(triples):
    """Build an IcsData from (IcsAdvisory, cves, fixes) triples."""
    advisories, links, all_fixes = {}, {}, {}
    for advisory, cves, fixes in triples:
        if advisory.id in advisories:
            raise ThreatDataError(f"advisory {advisory.id} is listed twice")
        advisories[advisory.id] = advisory
        if fixes:
            all_fixes[advisory.id] = fixes
        for cve in cves:
            links.setdefault(cve, []).append(advisory.id)
    by_cve = {cve: tuple(sorted(ids, key=lambda i: (advisories[i].updated, i), reverse=True))
              for cve, ids in links.items()}
    feed_date = max(a.updated for a in advisories.values())
    return IcsData(feed_date, advisories, by_cve, all_fixes)


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
    return _assemble([(a, c, f) for a, c, f in pairs if c])


def to_index(data):
    """Serialize an IcsData as the small index file the tool stores."""
    names = {}
    for cve, ids in data.by_cve.items():
        for ident in ids:
            names.setdefault(ident, []).append(cve)
    rows = [{"id": a.id, "title": a.title, "published": a.published, "updated": a.updated, "vendors": list(a.vendors),
             "cves": sorted(names.get(a.id, ())), "fixes": dict(sorted(data.fixes.get(a.id, {}).items()))}
            for a in sorted(data.advisories.values(), key=lambda a: a.id)]
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
    if not isinstance(row, dict) or set(row) != {"id", "title", "published", "updated", "vendors", "cves", "fixes"}:
        raise ValueError("unexpected fields")
    ident, title, vendors, cves, fixes = row["id"], row["title"], row["vendors"], row["cves"], row["fixes"]
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
    return IcsAdvisory(ident, title, _date(row["published"], "published"), _date(row["updated"], "updated"),
                       tuple(vendors)), cves, fixes


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

