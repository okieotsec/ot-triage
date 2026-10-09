"""CISA KEV and EPSS threat data: validated parsing, safe download and import, storage, lookup (no GUI)."""
import csv
import dataclasses
import datetime
import functools
import gzip
import hashlib
import http.client
import io
import json
import os
import re
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass
from pathlib import Path

import references
from prioritizer import Factor, Threat

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
KEV_HOSTS = frozenset({"www.cisa.gov"})
EPSS_HOSTS = frozenset({"epss.empiricalsecurity.com"})

MB = 1024 * 1024
KEV_MAX_BYTES = 25 * MB
KEV_MAX_ENTRIES = 100_000
EPSS_MAX_COMPRESSED = 50 * MB
EPSS_MAX_DECOMPRESSED = 100 * MB
EPSS_MAX_ROWS = 2_000_000
MAX_FIELD_CHARS = 10_000
META_MAX_BYTES = 64 * 1024

FETCH_TIMEOUT_SECONDS = 20
FETCH_DEADLINE_SECONDS = 120
MAX_REDIRECTS = 3
CHUNK_BYTES = 64 * 1024

KEV_FILE, EPSS_FILE, META_FILE = "kev.json", "epss.csv.gz", "meta.json"
RANSOMWARE_SCORE_BONUS = 0.5

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
VERSION_RE = re.compile(r"^[0-9A-Za-z._-]{1,64}$")
EPSS_HEADER_RE = re.compile(
    r"^#model_version:(v[0-9][0-9A-Za-z._-]{0,30}),score_date:(\d{4}-\d{2}-\d{2})(T[0-9:.]{1,20}Z?)?$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


class ThreatDataError(ValueError):
    """Threat data that is missing, malformed or unsafe to use."""


class FetchError(ThreatDataError):
    """A download that failed or was refused."""


@dataclass(frozen=True)
class KevEntry:
    """One CISA Known Exploited Vulnerabilities catalog entry."""

    cve: str
    vendor: str
    product: str
    name: str
    date_added: str
    required_action: str
    due_date: str
    ransomware: bool
    notes: str = ""

    @property
    def references(self):
        """Return the entry's notes as a tuple of references (safe links and plain text)."""
        return references.parse_references(self.notes)


@dataclass(frozen=True)
class KevData:
    """A validated KEV catalog."""

    catalog_version: str
    date_released: str
    entries: dict


@dataclass(frozen=True)
class EpssData:
    """Validated EPSS scores: cve -> (epss, percentile)."""

    model_version: str
    score_date: str
    scores: dict


@dataclass(frozen=True)
class CveInfo:
    """Local KEV and EPSS facts about one CVE; None means the source has no entry or is not loaded."""

    cve: str
    kev: KevEntry = None
    epss: float = None
    percentile: float = None
    kev_loaded: bool = False
    epss_loaded: bool = False


@dataclass(frozen=True)
class ThreatDecision:
    """A derived threat level with where it came from."""

    level: Threat
    sources: tuple
    notes: tuple = ()


@dataclass(frozen=True)
class SourceResult:
    """Outcome of updating or importing one data source."""

    name: str
    ok: bool
    message: str


@dataclass(frozen=True)
class Freshness:
    """How current one data source is."""

    name: str
    text: str
    stale: bool
    missing: bool


# ---- parsing and validation ------------------------------------------------

def normalize_cve(text):
    """Return an upper-case CVE ID, or raise ValueError if the text is not one."""
    cve = str(text).strip().upper()
    if not CVE_RE.match(cve):
        raise ValueError("not a valid CVE ID (expected a form like CVE-2024-12345)")
    return cve


def _reject_constant(name):
    raise ValueError(f"invalid number {name}")


def _reject_duplicates(pairs):
    keys = [k for k, _v in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate keys")
    return dict(pairs)


def _text(entry, key, where):
    value = entry.get(key)
    if not isinstance(value, str):
        raise ThreatDataError(f"{where}: '{key}' must be text")
    if len(value) > MAX_FIELD_CHARS:
        raise ThreatDataError(f"{where}: '{key}' is longer than {MAX_FIELD_CHARS} characters")
    return CONTROL_RE.sub(" ", value).strip()


def _valid_date(text):
    if not DATE_RE.match(text):
        return False
    try:
        datetime.date.fromisoformat(text)
    except ValueError:
        return False
    return True


def parse_kev(data):
    """Validate KEV catalog JSON bytes and return a KevData."""
    if len(data) > KEV_MAX_BYTES:
        raise ThreatDataError(f"KEV file is larger than {KEV_MAX_BYTES // MB} MB")
    try:
        doc = json.loads(data.decode("utf-8"), parse_constant=_reject_constant, object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise ThreatDataError(f"KEV file is not valid JSON ({error})") from None
    if not isinstance(doc, dict):
        raise ThreatDataError("KEV file must be a JSON object")
    version = doc.get("catalogVersion")
    if not isinstance(version, str) or not VERSION_RE.match(version):
        raise ThreatDataError("KEV file has no valid catalogVersion")
    released = doc.get("dateReleased")
    if not isinstance(released, str) or not _valid_date(released[:10]):
        raise ThreatDataError("KEV file has no valid dateReleased")
    items = doc.get("vulnerabilities")
    if not isinstance(items, list):
        raise ThreatDataError("KEV file has no vulnerabilities list")
    if len(items) > KEV_MAX_ENTRIES:
        raise ThreatDataError(f"KEV file has more than {KEV_MAX_ENTRIES:,} entries")
    if doc.get("count") != len(items) or isinstance(doc.get("count"), bool):
        raise ThreatDataError("KEV file count does not match its entries (possibly truncated)")
    entries = {}
    for index, item in enumerate(items):
        where = f"KEV entry {index + 1}"
        if not isinstance(item, dict):
            raise ThreatDataError(f"{where}: must be an object")
        cve = item.get("cveID")
        if not isinstance(cve, str) or not CVE_RE.match(cve):
            raise ThreatDataError(f"{where}: invalid cveID")
        where = f"KEV entry {cve}"
        if cve in entries:
            raise ThreatDataError(f"{where}: listed twice")
        added = item.get("dateAdded")
        due = item.get("dueDate", "")
        if not isinstance(added, str) or not _valid_date(added):
            raise ThreatDataError(f"{where}: invalid dateAdded")
        if not isinstance(due, str) or (due and not _valid_date(due)):
            raise ThreatDataError(f"{where}: invalid dueDate")
        ransomware = item.get("knownRansomwareCampaignUse")
        if ransomware not in ("Known", "Unknown"):
            raise ThreatDataError(f"{where}: invalid knownRansomwareCampaignUse")
        notes = item.get("notes", "")
        if not isinstance(notes, str):
            raise ThreatDataError(f"{where}: 'notes' must be text")
        if len(notes) > MAX_FIELD_CHARS:
            raise ThreatDataError(f"{where}: 'notes' is longer than {MAX_FIELD_CHARS} characters")
        entries[cve] = KevEntry(cve, _text(item, "vendorProject", where), _text(item, "product", where),
                                _text(item, "vulnerabilityName", where), added,
                                _text(item, "requiredAction", where), due, ransomware == "Known",
                                references.clean(notes))
    return KevData(version, released[:10], entries)


def _decompress(data):
    """Return plain bytes from gzip or plain input, enforcing size limits."""
    if data[:2] != b"\x1f\x8b":
        if len(data) > EPSS_MAX_DECOMPRESSED:
            raise ThreatDataError(f"EPSS file is larger than {EPSS_MAX_DECOMPRESSED // MB} MB")
        return data
    if len(data) > EPSS_MAX_COMPRESSED:
        raise ThreatDataError(f"EPSS download is larger than {EPSS_MAX_COMPRESSED // MB} MB")
    out = bytearray()
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
            while True:
                chunk = stream.read(CHUNK_BYTES)
                if not chunk:
                    break
                out += chunk
                if len(out) > EPSS_MAX_DECOMPRESSED:
                    raise ThreatDataError(f"EPSS file expands to more than {EPSS_MAX_DECOMPRESSED // MB} MB")
    except (OSError, EOFError, zlib.error) as error:
        raise ThreatDataError(f"EPSS file is not valid gzip data ({error})") from None
    return bytes(out)


def parse_epss(data):
    """Validate EPSS CSV (plain or gzip) bytes and return an EpssData."""
    raw = _decompress(data)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ThreatDataError("EPSS file is not valid UTF-8 text") from None
    first, _sep, rest = text.partition("\n")
    match = EPSS_HEADER_RE.match(first.rstrip("\r"))
    if not match:
        raise ThreatDataError("EPSS file is missing its '#model_version:...,score_date:...' first line")
    score_date = match.group(2)
    if not _valid_date(score_date):
        raise ThreatDataError("EPSS file has an invalid score date")
    reader = csv.reader(io.StringIO(rest))
    try:
        header = next(reader, None)
    except csv.Error as error:
        raise ThreatDataError(f"EPSS file could not be read ({error})") from None
    if header != ["cve", "epss", "percentile"]:
        raise ThreatDataError("EPSS file must have the columns cve, epss, percentile")
    scores = {}
    try:
        for row in reader:
            if not row:
                continue
            if len(scores) >= EPSS_MAX_ROWS:
                raise ThreatDataError(f"EPSS file has more than {EPSS_MAX_ROWS:,} rows")
            if len(row) != 3 or not CVE_RE.match(row[0]):
                raise ThreatDataError(f"EPSS file line {reader.line_num + 1}: invalid row")
            try:
                epss, percentile = float(row[1]), float(row[2])
            except ValueError:
                raise ThreatDataError(f"EPSS file line {reader.line_num + 1}: scores must be numbers") from None
            if not (0.0 <= epss <= 1.0 and 0.0 <= percentile <= 1.0):
                raise ThreatDataError(f"EPSS file line {reader.line_num + 1}: scores must be between 0 and 1")
            if row[0] in scores:
                raise ThreatDataError(f"EPSS file line {reader.line_num + 1}: {row[0]} listed twice")
            scores[row[0]] = (epss, percentile)
    except csv.Error as error:
        raise ThreatDataError(f"EPSS file could not be read ({error})") from None
    if not scores:
        raise ThreatDataError("EPSS file has no scores")
    return EpssData(match.group(1), score_date, scores)


# ---- download --------------------------------------------------------------

class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    """Follow a few redirects, only to HTTPS URLs on the expected hosts."""

    max_redirections = MAX_REDIRECTS

    def __init__(self, allowed_hosts):
        self.allowed_hosts = allowed_hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parts = urllib.parse.urlsplit(newurl)
        if parts.scheme != "https" or parts.hostname not in self.allowed_hosts or parts.username or parts.password:
            raise FetchError("the server redirected to an address that is not allowed")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url, max_bytes, allowed_hosts, context=None, timeout=FETCH_TIMEOUT_SECONDS,
          deadline=FETCH_DEADLINE_SECONDS, cancel=None):
    """Download a URL over HTTPS from an allowed host, with size and time limits; cancel is a threading.Event."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in allowed_hosts or parts.username or parts.password:
        raise FetchError("only HTTPS downloads from the expected hosts are allowed")
    # The URL scheme and host are validated above, and redirects are restricted the same way
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context or ssl.create_default_context()),
                                         _SafeRedirect(frozenset(allowed_hosts)))
    request = urllib.request.Request(  # noqa: S310  # nosec B310
        url, headers={"User-Agent": "vuln-prioritizer", "Accept-Encoding": "identity"})
    started = time.monotonic()
    try:
        with opener.open(request, timeout=timeout) as response:  # noqa: S310  # nosec B310
            length = response.headers.get("Content-Length")
            expected = int(length) if length and length.isdigit() else None
            if expected is not None and expected > max_bytes:
                raise FetchError(f"the download is larger than {max_bytes // MB} MB")
            body = bytearray()
            while True:
                chunk = response.read1(CHUNK_BYTES)
                if not chunk:
                    if expected is not None and len(body) != expected:
                        raise FetchError("the connection was cut off before the download finished")
                    return bytes(body)
                body += chunk
                if len(body) > max_bytes:
                    raise FetchError(f"the download is larger than {max_bytes // MB} MB")
                if time.monotonic() - started > deadline:
                    raise FetchError("the download took too long")
                if cancel is not None and cancel.is_set():
                    raise FetchError("the download was cancelled")
    except FetchError:
        raise
    except urllib.error.HTTPError as error:
        error.close()
        if 300 <= error.code < 400:
            raise FetchError("the server's redirects were refused or repeated too often") from None
        raise FetchError(f"the server returned HTTP {error.code}") from None
    except urllib.error.URLError as error:
        if isinstance(error.reason, ssl.SSLError):
            raise _tls_error(error.reason) from None
        if isinstance(error.reason, TimeoutError):
            raise FetchError("the connection timed out") from None
        raise FetchError(f"could not connect ({error.reason})") from None
    except ssl.SSLError as error:
        raise _tls_error(error) from None
    except TimeoutError:
        raise FetchError("the connection timed out") from None
    except (OSError, ValueError, http.client.HTTPException) as error:
        raise FetchError(f"network error ({error})") from None


def _tls_error(error):
    detail = getattr(error, "verify_message", None) or error.reason or str(error)
    message = f"the secure connection could not be verified ({detail})"
    if sys.platform == "win32" and "issuer" in str(detail):
        message += (". This Windows PC is missing a trusted root certificate that the server's chain needs. "
                    "Certificate checking is never turned off; see docs/THREAT_DATA.md, \"Troubleshooting\", "
                    "for the safe fix")
    return FetchError(message)


# ---- storage ---------------------------------------------------------------

def default_data_dir():
    """Return the folder where downloaded threat data is stored."""
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        xdg = os.environ.get("XDG_DATA_HOME", "")
        base = Path(xdg) if xdg and os.path.isabs(xdg) else Path.home() / ".local" / "share"
    return base / "vuln-prioritizer" / "data"


def _write_atomic(path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=".part")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.remove(temp_name)
        except OSError:
            pass
        raise


def _read_capped(path, cap):
    if not path.is_file():
        raise ThreatDataError(f"{path.name} is not a regular file")
    if path.stat().st_size > cap:
        raise ThreatDataError(f"{path.name} is larger than {cap // MB} MB")
    return path.read_bytes()


def _label(text):
    return CONTROL_RE.sub(" ", str(text)).strip()[:120]


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _read_meta(data_dir):
    path = Path(data_dir) / META_FILE
    if not path.exists():
        return {}
    try:
        meta = json.loads(_read_capped(path, META_MAX_BYTES).decode("utf-8"), object_pairs_hook=_reject_duplicates,
                          parse_constant=_reject_constant)
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return {}
    clean = {}
    for name in ("kev", "epss"):
        entry = meta.get(name) if isinstance(meta, dict) else None
        if isinstance(entry, dict):
            clean[name] = {k: _label(entry.get(k, "")) for k in ("source", "retrieved_at", "sha256", "count")}
    return clean


def _install(name, raw, source, data_dir, now):
    """Validate raw bytes and, only if valid, replace the stored copy and its metadata."""
    data_dir = Path(data_dir)
    if name == "kev":
        count = len(parse_kev(raw).entries)
        stored, filename = raw, KEV_FILE
    else:
        count = len(parse_epss(raw).scores)
        stored, filename = (raw if raw[:2] == b"\x1f\x8b" else gzip.compress(raw)), EPSS_FILE
    _write_atomic(data_dir / filename, stored)
    meta = _read_meta(data_dir)
    meta[name] = {"source": _label(source), "retrieved_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                  "sha256": hashlib.sha256(stored).hexdigest(), "count": str(count)}
    _write_atomic(data_dir / META_FILE, json.dumps({"version": 1, **meta}, indent=2).encode("utf-8"))


def _run(name, produce, source, data_dir, now):
    label = "KEV" if name == "kev" else "EPSS"
    try:
        _install(name, produce(), source, data_dir, now)
    except ThreatDataError as error:
        return SourceResult(name, False, f"{label} not updated: {error}. The previous copy was kept.")
    except OSError as error:
        return SourceResult(name, False, f"{label} not updated: file error ({error.strerror or error}). "
                                         "The previous copy was kept.")
    return SourceResult(name, True, f"{label} updated.")


def update_from_network(data_dir=None, fetcher=fetch, now=None, cancel=None, progress=None):
    """Download both sources, replacing each stored copy only if its new data validates."""
    data_dir = data_dir or default_data_dir()
    now = now or _now()
    specs = (("kev", "KEV", KEV_URL, KEV_MAX_BYTES, KEV_HOSTS), ("epss", "EPSS", EPSS_URL, EPSS_MAX_COMPRESSED,
                                                                   EPSS_HOSTS))
    results = []
    for name, label, url, cap, hosts in specs:
        if cancel is not None and cancel.is_set():
            results.append(SourceResult(name, False, f"{label} not updated: cancelled. The previous copy was kept."))
            continue
        if progress:
            progress(f"Downloading {label}...")
        get = fetcher if cancel is None else functools.partial(fetcher, cancel=cancel)
        results.append(_run(name, lambda u=url, c=cap, h=hosts, g=get: g(u, c, h), url, data_dir, now))
    return results


def import_from_files(kev_path=None, epss_path=None, data_dir=None, now=None):
    """Import KEV and/or EPSS files chosen by the user, with the same validation as a download."""
    data_dir = data_dir or default_data_dir()
    now = now or _now()
    results = []
    for name, path, cap in (("kev", kev_path, KEV_MAX_BYTES), ("epss", epss_path, EPSS_MAX_COMPRESSED)):
        if path:
            path = Path(path)
            results.append(_run(name, lambda p=path, c=cap: _read_capped(p, c), f"file import: {path.name}",
                                data_dir, now))
    return results


# ---- loaded data and lookups -----------------------------------------------

class ThreatData:
    """The stored KEV and EPSS data, re-validated on load."""

    def __init__(self, kev=None, epss=None, meta=None, warnings=()):
        self.kev, self.epss, self.meta, self.warnings = kev, epss, meta or {}, list(warnings)

    @classmethod
    def load(cls, data_dir=None):
        """Load stored data; unusable files become warnings, never exceptions."""
        data_dir = Path(data_dir or default_data_dir())
        found, warnings = {}, []
        for name, filename, parse, cap in (("kev", KEV_FILE, parse_kev, KEV_MAX_BYTES),
                                           ("epss", EPSS_FILE, parse_epss, EPSS_MAX_COMPRESSED)):
            path = data_dir / filename
            if not path.exists():
                continue
            try:
                found[name] = parse(_read_capped(path, cap))
            except (OSError, ThreatDataError) as error:
                warnings.append(f"Stored {name.upper()} data could not be used ({error}). Update or import it again.")
        return cls(found.get("kev"), found.get("epss"), _read_meta(data_dir), warnings)

    def lookup(self, cve):
        """Return the local KEV and EPSS facts for a CVE ID."""
        cve = normalize_cve(cve)
        score = self.epss.scores.get(cve) if self.epss else None
        return CveInfo(cve, self.kev.entries.get(cve) if self.kev else None, score[0] if score else None,
                       score[1] if score else None, self.kev is not None, self.epss is not None)

    def versions(self):
        """Return a one-line description of the KEV and EPSS versions in use, for summaries and exports."""
        kev = f"KEV {self.kev.catalog_version} ({self.kev.date_released})" if self.kev else "KEV not loaded"
        epss = f"EPSS {self.epss.model_version} ({self.epss.score_date})" if self.epss else "EPSS not loaded"
        return f"{kev}; {epss}"

    def freshness(self, stale_days, now=None):
        """Return the age and stale status of each source."""
        now = now or _now()
        report = []
        for name, label, data in (("kev", "KEV", self.kev), ("epss", "EPSS", self.epss)):
            if data is None:
                report.append(Freshness(label, f"{label}: not loaded", True, True))
                continue
            version = (f"{data.catalog_version}, released {data.date_released}" if name == "kev"
                       else f"{data.model_version}, scored {data.score_date}")
            report.append(_freshness(label, version, self.meta.get(name, {}).get("retrieved_at", ""), stale_days, now))
        return report


def _freshness(label, version, retrieved, stale_days, now):
    try:
        when = datetime.datetime.strptime(retrieved, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
        days = max(0, (now - when).days)
    except ValueError:
        return Freshness(label, f"{label} {version}: retrieval date unknown", True, False)
    return Freshness(label, f"{label} {version}: retrieved {days} day{'s' if days != 1 else ''} ago",
                     days > stale_days, False)


@dataclass(frozen=True)
class SourceStatus:
    """What is stored for one source, read cheaply from its file header and metadata."""

    name: str
    label: str
    loaded: bool = False
    version: str = ""
    date: str = ""
    count: int = None
    retrieved_at: str = ""
    problem: str = ""

    @property
    def version_text(self):
        """Return the version and date as one phrase."""
        word = "released" if self.name == "kev" else "scored"
        return f"{self.version}, {word} {self.date}"

    def freshness(self, stale_days, now=None):
        """Return the age and stale status of this source."""
        if self.problem:
            return Freshness(self.label, f"{self.label}: {self.problem}", True, False)
        if not self.loaded:
            return Freshness(self.label, f"{self.label}: not loaded", True, True)
        return _freshness(self.label, self.version_text, self.retrieved_at, stale_days, now or _now())


def _epss_header(path):
    """Read the model version and score date from the first line of a stored EPSS file."""
    if not path.is_file():
        raise ThreatDataError("stored EPSS file is not a regular file")
    with open(path, "rb") as raw:
        gzipped = raw.read(2) == b"\x1f\x8b"
    opener = gzip.open if gzipped else open
    try:
        with opener(path, "rb") as stream:
            first = stream.read(300).split(b"\n", 1)[0].decode("utf-8").rstrip("\r")
    except (OSError, EOFError, zlib.error, UnicodeDecodeError):
        raise ThreatDataError("stored EPSS data is unreadable") from None
    match = EPSS_HEADER_RE.match(first)
    if not match or not _valid_date(match.group(2)):
        raise ThreatDataError("stored EPSS data has no valid header line")
    return match.group(1), match.group(2)


def read_status(data_dir=None):
    """Return the stored status of KEV and EPSS without parsing the full EPSS file."""
    data_dir = Path(data_dir or default_data_dir())
    meta, report = _read_meta(data_dir), []
    for name, label, filename in (("kev", "KEV", KEV_FILE), ("epss", "EPSS", EPSS_FILE)):
        path = data_dir / filename
        if not path.exists():
            report.append(SourceStatus(name, label))
            continue
        saved = meta.get(name, {})
        count = int(saved["count"]) if saved.get("count", "").isdigit() else None
        try:
            if name == "kev":
                kev = parse_kev(_read_capped(path, KEV_MAX_BYTES))
                version, date, count = kev.catalog_version, kev.date_released, len(kev.entries)
            else:
                version, date = _epss_header(path)
        except (OSError, ThreatDataError) as error:
            report.append(SourceStatus(name, label, problem=f"stored data could not be used ({error})"[:200]))
            continue
        report.append(SourceStatus(name, label, True, version, date, count, saved.get("retrieved_at", "")))
    return report


# ---- threat derivation -----------------------------------------------------

_LEVEL = {Threat.NONE: 0, Threat.PUBLIC: 1, Threat.ACTIVE: 2}


def derive_threat(info, settings, analyst_confirmed=False, public_exploit=False, override=None, override_reason=""):
    """Derive a threat level from local data and analyst input, never lowering it for missing data."""
    level, sources, notes = Threat.NONE, [], []
    if info is not None:
        if not info.kev_loaded:
            notes.append("KEV data is not loaded; absence of data does not mean the CVE is not exploited")
        if not info.epss_loaded:
            notes.append("EPSS data is not loaded; absence of data does not mean exploitation is unlikely")
        if info.kev is not None:
            level, sources = Threat.ACTIVE, ["In CISA KEV"]
        elif info.epss_loaded and info.percentile is not None and info.percentile >= settings.epss_percentile_cutoff:
            level = Threat.PUBLIC
            sources.append(f"Elevated EPSS (percentile {info.percentile:.3f} at or above "
                           f"{settings.epss_percentile_cutoff:g})")
    if analyst_confirmed:
        level, sources = Threat.ACTIVE, sources + ["Analyst-confirmed exploitation (manual)"]
    if public_exploit and _LEVEL[level] < _LEVEL[Threat.PUBLIC]:
        level, sources = Threat.PUBLIC, sources + ["Public exploit (manual)"]
    if not sources:
        sources.append("No KEV or elevated EPSS signal")
    if override is not None:
        if not override_reason or not override_reason.strip():
            raise ValueError("a manual threat override needs a reason")
        reason = _label(override_reason)
        notes.append(f"Manual override from {level.name} to {override.name}: {reason}")
        level, sources = override, sources + [f"Manual override ({reason})"]
    return ThreatDecision(level, tuple(sources), tuple(notes))


def apply_threat_context(result, decision, info):
    """Add threat sources, KEV context and the ransomware ranking bonus to a result."""
    reasons = list(result.reasons) + ["Threat level from: " + "; ".join(decision.sources)] + list(decision.notes)
    action, score = result.action, result.score
    if info is not None and info.kev is not None:
        entry = info.kev
        due = f", remediation due {entry.due_date}" if entry.due_date else ""
        reasons.append(f"CISA KEV: added {entry.date_added}{due} (context only; does not change the bucket)")
        if entry.required_action:
            action = f"{action}. CISA required action: {entry.required_action}"
        if entry.ransomware:
            score = min(10.0, round(score + RANSOMWARE_SCORE_BONUS, 2))
            reasons.append("Known ransomware campaign use: ranked higher within the bucket; the bucket is unchanged")
    threat_factors = [_source_factor(source, info) for source in decision.sources
                      if not source.startswith("No KEV or elevated EPSS")]
    generic = {"Actively exploited", "Public or likely exploit"}
    factors = [f for f in result.factors if not (threat_factors and f.label in generic)]
    if threat_factors:
        position = next((i for i, f in enumerate(factors) if f.label.startswith("CVSS ")), -1) + 1
        factors[position:position] = threat_factors
    if info is not None and info.kev is not None and info.kev.ransomware:
        factors.insert(position + len(threat_factors) if threat_factors else 1, Factor("Ransomware use", "raise"))
    return dataclasses.replace(result, reasons=reasons, action=action, score=score, factors=factors)


def _source_factor(source, info):
    """Return a short chip for one threat-level source."""
    if source.startswith("Elevated EPSS") and info is not None and info.percentile is not None:
        return Factor(f"Elevated EPSS ({info.percentile * 100:.0f}th percentile)", "raise")
    if source.startswith("Manual override"):
        return Factor("Manual threat override", "neutral")
    return Factor(source.split(" (")[0], "raise")
