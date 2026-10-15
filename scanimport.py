"""Turn scanner exports into the findings and inventory files OT Triage reads (no GUI).

A scanner export is an untrusted file like every other the tool reads: its size and row count are limited, text is
cleaned and cut to a length, a header that is not recognised is refused (never guessed at by position), and the
files written are formula-safe. Nothing here scores anything: the importers only fill the columns OT Triage already
understands, so the scoring rules, and every result, are the same as for a findings file written by hand.

What is read, and what is left alone, follows docs/SCANNER_IMPORT.md:

* resolved or fixed findings, and informational ones, are skipped and counted, never silently dropped;
* a finding the export does not score stays in the file with an empty score, so OT Triage shows it as not scored;
* criticality, exposure and controls are never invented: a scanner does not know them.
"""
import copy
import csv
import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from typing import ClassVar
from xml.parsers import expat  # nosemgrep: python.lang.security.use-defused-xml.use-defused-xml (DTDs are refused)

import inventory
import safefile
import threatdata
from references import clean

MAX_FILE_BYTES = 200 * 1024 * 1024
MAX_INPUT_ROWS = 1_000_000
MAX_FINDINGS = 50_000                  # what the Batch view will read back
MAX_RAW_FINDINGS = 300_000             # read from all the files before merging (keeps memory bounded)
MAX_FIELD_BYTES = 8 * 1024 * 1024      # one cell: Nessus "Plugin Output" can be large
MAX_ALIASES = 100_000
MAX_NAME_CHARS = 200
MAX_ASSET_CHARS = 100
MAX_ID_CHARS = 200
MAX_SOURCES = 6
DEFAULT_MIN_QOD = 70                   # Greenbone's own default for hiding low-confidence detections
THREAT_LEVELS = ("none", "public", "active")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
FINDING_COLUMNS = ["id", "asset_id", "name", "cve", "cvss", "patch", "source_tool"]
NEW_INVENTORY_COLUMNS = ["asset_id", "name", "criticality", "exposure", "controls", "vendor", "product", "version"]
_FORMULA_START = "=+-@\t\r"

MAX_XML_DEPTH = 24
MAX_XML_TEXT_CHARS = 2_000            # text kept from one XML element that is read at all (the rest is thrown away)
XML_CHUNK_BYTES = 1024 * 1024
MAX_JSON_BYTES = 100 * 1024 * 1024    # a JSON file is read whole, so it is held to a smaller limit than a streamed one

NESSUS, TENABLE_VM, OPENVAS, NESSUS_XML = "nessus", "tenable-vm", "openvas", "nessus-xml"
NOZOMI, DRAGOS, CLAROTY = "nozomi", "dragos", "claroty"
EXPERIMENTAL = frozenset({NOZOMI, DRAGOS})
EXPERIMENTAL_NOTE = "read from a public description of this format and not yet checked against a real export"
CLAROTY_NOTE = "written from one Claroty report layout, so another layout may not be recognised"
JSON_LISTS = ("result", "results", "content", "detections", "data", "items")
_TRUE = frozenset({"true", "1", "yes", "y"})
_CLOSED = frozenset({"resolved", "closed", "fixed", "remediated"})
ID_PREFIX = {NESSUS: "nessus", TENABLE_VM: "tenable"}      # finding ids start with the tool, then plugin, asset, CVE
FORMAT_NAMES = {NESSUS: "Nessus CSV", TENABLE_VM: "Tenable Vulnerability Management CSV",
                OPENVAS: "OpenVAS / Greenbone CSV", NESSUS_XML: "Nessus .nessus (v2 XML)",
                NOZOMI: "Nozomi node_cves (experimental)", DRAGOS: "Dragos detections (experimental)",
                CLAROTY: "Claroty xDome device-vulnerability pairs"}


class ScanImportError(ValueError):
    """A file that cannot be imported, with a message for the person."""


@dataclass
class Finding:
    """One finding in OT Triage's own terms."""

    id: str
    asset_id: str
    name: str
    cve: str = ""
    cvss: str = ""
    patch: str = ""
    source: str = ""
    threat: str = ""


@dataclass
class Asset:
    """What a scanner says about one asset (vendor, product and version only come from the OT tools)."""

    asset_id: str
    name: str = ""
    vendor: str = ""
    product: str = ""
    version: str = ""


@dataclass
class FileReport:
    """What was read from one file."""

    path: str
    format: str
    rows: int = 0
    kept: int = 0
    skipped: dict = field(default_factory=dict)       # reason -> how many
    note: str = ""                                    # something to tell the person about how the file was read

    def skip(self, reason):
        self.skipped[reason] = self.skipped.get(reason, 0) + 1


@dataclass
class ImportResult:
    """Everything an import found, ready to be written."""

    findings: list = field(default_factory=list)
    assets: dict = field(default_factory=dict)        # lower-case asset id -> Asset
    reports: list = field(default_factory=list)
    merged: int = 0                                   # findings collapsed into another
    renamed: int = 0                                  # asset ids replaced through the aliases file
    need_threat: int = 0                              # findings with no CVE (so no threat level can be derived)
    not_scored: int = 0                               # findings the export did not score


def _norm(text):
    return " ".join(str(text).strip().lower().replace("_", " ").split())


def _cell(text, limit):
    return clean(str(text or ""))[:limit].rstrip()


def _score(text):
    """A CVSS score from a cell as "x.y", or an empty string if it is blank, not a number or outside 0 to 10."""
    try:
        value = float(str(text).strip())
    except ValueError:
        return ""
    return f"{value:.1f}" if 0 <= value <= 10 else ""


def _cves(text):
    """The distinct CVE ids named in a cell (any separator), upper case, in order."""
    found, seen = [], set()           # a set keeps a hostile cell with thousands of ids linear in its size
    for match in CVE_RE.findall(str(text or "")):
        cve = match.upper()
        if cve not in seen:
            seen.add(cve)
            found.append(cve)
    return found


# ---- reading -------------------------------------------------------------------

def _open_input(path, binary, limit=None, advice="", **options):
    """Open a file to read, after checking the opened file itself (see safefile.open_regular).

    Raises ScanImportError; the caller closes the file.
    """
    name = os.path.basename(path)
    try:
        return safefile.open_regular(path, binary, limit, ScanImportError,
                                     limit is not None and f"{name} is larger than {limit // (1024 * 1024)} MB{advice}",
                                     "imported", **options)
    except OSError as error:
        raise ScanImportError(f"{name} could not be read ({error.strerror or error})") from None


class _Table:
    """A CSV export read row by row, with its columns found by name (never by position)."""

    def __init__(self, path):
        self.path = path
        self._fh = _open_input(path, False, MAX_FILE_BYTES, newline="", encoding="utf-8-sig")
        self._saved_limit = csv.field_size_limit(MAX_FIELD_BYTES)
        self._reader = csv.reader(self._fh)
        try:
            header = next(self._reader)
        except StopIteration:
            self.close()
            raise ScanImportError(f"{os.path.basename(path)} is empty") from None
        except (csv.Error, UnicodeDecodeError) as error:
            self.close()
            raise ScanImportError(f"{os.path.basename(path)} is not a CSV text file ({str(error)[:80]})") from None
        self.header = [_norm(h) for h in header]
        self.columns = {}
        for position, name in enumerate(self.header):
            self.columns.setdefault(name, position)

    def has(self, *names):
        return any(n in self.columns for n in names)

    def get(self, cells, *names):
        """The first non-empty cell among the given column names (blank if none)."""
        for name in names:
            position = self.columns.get(name)
            if position is not None and position < len(cells) and cells[position].strip():
                return cells[position]
        return ""

    def rows(self):
        count = 0
        try:
            for cells in self._reader:
                if not any(c.strip() for c in cells):
                    continue
                count += 1
                if count > MAX_INPUT_ROWS:
                    raise ScanImportError(f"{os.path.basename(self.path)} has more than {MAX_INPUT_ROWS:,} rows")
                yield cells
        except (csv.Error, UnicodeDecodeError) as error:
            message = f"{os.path.basename(self.path)} is not a valid CSV file ({str(error)[:80]})"
            raise ScanImportError(message) from None

    def close(self):
        csv.field_size_limit(self._saved_limit)
        self._fh.close()


def detect_format(header):
    """Name the export a header belongs to (a key of FORMAT_NAMES), or None."""
    names = {_norm(h) for h in header}
    if "nvt name" in names and ("cves" in names or "nvt oid" in names):
        return OPENVAS
    if "asset name" in names and ("plugin id" in names or "plugin name" in names):
        return TENABLE_VM
    if "plugin id" in names and "host" in names:
        return NESSUS
    if {"device name", "vulnerability name", "cves"} <= names:
        return CLAROTY
    labels = {"node label", "assets name", "asset id", "node id"}
    if "cve" in names and ("cve score" in names or "score" in names) and names & labels:
        return NOZOMI
    return None


_V3 = ("cvss v3.0 base score", "cvss v3 base score", "cvss3 base score", "cvssv3 base score", "cvss3 score")
_V2 = ("cvss v2.0 base score", "cvss v2 base score", "cvss", "cvss base score", "cvssv2 base score", "cvss score")
_SKIP_RISK = {"none", "info", "informational"}
_SKIP_STATE = {"fixed", "resolved", "remediated", "closed"}


def scanner_hint(header):
    """A sentence for a person who opened a scanner export where a findings file or an inventory was expected.

    Returns an empty string when the header is not one of the exports this module reads.
    """
    first = str(header[0]).lstrip("\ufeff \t").lower() if header else ""
    if first[:1] in ("{", "["):
        return ("This is a JSON file. OT Triage reads CSV; if it is a Nozomi or Dragos export, convert it with python3 "
                "ot_triage_import.py EXPORT -o findings.csv --inventory-out inventory.csv (see docs/IMPORT.md), then "
                "open findings.csv here and load the inventory it wrote.")
    source = NESSUS_XML if first.startswith(("<?xml", "<nessusclientdata")) else detect_format(header)
    if source is None:
        return ""
    return (f"This is a scanner export ({FORMAT_NAMES[source]}), not an OT Triage findings file or inventory. "
            "Convert it with python3 ot_triage_import.py EXPORT -o findings.csv --inventory-out inventory.csv "
            "(see docs/IMPORT.md), then open findings.csv here and load the inventory it wrote.")


def _read_tenable_family(table, report, source):
    """Nessus CSV and Tenable Vulnerability Management findings CSV: one row per plugin, host and CVE."""
    if not table.has("plugin id") or not table.has("name", "plugin name"):
        raise ScanImportError(f"{os.path.basename(table.path)}: the header needs a Plugin ID and a plugin name column")
    findings, assets = [], {}
    for cells in table.rows():
        report.rows += 1
        level = _norm(table.get(cells, "risk", "severity"))
        state = _norm(table.get(cells, "vulnerability state", "state"))
        if level in _SKIP_RISK:
            report.skip("informational (no risk)")
            continue
        if state in _SKIP_STATE:
            report.skip("already fixed or resolved")
            continue
        asset = _cell(table.get(cells, "asset name", "host", "ipv4 address", "ip address"), MAX_ASSET_CHARS)
        if not asset:
            report.skip("no host or asset name")
            continue
        plugin = _cell(table.get(cells, "plugin id"), 40)
        title = _cell(table.get(cells, "plugin name", "name"), MAX_NAME_CHARS) or f"Plugin {plugin}"
        score = _score(table.get(cells, *_V3)) or _score(table.get(cells, *_V2))
        for cve in _cves(table.get(cells, "cve")) or [""]:
            ident = f"{ID_PREFIX[source]}:{plugin}:{asset}:{cve or 'nocve'}"[:MAX_ID_CHARS]
            findings.append(Finding(ident, asset, title, cve, score, "", source))
            _check_size(findings)
        name = _cell(table.get(cells, "fqdn", "asset name"), MAX_NAME_CHARS)
        assets.setdefault(asset.lower(), Asset(asset, name if name.lower() != asset.lower() else ""))
    return findings, assets


def _read_openvas(table, report, min_qod):
    """OpenVAS / Greenbone results CSV. Log entries and detections below the Quality of Detection limit are skipped."""
    if not table.has("ip") or not table.has("nvt name") or not table.has("cvss"):
        raise ScanImportError(f"{os.path.basename(table.path)}: the header needs IP, NVT Name and CVSS columns")
    findings, assets = [], {}
    for cells in table.rows():
        report.rows += 1
        score = _score(table.get(cells, "cvss"))
        if _norm(table.get(cells, "severity")) == "log" or score in ("", "0.0"):
            report.skip("log entry or no score")
            continue
        quality = _score_int(table.get(cells, "qod"))
        if quality is not None and quality < min_qod:
            report.skip(f"quality of detection below {min_qod}")
            continue
        asset = _cell(table.get(cells, "ip"), MAX_ASSET_CHARS)
        if not asset:
            report.skip("no IP address")
            continue
        result_id = _cell(table.get(cells, "result id", "nvt oid"), 80)
        title = _cell(table.get(cells, "nvt name"), MAX_NAME_CHARS) or "OpenVAS result"
        solution = _norm(table.get(cells, "solution type"))
        patch = "available" if solution == "vendorfix" else ""
        for cve in _cves(table.get(cells, "cves")) or [""]:
            ident = f"openvas:{result_id}:{cve or 'nocve'}"[:MAX_ID_CHARS]
            findings.append(Finding(ident, asset, title, cve, score, patch, OPENVAS))
            _check_size(findings)
        host = _cell(table.get(cells, "hostname"), MAX_NAME_CHARS)
        known = assets.setdefault(asset.lower(), Asset(asset))
        known.name = known.name or host
    return findings, assets


_CLAROTY_NONE = frozenset({"", "n/a", "na", "none", "-"})
_POTENTIAL_TAG = " [potentially relevant]"


def _claroty_ips(text):
    """The addresses in a Claroty "device ip" cell, without the "(Last known IP)" remarks, at most four."""
    found = []
    for part in str(text or "").split(","):
        address = _cell(part.split("(")[0], 60)
        if address and address not in found:
            found.append(address)
    return ", ".join(found[:4])


def _read_claroty(table, report, only_confirmed):
    """Claroty xDome "device-vulnerability pairs" CSV: one row per device and vulnerability (or advisory).

    A row can name several CVEs, so it becomes one finding per CVE with the row's score. Claroty's own risk scores,
    its "actively exploited" flag and its EPSS column are not used (the threat level comes from KEV and EPSS data).
    Rows with a resolution or patch-install date are skipped. A "potentially relevant" row is kept and marked in its
    name, unless only_confirmed is set.
    """
    findings, assets = [], {}
    potential = 0
    for cells in table.rows():
        report.rows += 1
        if _norm(table.get(cells, "device-vuln. resolution date")) not in _CLAROTY_NONE:
            report.skip("already resolved")
            continue
        if _norm(table.get(cells, "patch install date")) not in _CLAROTY_NONE:
            report.skip("patch already installed")
            continue
        is_potential = _norm(table.get(cells, "vulnerability relevance")).startswith("potentially")
        if is_potential and only_confirmed:
            report.skip("not confirmed (potentially relevant)")
            continue
        asset = _cell(table.get(cells, "device name"), MAX_ASSET_CHARS)
        if not asset:
            report.skip("no device name")
            continue
        potential += is_potential
        title = _cell(table.get(cells, "vulnerability name"), MAX_NAME_CHARS) or "Claroty vulnerability"
        if is_potential:
            title = title[:MAX_NAME_CHARS - len(_POTENTIAL_TAG)].rstrip() + _POTENTIAL_TAG
        score = _score(table.get(cells, "cvss v3 base score points")) or _score(table.get(cells, "cvss v3 base score"))
        remedy = _norm(table.get(cells, "manuf. remediation info"))
        fixed = ("patch available" in remedy or "version upgrade available" in remedy) and "not patching" not in remedy
        token = _cell(title.split(" ")[0], 60)
        for cve in _cves(table.get(cells, "cves")) or [""]:
            ident = f"claroty:{token}:{asset}:{cve or 'nocve'}"[:MAX_ID_CHARS]
            findings.append(Finding(ident, asset, title, cve, score, "available" if fixed else "", CLAROTY))
            _check_size(findings)
        known = assets.setdefault(asset.lower(), Asset(asset))
        known.name = known.name or _claroty_ips(table.get(cells, "device ip"))
    note = CLAROTY_NOTE
    if potential:
        note += (f"; {potential:,} rows are 'potentially relevant' (not confirmed by Claroty): they are marked in the "
                 "finding name, and --only-confirmed leaves them out")
    report.note = note
    return findings, assets


def _check_size(findings):
    if len(findings) > MAX_RAW_FINDINGS:
        raise ScanImportError(f"The export has more than {MAX_RAW_FINDINGS:,} findings; OT Triage reads at most "
                              f"{MAX_FINDINGS:,}. Narrow the export (by severity or by site) and import again")


def _score_int(text):
    try:
        return int(float(str(text).strip()))
    except ValueError:
        return None


class _NessusXml:
    """Reads a Nessus v2 (.nessus) file as it streams past, keeping only what is needed.

    The parser is expat (the standard library's), driven chunk by chunk, so a large file is never held in memory and the
    text of a plugin's output (which can be huge) is never kept. A file that declares a DTD or an entity is refused:
    that is how entity-expansion attacks are made, and a scanner never writes one.
    """

    KEPT: ClassVar = frozenset({"cve", "cvss_base_score", "cvss3_base_score"})
    HOST_TAGS: ClassVar = frozenset({"host-ip", "host-fqdn", "netbios-name", "operating-system"})

    def __init__(self, report):
        self.report = report
        self.findings, self.assets = [], {}
        self.depth = 0
        self.host = None
        self.item = None
        self.item_depth = 0
        self.tag = None
        self.child = None
        self.text = []
        self.size = 0
        self.hosts = 0

    # -- expat handlers (an exception raised here stops the parse and is passed on) --
    def start(self, name, attrs):
        self.depth += 1
        if self.depth > MAX_XML_DEPTH:
            raise ScanImportError("the file is nested too deeply to be a Nessus export")
        if self.depth == 1 and name != "NessusClientData_v2":
            raise ScanImportError(f"the root element is '{clean(name)[:40]}', not NessusClientData_v2: this is not a "
                                  "Nessus v2 (.nessus) file")
        if name == "ReportHost":
            self.host = {"name": attrs.get("name", ""), "tags": {}}
            self.hosts += 1
        elif self.host is not None and self.item is None and name == "tag" and attrs.get("name") in self.HOST_TAGS:
            self.tag = attrs["name"]
            self.begin_text()
        elif self.host is not None and self.item is None and name == "ReportItem":
            self.report.rows += 1
            if self.report.rows > MAX_INPUT_ROWS:
                raise ScanImportError(f"the file has more than {MAX_INPUT_ROWS:,} findings")
            self.item = {"attrs": dict(attrs), "cves": [], "v2": "", "v3": "", "compliance": False}
            self.item_depth = self.depth
        elif self.item is not None and self.depth == self.item_depth + 1:
            if name.startswith("cm:"):
                self.item["compliance"] = True
            if name in self.KEPT:
                self.child = name
                self.begin_text()

    def end(self, name):
        if self.tag is not None and name == "tag":
            self.host["tags"][self.tag] = self.take_text()
            self.tag = None
        elif self.child is not None and name == self.child and self.depth == self.item_depth + 1:
            text = self.take_text()
            if name == "cve":
                self.item["cves"] += [c for c in _cves(text) if c not in self.item["cves"]]
            else:
                self.item["v2" if name == "cvss_base_score" else "v3"] = text
            self.child = None
        elif name == "ReportItem" and self.item is not None and self.depth == self.item_depth:
            self.finish_item()
            self.item = None
        elif name == "ReportHost" and self.host is not None:
            self.finish_host()
            self.host = None
        self.depth -= 1

    def data(self, text):
        if self.text is not None and self.size < MAX_XML_TEXT_CHARS:
            self.text.append(text[:MAX_XML_TEXT_CHARS - self.size])
            self.size += len(text)

    def forbidden(self, *_args):
        raise ScanImportError("the file declares a DTD or an entity, which a Nessus export never does; it was refused")

    def begin_text(self):
        self.text, self.size = [], 0

    def take_text(self):
        text = "".join(self.text)
        self.text, self.size = None, 0
        return text

    # -- what a finished element means --
    def host_name(self):
        tags = self.host["tags"]
        return _cell(self.host["name"] or tags.get("host-ip", ""), MAX_ASSET_CHARS)

    def finish_item(self):
        report, item = self.report, self.item
        attrs = item["attrs"]
        if item["attrs"].get("severity", "").strip() == "0":
            report.skip("informational (no risk)")
            return
        if item["compliance"] or _norm(attrs.get("pluginFamily", "")) == "policy compliance":
            report.skip("compliance check (not a vulnerability)")
            return
        asset = self.host_name()
        if not asset:
            report.skip("no host or asset name")
            return
        plugin = _cell(attrs.get("pluginID", ""), 40)
        title = _cell(attrs.get("pluginName", ""), MAX_NAME_CHARS) or f"Plugin {plugin}"
        score = _score(item["v3"]) or _score(item["v2"])
        for cve in item["cves"] or [""]:
            ident = f"nessus:{plugin}:{asset}:{cve or 'nocve'}"[:MAX_ID_CHARS]
            self.findings.append(Finding(ident, asset, title, cve, score, "", NESSUS_XML))
            _check_size(self.findings)

    def finish_host(self):
        asset = self.host_name()
        if asset:
            tags = self.host["tags"]
            name = _cell(tags.get("host-fqdn") or tags.get("netbios-name", ""), MAX_NAME_CHARS)
            known = self.assets.setdefault(asset.lower(), Asset(asset))
            known.name = known.name or (name if name.lower() != asset.lower() else "")


def _text(value):
    """A value from a JSON record as text: numbers and booleans are written out, anything nested or missing is empty."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return value if isinstance(value, str) else ""


def _load_json(path):
    """Read a JSON file (size-limited; duplicate keys and NaN are refused); return the record list inside it."""
    name = os.path.basename(path)
    try:
        advice = " (a JSON export is read whole: export it in smaller pieces)"
        with _open_input(path, True, MAX_JSON_BYTES, advice) as fh:
            raw = fh.read(MAX_JSON_BYTES + 1)          # a file that grows after the check is still held to the limit
        if len(raw) > MAX_JSON_BYTES:
            raise ScanImportError(f"{name} is larger than {MAX_JSON_BYTES // (1024 * 1024)} MB{advice}")
        doc = json.loads(raw.decode("utf-8-sig"), parse_constant=threatdata._reject_constant,
                         object_pairs_hook=threatdata._reject_duplicates)
    except ScanImportError:
        raise
    except OSError as error:
        raise ScanImportError(f"{name} could not be read ({error.strerror or error})") from None
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise ScanImportError(f"{name} is not a valid JSON file") from None
    if isinstance(doc, dict):
        for key in JSON_LISTS:
            if isinstance(doc.get(key), list):
                return doc[key]
        raise ScanImportError(f"{name} has no list of records (looked for: {', '.join(JSON_LISTS)})")
    if isinstance(doc, list):
        return doc
    raise ScanImportError(f"{name} is not a list of records")


def detect_json(records):
    """Name the JSON export a list of records belongs to, or None."""
    for record in records[:20]:
        if not isinstance(record, dict):
            continue
        if isinstance(record.get("host"), dict) and isinstance(record.get("vulnerability"), dict):
            return DRAGOS
        if "cve" in record and ("node_label" in record or "asset_id" in record or "node_id" in record):
            return NOZOMI
    return None


def _nozomi_finding(record, report, assets):
    """One Nozomi node_cves record (from JSON or from a CSV row, with keys as in Nozomi's data model)."""
    def get(*names):
        for name in names:
            value = _text(record.get(name, "")).strip()
            if value:
                return value
        return ""

    if get("resolved").lower() in _TRUE:
        report.skip("already resolved")
        return None
    cves = _cves(get("cve"))
    if len(cves) != 1:
        report.skip("no CVE")
        return None
    asset = _cell(get("node_label", "assets_name", "asset_id", "node_id"), MAX_ASSET_CHARS)
    if not asset:
        report.skip("no node label or asset id")
        return None
    cve = cves[0]
    title = _cell(get("cve_summary"), MAX_NAME_CHARS) or f"{cve} on {asset}"
    patch = "available" if get("latest_hotfix", "minimum_hotfix") else ""
    ident = f"nozomi:{_cell(get('id'), 80) or cve + ':' + asset}"[:MAX_ID_CHARS]
    known = assets.setdefault(asset.lower(), Asset(asset))
    for attr, names in (("vendor", ("node_vendor",)), ("product", ("node_product_name",)),
                        ("version", ("node_firmware_version",))):
        if not getattr(known, attr):
            setattr(known, attr, _cell(get(*names), MAX_NAME_CHARS))
    return Finding(ident, asset, title, cve, _score(get("cve_score", "score")), patch, NOZOMI)


def _dragos_finding(record, report, assets):
    """One Dragos vulnerability detection: the host it was found on and the vulnerability."""
    host, vuln = record.get("host"), record.get("vulnerability")
    if not isinstance(host, dict) or not isinstance(vuln, dict):
        report.skip("not a detection (no host and vulnerability)")
        return None
    if _text(vuln.get("state")).strip().lower() in _CLOSED:
        report.skip("already resolved")
        return None
    asset = _cell(_text(host.get("name")) or _text(host.get("id")), MAX_ASSET_CHARS)
    if not asset:
        report.skip("no host name")
        return None
    cves = _cves(_text(vuln.get("enumeration"))) or _cves(_text(vuln.get("reference")))
    cve = cves[0] if cves else ""
    base = vuln.get("score")
    score = _score(_text(base.get("base"))) if isinstance(base, dict) else ""
    title = _cell(_text(vuln.get("title")), MAX_NAME_CHARS) or (f"{cve} on {asset}" if cve else "Dragos detection")
    ident = f"dragos:{_cell(_text(vuln.get('id')), 80) or (cve or 'nocve') + ':' + asset}"[:MAX_ID_CHARS]
    hardware = host.get("hardware") if isinstance(host.get("hardware"), dict) else {}
    known = assets.setdefault(asset.lower(), Asset(asset))
    for attr, value in (("vendor", host.get("vendor")), ("product", hardware.get("model")),
                        ("version", hardware.get("firmware_version"))):
        if not getattr(known, attr):
            setattr(known, attr, _cell(_text(value), MAX_NAME_CHARS))
    return Finding(ident, asset, title, cve, score, "", DRAGOS)


def _read_json_export(path):
    """Read a Nozomi or Dragos JSON export; return (findings, assets, FileReport)."""
    name = os.path.basename(path)
    records = _load_json(path)
    source = detect_json(records)
    if source is None:
        raise ScanImportError(f"{name} is not an export this tool knows (as JSON it reads Nozomi node_cves and "
                              "Dragos detections; the other formats are listed in docs/IMPORT.md)")
    report = FileReport(name, FORMAT_NAMES[source], note=EXPERIMENTAL_NOTE)
    convert = _nozomi_finding if source == NOZOMI else _dragos_finding
    findings, assets = [], {}
    for record in records:
        report.rows += 1
        if report.rows > MAX_INPUT_ROWS:
            raise ScanImportError(f"{name} has more than {MAX_INPUT_ROWS:,} records")
        if not isinstance(record, dict):
            report.skip("not a record")
            continue
        finding = convert({_norm(k).replace(" ", "_"): v for k, v in record.items()} if source == NOZOMI else record,
                          report, assets)
        if finding is not None:
            findings.append(finding)
            _check_size(findings)
    report.kept = len(findings)
    return findings, assets, report


def _read_nozomi_csv(table, report):
    """A CSV exported from a Nozomi query on node_cves: the columns are the fields of Nozomi's data model."""
    findings, assets = [], {}
    names = [h.replace(" ", "_") for h in table.header]
    for cells in table.rows():
        report.rows += 1
        record = {names[i]: cells[i] for i in range(min(len(names), len(cells)))}
        finding = _nozomi_finding(record, report, assets)
        if finding is not None:
            findings.append(finding)
            _check_size(findings)
    return findings, assets


def _first_bytes(path):
    with _open_input(path, True) as fh:
        return fh.read(1024)


def _looks_like_json(path):
    start = _first_bytes(path)
    return start.lstrip(b"\xef\xbb\xbf \t\r\n")[:1] in (b"{", b"[")


def _looks_like_xml(path):
    start = _first_bytes(path)
    if start[:2] in (b"\xff\xfe", b"\xfe\xff"):                      # UTF-16 with a byte order mark
        return start.decode("utf-16", errors="ignore").lstrip("\ufeff \t\r\n").startswith("<")
    return start.lstrip(b"\xef\xbb\xbf \t\r\n").startswith(b"<")


def _read_nessus_xml(path):
    """Read a Nessus v2 (.nessus) file; return (findings, assets, FileReport)."""
    name = os.path.basename(path)
    try:
        report = FileReport(name, FORMAT_NAMES[NESSUS_XML])
        reader = _NessusXml(report)
        parser = expat.ParserCreate()
        parser.buffer_text = True
        parser.StartElementHandler, parser.EndElementHandler = reader.start, reader.end
        parser.CharacterDataHandler = reader.data
        parser.StartDoctypeDeclHandler = parser.EntityDeclHandler = reader.forbidden
        parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
        with _open_input(path, True, MAX_FILE_BYTES) as fh:
            total = 0
            while True:
                chunk = fh.read(XML_CHUNK_BYTES)
                total += len(chunk)
                if total > MAX_FILE_BYTES:      # a file that grows while it is read is still held to the limit
                    raise ScanImportError(f"{name} is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB")
                parser.Parse(chunk, not chunk)
                if not chunk:
                    break
    except expat.ExpatError as error:
        raise ScanImportError(f"{name} is not a valid XML file ({expat.ErrorString(error.code)})") from None
    except OSError as error:
        raise ScanImportError(f"{name} could not be read ({error.strerror or error})") from None
    if reader.hosts == 0:
        raise ScanImportError(f"{name} has no ReportHost: it holds no scan results")
    report.kept = len(reader.findings)
    return reader.findings, reader.assets, report


def read_export(path, min_qod=DEFAULT_MIN_QOD, only_confirmed=False):
    """Read one export file; return (findings, assets, FileReport). Raises ScanImportError if it cannot be used."""
    if _looks_like_xml(path):
        return _read_nessus_xml(path)
    if _looks_like_json(path):
        return _read_json_export(path)
    table = _Table(path)
    try:
        source = detect_format(table.header)
        if source is None:
            names = ", ".join(FORMAT_NAMES.values())
            raise ScanImportError(f"{os.path.basename(path)} is not an export this tool knows (it reads: {names}). "
                                  f"The header starts: {', '.join(clean(h) for h in table.header[:6])[:150]}")
        report = FileReport(os.path.basename(path), FORMAT_NAMES[source])
        if source == OPENVAS:
            findings, assets = _read_openvas(table, report, min_qod)
        elif source == NOZOMI:
            report.note = EXPERIMENTAL_NOTE
            findings, assets = _read_nozomi_csv(table, report)
        elif source == CLAROTY:
            findings, assets = _read_claroty(table, report, only_confirmed)
        else:
            findings, assets = _read_tenable_family(table, report, source)
    finally:
        table.close()
    report.kept = len(findings)
    return findings, assets, report


# ---- aliases and merging ---------------------------------------------------------

def load_aliases(path):
    """Read an aliases file (columns alias and asset_id): {lower-case alias: asset id}."""
    table = _Table(path)
    try:
        if not table.has("alias") or not table.has("asset id"):
            raise ScanImportError(f"{os.path.basename(path)}: the aliases file needs an alias and an asset_id column")
        aliases = {}
        for cells in table.rows():
            alias = _cell(table.get(cells, "alias"), MAX_ASSET_CHARS)
            target = _cell(table.get(cells, "asset id"), MAX_ASSET_CHARS)
            if not alias or not target:
                continue
            if len(aliases) >= MAX_ALIASES:
                raise ScanImportError(f"{os.path.basename(path)} has more than {MAX_ALIASES:,} aliases")
            if alias.lower() in aliases and aliases[alias.lower()].lower() != target.lower():
                raise ScanImportError(f"{os.path.basename(path)}: '{alias}' is listed for two different assets")
            aliases[alias.lower()] = target
    finally:
        table.close()
    for alias, target in aliases.items():
        if target.lower() in aliases and aliases[target.lower()].lower() != target.lower():
            raise ScanImportError(f"The aliases file maps '{alias}' to '{target}', which is itself an alias "
                                  "(map every name straight to the asset id)")
    return aliases


def merge(result, aliases=None, default_threat=""):
    """Resolve aliases to one asset id, collapse the same finding reported twice, and count what needs a decision.

    A finding is the same when it has the same asset and CVE (or, with no CVE, the same asset and title). The highest
    score is kept, a patch status is kept if any report has one, and every source tool is listed.
    """
    if default_threat and default_threat not in THREAT_LEVELS:
        raise ScanImportError(f"default threat must be one of: {', '.join(THREAT_LEVELS)}")
    result = copy.deepcopy(result)          # the same reading can be merged again with other options
    aliases = aliases or {}
    resolved_assets, merged = {}, {}
    for finding in result.findings:
        target = aliases.get(finding.asset_id.lower(), finding.asset_id)
        if target != finding.asset_id:
            result.renamed += 1
            finding.asset_id = target
        key = (finding.asset_id.lower(), finding.cve.lower() or finding.name.lower())
        kept = merged.get(key)
        if kept is None:
            merged[key] = finding
            continue
        result.merged += 1
        if float(finding.cvss or 0) > float(kept.cvss or 0):
            kept.cvss = finding.cvss
        kept.patch = kept.patch or finding.patch
        sources = kept.source.split("+")
        if finding.source not in sources and len(sources) < MAX_SOURCES:
            kept.source = "+".join([*sources, finding.source])
    for key, asset in result.assets.items():
        target = aliases.get(key, asset.asset_id)
        known = resolved_assets.setdefault(target.lower(), Asset(target))
        for name in ("name", "vendor", "product", "version"):
            if getattr(asset, name) and not getattr(known, name):
                setattr(known, name, getattr(asset, name))
    for finding in merged.values():
        if not finding.cve:
            if default_threat:
                finding.threat = default_threat
            else:
                result.need_threat += 1
        if not finding.cvss:
            result.not_scored += 1
    result.findings = list(merged.values())
    result.assets = resolved_assets
    for finding in result.findings:                    # an asset that only appears in a finding still needs a row
        result.assets.setdefault(finding.asset_id.lower(), Asset(finding.asset_id))
    if len(result.findings) > MAX_FINDINGS:
        raise ScanImportError(f"The import has {len(result.findings):,} findings; OT Triage reads at most "
                              f"{MAX_FINDINGS:,}. Narrow the export (by severity or by site) and import again")
    return result


def read_exports(paths, min_qod=DEFAULT_MIN_QOD, only_confirmed=False):
    """Read several exports into one ImportResult that is not merged yet (see merge). Raises ScanImportError."""
    result = ImportResult()
    for path in paths:
        findings, assets, report = read_export(path, min_qod, only_confirmed)
        result.findings += findings
        _check_size(result.findings)
        result.reports.append(report)
        for key, asset in assets.items():
            known = result.assets.setdefault(key, asset)
            known.name = known.name or asset.name
    return result


def import_exports(paths, aliases=None, min_qod=DEFAULT_MIN_QOD, default_threat="", only_confirmed=False):
    """Read and merge several exports. Raises ScanImportError for a file that cannot be used."""
    return merge(read_exports(paths, min_qod, only_confirmed), aliases, default_threat)


# ---- writing ---------------------------------------------------------------------

def write_atomically(path, write):
    """Run write(temporary_path) and move the result into place, so a failure never leaves a half-written file."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, temp = tempfile.mkstemp(dir=directory, prefix=".ot-triage-", suffix=".part")
    os.close(fd)
    try:
        write(temp)
        os.replace(temp, path)
    except BaseException:
        try:
            os.remove(temp)
        except OSError:
            pass
        raise


def _safe(text):
    text = str(text)
    return "'" + text if text and text[0] in _FORMULA_START else text


def write_findings(path, result):
    """Write the findings as a CSV OT Triage can rank (formula-safe). A threat column is added only if a row has one."""
    columns = list(FINDING_COLUMNS)
    if any(f.threat for f in result.findings):
        columns.insert(columns.index("source_tool"), "threat")
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(columns)
        for f in result.findings:
            values = {"id": f.id, "asset_id": f.asset_id, "name": f.name, "cve": f.cve, "cvss": f.cvss,
                      "patch": f.patch, "source_tool": f.source, "threat": f.threat}
            writer.writerow([_safe(values[c]) for c in columns])


def write_inventory(path, result, existing=None):
    """Write an inventory: the existing one unchanged plus a row for each new asset, blanks filled in from the scan.

    Existing rows keep every column and value; a blank vendor, product, version or name is filled in from the scanner,
    and a value that is there is never replaced. New assets get empty criticality, exposure and controls, which only a
    person can fill in. Returns (new asset count, existing assets updated).
    """
    header, rows = list(NEW_INVENTORY_COLUMNS), []
    if existing:
        header, rows = _read_raw_inventory(existing)
    canonical = {inventory.canonical_header(h): i for i, h in enumerate(header)}
    if "asset_id" not in canonical:
        raise ScanImportError("The existing inventory needs an asset_id column")
    wanted = [c for c in ("name", "vendor", "product", "version") if any(getattr(a, c) for a in result.assets.values())]
    for column in wanted:
        if column not in canonical:
            header.append(column)
            canonical[column] = len(header) - 1
    by_id = {inventory.normalize_key(r[canonical["asset_id"]]): r for r in rows if len(r) > canonical["asset_id"]}
    new, updated = 0, 0
    for asset in result.assets.values():
        row = by_id.get(inventory.normalize_key(asset.asset_id))
        if row is None:
            row = [""] * len(header)
            row[canonical["asset_id"]] = asset.asset_id
            rows.append(row)
            by_id[inventory.normalize_key(asset.asset_id)] = row
            new += 1
            fresh = True
        else:
            fresh = False
        row.extend([""] * (len(header) - len(row)))
        touched = False
        for column in wanted:
            value = getattr(asset, column)
            if value and not row[canonical[column]].strip():
                row[canonical[column]] = value
                touched = touched or not fresh
        updated += touched
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow([_safe(c) for c in header])         # the header is the person's own text, so it is defused too
        for row in rows:
            writer.writerow([_safe(c) for c in row])
    return new, updated


def _read_raw_inventory(path):
    """The header cells exactly as written, and the data rows, of an existing inventory."""
    header = _original_header(path)
    table = _Table(path)
    try:
        rows = [list(cells) for cells in table.rows()]
    finally:
        table.close()
    return header, rows


def _original_header(path):
    """The header cells exactly as written (the table keeps only normalised names)."""
    saved = csv.field_size_limit(MAX_FIELD_BYTES)
    try:
        with _open_input(path, False, None, newline="", encoding="utf-8-sig") as fh:
            return next(csv.reader(fh))
    finally:
        csv.field_size_limit(saved)


def _n(count, one, many):
    return f"{count:,} {one if count == 1 else many}"


def summary_lines(result, min_qod=DEFAULT_MIN_QOD):
    """What the import did, one line each, for the person."""
    lines = []
    for report in result.reports:
        lines.append(f"{report.path}: {report.format}, {report.rows:,} rows, {report.kept:,} findings kept")
        if report.note:
            lines.append(f"  note: {report.note}")
        for reason, count in sorted(report.skipped.items()):
            lines.append(f"  skipped {count:,}: {reason}")
    if result.renamed:
        lines.append(f"{_n(result.renamed, 'finding', 'findings')} moved to their asset id through the aliases file")
    if result.merged:
        lines.append(f"{_n(result.merged, 'finding', 'findings')} reported more than once merged into another")
    lines.append(f"{_n(len(result.findings), 'finding', 'findings')} on {_n(len(result.assets), 'asset', 'assets')}")
    if result.not_scored:
        lines.append(f"{_n(result.not_scored, 'finding has', 'findings have')} no score in the export: OT Triage shows "
                     "them as not scored")
    if result.need_threat:
        lines.append(f"{_n(result.need_threat, 'finding has', 'findings have')} no CVE, so a threat level is needed: "
                     "add a threat column or import with --default-threat")
    # file names come from the person's disk: whatever shows them (a window or a terminal) gets clean text
    return [" " * (len(line) - len(line.lstrip())) + clean(line) for line in lines]
