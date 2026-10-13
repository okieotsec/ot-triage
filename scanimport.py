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
import csv
import os
import re
from dataclasses import dataclass, field

import inventory
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

NESSUS, TENABLE_VM, OPENVAS = "nessus", "tenable-vm", "openvas"
ID_PREFIX = {NESSUS: "nessus", TENABLE_VM: "tenable"}      # finding ids start with the tool, then plugin, asset, CVE
FORMAT_NAMES = {NESSUS: "Nessus CSV", TENABLE_VM: "Tenable Vulnerability Management CSV",
                OPENVAS: "OpenVAS / Greenbone CSV"}


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
    found = []
    for match in CVE_RE.findall(str(text or "")):
        cve = match.upper()
        if cve not in found:
            found.append(cve)
    return found


# ---- reading -------------------------------------------------------------------

class _Table:
    """A CSV export read row by row, with its columns found by name (never by position)."""

    def __init__(self, path):
        self.path = path
        try:
            if os.path.getsize(path) > MAX_FILE_BYTES:
                raise ScanImportError(f"{os.path.basename(path)} is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB")
            self._fh = open(path, newline="", encoding="utf-8-sig")  # noqa: SIM115 - closed in close()
        except OSError as error:
            raise ScanImportError(f"{os.path.basename(path)} could not be read ({error.strerror or error})") from None
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
    return None


_V3 = ("cvss v3.0 base score", "cvss v3 base score", "cvss3 base score", "cvssv3 base score", "cvss3 score")
_V2 = ("cvss v2.0 base score", "cvss v2 base score", "cvss", "cvss base score", "cvssv2 base score", "cvss score")
_SKIP_RISK = {"none", "info", "informational"}
_SKIP_STATE = {"fixed", "resolved", "remediated", "closed"}


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


def _check_size(findings):
    if len(findings) > MAX_RAW_FINDINGS:
        raise ScanImportError(f"The export has more than {MAX_RAW_FINDINGS:,} findings; OT Triage reads at most "
                              f"{MAX_FINDINGS:,}. Narrow the export (by severity or by site) and import again")


def _score_int(text):
    try:
        return int(float(str(text).strip()))
    except ValueError:
        return None


def read_export(path, min_qod=DEFAULT_MIN_QOD):
    """Read one export file; return (findings, assets, FileReport). Raises ScanImportError if it cannot be used."""
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


def import_exports(paths, aliases=None, min_qod=DEFAULT_MIN_QOD, default_threat=""):
    """Read and merge several exports. Raises ScanImportError for a file that cannot be used."""
    if default_threat and default_threat not in THREAT_LEVELS:
        raise ScanImportError(f"default threat must be one of: {', '.join(THREAT_LEVELS)}")
    result = ImportResult()
    for path in paths:
        findings, assets, report = read_export(path, min_qod)
        result.findings += findings
        _check_size(result.findings)
        result.reports.append(report)
        for key, asset in assets.items():
            known = result.assets.setdefault(key, asset)
            known.name = known.name or asset.name
    return merge(result, aliases, default_threat)


# ---- writing ---------------------------------------------------------------------

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
        writer.writerow(header)
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
        with open(path, newline="", encoding="utf-8-sig") as fh:
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
    return lines
