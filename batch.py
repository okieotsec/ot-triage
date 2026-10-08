"""Batch scoring of vulnerabilities from a CSV file (no GUI dependencies)."""
import csv
import os
from dataclasses import dataclass, field

import cvss
from prioritizer import (Asset, Controls, Exposure, NEVER, NEXT, NOW, Patch, Result, Threat,
                         parse_cvss, prioritize)
from settings import DEFAULT_SETTINGS
from threatdata import apply_threat_context, derive_threat, normalize_cve

MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_ROWS = 50_000
REQUIRED = ["asset", "exposure"]
MAX_ERROR_VECTOR_CHARS = 200
SCORE_TOLERANCE = 0.001
DEFAULTS = {"patch": Patch.AVAILABLE, "controls": Controls.NONE}
FIELD_ENUMS = {"threat": Threat, "asset": Asset, "exposure": Exposure, "patch": Patch, "controls": Controls}

_HEADER_ALIASES = {
    "cvss_score": "cvss", "cvss_base_score": "cvss", "base_score": "cvss",
    "vector": "cvss_vector", "cvss_vector_string": "cvss_vector",
    "threat_status": "threat", "threat_intel": "threat",
    "asset_criticality": "asset", "criticality": "asset",
    "network_exposure": "exposure",
    "patch_status": "patch",
    "compensating_controls": "controls", "mitigations": "controls",
    "vulnerability": "name",
}

_VALUE_ALIASES = {
    Threat: {"active": Threat.ACTIVE, "exploited": Threat.ACTIVE, "kev": Threat.ACTIVE,
             "public": Threat.PUBLIC, "poc": Threat.PUBLIC,
             "none": Threat.NONE, "no": Threat.NONE},
    Asset: {"crown": Asset.CROWN, "crown jewel": Asset.CROWN, "critical": Asset.CROWN,
            "important": Asset.IMPORTANT, "standard": Asset.STANDARD},
    Exposure: {"high": Exposure.HIGH, "internet": Exposure.HIGH,
               "medium": Exposure.MEDIUM, "low": Exposure.LOW},
    Patch: {"available": Patch.AVAILABLE, "yes": Patch.AVAILABLE, "pending": Patch.PENDING,
            "eol": Patch.EOL, "end of life": Patch.EOL, "unsupported": Patch.EOL},
    Controls: {"none": Controls.NONE, "no": Controls.NONE, "partial": Controls.PARTIAL,
               "strong": Controls.STRONG},
}


def _norm(text):
    return " ".join(str(text).strip().lower().replace("_", " ").replace("-", " ").split())


def _lookup(enum_cls):
    table = {_norm(m.name): m for m in enum_cls}
    table.update({_norm(m.value): m for m in enum_cls})
    table.update({_norm(k): v for k, v in _VALUE_ALIASES[enum_cls].items()})
    return table


_LOOKUPS = {cls: _lookup(cls) for cls in FIELD_ENUMS.values()}


def _parse_enum(field_name, text):
    cls = FIELD_ENUMS[field_name]
    if not text.strip():
        if field_name in DEFAULTS:
            return DEFAULTS[field_name]
        raise ValueError(f"{field_name}: value is required")
    try:
        return _LOOKUPS[cls][_norm(text)]
    except KeyError:
        options = ", ".join(sorted({k for k in _VALUE_ALIASES[cls]}))
        raise ValueError(f"{field_name}: unrecognized value {text.strip()!r} (try: {options})") from None


@dataclass
class BatchItem:
    """One CSV row with its parsed inputs and result or error."""
    line: int
    id: str = ""
    name: str = ""
    cve: str = ""
    cvss_vector: str = ""
    cvss_version: str = ""
    threat_sources: str = ""
    cvss_raw: str = ""
    inputs: dict = field(default_factory=dict)   # field -> enum member, for successfully parsed cells
    cvss: float = None
    result: Result = None
    error: str = ""

    @property
    def priority(self):
        return self.result.priority if self.result else "ERROR"


def _norm_header(name):
    key = _norm(name).replace(" ", "_")
    return _HEADER_ALIASES.get(key, key)


def read_rows(path):
    """Return [(line_number, {normalized_header: stripped_value})], skipping fully blank rows."""
    if os.path.getsize(path) > MAX_FILE_BYTES:
        raise ValueError(f"The file is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB")
    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.reader(fh)
        try:
            header = next(reader)
        except StopIteration:
            raise ValueError("The file is empty") from None
        columns = [_norm_header(h) for h in header]
        duplicates = sorted({c for c in columns if c and columns.count(c) > 1})
        if duplicates:
            raise ValueError(f"Duplicate column(s): {', '.join(duplicates)}")
        missing = []
        if "cvss" not in columns and "cvss_vector" not in columns:
            missing.append("cvss (or cvss_vector)")
        if "threat" not in columns and "cve" not in columns:
            missing.append("threat (or cve)")
        missing += [c for c in REQUIRED if c not in columns]
        if missing:
            raise ValueError(f"Missing required column(s): {', '.join(missing)}. "
                             f"Found: {', '.join(h.strip() for h in header)}")
        rows = []
        for cells in reader:
            if not any(c.strip() for c in cells):
                continue
            row = {col: (cells[i].strip() if i < len(cells) else "") for i, col in enumerate(columns)}
            rows.append((reader.line_num, row))
            if len(rows) > MAX_ROWS:
                raise ValueError(f"The file has more than {MAX_ROWS:,} data rows")
        return rows


def has_cve_column(path):
    """Return True if the CSV file has a cve column."""
    with open(path, newline="", encoding="utf-8-sig") as fh:
        header = next(csv.reader(fh), [])
    return "cve" in [_norm_header(h) for h in header]


def _read_cvss(item, vector_text, errors):
    """Set the item's CVSS score from the cvss column, the cvss_vector column, or both (which must agree)."""
    vector_text = vector_text.strip()
    if not vector_text:
        try:
            item.cvss = parse_cvss(item.cvss_raw)
        except ValueError as e:
            errors.append(f"cvss: {e}")
        return
    try:
        parsed = cvss.parse_vector(vector_text)
    except ValueError as e:
        item.cvss_vector = vector_text[:MAX_ERROR_VECTOR_CHARS]
        errors.append(f"cvss_vector: {e}")
        return
    item.cvss_vector, item.cvss_version, score = parsed.normalized, parsed.version, parsed.score
    if item.cvss_raw.strip():
        try:
            typed = parse_cvss(item.cvss_raw)
        except ValueError as e:
            errors.append(f"cvss: {e}")
            return
        if abs(typed - score) > SCORE_TOLERANCE:
            errors.append(f"cvss ({item.cvss_raw.strip()[:12]}) does not match the base score of cvss_vector "
                          f"({score:.1f})")
            return
    item.cvss_raw = f"{score:.1f}"
    item.cvss = score


def score_row(line, row, settings=DEFAULT_SETTINGS, threatdata=None):
    """Parse one normalized row and score it, recording any errors on the item."""
    item = BatchItem(line=line, id=row.get("id", ""), name=row.get("name", ""), cvss_raw=row.get("cvss", ""))
    errors, info, cve_valid = [], None, False
    if row.get("cve"):
        try:
            item.cve = normalize_cve(row["cve"])
            cve_valid = True
            info = threatdata.lookup(item.cve) if threatdata is not None else None
        except ValueError as e:
            item.cve = row["cve"]
            errors.append(f"cve: {e}")
    if info is not None and not (info.kev_loaded or info.epss_loaded):
        info = None
    _read_cvss(item, row.get("cvss_vector", ""), errors)
    manual = None
    if row.get("threat", "").strip():
        try:
            manual = _parse_enum("threat", row["threat"])
        except ValueError as e:
            errors.append(str(e))
    elif info is None:
        hint = " (no threat data loaded for the cve column)" if cve_valid else ""
        errors.append(f"threat: value is required{hint}")
    for field_name in FIELD_ENUMS:
        if field_name == "threat":
            continue
        try:
            item.inputs[field_name] = _parse_enum(field_name, row.get(field_name, ""))
        except ValueError as e:
            errors.append(str(e))
    if errors:
        item.error = "; ".join(errors)
        return item
    decision = None
    if info is not None:
        decision = derive_threat(info, settings, analyst_confirmed=manual is Threat.ACTIVE,
                                 public_exploit=manual is Threat.PUBLIC)
        item.inputs["threat"] = decision.level
        item.threat_sources = "; ".join(decision.sources)
    else:
        item.inputs["threat"] = manual
        item.threat_sources = "Manual (threat column)"
    item.result = prioritize(item.cvss, item.inputs["threat"], item.inputs["asset"], item.inputs["exposure"],
                             item.inputs["controls"], item.inputs["patch"], settings)
    if decision is not None:
        item.result = apply_threat_context(item.result, decision, info)
    return item


_BUCKET = {NOW: 0, NEXT: 1, NEVER: 2}


def sort_items(items):
    """Order items by bucket, then ordering score, then CVSS, with errors last."""
    ok = [i for i in items if i.result]
    bad = [i for i in items if not i.result]
    ok.sort(key=lambda i: (_BUCKET[i.result.priority], -i.result.score, -i.cvss, i.line))
    bad.sort(key=lambda i: i.line)
    return ok + bad


def process_file(path, settings=DEFAULT_SETTINGS, threatdata=None):
    """Read a CSV file and return its scored rows in ranked order."""
    return sort_items([score_row(line, row, settings, threatdata) for line, row in read_rows(path)])


def summarize(items):
    """Count items per priority bucket and errors."""
    counts = {NOW: 0, NEXT: 0, NEVER: 0, "ERROR": 0}
    for i in items:
        counts[i.priority] += 1
    return counts


def _safe(text):
    """Neutralize spreadsheet formula injection in user-supplied text."""
    text = str(text)
    return "'" + text if text and text[0] in "=+-@\t\r" else text


OUTPUT_COLUMNS = ["rank", "id", "cve", "name", "priority", "ordering_score", "cvss", "cvss_version", "cvss_vector",
                  "threat", "asset",
                  "exposure", "patch", "controls", "action", "rationale", "threat_source", "threat_data",
                  "scoring_settings", "error", "source_line"]


def write_results(path, items, threatdata=None):
    """Write ranked results to a CSV file with formula-safe text cells."""
    data_versions = threatdata.versions() if threatdata is not None else ""
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()
        rank = 0
        for item in items:
            row = {"id": _safe(item.id), "cve": _safe(item.cve), "name": _safe(item.name),
                   "priority": item.priority, "source_line": item.line, "cvss_version": item.cvss_version,
                   "cvss_vector": _safe(item.cvss_vector)}
            if item.result:
                rank += 1
                row.update(
                    rank=rank, ordering_score=f"{item.result.score:.2f}", cvss=f"{item.cvss:.1f}",
                    action=_safe(item.result.action), rationale=_safe(" | ".join(item.result.reasons)),
                    threat_source=_safe(item.threat_sources), threat_data=_safe(data_versions),
                    scoring_settings=item.result.profile,
                    **{k: item.inputs[k].value for k in FIELD_ENUMS},
                )
            else:
                row.update(cvss=_safe(item.cvss_raw), error=_safe(item.error))
            writer.writerow(row)
