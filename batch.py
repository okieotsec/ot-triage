"""Batch scoring of vulnerabilities from a CSV file (no GUI dependencies).

Required columns: cvss, threat, asset, exposure
Optional columns: id, name, patch (default: available), controls (default: none)
Extra columns are ignored. Enum cells accept short aliases or the full dropdown labels.
"""
import csv
from dataclasses import dataclass, field

from prioritizer import (Asset, Controls, Exposure, NEVER, NEXT, NOW, Patch, Result, Threat,
                         parse_cvss, prioritize)

REQUIRED = ["cvss", "threat", "asset", "exposure"]
DEFAULTS = {"patch": Patch.AVAILABLE, "controls": Controls.NONE}
FIELD_ENUMS = {"threat": Threat, "asset": Asset, "exposure": Exposure, "patch": Patch, "controls": Controls}

_HEADER_ALIASES = {
    "cvss_score": "cvss", "cvss_base_score": "cvss", "base_score": "cvss",
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
    line: int
    id: str = ""
    name: str = ""
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
    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.reader(fh)
        try:
            header = next(reader)
        except StopIteration:
            raise ValueError("The file is empty") from None
        columns = [_norm_header(h) for h in header]
        missing = [c for c in REQUIRED if c not in columns]
        if missing:
            raise ValueError(f"Missing required column(s): {', '.join(missing)}. "
                             f"Found: {', '.join(h.strip() for h in header)}")
        rows = []
        for cells in reader:
            if not any(c.strip() for c in cells):
                continue
            row = {col: (cells[i].strip() if i < len(cells) else "") for i, col in enumerate(columns)}
            rows.append((reader.line_num, row))
        return rows


def score_row(line, row):
    item = BatchItem(line=line, id=row.get("id", ""), name=row.get("name", ""), cvss_raw=row.get("cvss", ""))
    errors = []
    try:
        item.cvss = parse_cvss(item.cvss_raw)
    except ValueError as e:
        errors.append(f"cvss: {e}")
    for field_name in FIELD_ENUMS:
        try:
            item.inputs[field_name] = _parse_enum(field_name, row.get(field_name, ""))
        except ValueError as e:
            errors.append(str(e))
    if errors:
        item.error = "; ".join(errors)
        return item
    item.result = prioritize(item.cvss, item.inputs["threat"], item.inputs["asset"], item.inputs["exposure"],
                             item.inputs["controls"], item.inputs["patch"])
    return item


_BUCKET = {NOW: 0, NEXT: 1, NEVER: 2}


def sort_items(items):
    ok = [i for i in items if i.result]
    bad = [i for i in items if not i.result]
    ok.sort(key=lambda i: (_BUCKET[i.result.priority], -i.result.score, -i.cvss, i.line))
    bad.sort(key=lambda i: i.line)
    return ok + bad


def process_file(path):
    return sort_items([score_row(line, row) for line, row in read_rows(path)])


def summarize(items):
    counts = {NOW: 0, NEXT: 0, NEVER: 0, "ERROR": 0}
    for i in items:
        counts[i.priority] += 1
    return counts


def _safe(text):
    """Neutralize spreadsheet formula injection in user-supplied text."""
    text = str(text)
    return "'" + text if text and text[0] in "=+-@\t\r" else text


OUTPUT_COLUMNS = ["rank", "id", "name", "priority", "ordering_score", "cvss", "threat", "asset",
                  "exposure", "patch", "controls", "action", "rationale", "error", "source_line"]


def write_results(path, items):
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()
        rank = 0
        for item in items:
            row = {"id": _safe(item.id), "name": _safe(item.name), "priority": item.priority,
                   "source_line": item.line}
            if item.result:
                rank += 1
                row.update(
                    rank=rank, ordering_score=f"{item.result.score:.2f}", cvss=f"{item.cvss:.1f}",
                    action=item.result.action, rationale=" | ".join(item.result.reasons),
                    **{k: item.inputs[k].value for k in FIELD_ENUMS},
                )
            else:
                row.update(cvss=_safe(item.cvss_raw), error=_safe(item.error))
            writer.writerow(row)
