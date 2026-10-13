"""Asset inventory: a CSV that supplies each asset's criticality, exposure and controls to the findings (no GUI).

The inventory is untrusted input, like every file the tool reads: it is size-limited, bad rows are skipped and reported
(never guessed at), and an asset that appears twice is never used, because there is no safe way to choose between the
two entries.
"""
import csv
import os
from dataclasses import dataclass, field

import batch
from references import clean

MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_ASSETS = 20_000
MAX_KEY_CHARS = 100
MAX_NAME_CHARS = 200
MAX_PROBLEMS = 20
FIELDS = ("asset", "exposure", "controls")
# Optional per-asset security requirements (used only for the CVSS environmental score): column -> CVSS metric.
REQUIREMENT_COLUMNS = {"confidentiality": "CR", "integrity": "IR", "availability": "AR"}
# Optional free text, used only to point at CISA ICS advisories that may apply to the asset (never for scoring)
TEXT_COLUMNS = ("vendor", "product", "version")
MAX_TEXT_CHARS = 100
_REQUIREMENT_WORDS = {"l": "L", "low": "L", "m": "M", "med": "M", "medium": "M", "h": "H", "high": "H"}
_NOT_SET = {"", "x", "not defined", "n/a", "na", "unset", "not set"}
_KEY_ALIASES = {"assetid": "asset_id", "asset_tag": "asset_id", "id": "asset_id", "asset_name": "name",
                "cr": "confidentiality", "confidentiality_requirement": "confidentiality",
                "ir": "integrity", "integrity_requirement": "integrity",
                "ar": "availability", "availability_requirement": "availability",
                "manufacturer": "vendor", "make": "vendor", "model": "product", "product_name": "product",
                "firmware": "version", "firmware_version": "version", "fw_version": "version",
                "software_version": "version", "sw_version": "version"}


def normalize_key(text):
    """Return the form of an asset id that is used for matching: no stray white space, ignoring letter case."""
    return clean(str(text)).casefold()


def _header(name):
    key = batch._norm_header(name)
    return _KEY_ALIASES.get(key, key)


def canonical_header(name):
    """The name a column of an inventory is known by once its aliases are resolved (for example model -> product)."""
    return _header(name)


@dataclass(frozen=True)
class AssetRecord:
    """One asset: its id, an optional name, and the values the inventory states for it (blank cells are left out)."""

    asset_id: str
    name: str
    values: dict
    line: int
    requirements: dict = field(default_factory=dict)     # {"CR": "H", ...} the CVSS security requirements stated
    vendor: str = ""                                     # who makes the asset, as the inventory writes it
    product: str = ""                                    # what the asset is called, as the inventory writes it
    version: str = ""                                    # the firmware or software version, as the inventory writes it


@dataclass
class Inventory:
    """A loaded inventory and what was wrong with it."""

    label: str
    records: dict = field(default_factory=dict)       # normalized asset id -> AssetRecord
    duplicates: frozenset = frozenset()               # normalized ids that appear more than once (never used)
    problems: list = field(default_factory=list)      # readable messages about skipped rows, at most MAX_PROBLEMS
    skipped: int = 0

    def __len__(self):
        return len(self.records)

    def lookup(self, asset_id):
        """Return ("found", record), ("duplicate", None) or ("missing", None) for an asset id."""
        key = normalize_key(asset_id)
        if key in self.duplicates:
            return "duplicate", None
        record = self.records.get(key)
        return ("found", record) if record is not None else ("missing", None)

    def summary(self):
        """Return a one-line description for the interface."""
        text = f"{self.label} · {len(self):,} asset{'s' if len(self) != 1 else ''}"
        if self.duplicates:
            text += f" · {len(self.duplicates)} duplicated id{'s' if len(self.duplicates) != 1 else ''} not used"
        if self.skipped:
            text += f" · {self.skipped} row{'s' if self.skipped != 1 else ''} skipped"
        return text


def load(path):
    """Read an inventory CSV; raise ValueError (with a message for the person) if the file cannot be used at all."""
    try:
        return _load(path)
    except csv.Error as error:  # for example a single cell larger than the CSV reader's field limit
        raise ValueError(f"The inventory is not a valid CSV file ({str(error)[:100]})") from None
    except UnicodeDecodeError:
        raise ValueError("The inventory is not a UTF-8 text file (save it as 'CSV UTF-8' from your spreadsheet)") \
            from None


def _load(path):
    if os.path.getsize(path) > MAX_FILE_BYTES:
        raise ValueError(f"The inventory is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB")
    inventory = Inventory(label=clean(os.path.basename(str(path)))[:60])
    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.reader(fh)
        try:
            header = next(reader)
        except StopIteration:
            raise ValueError("The inventory file is empty") from None
        columns = [_header(h) for h in header]
        repeated = sorted({c for c in columns if c and columns.count(c) > 1})
        if repeated:
            raise ValueError(f"Duplicate column(s) in the inventory: {', '.join(repeated)}")
        if "asset_id" not in columns or not any(f in columns for f in (*FIELDS, *REQUIREMENT_COLUMNS, *TEXT_COLUMNS)):
            raise ValueError("The inventory needs an asset_id column and at least one of: asset (or criticality), "
                             "exposure, controls, confidentiality, integrity, availability, vendor, product, version. "
                             f"Found: {', '.join(clean(h) for h in header)[:200]}")
        seen = {}
        count = 0
        for cells in reader:
            if not any(c.strip() for c in cells):
                continue
            count += 1
            if count > MAX_ASSETS:
                raise ValueError(f"The inventory has more than {MAX_ASSETS:,} rows")
            row = {col: (cells[i] if i < len(cells) else "") for i, col in enumerate(columns)}
            _add_row(inventory, seen, reader.line_num, row)
    for key, lines in seen.items():
        if len(lines) > 1:
            inventory.duplicates |= {key}
            inventory.records.pop(key, None)
            _problem(inventory, f"asset_id {key[:MAX_KEY_CHARS]!r} appears {len(lines)} times (lines "
                                f"{', '.join(map(str, lines[:6]))}); findings that use it are not filled in",
                     row_skipped=False)
    return inventory


def _problem(inventory, message, row_skipped=True):
    inventory.skipped += 1 if row_skipped else 0
    if len(inventory.problems) < MAX_PROBLEMS:
        inventory.problems.append(message)


def _add_row(inventory, seen, line, row):
    asset_id = clean(row.get("asset_id", ""))
    if not asset_id:
        _problem(inventory, f"line {line}: asset_id is empty, so the row was skipped")
        return
    if len(asset_id) > MAX_KEY_CHARS:
        _problem(inventory, f"line {line}: asset_id is longer than {MAX_KEY_CHARS} characters, so the row was skipped")
        return
    values = {}
    for name in FIELDS:
        text = row.get(name, "").strip()
        if not text:
            continue
        try:
            values[name] = batch._parse_enum(name, text)
        except ValueError as error:
            _problem(inventory, f"line {line}: {str(error)[:160]}, so the row was skipped")
            return
    requirements = {}
    for column, metric in REQUIREMENT_COLUMNS.items():
        text = batch._norm(row.get(column, ""))
        if text in _NOT_SET:
            continue
        if text not in _REQUIREMENT_WORDS:
            _problem(inventory, f"line {line}: {column}: unrecognized value {clean(row.get(column, ''))[:30]!r} "
                                "(use low, medium or high), so the row was skipped")
            return
        requirements[metric] = _REQUIREMENT_WORDS[text]
    key = normalize_key(asset_id)
    seen.setdefault(key, []).append(line)
    vendor, product, version = (clean(row.get(name, ""))[:MAX_TEXT_CHARS] for name in TEXT_COLUMNS)
    inventory.records[key] = AssetRecord(asset_id, clean(row.get("name", ""))[:MAX_NAME_CHARS], values, line,
                                         requirements, vendor, product, version)
