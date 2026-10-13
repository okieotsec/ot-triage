"""Compare scored findings with a previous ranked export: what is new, what moved, what was resolved (no GUI).

The previous export is an ordinary CSV that the person chose, so it is untrusted like every file the tool reads: it
is size-limited, bad rows are skipped and counted, and a finding that cannot be matched with certainty is reported
as ambiguous instead of being guessed at.
"""
import csv
import os
from dataclasses import dataclass, field

import explain
from prioritizer import NEVER, NEXT, NOW
from references import clean

MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_ROWS = 50_000
MAX_CELL_CHARS = 300
PRIORITIES = (NOW, NEXT, NEVER, "ERROR")
NEW, UP, DOWN, SAME, UNSCORED, AMBIGUOUS = "new", "up", "down", "same", "unscored", "ambiguous"
KINDS = (NEW, UP, DOWN, SAME, UNSCORED, AMBIGUOUS)
_FORMULA_START = "=+-@\t\r"


class CompareError(ValueError):
    """A previous export that cannot be used, with a message for the person."""


@dataclass(frozen=True)
class PreviousRow:
    """One row of the previous export."""

    line: int
    id: str
    cve: str
    asset_id: str
    name: str
    priority: str
    score: float = None

    @property
    def label(self):
        """A short name for the row, like the one shown for a current finding."""
        return " · ".join(part for part in (self.id, self.cve, self.name) if part) or f"line {self.line}"


@dataclass(frozen=True)
class Change:
    """How one current finding differs from the previous export."""

    kind: str
    previous: PreviousRow = None

    @property
    def text(self):
        """The change in words, for the table and the details."""
        if self.kind == NEW:
            return "New"
        if self.kind == AMBIGUOUS:
            return "Could not match"
        if self.previous is None:
            return ""
        was = self.previous.priority
        return {UP: f"Up from {was}", DOWN: f"Down from {was}", SAME: "Same", UNSCORED: "Not comparable"}[self.kind]


@dataclass
class Comparison:
    """The result of comparing a batch with a previous export."""

    label: str
    changes: dict = field(default_factory=dict)       # id(item) -> Change
    resolved: tuple = ()                              # previous rows with no current counterpart
    skipped: int = 0                                  # previous rows that could not be read
    previous_rows: int = 0

    def counts(self):
        """How many current findings fall into each kind of change, plus how many were resolved."""
        found = dict.fromkeys(KINDS, 0)
        for change in self.changes.values():
            found[change.kind] += 1
        found["resolved"] = len(self.resolved)
        return found

    def summary(self):
        """One line describing the comparison."""
        counts = self.counts()
        parts = [f"{counts[NEW]} new", f"{counts[UP]} moved up", f"{counts[DOWN]} moved down",
                 f"{counts['resolved']} resolved"]
        if counts[AMBIGUOUS]:
            parts.append(f"{counts[AMBIGUOUS]} could not be matched")
        return f"Compared with {self.label}: " + ", ".join(parts)


def _unprotect(cell):
    """Undo the quote the export puts in front of a cell that could run as a formula, so keys still match."""
    if len(cell) > 1 and cell[0] == "'" and cell[1] in _FORMULA_START:
        return cell[1:]
    return cell


def _cell(row, name):
    return clean(_unprotect(row.get(name) or ""))[:MAX_CELL_CHARS]


def _score(text):
    """An ordering score from a cell, or None if it is blank, not a number, or outside 0 to 10."""
    try:
        score = float((text or "").strip())
    except ValueError:
        return None
    return score if 0.0 <= score <= 10.0 else None


def load_previous(path):
    """Read a previous ranked export. Return (rows, skipped); raise CompareError if it cannot be used at all."""
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            raise CompareError(f"The previous export is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB")
        with open(path, newline="", encoding="utf-8-sig") as fh:
            reader = csv.DictReader(fh)
            names = [(n or "").strip().lower() for n in (reader.fieldnames or [])]
            if "priority" not in names or not {"id", "cve", "name"} & set(names):
                raise CompareError("The previous export needs a 'priority' column and at least one of id, cve or "
                                   "name (use a file saved with Export ranked CSV)")
            reader.fieldnames = names
            rows, skipped = [], 0
            for row in reader:
                if not any((v or "").strip() for v in row.values() if isinstance(v, str)):
                    continue
                if len(rows) + skipped >= MAX_ROWS:
                    raise CompareError(f"The previous export has more than {MAX_ROWS:,} rows")
                priority = _cell(row, "priority").upper()
                if priority not in PRIORITIES:
                    skipped += 1
                    continue
                score = _score(row.get("ordering_score"))
                rows.append(PreviousRow(reader.line_num, _cell(row, "id"), _cell(row, "cve").upper(),
                                        _cell(row, "asset_id"), _cell(row, "name"), priority, score))
    except UnicodeDecodeError:
        raise CompareError("The previous export is not a UTF-8 text file") from None
    except csv.Error as error:
        raise CompareError(f"The previous export is not a valid CSV file ({str(error)[:100]})") from None
    except OSError as error:
        raise CompareError(f"The previous export could not be read ({error.strerror or error})") from None
    if not rows:
        raise CompareError("The previous export has no rows that can be compared")
    return rows, skipped


def _keys(id_, cve, asset_id, name):
    """The ways a finding can be recognised, most specific first. Each is (kind, value); blank parts are not used."""
    fold = lambda text: " ".join(text.casefold().split())  # noqa: E731
    keys = []
    if id_:
        keys.append(("id", fold(id_)))
    if cve:
        keys.append(("cve+asset", (fold(cve), fold(asset_id))))
    if name:
        keys.append(("name+asset", (fold(name), fold(asset_id))))
    return keys


def compare(items, previous_rows, label="the previous export", skipped=0):
    """Compare scored batch items with the rows of a previous export; return a Comparison.

    A finding is recognised by its id, or else by its CVE and asset, or else by its name and asset. If more than one
    row could be the same finding it is reported as "could not be matched" rather than guessed at.
    """
    index = {}      # recognition key -> {id(row): row} for the rows not yet used
    for row in previous_rows:
        for key in _keys(row.id, row.cve, row.asset_id, row.name):
            index.setdefault(key, {})[id(row)] = row
    matched, changes = set(), {}
    for item in items:
        outcome = _match(item, index)
        if outcome is None:
            changes[id(item)] = Change(NEW)
        elif isinstance(outcome, str):
            changes[id(item)] = Change(AMBIGUOUS)
        else:
            matched.add(id(outcome))
            for key in _keys(outcome.id, outcome.cve, outcome.asset_id, outcome.name):
                index[key].pop(id(outcome), None)       # a previous row is used once
            changes[id(item)] = Change(_kind(item.priority, outcome.priority), outcome)
    resolved = tuple(row for row in previous_rows if id(row) not in matched)
    return Comparison(label, changes, resolved, skipped, len(previous_rows))


def _match(item, index):
    """Return the one unused previous row that is this item, None if there is none, or AMBIGUOUS.

    Each key is looked up in a dict of unused rows, so a file full of identical ids costs nothing extra.
    """
    ambiguous = False
    for key in _keys(item.id, item.cve, item.asset_id, item.name):
        candidates = index.get(key)
        if candidates and len(candidates) == 1:
            return next(iter(candidates.values()))
        if candidates:
            ambiguous = True
    return AMBIGUOUS if ambiguous else None


def _kind(now, before):
    if now == "ERROR" or before == "ERROR":
        return SAME if now == before else UNSCORED
    difference = explain.URGENCY[now] - explain.URGENCY[before]
    return UP if difference > 0 else DOWN if difference < 0 else SAME
