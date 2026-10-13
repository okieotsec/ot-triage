"""Per-asset roll-up of scored findings: what is the worst thing on each asset, and what could be fixed on one visit.

OT assets are usually patched in short outage windows, so the useful question is "what is on this asset?", not only
"what is the worst finding?". This module groups the rows of a scored batch by asset id (no GUI).
"""
import csv
from dataclasses import dataclass

import explain
import inventory
from prioritizer import NEVER, NEXT, NOW

MAX_LISTED_IDS = 20
UNASSIGNED = "(no asset id)"
BUCKETS = (NOW, NEXT, NEVER)


@dataclass(frozen=True)
class AssetSummary:
    """Everything the batch says about one asset."""

    asset_id: str
    items: tuple                # the asset's rows, in the order they were given (ranked order for a ranked batch)

    @property
    def counts(self):
        """How many rows are in each bucket, and how many could not be scored."""
        found = {NOW: 0, NEXT: 0, NEVER: 0, "ERROR": 0}
        for item in self.items:
            found[item.priority] += 1
        return found

    @property
    def worst(self):
        """The most urgent bucket on the asset, or ERROR when none of its rows could be scored."""
        counts = self.counts
        return next((b for b in BUCKETS if counts[b]), "ERROR")

    @property
    def visit_items(self):
        """The rows that call for action (NOW and NEXT), so they can be handled together."""
        return tuple(i for i in self.items if i.priority in (NOW, NEXT))

    @property
    def top(self):
        """The most urgent scored row: the first one of the worst bucket with the highest ordering score."""
        scored = [i for i in self.items if i.result]
        if not scored:
            return None
        return max(scored, key=lambda i: (explain.URGENCY[i.priority], i.result.score))

    @property
    def top_score(self):
        """The highest ordering score on the asset, or None when nothing was scored."""
        top = self.top
        return top.result.score if top else None


def _sort_key(summary):
    counts = summary.counts
    return (-explain.URGENCY.get(summary.worst, -1), -counts[NOW], -counts[NEXT],
            -(summary.top_score if summary.top_score is not None else -1.0), summary.asset_id.casefold())


def rollup(items):
    """Group scored rows by asset id. Return (summaries, rows_without_an_asset_id).

    Asset ids match without regard to letter case or surrounding white space. The first spelling seen is the one
    shown. Summaries are ordered by the worst bucket, then by how many NOW and NEXT rows the asset has.
    """
    groups, names, unassigned = {}, {}, []
    for item in items:
        key = inventory.normalize_key(item.asset_id) if item.asset_id else ""
        if not key:
            unassigned.append(item)
            continue
        groups.setdefault(key, []).append(item)
        names.setdefault(key, item.asset_id)
    summaries = [AssetSummary(names[key], tuple(rows)) for key, rows in groups.items()]
    summaries.sort(key=_sort_key)
    return summaries, tuple(unassigned)


def label(item):
    """A short name for a row: its id, CVE and name, or its source line when it has none of those."""
    return " · ".join(part for part in (item.id, item.cve, item.name) if part) or f"line {item.line}"


COLUMNS = ["asset_id", "worst_priority", "now", "next", "never", "errors", "findings", "visit_together",
           "top_ordering_score", "top_finding", "finding_ids", "vendor", "product", "possible_advisories",
           "newest_possible_advisory"]


@dataclass(frozen=True)
class PossibleAdvisories:
    """The CISA ICS advisories that may apply to one asset, found from the vendor and product in the inventory."""

    vendor: str
    product: str
    advisories: tuple = ()      # the newest few
    count: int = 0              # how many match in all
    vendor_known: bool = False  # whether any advisory names this vendor at all


def possible_advisories(summaries, inventory_data, ics):
    """For every asset whose inventory entry has a vendor and a product, find the advisories that may apply.

    Returns {the asset id as shown: PossibleAdvisories}. Assets with no vendor or product, or an inventory or
    advisory data that is not loaded, are left out. This points at advisories to read; it does not know versions.
    """
    found = {}
    if inventory_data is None or ics is None:
        return found
    for summary in summaries:
        status, record = inventory_data.lookup(summary.asset_id)
        if status != "found" or not record.vendor or not record.product:
            continue
        advisories, count, known = ics.match(record.vendor, record.product)
        found[summary.asset_id] = PossibleAdvisories(record.vendor, record.product, advisories, count, known)
    return found


def _safe(text):
    text = str(text)
    return "'" + text if text and text[0] in "=+-@\t\r" else text


def write_rollup(path, summaries, possible=None):
    """Write the per-asset roll-up to a CSV file with formula-safe text cells.

    possible is the result of possible_advisories(); without it the vendor and advisory columns are blank.
    """
    possible = possible or {}
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS)
        writer.writeheader()
        for summary in summaries:
            counts, top = summary.counts, summary.top
            names = [label(i) for i in summary.items]
            listed = "; ".join(names[:MAX_LISTED_IDS])
            if len(names) > MAX_LISTED_IDS:
                listed += f"; and {len(names) - MAX_LISTED_IDS} more"
            match = possible.get(summary.asset_id)
            writer.writerow({
                "vendor": _safe(match.vendor) if match else "", "product": _safe(match.product) if match else "",
                "possible_advisories": match.count if match else "",
                "newest_possible_advisory": _safe(match.advisories[0].id) if match and match.advisories else "",
                "asset_id": _safe(summary.asset_id), "worst_priority": summary.worst, "now": counts[NOW],
                "next": counts[NEXT], "never": counts[NEVER], "errors": counts["ERROR"],
                "findings": len(summary.items), "visit_together": len(summary.visit_items),
                "top_ordering_score": "" if top is None else f"{top.result.score:.2f}",
                "top_finding": "" if top is None else _safe(label(top)), "finding_ids": _safe(listed)})
