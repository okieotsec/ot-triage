"""Plain-language explanations of a prioritization: what would change it, summaries, chips (no GUI)."""
from dataclasses import dataclass

import references as refs
from prioritizer import NEVER, NEXT, NOW, Asset, Controls, Exposure, Patch, Threat, prioritize
from settings import DEFAULT_SETTINGS

HEADLINES = {
    NOW: ("Act immediately", "Remediate or mitigate right away."),
    NEXT: ("Schedule remediation", "Plan it into the next patch cycle (roughly 30-90 days)."),
    NEVER: ("No scheduled remediation", "Re-evaluate if conditions change."),
}
URGENCY = {NOW: 2, NEXT: 1, NEVER: 0}

SHORT_LABELS = {
    Threat: {Threat.NONE: "None", Threat.PUBLIC: "Public exploit", Threat.ACTIVE: "Active"},
    Asset: {Asset.STANDARD: "Standard", Asset.IMPORTANT: "Important", Asset.CROWN: "Crown jewel"},
    Exposure: {Exposure.LOW: "Low", Exposure.MEDIUM: "Medium", Exposure.HIGH: "High"},
    Patch: {Patch.AVAILABLE: "Available", Patch.PENDING: "Pending", Patch.EOL: "None (end of life)"},
    Controls: {Controls.NONE: "None", Controls.PARTIAL: "Partial", Controls.STRONG: "Strong"},
}
FIELD_PHRASES = {"threat": "the threat", "asset": "the asset", "exposure": "the exposure",
                 "patch": "the patch status", "controls": "compensating controls"}
FIELD_ENUMS = {"threat": Threat, "asset": Asset, "exposure": Exposure, "patch": Patch, "controls": Controls}


CVSS_BANDS = [(9.0, "CRITICAL", "raise"), (7.0, "HIGH", "raise"), (4.0, "MEDIUM", "warn"), (0.1, "LOW", "ok"),
              (0.0, "NONE", "neutral")]


def cvss_band(value):
    """Return the CVSS standard's severity label and a status direction for a base score."""
    _minimum, label, direction = next(band for band in CVSS_BANDS if value >= band[0])
    return label, direction


@dataclass(frozen=True)
class AssessInputs:
    """The six inputs to one prioritization."""

    cvss: float
    threat: Threat
    asset: Asset
    exposure: Exposure
    controls: Controls
    patch: Patch

    def run(self, settings=DEFAULT_SETTINGS):
        """Prioritize with these inputs."""
        return prioritize(self.cvss, self.threat, self.asset, self.exposure, self.controls, self.patch, settings)


@dataclass(frozen=True)
class Change:
    """One single-input change that moves the bucket."""

    priority: str
    text: str


@dataclass(frozen=True)
class WhatIf:
    """Single changes that would make the item more or less urgent."""

    current: str
    more_urgent: tuple
    less_urgent: tuple

    @property
    def is_empty(self):
        """True when no single change moves the bucket."""
        return not self.more_urgent and not self.less_urgent


def _tenths(value):
    return round(value * 10)


def what_would_change(inputs, settings=DEFAULT_SETTINGS):
    """List the single input changes that would move the bucket, using the real rules."""
    current = inputs.run(settings).priority
    more, less = [], []
    for name, enum in FIELD_ENUMS.items():
        for member in enum:
            if member is getattr(inputs, name):
                continue
            changed = AssessInputs(**{**inputs.__dict__, name: member}).run(settings).priority
            if changed != current:
                change = Change(changed, f"if {FIELD_PHRASES[name]} were {SHORT_LABELS[enum][member]}")
                (more if URGENCY[changed] > URGENCY[current] else less).append(change)
    here = _tenths(inputs.cvss)
    for direction, scores in (("at or above", range(here + 1, 101)), ("at or below", range(here - 1, -1, -1))):
        for tenths in scores:
            changed = AssessInputs(**{**inputs.__dict__, "cvss": tenths / 10}).run(settings).priority
            if changed != current:
                change = Change(changed, f"if the CVSS score were {direction} {tenths / 10:.1f}")
                (more if URGENCY[changed] > URGENCY[current] else less).append(change)
                break
    key = lambda c: (-URGENCY[c.priority], c.text)  # noqa: E731
    return WhatIf(current, tuple(sorted(more, key=key)), tuple(sorted(less, key=key)))


def what_if_lines(what_if):
    """Return the what-if result as readable lines."""
    lines = [f"{c.priority} {c.text}" for c in what_if.less_urgent + what_if.more_urgent]
    if what_if.is_empty:
        lines.append("No single change to one input moves this item.")
    elif not what_if.more_urgent and what_if.current == NOW:
        lines.append("Already at the highest urgency, so nothing makes it more urgent.")
    return lines


def sorted_factors(factors):
    """Order chips: raising factors first, then lowering, then neutral."""
    order = {"raise": 0, "lower": 1, "neutral": 2}
    return sorted(factors, key=lambda f: order.get(f.direction, 3))


def summary_text(result, data_versions="", extra=(), references=()):
    """Return a plain-text summary of a result, with inputs and settings so it can be reproduced."""
    headline = HEADLINES[result.priority][0]
    lines = [f"Priority: {result.priority} ({headline})", f"Ordering score: {result.score:.2f}/10",
             f"Action: {result.action}", "", "Inputs:", *[f"- {i}" for i in result.inputs], *[f"- {e}" for e in extra],
             f"- Scoring settings: {result.profile}"]
    if data_versions:
        lines.append(f"- Threat data: {data_versions}")
    lines += ["", "Rationale:", *[f"- {r}" for r in result.reasons]]
    if references:
        lines += ["", "References (from the CISA KEV notes):", *[f"- {refs.describe(r)}" for r in references]]
    return "\n".join(lines)


def markdown_summary(result, data_versions="", extra=(), references=()):
    """Return a Markdown summary of a result, suitable for pasting into a ticket."""
    headline = HEADLINES[result.priority][0]
    lines = [f"**Priority: {result.priority}** ({headline})", "", f"- Ordering score: {result.score:.2f} / 10",
             f"- Action: {result.action}", "", "**Inputs**", "", *[f"- {i}" for i in result.inputs],
             *[f"- {e}" for e in extra], f"- Scoring settings: {result.profile}"]
    if data_versions:
        lines.append(f"- Threat data: {data_versions}")
    lines += ["", "**Rationale**", "", *[f"- {r}" for r in result.reasons]]
    if references:
        lines += ["", "**References (from the CISA KEV notes)**", "", *[refs.markdown_item(r) for r in references]]
    return "\n".join(lines)
