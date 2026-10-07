"""Rule-based Now/Next/Never vulnerability prioritization (no GUI dependencies)."""
import math
from dataclasses import dataclass, field
from enum import Enum

from settings import DEFAULT_SETTINGS


class Threat(Enum):
    """Exploitation status of a vulnerability."""
    ACTIVE = "Active exploitation in wild"
    PUBLIC = "Public exploit available"
    NONE = "No known exploitation"


class Asset(Enum):
    """Business criticality of the affected asset."""
    CROWN = "Critical crown jewel asset"
    IMPORTANT = "Important asset"
    STANDARD = "Standard asset"


class Exposure(Enum):
    """How reachable the affected asset is from outside its trust zone."""
    HIGH = "High exposure (internet connected)"
    MEDIUM = "Medium exposure"
    LOW = "Low exposure"


class Patch(Enum):
    """Remediation availability."""
    AVAILABLE = "Patch available"
    PENDING = "No patch yet (vendor supported, fix pending)"
    EOL = "No patch ever (end-of-life / unsupported)"


class Controls(Enum):
    """Compensating controls in place."""
    NONE = "None"
    PARTIAL = "Partial (e.g. ACLs, monitoring only)"
    STRONG = "Strong (e.g. segmentation, virtual patching, allow-listing)"


# Points subtracted from the ordering score when partial controls are in place
PARTIAL_SCORE_CREDIT = 0.5

NOW, NEXT, NEVER = "NOW", "NEXT", "NEVER"
_ORDER = [NOW, NEXT, NEVER]

# Points used to order items within a bucket
_THREAT_PTS = {Threat.ACTIVE: 10, Threat.PUBLIC: 7, Threat.NONE: 3}
_ASSET_PTS = {Asset.CROWN: 10, Asset.IMPORTANT: 7, Asset.STANDARD: 3}
_EXPOSURE_PTS = {Exposure.HIGH: 10, Exposure.MEDIUM: 7, Exposure.LOW: 3}


@dataclass
class Result:
    """Outcome of a prioritization."""
    priority: str
    score: float
    reasons: list = field(default_factory=list)
    action: str = ""
    inputs: list = field(default_factory=list)
    profile: str = ""


def parse_cvss(text):
    """Parse and validate a CVSS base score; raises ValueError with a user-facing message."""
    try:
        value = float(text)
    except (TypeError, ValueError):
        raise ValueError("CVSS score must be a number") from None
    if not math.isfinite(value) or not 0.0 <= value <= 10.0:
        raise ValueError("CVSS score must be between 0.0 and 10.0")
    return value


def _shift(priority, steps):
    """Move a priority `steps` levels less urgent (negative = more urgent), clamped to NOW..NEVER."""
    return _ORDER[max(0, min(_ORDER.index(priority) + steps, len(_ORDER) - 1))]


def _fmt(value):
    """Format a CVSS line with at least one decimal place."""
    text = f"{value:.2f}".rstrip("0")
    return text + "0" if text.endswith(".") else text


def prioritize(cvss, threat, asset, exposure, controls=Controls.NONE, patch=Patch.AVAILABLE,
               settings=DEFAULT_SETTINGS):
    """Return the priority, ordering score, reasons, action, inputs and settings profile."""
    if not math.isfinite(cvss) or not 0.0 <= cvss <= 10.0:
        raise ValueError("CVSS score must be between 0.0 and 10.0")

    high, critical = settings.cvss_high, settings.cvss_critical
    reachable = exposure in (Exposure.HIGH, Exposure.MEDIUM)
    exposed_crown = asset is Asset.CROWN and exposure is Exposure.HIGH
    reasons = []

    if threat is Threat.ACTIVE:
        if reachable:
            priority = NOW
            reasons.append("Actively exploited and reachable from outside the asset's trust zone")
        elif asset is Asset.CROWN:
            priority = NOW
            reasons.append("Actively exploited and the asset is a crown jewel")
        else:
            priority = NEXT
            reasons.append("Actively exploited, but low exposure and not a crown jewel")
    elif threat is Threat.PUBLIC:
        if exposure is Exposure.HIGH and cvss >= high:
            priority = NOW
            reasons.append(f"Public exploit, internet-exposed, and CVSS >= {_fmt(high)}")
        else:
            priority = NEXT
            reasons.append("Public exploit available")
    else:
        if cvss >= critical and exposure is Exposure.HIGH and asset is Asset.CROWN:
            priority = NOW
            reasons.append("Critical CVSS on an internet-exposed crown jewel, even without known exploitation")
        elif cvss >= high and (reachable or asset is not Asset.STANDARD):
            priority = NEXT
            reasons.append(f"High CVSS (>= {_fmt(high)}) with exposure or elevated asset value")
        else:
            priority = NEVER
            reasons.append("No known exploitation and low combined risk; re-evaluate if conditions change")

    # Cap low-severity items at NEXT, except actively exploited exposed crown jewels
    if cvss < 4.0 and priority == NOW:
        if threat is Threat.ACTIVE and exposed_crown:
            reasons.append("Kept at NOW despite CVSS < 4.0: actively exploited, exposed crown jewel")
        else:
            priority = NEXT
            reasons.append("Capped at NEXT: CVSS < 4.0")

    if patch is Patch.AVAILABLE:
        action = "Apply the patch"
        # Strong controls lower the priority one level, never below NEXT when actively exploited
        if controls is Controls.STRONG:
            lowered = _shift(priority, 1)
            if threat is Threat.ACTIVE and lowered == NEVER:
                lowered = NEXT
            if lowered != priority:
                reasons.append(f"Lowered {priority} -> {lowered}: strong compensating controls")
                priority = lowered
    else:
        # Without a patch, raise the priority one level unless strong controls are in place
        if cvss >= 4.0:
            if controls is Controls.STRONG:
                reasons.append("No patch, but strong compensating controls: priority not raised")
            else:
                raised = _shift(priority, -1)
                if raised != priority:
                    reasons.append(f"Raised {priority} -> {raised}: no patch and no effective compensating controls")
                    priority = raised
                else:
                    reasons.append("No patch and no effective compensating controls (already at highest urgency)")

        if patch is Patch.PENDING:
            action = ("Mitigate now with compensating controls; monitor the vendor advisory and "
                      "patch as soon as the fix ships (re-evaluate on release)")
            reasons.append("Vendor-supported: exposure window is temporary")
        else:
            action = ("Isolate/segment and monitor; plan replacement or migration "
                      "(no fix will ever ship)")
            reasons.append("End-of-life: exposure is permanent and accumulates over time")
            if cvss >= high and priority == NEVER:
                priority = NEXT
                reasons.append(f"Floored at NEXT: unpatchable device with CVSS >= {_fmt(high)} "
                               "needs a replacement plan")

    # Exposed crown jewels with meaningful severity are never left at NEVER
    if exposed_crown and cvss >= 4.0 and priority == NEVER:
        priority = NEXT
        reasons.append("Floored at NEXT: internet-exposed crown jewel with CVSS >= 4.0")

    score = cvss * 0.3 + _THREAT_PTS[threat] * 0.25 + _ASSET_PTS[asset] * 0.25 + _EXPOSURE_PTS[exposure] * 0.2
    if controls is Controls.PARTIAL:
        score -= PARTIAL_SCORE_CREDIT
        reasons.append("Partial controls: ranked lower within the bucket; the bucket itself is unchanged")
    score = max(0.0, min(10.0, score))
    inputs = [
        f"CVSS: {cvss:.1f}",
        f"Threat: {threat.value}",
        f"Asset: {asset.value}",
        f"Exposure: {exposure.value}",
        f"Patch: {patch.value}",
        f"Compensating controls: {controls.value}",
    ]
    return Result(priority, round(score, 2), reasons, action, inputs, settings.describe())
