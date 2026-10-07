"""Rule-based Now/Next/Never vulnerability prioritization (no GUI dependencies)."""
import math
from dataclasses import dataclass, field
from enum import Enum


class Threat(Enum):
    ACTIVE = "Active exploitation in wild"
    PUBLIC = "Public exploit available"
    NONE = "No known exploitation"


class Asset(Enum):
    CROWN = "Critical crown jewel asset"
    IMPORTANT = "Important asset"
    STANDARD = "Standard asset"


class Exposure(Enum):
    HIGH = "High exposure (internet connected)"
    MEDIUM = "Medium exposure"
    LOW = "Low exposure"


class Patch(Enum):
    AVAILABLE = "Patch available"
    PENDING = "No patch yet (vendor supported, fix pending)"
    EOL = "No patch ever (end-of-life / unsupported)"


class Controls(Enum):
    NONE = "None"
    PARTIAL = "Partial (e.g. ACLs, monitoring only)"
    STRONG = "Strong (e.g. segmentation, virtual patching, allow-listing)"


# Partial controls earn 35% of the 3-point span between "High" (7.0) and "Critical" (10.0) CVSS.
# Buckets are discrete, so fractional credit is applied to the CVSS the rules see (it only changes the
# outcome near a threshold); strong controls instead move the item a full level.
PARTIAL_CREDIT_FRACTION = 0.35
PARTIAL_CVSS_CREDIT = PARTIAL_CREDIT_FRACTION * 3.0

NOW, NEXT, NEVER = "NOW", "NEXT", "NEVER"
_ORDER = [NOW, NEXT, NEVER]

# Used only to order items within a bucket; it never decides the bucket.
_THREAT_PTS = {Threat.ACTIVE: 10, Threat.PUBLIC: 7, Threat.NONE: 3}
_ASSET_PTS = {Asset.CROWN: 10, Asset.IMPORTANT: 7, Asset.STANDARD: 3}
_EXPOSURE_PTS = {Exposure.HIGH: 10, Exposure.MEDIUM: 7, Exposure.LOW: 3}


@dataclass
class Result:
    priority: str
    score: float
    reasons: list = field(default_factory=list)
    action: str = ""
    inputs: list = field(default_factory=list)


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


def prioritize(cvss, threat, asset, exposure, controls=Controls.NONE, patch=Patch.AVAILABLE):
    if not math.isfinite(cvss) or not 0.0 <= cvss <= 10.0:
        raise ValueError("CVSS score must be between 0.0 and 10.0")

    reachable = exposure in (Exposure.HIGH, Exposure.MEDIUM)
    reasons = []

    raw_cvss = cvss
    if controls is Controls.PARTIAL:
        cvss = max(0.0, cvss - PARTIAL_CVSS_CREDIT)
        reasons.append(f"Partial controls credited at {PARTIAL_CREDIT_FRACTION:.0%}: "
                       f"CVSS treated as {cvss:.2f} instead of {raw_cvss:.1f} for threshold checks")

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
        if exposure is Exposure.HIGH and cvss >= 7.0:
            priority = NOW
            reasons.append("Public exploit, internet-exposed, and CVSS >= 7.0")
        else:
            priority = NEXT
            reasons.append("Public exploit available")
    else:
        if cvss >= 9.0 and exposure is Exposure.HIGH and asset is Asset.CROWN:
            priority = NOW
            reasons.append("Critical CVSS on an internet-exposed crown jewel, even without known exploitation")
        elif cvss >= 7.0 and (reachable or asset is not Asset.STANDARD):
            priority = NEXT
            reasons.append("High CVSS (>= 7.0) with exposure or elevated asset value")
        else:
            priority = NEVER
            reasons.append("No known exploitation and low combined risk; re-evaluate if conditions change")

    # Very low severity can never justify more than NEXT.
    if cvss < 4.0 and priority == NOW:
        priority = NEXT
        reasons.append("Capped at NEXT: CVSS < 4.0")

    if patch is Patch.AVAILABLE:
        action = "Apply the patch"
        # Strong controls are defense in depth: one level down, but never below NEXT if actively exploited.
        if controls is Controls.STRONG:
            lowered = _shift(priority, 1)
            if threat is Threat.ACTIVE and lowered == NEVER:
                lowered = NEXT
            if lowered != priority:
                reasons.append(f"Lowered {priority} -> {lowered}: strong compensating controls")
                priority = lowered
    else:
        # With no patch, controls are the only defense. Without strong ones the open-ended exposure raises
        # urgency (partial controls only helped via the CVSS credit above). Strong controls withhold the
        # raise but earn no extra downgrade, since nothing backs them up.
        if raw_cvss >= 4.0:
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
            if raw_cvss >= 7.0 and priority == NEVER:
                priority = NEXT
                reasons.append("Floored at NEXT: unpatchable device with CVSS >= 7.0 needs a replacement plan")

    score = min(
        10.0,
        cvss * 0.3 + _THREAT_PTS[threat] * 0.25 + _ASSET_PTS[asset] * 0.25 + _EXPOSURE_PTS[exposure] * 0.2,
    )
    inputs = [
        f"CVSS: {raw_cvss:.1f}",
        f"Threat: {threat.value}",
        f"Asset: {asset.value}",
        f"Exposure: {exposure.value}",
        f"Patch: {patch.value}",
        f"Compensating controls: {controls.value}",
    ]
    return Result(priority, round(score, 2), reasons, action, inputs)
