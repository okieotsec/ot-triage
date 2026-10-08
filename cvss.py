"""Parse CVSS vector strings and compute base scores for CVSS 3.0, 3.1 and 4.0 (no GUI dependencies).

Scoring follows the official FIRST reference calculators. Only the base score is computed: temporal, threat,
environmental and supplemental metrics are accepted and checked, but they never change the result.
"""
import math
import re
from dataclasses import dataclass

from cvss4_tables import LOOKUP, MAX_COMPOSED, MAX_SEVERITY

MAX_VECTOR_CHARS = 400
SUPPORTED_VERSIONS = ("3.0", "3.1", "4.0")
SAFE_CHARS = re.compile(r"[A-Za-z0-9:/.]+")
VERSION_2_HINT = re.compile(r"^(\(?AV:[LAN]/AC:[HML]/Au:[MSN]/)")

V3_BASE = {"AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR", "S": "UC", "C": "HLN", "I": "HLN", "A": "HLN"}
V3_OPTIONAL = {"E": "XUPFH", "RL": "XOTWU", "RC": "XURC", "CR": "XLMH", "IR": "XLMH", "AR": "XLMH",
               "MAV": "XNALP", "MAC": "XLH", "MPR": "XNLH", "MUI": "XNR", "MS": "XUC", "MC": "XNLH", "MI": "XNLH",
               "MA": "XNLH"}
V4_BASE = {"AV": ("N", "A", "L", "P"), "AC": ("L", "H"), "AT": ("N", "P"), "PR": ("N", "L", "H"),
           "UI": ("N", "P", "A"), "VC": ("H", "L", "N"), "VI": ("H", "L", "N"), "VA": ("H", "L", "N"),
           "SC": ("H", "L", "N"), "SI": ("H", "L", "N"), "SA": ("H", "L", "N")}
V4_OPTIONAL = {"E": ("X", "A", "P", "U"), "CR": ("X", "H", "M", "L"), "IR": ("X", "H", "M", "L"),
               "AR": ("X", "H", "M", "L"), "MAV": ("X", "N", "A", "L", "P"), "MAC": ("X", "L", "H"),
               "MAT": ("X", "N", "P"), "MPR": ("X", "N", "L", "H"), "MUI": ("X", "N", "P", "A"),
               "MVC": ("X", "H", "L", "N"), "MVI": ("X", "H", "L", "N"), "MVA": ("X", "H", "L", "N"),
               "MSC": ("X", "H", "L", "N"), "MSI": ("X", "S", "H", "L", "N"), "MSA": ("X", "S", "H", "L", "N"),
               "S": ("X", "N", "P"), "AU": ("X", "N", "Y"), "R": ("X", "A", "U", "I"), "V": ("X", "D", "C"),
               "RE": ("X", "L", "M", "H"), "U": ("X", "Clear", "Green", "Amber", "Red")}


def _allowed(version):
    """Return (base metrics, optional metrics), each mapping a metric to its allowed values."""
    if version == "4.0":
        return V4_BASE, V4_OPTIONAL
    return {k: tuple(v) for k, v in V3_BASE.items()}, {k: tuple(v) for k, v in V3_OPTIONAL.items()}


@dataclass(frozen=True)
class CvssVector:
    """A validated CVSS vector: its version, the metrics given, and its normalized text."""

    version: str
    metrics: dict
    normalized: str

    @property
    def label(self):
        """Return the version as a short label such as 'CVSS 4.0'."""
        return f"CVSS {self.version}"

    @property
    def score(self):
        """Return the base score (0.0 to 10.0)."""
        return base_score(self)


def parse_vector(text):
    """Validate a CVSS 3.0, 3.1 or 4.0 vector string and return a CvssVector; raises ValueError with a clear message."""
    if not isinstance(text, str):
        raise ValueError("The CVSS vector must be text")
    raw = text.strip()
    if not raw:
        raise ValueError("Enter a CVSS vector string such as CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    if len(raw) > MAX_VECTOR_CHARS:
        raise ValueError(f"The CVSS vector is longer than {MAX_VECTOR_CHARS} characters")
    if VERSION_2_HINT.match(raw):
        raise ValueError("CVSS version 2 vectors are not supported; enter the base score instead")
    if not SAFE_CHARS.fullmatch(raw):
        raise ValueError("The CVSS vector may contain only letters, digits, ':', '/' and '.'")
    parts = raw.split("/")
    prefix = parts[0]
    if not prefix.startswith("CVSS:"):
        raise ValueError("The vector must start with CVSS:3.0/, CVSS:3.1/ or CVSS:4.0/")
    version = prefix[5:]
    if version not in SUPPORTED_VERSIONS:
        raise ValueError(f"CVSS {version[:10]} is not supported; supported versions are 3.0, 3.1 and 4.0")
    base, optional = _allowed(version)
    metrics = {}
    for part in parts[1:]:
        name, separator, value = part.partition(":")
        if not separator or not name or not value or ":" in value:
            raise ValueError(f"'{part[:30]}' is not a metric in the form NAME:VALUE")
        if name in metrics:
            raise ValueError(f"The metric {name} appears more than once")
        allowed = base.get(name) or optional.get(name)
        if allowed is None:
            raise ValueError(f"Unknown CVSS {version} metric '{name[:10]}'")
        if value not in allowed:
            raise ValueError(f"'{value[:12]}' is not a valid value for {name} in CVSS {version}")
        metrics[name] = value
    missing = [name for name in base if name not in metrics]
    if missing:
        raise ValueError(f"The vector is missing required metric(s): {', '.join(missing)}")
    order = [*base, *optional]
    normalized = "/".join([prefix, *[f"{n}:{metrics[n]}" for n in order if n in metrics]])
    return CvssVector(version, metrics, normalized)


def base_score(vector):
    """Return the base score of a parsed vector."""
    if vector.version == "4.0":
        return _score_v4(vector.metrics)
    return _score_v3(vector.metrics, vector.version)


# ---- CVSS 3.0 and 3.1 -----------------------------------------------------

_V3_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"H": 0.44, "L": 0.77},
    "PR": {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}},
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": 6.42, "C": 7.52},
    "CIA": {"N": 0, "L": 0.22, "H": 0.56},
}


def _roundup_v31(value):
    scaled = math.floor(value * 100000 + 0.5)
    if scaled % 10000 == 0:
        return scaled / 100000
    return (math.floor(scaled / 10000) + 1) / 10


def _roundup_v30(value):
    return math.ceil(value * 10) / 10


def _score_v3(metrics, version):
    roundup = _roundup_v31 if version == "3.1" else _roundup_v30
    w = _V3_WEIGHTS
    scope = metrics["S"]
    iss = 1 - ((1 - w["CIA"][metrics["C"]]) * (1 - w["CIA"][metrics["I"]]) * (1 - w["CIA"][metrics["A"]]))
    if scope == "U":
        impact = w["S"][scope] * iss
    else:
        impact = w["S"][scope] * (iss - 0.029) - 3.25 * math.pow(iss - 0.02, 15)
    exploitability = 8.22 * w["AV"][metrics["AV"]] * w["AC"][metrics["AC"]] * w["PR"][scope][metrics["PR"]] \
        * w["UI"][metrics["UI"]]
    if impact <= 0:
        return 0.0
    if scope == "U":
        return float(roundup(min(exploitability + impact, 10)))
    return float(roundup(min(1.08 * (exploitability + impact), 10)))


# ---- CVSS 4.0 -------------------------------------------------------------

_LEVELS = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}, "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI": {"N": 0.0, "P": 0.1, "A": 0.2}, "AC": {"L": 0.0, "H": 0.1}, "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2}, "VI": {"H": 0.0, "L": 0.1, "N": 0.2}, "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC": {"H": 0.1, "L": 0.2, "N": 0.3}, "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR": {"H": 0.0, "M": 0.1, "L": 0.2}, "IR": {"H": 0.0, "M": 0.1, "L": 0.2}, "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
}
_DISTANCE_METRICS = ("AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA", "SC", "SI", "SA", "CR", "IR", "AR")


def _selection(base_metrics):
    """Return all v4.0 metrics, with every non-base metric left undefined (X) so only the base score is computed."""
    selected = {name: "X" for name in V4_OPTIONAL}
    selected.update({name: base_metrics[name] for name in V4_BASE})
    return selected


def _effective(selected, name):
    """Return the value a metric takes in scoring, applying the standard's worst-case defaults."""
    value = selected[name]
    if name == "E" and value == "X":
        return "A"
    if name in ("CR", "IR", "AR") and value == "X":
        return "H"
    modified = selected.get("M" + name)
    if modified is not None and modified != "X":
        return modified
    return value


def _macro_vector(selected):
    m = lambda name: _effective(selected, name)  # noqa: E731
    if m("AV") == "N" and m("PR") == "N" and m("UI") == "N":
        eq1 = 0
    elif (m("AV") == "N" or m("PR") == "N" or m("UI") == "N") and m("AV") != "P":
        eq1 = 1
    else:
        eq1 = 2
    eq2 = 0 if (m("AC") == "L" and m("AT") == "N") else 1
    if m("VC") == "H" and m("VI") == "H":
        eq3 = 0
    elif m("VC") == "H" or m("VI") == "H" or m("VA") == "H":
        eq3 = 1
    else:
        eq3 = 2
    if m("MSI") == "S" or m("MSA") == "S":
        eq4 = 0
    elif m("SC") == "H" or m("SI") == "H" or m("SA") == "H":
        eq4 = 1
    else:
        eq4 = 2
    eq5 = {"A": 0, "P": 1, "U": 2}[m("E")]
    eq6 = 0 if ((m("CR") == "H" and m("VC") == "H") or (m("IR") == "H" and m("VI") == "H")
                or (m("AR") == "H" and m("VA") == "H")) else 1
    return f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"


def _parse_max_vector(text):
    return dict(part.split(":") for part in text.strip("/").split("/"))


def _score_v4(base_metrics):
    selected = _selection(base_metrics)
    if all(_effective(selected, name) == "N" for name in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0
    macro = _macro_vector(selected)
    value = LOOKUP[macro]
    eq1, eq2, eq3, eq4, eq5, eq6 = (int(digit) for digit in macro)

    def lower(*digits):
        return LOOKUP.get("".join(str(d) for d in digits))

    score_eq1, score_eq2 = lower(eq1 + 1, eq2, eq3, eq4, eq5, eq6), lower(eq1, eq2 + 1, eq3, eq4, eq5, eq6)
    if eq3 == 1 and eq6 == 1:
        score_eq3eq6 = lower(eq1, eq2, eq3 + 1, eq4, eq5, eq6)
    elif eq3 == 0 and eq6 == 1:
        score_eq3eq6 = lower(eq1, eq2, eq3 + 1, eq4, eq5, eq6)
    elif eq3 == 1 and eq6 == 0:
        score_eq3eq6 = lower(eq1, eq2, eq3, eq4, eq5, eq6 + 1)
    elif eq3 == 0 and eq6 == 0:
        left, right = lower(eq1, eq2, eq3, eq4, eq5, eq6 + 1), lower(eq1, eq2, eq3 + 1, eq4, eq5, eq6)
        score_eq3eq6 = left if (left is not None and right is not None and left > right) else right
    else:
        score_eq3eq6 = lower(eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1)
    score_eq4, score_eq5 = lower(eq1, eq2, eq3, eq4 + 1, eq5, eq6), lower(eq1, eq2, eq3, eq4, eq5 + 1, eq6)

    max_vectors = [a + b + c + d + e
                   for a in MAX_COMPOSED["eq1"][eq1] for b in MAX_COMPOSED["eq2"][eq2]
                   for c in MAX_COMPOSED["eq3"][eq3][eq6] for d in MAX_COMPOSED["eq4"][eq4]
                   for e in MAX_COMPOSED["eq5"][eq5]]
    distance = {}
    for candidate in max_vectors:
        best = _parse_max_vector(candidate)
        distance = {name: _LEVELS[name][_effective(selected, name)] - _LEVELS[name][best[name]]
                    for name in _DISTANCE_METRICS}
        if not any(d < 0 for d in distance.values()):
            break

    step = 0.1
    current = {"eq1": distance["AV"] + distance["PR"] + distance["UI"],
               "eq2": distance["AC"] + distance["AT"],
               "eq3eq6": distance["VC"] + distance["VI"] + distance["VA"] + distance["CR"] + distance["IR"]
               + distance["AR"],
               "eq4": distance["SC"] + distance["SI"] + distance["SA"]}
    maximum = {"eq1": MAX_SEVERITY["eq1"][eq1] * step, "eq2": MAX_SEVERITY["eq2"][eq2] * step,
               "eq3eq6": MAX_SEVERITY["eq3eq6"][eq3][eq6] * step, "eq4": MAX_SEVERITY["eq4"][eq4] * step}
    lowers = {"eq1": score_eq1, "eq2": score_eq2, "eq3eq6": score_eq3eq6, "eq4": score_eq4, "eq5": score_eq5}
    existing, total = 0, 0.0
    for name, lower_score in lowers.items():
        if lower_score is None:
            continue
        existing += 1
        if name != "eq5":
            total += (value - lower_score) * (current[name] / maximum[name])
    mean_distance = total / existing if existing else 0
    value = min(max(value - mean_distance, 0.0), 10.0)
    return math.floor(value * 10 + 0.5) / 10


def score_from_vector(text):
    """Parse a vector string and return (CvssVector, base score)."""
    vector = parse_vector(text)
    return vector, base_score(vector)
