"""Deterministic CVSS vector sets for checking cvss.py against the official FIRST calculators (developer tool).

Nothing here is random: every vector is derived from a hash of its version and number, so the same set is rebuilt
exactly on any machine and Python version. The tool and the offline unit tests share this file.
"""
import hashlib
import itertools
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import cvss

VERSIONS = ("3.0", "3.1", "4.0")
ENVIRONMENTAL_COUNT = 60_000
# Vector numbers (beyond the first 60,000) that reach the 12 MacroVectors the first 60,000 vectors never reach.
V4_COVERAGE_NUMBERS = (61077, 63407, 71716, 72761, 84110, 93028, 93158, 105005, 167913, 185495, 226937, 504806)


def all_vectors(version):
    """Yield every base vector of a version, in a fixed order."""
    base, _optional = cvss._allowed(version)
    names = list(base)
    for combo in itertools.product(*[base[name] for name in names]):
        yield f"CVSS:{version}/" + "/".join(f"{n}:{v}" for n, v in zip(names, combo, strict=True))


def _vector_for(version, number, bases, optional):
    """Build the vector with this number: a base vector plus a hash-chosen mix of the optional metrics."""
    digest = hashlib.sha256(f"{version}:{number}".encode()).digest()
    parts = [bases[int.from_bytes(digest[:4], "big") % len(bases)]]
    for position, (name, allowed) in enumerate(optional.items()):
        pick = digest[4 + position % 28]
        if pick >= 100:  # below 100 the metric stays "not defined" (X)
            parts.append(f"{name}:{allowed[1 + (pick - 100) % (len(allowed) - 1)]}")
    return "/".join(parts)


def environmental_vectors(version, count=ENVIRONMENTAL_COUNT):
    """Return `count` vectors that mix a base vector with temporal, environmental (and for v4 supplemental) metrics.

    Each optional metric is "not defined" (X) about 40 percent of the time, otherwise one of its other values. For
    CVSS 4.0 a few extra vectors are appended so that all 270 MacroVectors of the scoring table are exercised.
    """
    _base, optional = cvss._allowed(version)
    bases = list(all_vectors(version))
    numbers = [*range(count), *(V4_COVERAGE_NUMBERS if version == "4.0" else ())]
    return [_vector_for(version, number, bases, optional) for number in numbers]


def macro_vectors_reached(version, vectors):
    """Return the set of v4.0 MacroVectors the given vectors reach (a measure of how much of the table is tested)."""
    return {cvss._macro_vector(cvss._selection(cvss.parse_vector(v).metrics, environmental=True)) for v in vectors}
