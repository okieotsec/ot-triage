"""Compare a version with the version ranges a CISA advisory lists (no GUI).

CISA's advisories name the affected versions as free text that follows no single rule: "<=Firmware_3.11.0",
"vers:intdot/>=4.0|<5.2", ">= 6.02 | <= 6.05", "V7.1_SP2 and prior", "9.21", "vers:all/*". This module reads the common
shapes and answers one question: is this version inside the range? The answer is True, False, or None when it cannot
be said with certainty (a text it does not understand, or two versions that differ only in a qualifier such as
"SP2"). It never guesses: None is always better than a wrong True or False.

Both the range text and the version text come from files, so they are bounded: at most MAX_TEXT_CHARS characters,
MAX_PARTS numbers in a version, and MAX_DIGITS digits in each number.
"""
import functools
import re
from dataclasses import dataclass

MAX_TEXT_CHARS = 120
MAX_PARTS = 8
MAX_DIGITS = 9
MAX_SUFFIX_CHARS = 30
CACHE_SIZE = 20_000

_NUMBER = re.compile(r"\d+(?:\.\d+)*")
_PREFIX = re.compile(r"[A-Za-z _:\-]{0,30}")
_VERS = re.compile(r"vers:[a-z0-9._-]+/", re.IGNORECASE)
_CONSTRAINT = re.compile(r"(<=|>=|==|<|>|=)?\s*(.+)")
_ALL = frozenset({"*", "all", "all versions", "any", "any version", "any versions", "all firmware versions"})
_AND_BELOW = re.compile(r"(.+?)\s+(?:and|or)\s+(?:prior|earlier|before|below|lower|older)\b.*", re.IGNORECASE)
_AND_ABOVE = re.compile(r"(.+?)\s+(?:and|or)\s+(?:later|newer|above|higher)\b.*", re.IGNORECASE)
_BEFORE = re.compile(r"(?:prior to|before|earlier than|below)\s+(.+)", re.IGNORECASE)


@dataclass(frozen=True)
class Version:
    """A version as numbers (3.11.0 is (3, 11, 0)) and any text after them (such as "sp2")."""

    parts: tuple
    suffix: str = ""


@dataclass(frozen=True)
class VersionRange:
    """The versions an advisory lists: every version, or those between a lower and an upper bound (either may be open).

    A bound is (version, inclusive). An exact version has the same inclusive bound on both sides.
    """

    everything: bool = False
    lower: tuple = None
    upper: tuple = None


def parse_version(text):
    """Read a version such as "3.11.0", "V3.01.012" or "Firmware_3.11.0"; None if there is no usable number."""
    if not isinstance(text, str):
        return None
    text = " ".join(text.split())
    if not text or len(text) > MAX_TEXT_CHARS:
        return None
    found = _NUMBER.search(text)
    if not found or not _PREFIX.fullmatch(text[:found.start()]):
        return None
    pieces = found.group().split(".")
    if len(pieces) > MAX_PARTS or any(len(piece) > MAX_DIGITS for piece in pieces):
        return None
    suffix = text[found.end():].strip(" _-.,;:()").lower()[:MAX_SUFFIX_CHARS]
    return Version(tuple(int(piece) for piece in pieces), suffix)


def describe_range(text):
    """An advisory's version text as a person reads it: no "vers:scheme/" prefix, and "*" as all versions."""
    if not isinstance(text, str):
        return ""
    plain = _VERS.sub("", " ".join(text.split()), count=1).strip()
    return "all versions" if plain.lower() in _ALL else plain


def compare(left, right):
    """Return -1, 0 or 1 for left <, == or > right, or None when only a qualifier tells them apart (or is unclear)."""
    width = max(len(left.parts), len(right.parts))
    a = left.parts + (0,) * (width - len(left.parts))
    b = right.parts + (0,) * (width - len(right.parts))
    if a != b:
        return -1 if a < b else 1
    return 0 if left.suffix == right.suffix else None


def parse_range(text):
    """Read the version text an advisory lists as a VersionRange; None if it is not one of the shapes understood."""
    return _parse_range(text) if isinstance(text, str) else None


@functools.lru_cache(maxsize=CACHE_SIZE)
def _parse_range(text):
    text = " ".join(text.split())
    if not text or len(text) > MAX_TEXT_CHARS:
        return None
    text = _VERS.sub("", text, count=1).strip()
    if text.lower() in _ALL:
        return VersionRange(everything=True)
    for pattern, kind in ((_AND_BELOW, "upper"), (_AND_ABOVE, "lower")):
        found = pattern.fullmatch(text)
        if found:
            return _bounded([(">=" if kind == "lower" else "<=", found.group(1))])
    found = _BEFORE.fullmatch(text)
    if found:
        return _bounded([("<", found.group(1))])
    pieces = [piece.strip() for piece in re.split(r"[|,]", text)]
    if not 1 <= len(pieces) <= 2 or not all(pieces):
        return None
    constraints = []
    for piece in pieces:
        operator, value = _CONSTRAINT.fullmatch(piece).groups()
        constraints.append((operator or "", value))
    return _bounded(constraints)


def _bounded(constraints):
    lower = upper = None
    for operator, value in constraints:
        version = parse_version(value)
        if version is None:
            return None
        if not operator:
            if len(constraints) != 1 or version.suffix:
                return None         # a bare version is an exact version only when nothing else is said about it
            operator = "=="
        if operator in ("==", "="):
            bound = (version, True)
            if lower is not None or upper is not None:
                return None
            lower = upper = bound
        elif operator in (">", ">="):
            if lower is not None:
                return None
            lower = (version, operator == ">=")
        else:
            if upper is not None:
                return None
            upper = (version, operator == "<=")
    return VersionRange(lower=lower, upper=upper)


def in_range(version, version_range):
    """True if the version is inside the range, False if it is outside, None if that cannot be said for certain."""
    if version_range is None or version is None:
        return None
    undecided = False         # a range with no bounds (every version) is never undecided and holds for all
    for bound, wanted in ((version_range.lower, 1), (version_range.upper, -1)):
        if bound is None:
            continue
        order = compare(version, bound[0])
        if order is None:
            undecided = True
        elif order == 0:
            if not bound[1]:
                return False
        elif order != wanted:
            return False
    return None if undecided else True
