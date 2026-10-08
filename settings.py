"""Adjustable scoring settings with validation and safe loading and saving (no GUI dependencies)."""
import math
import os
import sys
from dataclasses import dataclass, fields
from pathlib import Path

import jsonfile

SETTINGS_VERSION = 1
MAX_SETTINGS_BYTES = 16 * 1024
MIN_LINE_GAP = 0.5

# name -> (type, default, minimum, maximum, description)
SPEC = {
    "cvss_high": (float, 7.0, 5.0, 8.0, "CVSS score where a vulnerability counts as High"),
    "cvss_critical": (float, 9.0, 8.0, 10.0, "CVSS score where a vulnerability counts as Critical"),
    "epss_percentile_cutoff": (float, 0.95, 0.5, 0.999, "EPSS percentile above which exploitation counts as likely"),
    "stale_days": (int, 7, 1, 90, "Days before threat data is flagged as stale"),
}


def _show(value):
    """Return a short, safe description of a value for error messages."""
    if isinstance(value, int) and not isinstance(value, bool) and value.bit_length() > 64:
        return "<very large number>"
    if not isinstance(value, (bool, int, float, str, type(None))):
        return f"<{type(value).__name__}>"
    text = repr(value)
    return text if len(text) <= 40 else text[:37] + "..."


def _check(name, value):
    """Return (clean_value, error) for one setting."""
    kind, _default, low, high, _description = SPEC[name]
    if isinstance(value, bool):
        return None, f"{name}: must be a number, not true/false"
    if kind is int:
        if not isinstance(value, int):
            return None, f"{name}: must be a whole number between {low} and {high} (got {_show(value)})"
    elif not isinstance(value, (int, float)):
        return None, f"{name}: must be a number between {low} and {high} (got {_show(value)})"
    try:
        in_range = math.isfinite(value) and low <= value <= high
    except OverflowError:
        in_range = False
    if not in_range:
        return None, f"{name}: must be between {low} and {high} (got {_show(value)})"
    return kind(value), None


@dataclass(frozen=True)
class Settings:
    """Validated scoring settings; construction fails with a clear message if any value is invalid."""

    cvss_high: float = SPEC["cvss_high"][1]
    cvss_critical: float = SPEC["cvss_critical"][1]
    epss_percentile_cutoff: float = SPEC["epss_percentile_cutoff"][1]
    stale_days: int = SPEC["stale_days"][1]

    def __post_init__(self):
        errors = []
        for name in SPEC:
            clean, error = _check(name, getattr(self, name))
            if error:
                errors.append(error)
            else:
                object.__setattr__(self, name, clean)
        if not errors and self.cvss_critical < self.cvss_high + MIN_LINE_GAP:
            errors.append(f"cvss_critical must be at least {MIN_LINE_GAP} above cvss_high "
                          f"(got {self.cvss_critical} and {self.cvss_high})")
        if errors:
            raise ValueError("; ".join(errors))

    def to_dict(self):
        """Return the settings as a plain dict, including the file format version."""
        return {"version": SETTINGS_VERSION, **{f.name: getattr(self, f.name) for f in fields(self)}}

    @classmethod
    def from_dict(cls, data):
        """Build settings from a dict that must contain exactly the known keys."""
        if not isinstance(data, dict):
            raise ValueError("settings must be a JSON object")
        expected = {"version", *SPEC}
        problems = []
        version = data.get("version")
        if type(version) is not int or version != SETTINGS_VERSION:
            problems.append(f"version: must be {SETTINGS_VERSION}")
        for name in sorted(expected - set(data)):
            if name != "version":
                problems.append(f"{name}: missing")
        for name in sorted(set(data) - expected):
            problems.append(f"{_show(name)}: unknown setting")
        if problems:
            raise ValueError("; ".join(problems))
        return cls(**{name: data[name] for name in SPEC})

    @property
    def is_default(self):
        """True when every value matches the shipped default."""
        return self == DEFAULT_SETTINGS

    def describe(self):
        """One-line summary of the settings, for summaries and exports."""
        values = ", ".join(f"{f.name}={getattr(self, f.name)}" for f in fields(self))
        return f"{'defaults' if self.is_default else 'custom'} ({values})"


DEFAULT_SETTINGS = Settings()


@dataclass(frozen=True)
class LoadResult:
    """Settings in effect plus any warnings to show the user."""

    settings: Settings
    warnings: tuple = ()


def default_path():
    """Return the settings file location in the user's config folder."""
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        xdg = os.environ.get("XDG_CONFIG_HOME", "")
        base = Path(xdg) if xdg and os.path.isabs(xdg) else Path.home() / ".config"
    return base / "vuln-prioritizer" / "settings.json"


def load(path=None):
    """Load settings, falling back to defaults with a warning if the file is unusable."""
    path = Path(path) if path else default_path()
    if not path.exists():
        return LoadResult(DEFAULT_SETTINGS)
    try:
        return LoadResult(Settings.from_dict(jsonfile.read_json(path, MAX_SETTINGS_BYTES)))
    except (OSError, ValueError, RecursionError) as error:
        warning = f"Scoring settings in {path} could not be used ({error}). Default settings are in effect."
        return LoadResult(DEFAULT_SETTINGS, (warning,))


def save(settings, path=None):
    """Write settings atomically with user-only permissions."""
    jsonfile.write_json_atomic(Path(path) if path else default_path(), settings.to_dict())


def restore_defaults(path=None):
    """Reset the saved settings to the shipped defaults and return them."""
    save(DEFAULT_SETTINGS, path)
    return DEFAULT_SETTINGS
