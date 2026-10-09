"""Appearance preferences, stored apart from the scoring settings (no GUI dependencies)."""
from dataclasses import dataclass, fields
from pathlib import Path

import jsonfile
import settings

PREFS_VERSION = 1
MAX_PREFS_BYTES = 4 * 1024
THEMES = ("dark", "light")
TEXT_PERCENTS = (90, 100, 115, 130)


@dataclass(frozen=True)
class UiPrefs:
    """Validated appearance preferences; construction fails with a clear message if any value is invalid."""

    theme: str = "dark"
    text_percent: int = 100
    startup_update: bool = False

    def __post_init__(self):
        errors = []
        if not isinstance(self.theme, str) or self.theme not in THEMES:
            errors.append(f"theme: must be one of {', '.join(THEMES)}")
        if type(self.text_percent) is not int or self.text_percent not in TEXT_PERCENTS:
            errors.append(f"text_percent: must be one of {', '.join(map(str, TEXT_PERCENTS))}")
        if type(self.startup_update) is not bool:
            errors.append("startup_update: must be true or false")
        if errors:
            raise ValueError("; ".join(errors))

    def to_dict(self):
        """Return the preferences as a plain dict, including the file format version."""
        return {"version": PREFS_VERSION, **{f.name: getattr(self, f.name) for f in fields(self)}}

    @classmethod
    def from_dict(cls, data):
        """Build preferences from a dict that must contain exactly the known keys."""
        if not isinstance(data, dict):
            raise ValueError("preferences must be a JSON object")
        names = {f.name for f in fields(cls)}
        version = data.get("version")
        problems = [] if type(version) is int and version == PREFS_VERSION else [f"version: must be {PREFS_VERSION}"]
        problems += [f"{name}: missing" for name in sorted(names - set(data))]
        problems += [f"{str(name)[:30]!r}: unknown preference" for name in sorted(set(data) - names - {"version"})]
        if problems:
            raise ValueError("; ".join(problems))
        return cls(**{name: data[name] for name in names})

    @property
    def text_scale(self):
        """Return the text size as a multiplier."""
        return self.text_percent / 100


DEFAULT_PREFS = UiPrefs()


@dataclass(frozen=True)
class PrefsLoad:
    """Preferences in effect plus any warnings to show the user."""

    prefs: UiPrefs
    warnings: tuple = ()


def default_path():
    """Return the preferences file location, next to the scoring settings."""
    return settings.default_path().with_name("ui.json")


def load(path=None):
    """Load preferences, falling back to defaults with a warning if the file is unusable."""
    path = Path(path) if path else default_path()
    if not path.exists():
        return PrefsLoad(DEFAULT_PREFS)
    try:
        return PrefsLoad(UiPrefs.from_dict(jsonfile.read_json(path, MAX_PREFS_BYTES)))
    except (OSError, ValueError, RecursionError) as error:
        return PrefsLoad(DEFAULT_PREFS, ((f"Appearance preferences in {path} could not be used ({error}). "
                                          "Default preferences are in effect."),))


def save(prefs, path=None):
    """Write preferences atomically with user-only permissions."""
    jsonfile.write_json_atomic(Path(path) if path else default_path(), prefs.to_dict())
