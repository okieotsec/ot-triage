"""Colour tokens, fonts and ttk styling for the dark and light themes."""
import tkinter.font as tkfont
from dataclasses import dataclass
from tkinter import ttk


@dataclass(frozen=True)
class Theme:
    """One complete colour set."""

    name: str
    bg: str
    header: str
    card: str
    field: str
    border: str
    text: str
    muted: str
    accent: str
    on_accent: str
    primary: str
    on_primary: str
    copper: str
    error: str
    now: str
    on_now: str
    next: str
    on_next: str
    never: str
    on_never: str
    raise_: str
    lower: str
    neutral: str
    ok: str
    warn: str


# The OkieOTSec brand guide (v1.1): Oklahoma blue #2E6CB5, navy #14365C, sky #6BB0EC, copper #C56A33 (on dark
# #E08A4E), cream #FAF4E8, ink #13202E, dark surface #0D1520. Risk colours are not brand colours: NOW #D7263D,
# NEXT #E9A23B, NEVER #6B7682. Blue means navigation and action, copper is decoration only, and buttons are blue
# with white text.
DARK = Theme("dark", bg="#0d1520", header="#14365c", card="#13202e", field="#0d1520", border="#2c4258",
             text="#faf4e8", muted="#a9b8c9", accent="#6bb0ec", on_accent="#0d1520", primary="#2e6cb5",
             on_primary="#ffffff", copper="#e08a4e", error="#ff8b8b",
             now="#d7263d", on_now="#ffffff", next="#e9a23b", on_next="#13202e", never="#6b7682", on_never="#ffffff",
             raise_="#ff8b8b", lower="#4ade80", neutral="#a9b8c9", ok="#4ade80", warn="#fbbf24")
LIGHT = Theme("light", bg="#faf4e8", header="#ffffff", card="#ffffff", field="#fbf7ee", border="#d6c9ae",
              text="#13202e", muted="#4a5868", accent="#2e6cb5", on_accent="#ffffff", primary="#2e6cb5",
              on_primary="#ffffff", copper="#c56a33", error="#b91c1c",
              now="#d7263d", on_now="#ffffff", next="#e9a23b", on_next="#13202e", never="#6b7682", on_never="#ffffff",
              raise_="#b91c1c", lower="#166534", neutral="#4a5868", ok="#166534", warn="#92400e")
THEMES = {"dark": DARK, "light": LIGHT}

# Body text: the brand's IBM Plex Sans when it is installed, then a good system font. Titles use Space Grotesk and
# values and identifiers use IBM Plex Mono, each with fallbacks (the guide's own fallbacks are Arial and Consolas).
PREFERRED_FONTS = ("IBM Plex Sans", "Inter", "Adwaita Sans", "Cantarell", "Noto Sans", "Segoe UI", "SF Pro Text",
                   "Helvetica Neue")
TITLE_FONTS = ("Space Grotesk",)
MONO_FONTS = ("IBM Plex Mono", "Cascadia Mono", "Consolas", "DejaVu Sans Mono", "Menlo", "Liberation Mono")
FONT_BOOST = 1.1

SYMBOLS = {"raise": "▲", "lower": "▼", "neutral": "▬", "ok": "✓", "warn": "⚠",
           "error": "!"}
PRIORITY_SYMBOLS = {"NOW": "▲", "NEXT": "▬", "NEVER": "▼", "ERROR": "!"}

# (foreground, background) pairs that carry text, used by the contrast test
TEXT_PAIRS = [("text", "bg"), ("text", "card"), ("text", "field"), ("text", "header"), ("muted", "bg"),
              ("muted", "card"), ("muted", "field"), ("muted", "header"), ("accent", "card"), ("accent", "bg"),
              ("accent", "header"), ("on_accent", "accent"), ("on_primary", "primary"),
              ("on_now", "now"), ("on_next", "next"), ("on_never", "never"), ("raise_", "card"), ("lower", "card"),
              ("neutral", "card"), ("ok", "card"), ("warn", "card"), ("error", "card"), ("raise_", "bg"),
              ("warn", "header"), ("ok", "header")]


def _luminance(color):
    channels = [int(color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def contrast(foreground, background):
    """Return the WCAG contrast ratio between two #rrggbb colours."""
    high, low = sorted((_luminance(foreground), _luminance(background)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def choose_family(root, preferred=PREFERRED_FONTS):
    """Return the nicest installed font from a list, falling back to the system default."""
    available = set(tkfont.families(root))
    for family in preferred:
        if family in available:
            return family
    return tkfont.nametofont("TkDefaultFont", root=root).actual("family")


class Style:
    """A theme plus a text scale, handing out colours and fonts to widgets."""

    def __init__(self, theme, scale=1.0):
        self.theme, self.scale = theme, scale
        self.family = self.title_family = self.mono_family = "TkDefaultFont"

    def font(self, size, weight="normal", kind="body"):
        """Return a Tk font tuple scaled by the text size preference; kind is body, title or mono."""
        family = {"title": self.title_family, "mono": self.mono_family}.get(kind, self.family)
        return (family, max(7, round(size * FONT_BOOST * self.scale)), weight)

    def bucket(self, priority):
        """Return (background, foreground) colours for a priority badge."""
        t = self.theme
        return {"NOW": (t.now, t.on_now), "NEXT": (t.next, t.on_next), "NEVER": (t.never, t.on_never)}.get(
            priority, (t.field, t.error if priority == "ERROR" else t.muted))

    def direction(self, direction):
        """Return the colour for a raise, lower, neutral, ok, warn or error indicator."""
        t = self.theme
        return {"raise": t.raise_, "lower": t.lower, "neutral": t.neutral, "ok": t.ok, "warn": t.warn,
                "error": t.error}.get(direction, t.neutral)

    def priority_text_color(self, priority):
        """Return the colour for priority text on a card."""
        return {"NOW": self.theme.raise_, "NEXT": self.theme.warn, "NEVER": self.theme.neutral,
                "ERROR": self.theme.error}.get(priority, self.theme.text)


def apply_ttk_styles(root, style):
    """Configure the ttk widgets (table, scrollbar, progress bar) for the theme."""
    t, s = style.theme, ttk.Style(root)
    style.family = choose_family(root)
    style.title_family = choose_family(root, TITLE_FONTS + (style.family,))
    style.mono_family = choose_family(root, MONO_FONTS)
    s.theme_use("clam")
    s.configure("Treeview", background=t.card, fieldbackground=t.card, foreground=t.text, borderwidth=0,
                rowheight=round(28 * style.scale), font=style.font(10), bordercolor=t.card, lightcolor=t.card,
                darkcolor=t.card)
    s.configure("Treeview.Heading", background=t.border, foreground=t.text, relief="flat", padding=6,
                font=style.font(9, "bold"), bordercolor=t.border, lightcolor=t.border, darkcolor=t.border)
    s.map("Treeview", background=[("selected", t.primary)], foreground=[("selected", t.on_primary)])
    s.map("Treeview.Heading", background=[("active", t.border)])
    s.configure("Vertical.TScrollbar", background=t.border, troughcolor=t.card, bordercolor=t.card,
                arrowcolor=t.text, lightcolor=t.border, darkcolor=t.border)
    s.map("Vertical.TScrollbar", background=[("disabled", t.card), ("pressed", t.muted), ("active", t.muted)],
          lightcolor=[("disabled", t.card), ("pressed", t.muted), ("active", t.muted)],
          darkcolor=[("disabled", t.card), ("pressed", t.muted), ("active", t.muted)],
          arrowcolor=[("disabled", t.border)])
    s.configure("Score.Horizontal.TProgressbar", troughcolor=t.field, background=t.accent, bordercolor=t.border,
                lightcolor=t.accent, darkcolor=t.accent, thickness=10)
    for name in ("Score.Horizontal.TProgressbar", "Busy.Horizontal.TProgressbar"):
        s.map(name, background=[("disabled", t.border)], lightcolor=[("disabled", t.border)],
              darkcolor=[("disabled", t.border)])
    s.configure("Busy.Horizontal.TProgressbar", troughcolor=t.field, background=t.accent, bordercolor=t.border,
                lightcolor=t.accent, darkcolor=t.accent, thickness=6)
