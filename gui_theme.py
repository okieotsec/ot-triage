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


DARK = Theme("dark", bg="#0f172a", header="#111c33", card="#1e293b", field="#0f172a", border="#334155",
             text="#e2e8f0", muted="#94a3b8", accent="#38bdf8", on_accent="#0f172a", error="#f87171",
             now="#dc2626", on_now="#ffffff", next="#f59e0b", on_next="#0f172a", never="#22c55e", on_never="#0f172a",
             raise_="#f87171", lower="#4ade80", neutral="#94a3b8", ok="#4ade80", warn="#fbbf24")
LIGHT = Theme("light", bg="#f4efe2", header="#fffdf8", card="#fffdf8", field="#faf6ea", border="#cfc6ad",
              text="#111c2e", muted="#4a4a42", accent="#0369a1", on_accent="#ffffff", error="#b91c1c",
              now="#dc2626", on_now="#ffffff", next="#f59e0b", on_next="#0f172a", never="#22c55e", on_never="#0f172a",
              raise_="#b91c1c", lower="#166534", neutral="#4a4a42", ok="#166534", warn="#92400e")
THEMES = {"dark": DARK, "light": LIGHT}

PREFERRED_FONTS = ("Inter", "Adwaita Sans", "Cantarell", "Noto Sans", "Segoe UI", "SF Pro Text", "Helvetica Neue")
FONT_BOOST = 1.1

SYMBOLS = {"raise": "▲", "lower": "▼", "neutral": "▬", "ok": "✓", "warn": "⚠",
           "error": "!"}
PRIORITY_SYMBOLS = {"NOW": "▲", "NEXT": "▬", "NEVER": "▼", "ERROR": "!"}

# (foreground, background) pairs that carry text, used by the contrast test
TEXT_PAIRS = [("text", "bg"), ("text", "card"), ("text", "field"), ("text", "header"), ("muted", "bg"),
              ("muted", "card"), ("muted", "field"), ("accent", "card"), ("accent", "bg"), ("on_accent", "accent"),
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


def choose_family(root):
    """Return the nicest installed UI font, falling back to the system default."""
    available = set(tkfont.families(root))
    for family in PREFERRED_FONTS:
        if family in available:
            return family
    return tkfont.nametofont("TkDefaultFont", root=root).actual("family")


class Style:
    """A theme plus a text scale, handing out colours and fonts to widgets."""

    def __init__(self, theme, scale=1.0):
        self.theme, self.scale = theme, scale
        self.family = "TkDefaultFont"

    def font(self, size, weight="normal"):
        """Return a Tk font tuple scaled by the text size preference."""
        return (self.family, max(7, round(size * FONT_BOOST * self.scale)), weight)

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
        return {"NOW": self.theme.raise_, "NEXT": self.theme.warn, "NEVER": self.theme.ok,
                "ERROR": self.theme.error}.get(priority, self.theme.text)


def apply_ttk_styles(root, style):
    """Configure the ttk widgets (table, scrollbar, progress bar) for the theme."""
    t, s = style.theme, ttk.Style(root)
    style.family = choose_family(root)
    s.theme_use("clam")
    s.configure("Treeview", background=t.card, fieldbackground=t.card, foreground=t.text, borderwidth=0,
                rowheight=round(28 * style.scale), font=style.font(10), bordercolor=t.card, lightcolor=t.card,
                darkcolor=t.card)
    s.configure("Treeview.Heading", background=t.border, foreground=t.text, relief="flat", padding=6,
                font=style.font(9, "bold"), bordercolor=t.border, lightcolor=t.border, darkcolor=t.border)
    s.map("Treeview", background=[("selected", t.accent)], foreground=[("selected", t.on_accent)])
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
