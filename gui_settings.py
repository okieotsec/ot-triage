"""The Settings view: scoring settings with live validation, and appearance preferences."""
import tkinter as tk

import settings as scoring
import uiprefs
from gui_widgets import ScrollFrame, Segmented, button, card, rounded_entry, set_enabled
from settings import SPEC, Settings

TITLES = {"cvss_high": "CVSS High line", "cvss_critical": "CVSS Critical line",
          "epss_percentile_cutoff": "EPSS percentile cutoff", "stale_days": "Stale after (days)"}
DESCRIPTIONS = {
    "cvss_high": "CVSS score where a vulnerability counts as High. Used by the public-exploit rule, the "
                 "no-exploit rule and the end-of-life floor.",
    "cvss_critical": "CVSS score where a vulnerability counts as Critical. Must be at least 0.5 above the High line.",
    "epss_percentile_cutoff": "EPSS percentile at or above which exploitation counts as likely.",
    "stale_days": "Days before downloaded threat data is flagged as stale. Only a warning; nothing stops working.",
}


def _show(value):
    return f"{value:g}" if isinstance(value, float) else str(value)


class SettingsState:
    """The text typed into the scoring fields, kept apart from the widgets so a rebuild does not lose it."""

    def __init__(self, root, settings):
        self.vars = {name: tk.StringVar(root, _show(getattr(settings, name))) for name in SPEC}


def parse_fields(texts):
    """Turn typed text into a Settings; return (settings, {field: message}). Fields without a message are fine."""
    values, errors = {}, {}
    for name, text in texts.items():
        kind = SPEC[name][0]
        text = text.strip()
        try:
            values[name] = int(text) if kind is int else float(text)
        except ValueError:
            kind_word = "a whole number" if kind is int else "a number"
            errors[name] = f"must be {kind_word} between {SPEC[name][2]} and {SPEC[name][3]}"
    if errors:
        return None, errors
    try:
        return Settings(**values), {}
    except ValueError as error:
        for part in str(error).split("; "):
            field = part.split(":", 1)[0].split(" ", 1)[0]
            errors[field if field in SPEC else "cvss_critical"] = part.split(": ", 1)[-1]
        return None, errors


class SettingsView:
    """Builds and updates the Settings screen."""

    name = "settings"

    def __init__(self, ctx, parent):
        self.ctx, self.style = ctx, ctx.style
        t = self.style.theme
        if ctx.settings_state is None:
            ctx.settings_state = SettingsState(ctx.root, ctx.settings)
        self.state = ctx.settings_state
        self.frame = tk.Frame(parent, bg=t.bg)
        self.scroll = ScrollFrame(self.frame, t.bg)
        self.scroll.pack(fill=tk.BOTH, expand=True)
        self.scroll.body.configure(padx=28, pady=24)
        self.entries, self.messages, self._traces = {}, {}, []
        self._build_scoring(self.scroll.body)
        self._build_appearance(self.scroll.body)
        for var in self.state.vars.values():
            self._traces.append((var, var.trace_add("write", self.validate)))
        self.frame.bind("<Destroy>", self._on_destroy)
        self.validate()

    def _on_destroy(self, event):
        if event.widget is self.frame:
            for var, trace in self._traces:
                try:
                    var.trace_remove("write", trace)
                except tk.TclError:
                    pass

    def _build_scoring(self, parent):
        s, t = self.style, self.style.theme
        box = card(parent, s, "Scoring")
        intro = tk.Label(box, text=("Only these four values can be changed. The rule structure is fixed. Changed "
                                    "values show a Custom scoring badge and are recorded in summaries and exports."),
                         font=s.font(9), bg=t.card, fg=t.muted, anchor="w", justify="left")
        intro.pack(fill=tk.X)
        intro.bind("<Configure>", lambda e: intro.configure(wraplength=max(e.width - 4, 100)))
        for name in SPEC:
            _kind, default, low, high, _description = SPEC[name]
            row = tk.Frame(box, bg=t.card)
            row.pack(fill=tk.X, pady=(12, 0))
            row.columnconfigure(0, weight=1)
            text = tk.Frame(row, bg=t.card)
            text.grid(row=0, column=0, sticky="ew", padx=(0, 16))
            tk.Label(text, text=TITLES[name], font=s.font(10, "bold"), bg=t.card, fg=t.text, anchor="w").pack(fill=tk.X)
            hint = tk.Label(text, text=f"{DESCRIPTIONS[name]} Default {_show(default)}, allowed {low} to {high}.",
                            font=s.font(9), bg=t.card, fg=t.muted, anchor="w", justify="left")
            hint.pack(fill=tk.X)
            hint.bind("<Configure>", lambda e, w=hint: w.configure(wraplength=max(e.width - 4, 100)))
            entry = rounded_entry(row, s, self.state.vars[name], width=9, justify="center", outside=t.card)
            entry.grid(row=0, column=1, ipady=5)
            message = tk.Label(row, text="", font=s.font(9), bg=t.card, fg=t.error, anchor="w", justify="left")
            message.grid(row=1, column=0, columnspan=2, sticky="ew")
            self.entries[name], self.messages[name] = entry, message
        self.status = tk.Label(box, text="", font=s.font(9), bg=t.card, fg=t.muted, anchor="w")
        self.status.pack(fill=tk.X, pady=(12, 0))
        buttons = tk.Frame(box, bg=t.card)
        buttons.pack(fill=tk.X, pady=(8, 0))
        self.save_button = button(buttons, s, "Save", self.save)
        self.save_button.pack(side=tk.LEFT)
        button(buttons, s, "Restore defaults…", self.restore_defaults, "secondary").pack(side=tk.LEFT, padx=8)
        tk.Label(buttons, text="Restore asks for confirmation first.", font=s.font(9), bg=t.card, fg=t.muted).pack(
            side=tk.LEFT)

    def _build_appearance(self, parent):
        s, t = self.style, self.style.theme
        box = card(parent, s, "Appearance (this computer only)")
        prefs = self.ctx.prefs
        self.theme_var = tk.StringVar(box, prefs.theme)
        self.size_var = tk.StringVar(box, str(prefs.text_percent))
        self.startup_var = tk.BooleanVar(box, prefs.startup_update)
        row = tk.Frame(box, bg=t.card)
        row.pack(fill=tk.X)
        tk.Label(row, text="Theme", font=s.font(10), bg=t.card, fg=t.text, width=10, anchor="w").pack(side=tk.LEFT)
        Segmented(row, s, [("dark", "Dark"), ("light", "Light")], self.theme_var, self.apply_appearance).pack(
            side=tk.LEFT, fill=tk.X, expand=True)
        row = tk.Frame(box, bg=t.card)
        row.pack(fill=tk.X, pady=(10, 0))
        tk.Label(row, text="Text size", font=s.font(10), bg=t.card, fg=t.text, width=10, anchor="w").pack(side=tk.LEFT)
        Segmented(row, s, [(str(p), f"{p}%") for p in uiprefs.TEXT_PERCENTS], self.size_var,
                  self.apply_appearance).pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.startup_check = tk.Checkbutton(box, text="Update threat data when the app starts (off by default)",
                                            variable=self.startup_var, command=self.apply_appearance,
                                            font=s.font(10), bg=t.card, fg=t.text, selectcolor=t.field,
                                            activebackground=t.card, activeforeground=t.text, anchor="w",
                                            highlightthickness=0)
        self.startup_check.pack(fill=tk.X, pady=(12, 0))
        note = tk.Label(box, text=("Appearance choices are saved in a separate file from the scoring settings, so "
                                   "changing the theme can never make a result look custom."), font=s.font(9),
                        bg=t.card, fg=t.muted, anchor="w", justify="left")
        note.pack(fill=tk.X, pady=(8, 0))
        note.bind("<Configure>", lambda e: note.configure(wraplength=max(e.width - 4, 100)))

    # ---- scoring ----
    def typed(self):
        """Return the current text of each scoring field."""
        return {name: var.get() for name, var in self.state.vars.items()}

    def validate(self, *_args):
        """Check the typed values, show messages next to the fields, and enable Save accordingly."""
        t = self.style.theme
        parsed, errors = parse_fields(self.typed())
        for name, entry in self.entries.items():
            entry.configure(highlightbackground=t.error if name in errors else t.border,
                            highlightcolor=t.error if name in errors else t.accent)
            entry.repaint()
            self.messages[name].configure(text=f"✖ {errors[name]}" if name in errors else "")
        self.parsed = parsed
        if parsed is None:
            self.status.configure(text="Fix the highlighted values to save.", fg=t.error)
        elif parsed == self.ctx.settings:
            self.status.configure(text="Saved. " + ("These are the default values." if parsed.is_default else
                                                    "These values differ from the defaults, so the Custom scoring "
                                                    "badge is shown."), fg=t.muted)
        else:
            self.status.configure(text="Not saved yet.", fg=t.warn)
        set_enabled(self.save_button, parsed is not None and parsed != self.ctx.settings)

    def save(self):
        """Save the typed values and use them everywhere."""
        if self.parsed is None:
            return
        try:
            scoring.save(self.parsed, self.ctx.settings_path)
        except OSError as error:
            self.ctx.error("Settings not saved", f"The settings file could not be written: {error.strerror or error}")
            return
        self.ctx.settings_changed(self.parsed)
        self.validate()

    def restore_defaults(self):
        """After confirmation, reset every scoring value to its default."""
        if not self.ctx.confirm("Restore defaults", "Reset all four scoring settings to their default values?"):
            return
        try:
            restored = scoring.restore_defaults(self.ctx.settings_path)
        except OSError as error:
            self.ctx.error("Settings not saved", f"The settings file could not be written: {error.strerror or error}")
            return
        for name, var in self.state.vars.items():
            var.set(_show(getattr(restored, name)))
        self.ctx.settings_changed(restored)
        self.validate()

    # ---- appearance ----
    def apply_appearance(self):
        """Save the appearance choices and rebuild the window with them."""
        new = uiprefs.UiPrefs(self.theme_var.get(), int(self.size_var.get()), bool(self.startup_var.get()))
        if new == self.ctx.prefs:
            return
        try:
            uiprefs.save(new, self.ctx.prefs_path)
        except OSError as error:
            self.ctx.error("Preferences not saved", f"The preferences file could not be written: "
                                                    f"{error.strerror or error}")
            self.theme_var.set(self.ctx.prefs.theme)
            self.size_var.set(str(self.ctx.prefs.text_percent))
            self.startup_var.set(self.ctx.prefs.startup_update)
            return
        self.ctx.prefs_changed(new)
