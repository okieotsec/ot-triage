#!/usr/bin/env python3
"""Tkinter GUI for the Now / Next / Never vulnerability prioritizer: window shell, navigation and status bar."""
import dataclasses
import gc
import sys
import tkinter as tk
import traceback
from tkinter import messagebox

import settings as scoring
import uiprefs
from gui_about import AboutView
from gui_assess import AssessView
from gui_batch import BatchView
from gui_context import Context
from gui_round import shape_label
from gui_settings import SettingsView
from gui_theme import THEMES, Style, apply_ttk_styles
from gui_threat import ThreatUpdater, ThreatView
from gui_widgets import chip
from version import __version__

VIEWS = [("assess", "Assess", AssessView), ("batch", "Batch", BatchView), ("threat", "Threat data", ThreatView),
         ("settings", "Settings", SettingsView), ("about", "About", AboutView)]
NARROW_BELOW = 900
NARROW_MARGIN = 40  # the layout only changes when the width is clearly past the threshold, never right on it
SUBTITLE = "Now / Next / Never triage from CVSS, threat intel, asset value, exposure and mitigations"


def fit_window(win, width, height, min_width, min_height):
    """Size a window to the requested size, capped to the screen, and set its minimum size."""
    max_w = int(win.winfo_screenwidth() * 0.92)
    max_h = int(win.winfo_screenheight() * 0.85)
    win.geometry(f"{min(width, max_w)}x{min(height, max_h)}")
    win.minsize(min(min_width, max_w), min(min_height, max_h))


class App:
    """The application window."""

    def __init__(self, root, settings_path=None, prefs_path=None, data_dir=None):
        self.root = root
        loaded = scoring.load(settings_path)
        prefs_loaded = uiprefs.load(prefs_path)
        self.style = Style(THEMES[prefs_loaded.prefs.theme], prefs_loaded.prefs.text_scale)
        apply_ttk_styles(root, self.style)
        self.ctx = Context(root, self.style, loaded.settings, prefs_loaded.prefs, app=self)
        self.ctx.settings_path, self.ctx.prefs_path, self.ctx.data_dir = settings_path, prefs_path, data_dir
        self.ctx.updater = ThreatUpdater(self.ctx)
        self.ctx.updater.listeners.append(self.refresh_status)
        self.views, self.current, self.narrow = {}, "assess", None
        root.title("Vulnerability Prioritizer")
        fit_window(root, 1180, 800, 700, 560)
        root.report_callback_exception = self.report_exception
        self._bind_shortcuts()
        self.build()
        warnings = list(loaded.warnings) + list(prefs_loaded.warnings)
        if warnings:
            root.after(200, lambda: self.ctx.warn("Settings", "\n\n".join(warnings)))
        if self.ctx.prefs.startup_update:
            root.after(600, lambda: self.ctx.updater.update(ask=False))

    # ---- building ----
    def build(self):
        """Create the header, navigation, content area and status bar from the current theme and text size."""
        for child in self.root.winfo_children():
            child.destroy()
        self.views = {}
        gc.collect()
        self.style = Style(THEMES[self.ctx.prefs.theme], self.ctx.prefs.text_scale)
        self.ctx.style = self.style
        apply_ttk_styles(self.root, self.style)
        t, s = self.style.theme, self.style
        self.root.configure(bg=t.bg)
        shell = self.shell = tk.Frame(self.root, bg=t.bg)
        shell.pack(fill=tk.BOTH, expand=True)
        shell.columnconfigure(1, weight=1)
        shell.rowconfigure(1, weight=1)
        self._build_header(shell)
        self.nav = tk.Frame(shell, bg=t.header, highlightthickness=0)
        self.nav_buttons, self.nav_items, self.nav_bars, self.nav_hints = {}, {}, {}, {}
        for index, (name, label, _cls) in enumerate(VIEWS, start=1):
            item = tk.Frame(self.nav, bg=t.header)
            bar = tk.Frame(item, width=4, bg=t.header)
            bar.pack(side=tk.LEFT, fill=tk.Y)
            button = tk.Button(item, text=label, anchor="w", relief="flat", bd=0, padx=12, pady=11, font=s.font(10),
                               cursor="hand2", highlightthickness=2, command=lambda n=name: self.show_view(n))
            button.pack(side=tk.LEFT, fill=tk.X, expand=True)
            hint = tk.Label(item, text=f"Ctrl+{index}", font=s.font(8), cursor="hand2")
            hint.pack(side=tk.RIGHT, padx=(0, 12))
            hint.bind("<Button-1>", lambda _e, n=name: self.show_view(n))
            self.nav_items[name], self.nav_bars[name], self.nav_buttons[name], self.nav_hints[name] = (
                item, bar, button, hint)
        self.content = tk.Frame(shell, bg=t.bg)
        self.status_bar = tk.Frame(shell, bg=t.header, highlightthickness=1, highlightbackground=t.border,
                                   highlightcolor=t.border)
        self.narrow = None
        width = self.root.winfo_width()
        self._layout(1 < width < NARROW_BELOW)
        self.root.bind("<Configure>", self._on_resize)
        self.show_view(self.current)
        self.refresh_status()

    def _build_header(self, parent):
        t, s = self.style.theme, self.style
        self.header = tk.Frame(parent, bg=t.header)
        self.header.grid(row=0, column=0, columnspan=2, sticky="ew")
        tk.Frame(self.header, bg=t.accent, height=3).pack(side=tk.BOTTOM, fill=tk.X)
        text = tk.Frame(self.header, bg=t.header)
        text.pack(side=tk.LEFT, padx=20, pady=12)
        tk.Label(text, text="Vulnerability Prioritizer", font=s.font(18, "bold"), bg=t.header, fg=t.text).pack(
            anchor="w")
        subtitle = tk.Label(text, text=SUBTITLE, font=s.font(9), bg=t.header, fg=t.muted, anchor="w", justify="left")
        subtitle.pack(anchor="w")
        subtitle.bind("<Configure>", lambda e: subtitle.configure(wraplength=max(e.width, 200)))
        self.badge = shape_label(self.header, "\u26a0 Custom scoring", s.font(9, "bold"), t.on_next, fill=t.next,
                                 outside=t.header, padx=14, pady=5)
        self._update_badge()

    def _update_badge(self):
        if self.ctx.settings.is_default:
            self.badge.pack_forget()
        else:
            self.badge.pack(side=tk.RIGHT, padx=20)

    def _layout(self, narrow):
        if narrow == self.narrow:
            return
        self.narrow = narrow
        self.nav.grid_forget()
        self.content.grid_forget()
        self.status_bar.grid_forget()
        for item in self.nav_items.values():
            item.pack_forget()
        if narrow:
            self.shell.rowconfigure(1, weight=0)
            self.shell.rowconfigure(2, weight=1)
            self.nav.grid(row=1, column=0, columnspan=2, sticky="new")
            self.content.grid(row=2, column=0, columnspan=2, sticky="nsew")
            self.status_bar.grid(row=3, column=0, columnspan=2, sticky="ew")
            for item in self.nav_items.values():
                item.pack(side=tk.LEFT, padx=2, pady=4)
            for hint in self.nav_hints.values():
                hint.pack_forget()
        else:
            self.shell.rowconfigure(2, weight=0)
            self.shell.rowconfigure(1, weight=1)
            self.nav.grid(row=1, column=0, sticky="ns")
            self.content.grid(row=1, column=1, sticky="nsew")
            self.status_bar.grid(row=2, column=0, columnspan=2, sticky="ew")
            self.nav.configure(width=int(210 * self.style.scale))
            for item in self.nav_items.values():
                item.pack(fill=tk.X, padx=8, pady=3)
            for hint in self.nav_hints.values():
                hint.pack(side=tk.RIGHT, padx=(0, 12))
        self._mark_current()

    def _on_resize(self, event):
        if event.widget is self.root:
            limit = NARROW_BELOW + NARROW_MARGIN if self.narrow else NARROW_BELOW - NARROW_MARGIN
            self._layout(event.width < limit)

    # ---- navigation ----
    def show_view(self, name):
        """Show one view, creating it the first time."""
        if name not in self.views:
            cls = next(c for n, _label, c in VIEWS if n == name)
            self.views[name] = cls(self.ctx, self.content)
        for view_name, view in self.views.items():
            if view_name == name:
                view.frame.pack(fill=tk.BOTH, expand=True)
            else:
                view.frame.pack_forget()
        self.current = name
        self._mark_current()
        view = self.views[name]
        if hasattr(view, "focus_first"):
            view.focus_first()

    def _mark_current(self):
        t = self.style.theme
        for name, button in self.nav_buttons.items():
            on = name == self.current
            row_bg = t.card if on else t.header
            self.nav_items[name].configure(bg=row_bg)
            self.nav_bars[name].configure(bg=t.accent if on else t.header)
            self.nav_hints[name].configure(bg=row_bg, fg=t.muted)
            button.configure(bg=row_bg, fg=t.text if on else t.muted, activebackground=t.card,
                             activeforeground=t.text, font=self.style.font(10, "bold" if on else "normal"),
                             highlightbackground=row_bg, highlightcolor=t.accent)

    def _bind_shortcuts(self):
        for index, (name, _label, _cls) in enumerate(VIEWS, start=1):
            self.root.bind_all(f"<Control-Key-{index}>", lambda _e, n=name: self.show_view(n))
        for sequence in ("<Control-l>", "<Control-L>"):
            self.root.bind_all(sequence, self._focus_cve)
        for sequence in ("<Control-Shift-C>", "<Control-Shift-c>"):
            self.root.bind_all(sequence, self._copy_summary)
        for sequence in ("<Control-plus>", "<Control-equal>", "<Control-KP_Add>"):
            self.root.bind_all(sequence, lambda _e: self.zoom(+1))
        for sequence in ("<Control-minus>", "<Control-KP_Subtract>"):
            self.root.bind_all(sequence, lambda _e: self.zoom(-1))
        for sequence in ("<Control-Key-0>", "<Control-KP_0>"):
            self.root.bind_all(sequence, lambda _e: self.zoom(0))

    def zoom(self, direction):
        """Make the text one step larger or smaller (0 resets it), remember the choice and rebuild the window."""
        steps = uiprefs.TEXT_PERCENTS
        current = steps.index(self.ctx.prefs.text_percent)
        target = steps.index(uiprefs.DEFAULT_PREFS.text_percent) if direction == 0 else current + direction
        if not 0 <= target < len(steps) or target == current:
            return "break"
        new = dataclasses.replace(self.ctx.prefs, text_percent=steps[target])
        try:
            uiprefs.save(new, self.ctx.prefs_path)
        except OSError as error:
            self.ctx.error("Preferences not saved", f"The preferences file could not be written: "
                                                    f"{error.strerror or error}")
            return "break"
        self.ctx.prefs_changed(new)
        return "break"

    def _focus_cve(self, _event=None):
        self.show_view("assess")
        self.views["assess"].focus_cve()
        return "break"

    def _copy_summary(self, _event=None):
        view = self.views.get(self.current)
        if hasattr(view, "copy_summary"):
            view.copy_summary()
        return "break"

    # ---- status bar ----
    def refresh_status(self):
        """Redraw the status bar: freshness of each data source, scoring mode and the Update button."""
        if not self.status_bar.winfo_exists():
            return
        t, s = self.style.theme, self.style
        for child in self.status_bar.winfo_children():
            child.destroy()
        for status in self.ctx.status():
            fresh = status.freshness(self.ctx.settings.stale_days)
            if status.problem:
                direction, text = "error", f"{status.label} problem"
            elif not status.loaded:
                direction, text = "warn", f"{status.label} not loaded"
            else:
                direction = "warn" if fresh.stale else "ok"
                age = fresh.text.rsplit("retrieved ", 1)[-1].replace(" ago", "") if "retrieved" in fresh.text else "?"
                text = f"{status.label} {status.version} · {age}" + (" (stale)" if fresh.stale else "")
            widget = chip(self.status_bar, s, text, direction, bg=t.header)
            widget.pack(side=tk.LEFT, padx=(12, 0), pady=6)
            widget.bind("<Button-1>", lambda _e: self.show_view("threat"))
            widget.configure(cursor="hand2")
        busy = self.ctx.updater is not None and self.ctx.updater.busy
        tk.Button(self.status_bar, text="Updating…" if busy else "Update", font=s.font(9), relief="flat", bd=0,
                  padx=10, pady=3, bg=t.field, fg=t.text, activebackground=t.card, activeforeground=t.text,
                  highlightthickness=2, highlightbackground=t.field, highlightcolor=t.accent,
                  state="disabled" if busy else "normal", disabledforeground=t.muted,
                  command=self.start_update).pack(side=tk.RIGHT, padx=12, pady=4)
        tk.Label(self.status_bar, text="Scoring: " + ("defaults" if self.ctx.settings.is_default else "custom"),
                 font=s.font(9), bg=t.header, fg=t.warn if not self.ctx.settings.is_default else t.muted).pack(
            side=tk.RIGHT)

    def start_update(self):
        """Open the Threat data view and start an update (after confirmation)."""
        self.show_view("threat")
        self.ctx.updater.update()

    # ---- changes from the views ----
    def settings_changed(self):
        """Apply new scoring settings: update the badge, status bar and any view that shows results."""
        self._update_badge()
        self.refresh_status()
        for name in ("assess", "batch"):
            if name in self.views:
                self.views[name].refresh()

    def prefs_changed(self):
        """Rebuild the whole window with new appearance preferences."""
        self.build()

    def report_exception(self, exc_type, exc, tb):
        """Show a short message for an unexpected error and keep the details on the terminal only."""
        traceback.print_exception(exc_type, exc, tb, file=sys.stderr)
        try:
            messagebox.showerror("Something went wrong", f"An unexpected error occurred ({exc_type.__name__}). "
                                                         "Your data was not changed. You can keep working.",
                                 parent=self.root)
        except tk.TclError:
            pass


def main():
    """Start the application."""
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    print(f"Vulnerability Prioritizer {__version__}", file=sys.stderr)
    main()
