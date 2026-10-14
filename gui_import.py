"""The scanner import preview: what will be imported and skipped, and the choices that change it.

The reading of the export files is done before this window opens (in the background, see gui_batch); everything here is
quick: it merges the same reading again each time an option changes, and shows what the result would be.
"""
import tkinter as tk
from dataclasses import dataclass

import scanimport
from gui_widgets import Segmented, button, grab_when_visible, set_enabled

THREAT_CHOICES = [("", "Leave empty"), ("none", "None"), ("public", "Public exploit"), ("active", "Active")]
EXPORT_TYPES = [("Scanner exports", "*.csv *.nessus *.json *.xml"), ("All files", "*.*")]
CSV_TYPES = [("CSV files", "*.csv"), ("All files", "*.*")]


@dataclass
class ImportChoice:
    """What the person decided in the preview."""

    result: object              # the merged scanimport.ImportResult
    existing_inventory: str     # an inventory to extend ("" for none)
    aliases: str                # an aliases file ("" for none)
    threat: str                 # the threat level for findings with no CVE ("" for none)


class ImportPreview:
    """A modal window with the summary of an import and the options that change it."""

    def __init__(self, parent, style, raw, ask_file, title="Import scanner export"):
        self.parent, self.style, self.raw, self.ask_file = parent, style, raw, ask_file
        self.aliases_path, self.inventory_path, self.aliases = "", "", None
        self.result, self.choice = None, None
        t = style.theme
        self.window = tk.Toplevel(parent)
        self.window.title(title)
        self.window.configure(bg=t.card)
        self.window.transient(parent.winfo_toplevel())
        self.window.resizable(False, False)
        self._build()
        self.refresh()
        self.window.bind("<Escape>", lambda _e: self.cancel())
        self.window.protocol("WM_DELETE_WINDOW", self.cancel)
        self.window.lift()
        self.window.focus_force()
        grab_when_visible(self.window)

    def _build(self):
        s, t, w = self.style, self.style.theme, self.window
        width = int(520 * s.scale)
        tk.Label(w, text="What will be imported", font=s.font(11, "bold"), bg=t.card, fg=t.text, anchor="w").pack(
            fill=tk.X, padx=18, pady=(16, 6))
        frame = tk.Frame(w, bg=t.card)
        frame.pack(fill=tk.X, padx=18)
        self.summary = tk.Text(frame, width=70, height=13, wrap="word", font=s.font(9), bg=t.field, fg=t.text,
                               relief="flat", padx=8, pady=6, highlightthickness=1, highlightbackground=t.border,
                               state="disabled")
        self.summary.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        bar = tk.Scrollbar(frame, command=self.summary.yview)
        bar.pack(side=tk.RIGHT, fill=tk.Y)
        self.summary.configure(yscrollcommand=bar.set)
        self.need = tk.Label(w, text="", font=s.font(9), bg=t.card, fg=t.muted, anchor="w", justify="left",
                             wraplength=width)
        self.need.pack(fill=tk.X, padx=18, pady=(10, 4))
        self.threat = tk.StringVar(w, "")
        self.threat_control = Segmented(w, s, THREAT_CHOICES, self.threat, command=lambda *_: self.refresh())
        self.threat_control.pack(fill=tk.X, padx=18)
        tk.Label(w, text="Aliases file (optional): the names one device goes by in different tools",
                 font=s.font(9), bg=t.card, fg=t.muted, anchor="w").pack(fill=tk.X, padx=18, pady=(12, 2))
        row = tk.Frame(w, bg=t.card)
        row.pack(fill=tk.X, padx=18)
        self.aliases_label = tk.Label(row, text="None", font=s.font(9), bg=t.card, fg=t.text, anchor="w")
        button(row, s, "Choose…", self.choose_aliases, "secondary").pack(side=tk.RIGHT)
        self.aliases_clear = button(row, s, "Clear", self.clear_aliases, "secondary")
        self.aliases_clear.pack(side=tk.RIGHT, padx=(0, 6))
        self.aliases_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Label(w, text="Your existing inventory (optional): new assets are added to a copy, and it is never changed",
                 font=s.font(9), bg=t.card, fg=t.muted, anchor="w").pack(fill=tk.X, padx=18, pady=(12, 2))
        row = tk.Frame(w, bg=t.card)
        row.pack(fill=tk.X, padx=18)
        self.inventory_label = tk.Label(row, text="None", font=s.font(9), bg=t.card, fg=t.text, anchor="w")
        button(row, s, "Choose…", self.choose_inventory, "secondary").pack(side=tk.RIGHT)
        self.inventory_clear = button(row, s, "Clear", self.clear_inventory, "secondary")
        self.inventory_clear.pack(side=tk.RIGHT, padx=(0, 6))
        self.inventory_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.error = tk.Label(w, text="", font=s.font(9), bg=t.card, fg=t.error, anchor="w", justify="left",
                              wraplength=width)
        self.error.pack(fill=tk.X, padx=18, pady=(8, 0))
        buttons = tk.Frame(w, bg=t.card)
        buttons.pack(fill=tk.X, padx=18, pady=14)
        self.accept_button = button(buttons, s, "Save and open…", self.accept)
        self.accept_button.pack(side=tk.RIGHT)
        button(buttons, s, "Cancel", self.cancel, "secondary").pack(side=tk.RIGHT, padx=(0, 8))
        self.window.bind("<Return>", lambda _e: self.accept())

    # ---- choices ----
    def choose_aliases(self):
        path = self.ask_file("Select an aliases file (alias and asset_id columns)", CSV_TYPES)
        if path:
            self.aliases_path = path
            self.refresh()

    def clear_aliases(self):
        self.aliases_path = ""
        self.refresh()

    def choose_inventory(self):
        path = self.ask_file("Select your existing asset inventory", CSV_TYPES)
        if path:
            self.inventory_path = path
            self.refresh()

    def clear_inventory(self):
        self.inventory_path = ""
        self.refresh()

    def refresh(self):
        """Merge the reading again with the current choices and show what it would give."""
        self.error.configure(text="")
        self.aliases_label.configure(text=self.aliases_path or "None")
        self.inventory_label.configure(text=self.inventory_path or "None")
        set_enabled(self.aliases_clear, bool(self.aliases_path))
        set_enabled(self.inventory_clear, bool(self.inventory_path))
        try:
            aliases = scanimport.load_aliases(self.aliases_path) if self.aliases_path else None
            self.result = scanimport.merge(self.raw, aliases, self.threat.get())
        except scanimport.ScanImportError as error:
            self.result = None
            self.error.configure(text=str(error)[:400])
            self._show("")
            set_enabled(self.accept_button, False)
            return
        self._show("\n".join(scanimport.summary_lines(self.result)))
        count = self.result.need_threat
        plural = "s" if count != 1 else ""
        self.need.configure(text=(f"{count:,} finding{plural} with no CVE: choose a threat level for them below, or "
                                  "leave it empty and they will show as not scored until you add one."
                                  if count else "Every finding has a CVE, so a threat level can be looked up."))
        set_enabled(self.accept_button, bool(self.result.findings))

    def _show(self, text):
        self.summary.configure(state="normal")
        self.summary.delete("1.0", tk.END)
        self.summary.insert("1.0", text)
        self.summary.configure(state="disabled")

    def accept(self):
        if self.result is None or not self.result.findings:
            return
        self.choice = ImportChoice(self.result, self.inventory_path, self.aliases_path, self.threat.get())
        self.window.destroy()

    def cancel(self):
        self.window.destroy()

    def show(self):
        """Wait for the window to close; return the ImportChoice, or None if it was cancelled."""
        self.parent.wait_window(self.window)
        return self.choice


def ask_import(parent, style, raw, ask_file):
    """Show the preview for an unmerged reading; return an ImportChoice, or None if the person cancelled."""
    return ImportPreview(parent, style, raw, ask_file).show()
