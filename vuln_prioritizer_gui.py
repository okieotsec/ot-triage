import csv
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import tkinter.font as tkfont

import batch
from prioritizer import Asset, Controls, Exposure, Patch, Threat, parse_cvss, prioritize

# Palette
BG = "#0f172a"
HEADER = "#111c33"
CARD = "#1e293b"
FIELD = "#0f172a"
BORDER = "#334155"
TEXT = "#e2e8f0"
MUTED = "#94a3b8"
ACCENT = "#38bdf8"
ERROR = "#f87171"
PRIORITY_COLORS = {"NOW": "#ef4444", "NEXT": "#f59e0b", "NEVER": "#22c55e"}
PRIORITY_FG = {"NOW": "#ffffff", "NEXT": BG, "NEVER": BG}
PRIORITY_TEXT = {
    "NOW": ("Act immediately", "Remediate or mitigate right away."),
    "NEXT": ("Schedule remediation", "Plan it into the next patch cycle (roughly 30-90 days)."),
    "NEVER": ("No scheduled remediation", "Re-evaluate if conditions change."),
}
CVSS_BANDS = [  # (minimum score, label, colour)
    (9.0, "CRITICAL", "#ef4444"),
    (7.0, "HIGH", "#f97316"),
    (4.0, "MEDIUM", "#f59e0b"),
    (0.1, "LOW", "#22c55e"),
    (0.0, "NONE", MUTED),
]


def fit_window(win, width, height, min_width, min_height):
    """Size a window to the requested size, capped to the screen, and set its minimum size."""
    max_w = int(win.winfo_screenwidth() * 0.92)
    max_h = int(win.winfo_screenheight() * 0.85)
    win.geometry(f"{min(width, max_w)}x{min(height, max_h)}")
    win.minsize(min(min_width, max_w), min(min_height, max_h))


class VulnerabilityPrioritizer:
    def __init__(self, root):
        self.root = root
        root.title("Vulnerability Prioritizer")
        fit_window(root, 1120, 740, 980, 660)
        root.configure(bg=BG)

        self.family = tkfont.nametofont("TkDefaultFont").actual("family")
        self._init_styles()
        self._summary = ""

        self._build_header()
        body = tk.Frame(root, bg=BG)
        body.pack(fill=tk.BOTH, expand=True, padx=24, pady=20)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        left = tk.Frame(body, bg=BG)
        left.grid(row=0, column=0, sticky="ns", padx=(0, 20))
        right = tk.Frame(body, bg=BG)
        right.grid(row=0, column=1, sticky="nsew")

        self._build_inputs(left)
        self._build_results(right)

        for var in (self.cvss_var, self.threat_var, self.asset_var,
                    self.exposure_var, self.patch_var, self.controls_var):
            var.trace_add("write", self._update)
        self._update()
        self.cvss_entry.focus_set()

    # ---- helpers -------------------------------------------------------
    def font(self, size, weight="normal"):
        return (self.family, size, weight)

    def _init_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TCombobox", fieldbackground=FIELD, background=BORDER, foreground=TEXT,
                        arrowcolor=TEXT, bordercolor=BORDER, lightcolor=FIELD, darkcolor=FIELD,
                        selectbackground=FIELD, selectforeground=TEXT, padding=6)
        style.map("TCombobox",
                  fieldbackground=[("readonly", FIELD)],
                  foreground=[("readonly", TEXT)],
                  selectbackground=[("readonly", FIELD)],
                  selectforeground=[("readonly", TEXT)],
                  bordercolor=[("focus", ACCENT)])
        style.configure("Score.Horizontal.TProgressbar", troughcolor=FIELD, background=ACCENT,
                        bordercolor=CARD, lightcolor=ACCENT, darkcolor=ACCENT, thickness=10)
        style.configure("Vertical.TScrollbar", background=BORDER, troughcolor=CARD, bordercolor=CARD,
                        arrowcolor=TEXT, lightcolor=BORDER, darkcolor=BORDER)
        style.configure("Treeview", background=CARD, fieldbackground=CARD, foreground=TEXT,
                        borderwidth=0, rowheight=28, font=(self.family, 10))
        style.configure("Treeview.Heading", background=BORDER, foreground=TEXT, relief="flat",
                        padding=6, font=(self.family, 9, "bold"))
        style.map("Treeview", background=[("selected", ACCENT)], foreground=[("selected", BG)])
        style.map("Treeview.Heading", background=[("active", BORDER)])
        self.style = style
        self.root.option_add("*TCombobox*Listbox.background", FIELD)
        self.root.option_add("*TCombobox*Listbox.foreground", TEXT)
        self.root.option_add("*TCombobox*Listbox.selectBackground", ACCENT)
        self.root.option_add("*TCombobox*Listbox.selectForeground", BG)
        self.root.option_add("*TCombobox*Listbox.font", self.font(10))

    def _card(self, parent, title, expand=False):
        outer = tk.Frame(parent, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        outer.pack(fill=tk.BOTH if expand else tk.X, expand=expand, pady=(0, 14))
        tk.Label(outer, text=title.upper(), font=self.font(9, "bold"), bg=CARD, fg=ACCENT).pack(
            anchor="w", padx=16, pady=(12, 4))
        inner = tk.Frame(outer, bg=CARD)
        inner.pack(fill=tk.BOTH, expand=expand, padx=16, pady=(0, 14))
        return inner

    def _field_label(self, parent, text):
        tk.Label(parent, text=text, font=self.font(9), bg=CARD, fg=MUTED).pack(anchor="w", pady=(8, 3))

    def _combo(self, parent, label, enum_cls, default):
        self._field_label(parent, label)
        var = tk.StringVar(value=default.value)
        box = ttk.Combobox(parent, textvariable=var, values=[m.value for m in enum_cls],
                           state="readonly", font=self.font(10))
        box.pack(fill=tk.X)
        box.bind("<<ComboboxSelected>>", lambda _e: box.selection_clear())
        return var

    # ---- layout --------------------------------------------------------
    def _build_header(self):
        header = tk.Frame(self.root, bg=HEADER)
        header.pack(fill=tk.X)
        tk.Label(header, text="Vulnerability Prioritizer", font=self.font(20, "bold"),
                 bg=HEADER, fg=TEXT).pack(anchor="w", padx=24, pady=(16, 0))
        tk.Label(header, text="Now / Next / Never triage from CVSS, threat intel, asset value, exposure and mitigations",
                 font=self.font(10), bg=HEADER, fg=MUTED).pack(anchor="w", padx=24, pady=(2, 14))
        tk.Frame(header, bg=ACCENT, height=3).pack(fill=tk.X)
        self._button(header, "Batch import (CSV)", self.open_batch).place(relx=1.0, x=-24, y=22, anchor="ne")

    def _button(self, parent, text, command, **kwargs):
        btn = tk.Button(parent, text=text, command=command, font=self.font(10, "bold"), bg=ACCENT, fg=BG,
                        activebackground=TEXT, activeforeground=BG, relief="flat", bd=0, padx=16, pady=8,
                        cursor="hand2", **kwargs)
        return btn

    def open_batch(self):
        path = filedialog.askopenfilename(
            parent=self.root, title="Select a CSV of vulnerabilities",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if not path:
            return
        try:
            items = batch.process_file(path)
        except (OSError, UnicodeDecodeError, csv.Error, ValueError) as e:
            messagebox.showerror("Batch import failed", str(e), parent=self.root)
            return
        if not items:
            messagebox.showinfo("Batch import", "The file has a header but no data rows.", parent=self.root)
            return
        BatchWindow(self, path, items)

    def _build_inputs(self, parent):
        vuln = self._card(parent, "Vulnerability")
        self._field_label(vuln, "CVSS base score")
        row = tk.Frame(vuln, bg=CARD)
        row.pack(fill=tk.X)
        self.cvss_var = tk.StringVar()
        self.cvss_entry = tk.Entry(row, textvariable=self.cvss_var, width=6, justify="center",
                                   font=self.font(18, "bold"), bg=FIELD, fg=TEXT, insertbackground=TEXT,
                                   relief="flat", highlightthickness=1, highlightbackground=BORDER,
                                   highlightcolor=ACCENT)
        self.cvss_entry.pack(side=tk.LEFT, ipady=6)
        self.cvss_chip = tk.Label(row, text="", font=self.font(10, "bold"), bg=CARD, fg=MUTED)
        self.cvss_chip.pack(side=tk.LEFT, padx=14)
        self.cvss_hint = tk.Label(vuln, text="Enter a base score from 0.0 to 10.0", font=self.font(9),
                                  bg=CARD, fg=MUTED)
        self.cvss_hint.pack(anchor="w", pady=(4, 0))
        self.threat_var = self._combo(vuln, "Threat status", Threat, Threat.NONE)

        env = self._card(parent, "Asset & environment")
        self.asset_var = self._combo(env, "Asset criticality", Asset, Asset.STANDARD)
        self.exposure_var = self._combo(env, "Network exposure", Exposure, Exposure.LOW)

        rem = self._card(parent, "Remediation & mitigation")
        self.patch_var = self._combo(rem, "Patch status", Patch, Patch.AVAILABLE)
        self.controls_var = self._combo(rem, "Compensating controls", Controls, Controls.NONE)

    def _build_results(self, parent):
        result = self._card(parent, "Priority")
        top = tk.Frame(result, bg=CARD)
        top.pack(fill=tk.X)
        self.badge = tk.Label(top, text="-", width=7, font=self.font(34, "bold"), bg=FIELD, fg=MUTED)
        self.badge.pack(side=tk.LEFT, ipady=12)
        info = tk.Frame(top, bg=CARD)
        info.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=18)
        self.verdict = tk.Label(info, text="", font=self.font(16, "bold"), bg=CARD, fg=TEXT, anchor="w")
        self.verdict.pack(fill=tk.X)
        self.subtitle = tk.Label(info, text="", font=self.font(10), bg=CARD, fg=MUTED, anchor="w",
                                 justify="left")
        self.subtitle.pack(fill=tk.X, pady=(4, 0))
        self.subtitle.bind("<Configure>", lambda e: self.subtitle.config(wraplength=max(e.width - 4, 100)))

        score_row = tk.Frame(result, bg=CARD)
        score_row.pack(fill=tk.X, pady=(16, 4))
        tk.Label(score_row, text="Ordering score", font=self.font(9), bg=CARD, fg=MUTED).pack(side=tk.LEFT)
        self.score_label = tk.Label(score_row, text="", font=self.font(10, "bold"), bg=CARD, fg=TEXT)
        self.score_label.pack(side=tk.RIGHT)
        self.score_bar = ttk.Progressbar(result, maximum=10, style="Score.Horizontal.TProgressbar")
        self.score_bar.pack(fill=tk.X)
        tk.Label(result, text="Ranks items within a bucket; it does not decide the bucket.",
                 font=self.font(8), bg=CARD, fg=MUTED).pack(anchor="w", pady=(4, 0))

        action = self._card(parent, "Recommended action")
        self.action_label = tk.Label(action, text="", font=self.font(11), bg=CARD, fg=TEXT,
                                     anchor="w", justify="left")
        self.action_label.pack(fill=tk.X)
        self.action_label.bind("<Configure>", lambda e: self.action_label.config(wraplength=max(e.width - 4, 100)))

        why = self._card(parent, "Rationale", expand=True)
        holder = tk.Frame(why, bg=CARD)
        holder.pack(fill=tk.BOTH, expand=True)
        scroll = ttk.Scrollbar(holder, orient=tk.VERTICAL)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.rationale = tk.Text(holder, wrap=tk.WORD, height=8, font=self.font(10), bg=CARD, fg=TEXT,
                                 relief="flat", highlightthickness=0, padx=2, pady=2, cursor="arrow",
                                 yscrollcommand=scroll.set, state="disabled")
        self.rationale.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.config(command=self.rationale.yview)
        self.rationale.tag_config("item", lmargin1=0, lmargin2=16, spacing3=5)

        self.copy_btn = tk.Button(why, text="Copy summary", command=self._copy_summary, font=self.font(9, "bold"),
                                  bg=BORDER, fg=TEXT, activebackground=ACCENT, activeforeground=BG,
                                  relief="flat", bd=0, padx=12, pady=5, cursor="hand2", state="disabled")
        self.copy_btn.pack(anchor="e", pady=(10, 0))

    # ---- behaviour -----------------------------------------------------
    def _update(self, *_args):
        raw = self.cvss_var.get().strip()
        self._update_cvss_chip(raw)
        if not raw:
            self._show_idle("Waiting for input", "Enter a CVSS base score to calculate a priority.")
            return
        try:
            cvss = parse_cvss(raw)
        except ValueError as e:
            self.cvss_entry.config(highlightbackground=ERROR, highlightcolor=ERROR)
            self.cvss_hint.config(text=str(e), fg=ERROR)
            self._show_idle("Invalid input", str(e), error=True)
            return

        self.cvss_entry.config(highlightbackground=BORDER, highlightcolor=ACCENT)
        self.cvss_hint.config(text="Enter a base score from 0.0 to 10.0", fg=MUTED)
        res = prioritize(
            cvss,
            Threat(self.threat_var.get()),
            Asset(self.asset_var.get()),
            Exposure(self.exposure_var.get()),
            Controls(self.controls_var.get()),
            Patch(self.patch_var.get()),
        )
        color = PRIORITY_COLORS[res.priority]
        headline, sub = PRIORITY_TEXT[res.priority]
        self.badge.config(text=res.priority, bg=color, fg=PRIORITY_FG[res.priority])
        self.verdict.config(text=headline)
        self.subtitle.config(text=sub)
        self.style.configure("Score.Horizontal.TProgressbar", background=color, lightcolor=color, darkcolor=color)
        self.score_bar.config(value=res.score)
        self.score_label.config(text=f"{res.score:.2f} / 10")
        self.action_label.config(text=res.action)
        self._set_rationale(res.reasons)
        self._summary = (f"Priority: {res.priority} ({headline})\n"
                         f"Ordering score: {res.score:.2f}/10\n"
                         f"Action: {res.action}\n\n"
                         "Inputs:\n" + "\n".join(f"- {i}" for i in res.inputs)
                         + "\n\nRationale:\n" + "\n".join(f"- {r}" for r in res.reasons))
        self.copy_btn.config(state="normal")

    def _update_cvss_chip(self, raw):
        try:
            value = parse_cvss(raw)
        except ValueError:
            self.cvss_chip.config(text="")
            return
        _min, label, color = next(b for b in CVSS_BANDS if value >= b[0])
        self.cvss_chip.config(text=label, fg=color)

    def _show_idle(self, headline, sub, error=False):
        self.badge.config(text="!" if error else "-", bg=FIELD, fg=ERROR if error else MUTED)
        self.verdict.config(text=headline)
        self.subtitle.config(text=sub)
        self.score_bar.config(value=0)
        self.score_label.config(text="")
        self.action_label.config(text="")
        self._set_rationale([])
        self._summary = ""
        self.copy_btn.config(state="disabled")

    def _set_rationale(self, reasons):
        self.rationale.config(state="normal")
        self.rationale.delete("1.0", tk.END)
        for reason in reasons:
            self.rationale.insert(tk.END, f"•  {reason}\n", "item")
        self.rationale.config(state="disabled")

    def _copy_summary(self):
        if self._summary:
            self.root.clipboard_clear()
            self.root.clipboard_append(self._summary)


class BatchWindow:
    """Ranked results of a batch import, with a detail pane and CSV export."""

    COLUMNS = [("rank", "#", 50, "center"), ("id", "ID", 100, "w"), ("name", "Name", 280, "w"),
               ("priority", "Priority", 80, "center"), ("score", "Score", 70, "center"),
               ("cvss", "CVSS", 60, "center"), ("action", "Action / error", 420, "w")]

    def __init__(self, app, path, items):
        self.app, self.path, self.items = app, path, items
        font = app.font
        win = self.win = tk.Toplevel(app.root)
        win.title(f"Batch results - {os.path.basename(path)}")
        fit_window(win, 1180, 720, 900, 560)
        win.configure(bg=BG)
        win.transient(app.root)

        top = tk.Frame(win, bg=HEADER)
        top.pack(fill=tk.X)
        tk.Label(top, text="Batch results", font=font(18, "bold"), bg=HEADER, fg=TEXT).pack(
            anchor="w", padx=24, pady=(14, 0))
        tk.Label(top, text=path, font=font(9), bg=HEADER, fg=MUTED).pack(anchor="w", padx=24, pady=(2, 12))
        tk.Frame(top, bg=ACCENT, height=3).pack(fill=tk.X)
        app._button(top, "Export ranked CSV", self.export).place(relx=1.0, x=-24, y=18, anchor="ne")

        body = tk.Frame(win, bg=BG)
        body.pack(fill=tk.BOTH, expand=True, padx=24, pady=16)

        counts = batch.summarize(items)
        chips = tk.Frame(body, bg=BG)
        chips.pack(fill=tk.X, pady=(0, 12))
        for label, color in (("NOW", PRIORITY_COLORS["NOW"]), ("NEXT", PRIORITY_COLORS["NEXT"]),
                             ("NEVER", PRIORITY_COLORS["NEVER"]), ("ERROR", ERROR)):
            chip = tk.Frame(chips, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
            chip.pack(side=tk.LEFT, padx=(0, 10))
            tk.Label(chip, text=str(counts[label]), font=font(18, "bold"), bg=CARD, fg=color).pack(
                side=tk.LEFT, padx=(14, 6), pady=8)
            tk.Label(chip, text=label.title() if label == "ERROR" else label, font=font(9, "bold"),
                     bg=CARD, fg=MUTED).pack(side=tk.LEFT, padx=(0, 14))
        tk.Label(chips, text=f"{len(items)} rows", font=font(10), bg=BG, fg=MUTED).pack(side=tk.RIGHT)

        table = tk.Frame(body, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        table.pack(fill=tk.BOTH, expand=True)
        scroll = ttk.Scrollbar(table, orient=tk.VERTICAL)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree = ttk.Treeview(table, columns=[c[0] for c in self.COLUMNS], show="headings",
                                 selectmode="browse", yscrollcommand=scroll.set)
        scroll.config(command=self.tree.yview)
        for key, title, width, anchor in self.COLUMNS:
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width, anchor=anchor, stretch=(key == "action"))
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        for name, color in list(PRIORITY_COLORS.items()) + [("ERROR", ERROR)]:
            self.tree.tag_configure(name, foreground=color)

        rank = 0
        for index, item in enumerate(items):
            if item.result:
                rank += 1
                values = (rank, item.id, item.name, item.priority, f"{item.result.score:.2f}",
                          f"{item.cvss:.1f}", item.result.action)
            else:
                values = ("", item.id, item.name, "ERROR", "", item.cvss_raw, item.error)
            self.tree.insert("", tk.END, iid=str(index), values=values, tags=(item.priority,))

        detail = tk.Frame(body, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        detail.pack(fill=tk.X, pady=(12, 0))
        tk.Label(detail, text="DETAILS", font=font(9, "bold"), bg=CARD, fg=ACCENT).pack(
            anchor="w", padx=16, pady=(10, 2))
        self.detail = tk.Text(detail, wrap=tk.WORD, height=7, font=font(10), bg=CARD, fg=TEXT, relief="flat",
                              highlightthickness=0, padx=14, pady=4, cursor="arrow", state="disabled")
        self.detail.pack(fill=tk.X, padx=2, pady=(0, 10))
        self.detail.tag_config("item", lmargin1=0, lmargin2=16, spacing3=4)

        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        if self.tree.get_children():
            first = self.tree.get_children()[0]
            self.tree.selection_set(first)
            self.tree.focus(first)

    def _on_select(self, _event):
        selection = self.tree.selection()
        if not selection:
            return
        item = self.items[int(selection[0])]
        label = f"{item.id}  {item.name}".strip() or f"Line {item.line}"
        lines = [f"Source line {item.line}: {label}"]
        if item.result:
            lines += ([f"Action: {item.result.action}"] + [f"•  {r}" for r in item.result.reasons]
                      + ["Inputs: " + "; ".join(item.result.inputs)])
        else:
            lines += [f"•  {part}" for part in item.error.split("; ")]
        self.detail.config(state="normal")
        self.detail.delete("1.0", tk.END)
        self.detail.insert(tk.END, "\n".join(lines), "item")
        self.detail.config(state="disabled")

    def export(self):
        stem = os.path.splitext(os.path.basename(self.path))[0]
        out = filedialog.asksaveasfilename(
            parent=self.win, title="Export ranked results", defaultextension=".csv",
            initialfile=f"{stem}_ranked.csv", filetypes=[("CSV files", "*.csv")])
        if not out:
            return
        try:
            batch.write_results(out, self.items)
        except OSError as e:
            messagebox.showerror("Export failed", str(e), parent=self.win)
            return
        messagebox.showinfo("Exported", f"Saved {len(self.items)} rows to\n{out}", parent=self.win)


if __name__ == "__main__":
    root = tk.Tk()
    VulnerabilityPrioritizer(root)
    root.mainloop()
