"""The Batch view: score a CSV file, filter and search the ranked results, export them."""
import dataclasses
import os
import tkinter as tk
from tkinter import ttk

import batch
import compare
import explain
import gui_import
import inventory
import rollup
import scanimport
import threatdata
from gui_round import recolor_corners, round_corners
from gui_theme import PRIORITY_SYMBOLS
from gui_widgets import (
    AdvisoryList,
    FlowFrame,
    ReferenceList,
    ScrollFrame,
    Segmented,
    button,
    card,
    chip,
    rounded_entry,
    set_enabled,
    wrap_to_width,
)

ADVISORIES_TITLE = "ICS ADVISORIES FROM CISA"
POSSIBLE_TITLE = "ICS ADVISORIES THAT MAY APPLY (MATCHED ON VENDOR AND PRODUCT)"
REFERENCE_LIMIT = 5
DETAILS_MAX_HEIGHT = 150
FILTERS = [("all", "All"), ("NOW", "Now"), ("NEXT", "Next"), ("NEVER", "Never"), ("ERROR", "Error")]
COLUMNS = [("rank", "#", 46, "center"), ("id", "ID", 80, "w"), ("asset", "Asset", 112, "w"),
           ("cve", "CVE", 124, "w"), ("name", "Name", 200, "w"),
           ("priority", "Priority", 96, "w"), ("change", "Change", 118, "w"), ("score", "Score", 62, "center"),
           ("cvss", "CVSS", 54, "center"),
           ("source", "Threat source", 190, "w")]
ASSET_COLUMNS = [("asset", "Asset", 160, "w"), ("worst", "Worst", 92, "w"), ("now", "Now", 56, "center"),
                 ("next", "Next", 56, "center"), ("never", "Never", 62, "center"),
                 ("findings", "Findings", 76, "center"), ("score", "Top score", 84, "center"),
                 ("top", "Top finding", 260, "w")]
MODES = [("findings", "Findings"), ("assets", "By asset")]
CHANGE_ORDER = {compare.NEW: 0, compare.UP: 1, compare.DOWN: 2, compare.AMBIGUOUS: 3, compare.UNSCORED: 4,
                compare.SAME: 5, "": 6}
RESOLVED_LISTED = 25
FLEXIBLE_COLUMNS = ("name", "source")   # share what the fixed-width columns leave over
MIN_FLEXIBLE = {"name": 110, "source": 90}
NAME_SHARE = 0.55
HEADING_ARROWS = {False: " ▲", True: " ▼"}
SEARCH_DELAY_MS = 250


class BatchState:
    """The loaded batch, kept apart from the widgets so a theme change does not lose it."""

    def __init__(self):
        self.path, self.items, self.data = "", [], None
        self.inventory = None
        self.sort_key, self.sort_desc = "rank", False
        self.filter, self.search = "all", ""
        self.ranks = {}
        self.mode = "findings"                       # "findings" or "assets" (the per-asset roll-up)
        self.asset_sort_key, self.asset_sort_desc = "rollup", False
        self.summaries, self.unassigned = None, ()   # the roll-up, worked out the first time it is needed
        self.previous = None                         # (label, rows, skipped) of the export to compare with
        self.comparison = None                       # the current findings compared with it (compare.Comparison)


def _text(item):
    return f"{item.id} {item.name} {item.cve} {item.asset_id} {item.error} {item.threat_sources}".lower()


def _same_file(first, second):
    """True if two paths name the same file (an existing one, or the same path for one not written yet)."""
    try:
        if os.path.exists(first) and os.path.exists(second):
            return os.path.samefile(first, second)
    except OSError:
        return False
    return os.path.normcase(os.path.abspath(first)) == os.path.normcase(os.path.abspath(second))


class BatchView:
    """Builds and updates the Batch screen."""

    name = "batch"

    def __init__(self, ctx, parent):
        self.ctx, self.style = ctx, ctx.style
        t = self.style.theme
        if getattr(ctx, "batch_state", None) is None:
            ctx.batch_state = BatchState()
        self.state = ctx.batch_state
        self.frame = tk.Frame(parent, bg=t.bg)
        self.body = tk.Frame(self.frame, bg=t.bg, padx=28, pady=20)
        self.body.pack(fill=tk.BOTH, expand=True)
        self.search_var = tk.StringVar(self.frame, self.state.search)
        self._build_toolbar()
        self._build_counters()
        self._build_table()
        self._build_details()
        self._search_job = None
        self.search_var.trace_add("write", self._search_changed)
        self.frame.bind("<Destroy>", self._on_destroy)
        self.refresh()

    # ---- building ----
    def _build_toolbar(self):
        s, t = self.style, self.style.theme
        bar = self.toolbar = tk.Frame(self.body, bg=t.bg)
        bar.pack(fill=tk.X)
        self.open_button = button(bar, s, "Open CSV…", self.open_file)
        self.open_button.pack(side=tk.LEFT)
        self.import_button = button(bar, s, "Import scan\u2026", self.import_scanner, "secondary")
        self.import_button.pack(side=tk.LEFT, padx=(8, 0))
        self.file_label = tk.Label(bar, text="No file loaded", font=s.font(9), bg=t.bg, fg=t.muted, anchor="w")
        self.export_button = button(bar, s, "Export ranked CSV", self.export_current, "secondary")
        self.export_button.pack(side=tk.RIGHT)
        self.search_entry = rounded_entry(bar, s, self.search_var, width=26, size=10, outside=t.bg)
        self.search_entry.pack(side=tk.RIGHT, padx=10, ipady=5)
        tk.Label(bar, text="Search", font=s.font(9), bg=t.bg, fg=t.muted).pack(side=tk.RIGHT)
        # Packed last, so a long file description is clipped instead of squeezing the search box out.
        self.file_label.pack(side=tk.LEFT, padx=12, fill=tk.X, expand=True)
        self.inventory_row = tk.Frame(self.body, bg=t.bg)
        self.inventory_row.pack(fill=tk.X, pady=(8, 0))
        self.inventory_button = button(self.inventory_row, s, "Load inventory\u2026", self.load_inventory, "secondary")
        self.inventory_button.pack(side=tk.LEFT)
        self.inventory_clear_button = button(self.inventory_row, s, "Clear", self.clear_inventory, "secondary")
        self.inventory_clear_button.pack(side=tk.RIGHT)
        self.inventory_label = tk.Label(self.inventory_row, text="", font=s.font(9), bg=t.bg, fg=t.muted, anchor="w")
        self.inventory_label.pack(side=tk.LEFT, padx=12, fill=tk.X, expand=True)
        self._update_inventory_label()
        self.compare_row = tk.Frame(self.body, bg=t.bg)
        self.compare_row.pack(fill=tk.X, pady=(8, 0))
        self.compare_button = button(self.compare_row, s, "Compare with previous\u2026", self.compare_with,
                                     "secondary")
        self.compare_button.pack(side=tk.LEFT)
        self.compare_clear_button = button(self.compare_row, s, "Clear", self.clear_comparison, "secondary")
        self.compare_clear_button.pack(side=tk.RIGHT)
        self.resolved_button = button(self.compare_row, s, "Show resolved\u2026", self.show_resolved, "secondary")
        self.resolved_button.pack(side=tk.RIGHT, padx=8)
        self.compare_label = tk.Label(self.compare_row, text="", font=s.font(9), bg=t.bg, fg=t.muted, anchor="w")
        self.compare_label.pack(side=tk.LEFT, padx=12, fill=tk.X, expand=True)
        self._update_compare_label()
        self.progress_row = tk.Frame(self.body, bg=t.bg)
        self.progress_label = tk.Label(self.progress_row, text="", font=s.font(9), bg=t.bg, fg=t.muted)
        self.progress_label.pack(side=tk.LEFT)
        self.progress_bar = ttk.Progressbar(self.progress_row, mode="indeterminate", length=200,
                                            style="Busy.Horizontal.TProgressbar")
        self.progress_bar.pack(side=tk.LEFT, padx=10)
        button(self.progress_row, s, "Cancel", self.ctx.worker.cancel, "secondary").pack(side=tk.LEFT)

    def _build_counters(self):
        s, t = self.style, self.style.theme
        self.counter_row = tk.Frame(self.body, bg=t.bg)
        self.counter_row.pack(fill=tk.X, pady=(8, 8))
        # The bucket counters (findings view) and the asset summary (By asset view) share the left side
        self.counter_boxes = tk.Frame(self.counter_row, bg=t.bg)
        self.counter_boxes.pack(side=tk.LEFT)
        self.mode_note = tk.Label(self.counter_row, text="", font=s.font(9), bg=t.bg, fg=t.muted, anchor="w")
        self.counters = {}
        for key, label in FILTERS:
            box = tk.Frame(self.counter_boxes, bg=t.card, highlightthickness=2, highlightbackground=t.border,
                           highlightcolor=t.accent, takefocus=1, cursor="hand2")
            box.pack(side=tk.LEFT, padx=(0, 10))
            number = tk.Label(box, text="0", font=s.font(18, "bold"), bg=t.card,
                              fg=s.priority_text_color(key) if key != "all" else t.text)
            number.pack(anchor="w", padx=14, pady=(6, 0))
            word = tk.Label(box, text=f"{PRIORITY_SYMBOLS.get(key, '')} {label}".strip(), font=s.font(9, "bold"),
                            bg=t.card, fg=t.muted)
            word.pack(anchor="w", padx=14, pady=(0, 6))
            round_corners(box, 10, t.border, t.bg, ring_width=2, fill=t.card)
            for widget in (box, number, word):
                widget.bind("<Button-1>", lambda _e, k=key: self.set_filter(k))
            for sequence in ("<Return>", "<space>"):
                box.bind(sequence, lambda _e, k=key: self.set_filter(k))
            self.counters[key] = (box, number)
        self.mode_var = tk.StringVar(self.frame, self.state.mode)
        self.mode_control = Segmented(self.counter_row, s, MODES, self.mode_var)
        self.mode_control.pack(side=tk.RIGHT)
        self.mode_var.trace_add("write", lambda *_: self.set_mode(self.mode_var.get()))
        self.count_label = tk.Label(self.counter_row, text="", font=s.font(10), bg=t.bg, fg=t.muted)
        self.count_label.pack(side=tk.RIGHT, padx=(0, 14))

    def _build_table(self):
        s, t = self.style, self.style.theme
        wrap = tk.Frame(self.body, bg=t.card, highlightthickness=1, highlightbackground=t.border,
                        highlightcolor=t.border)
        wrap.pack(fill=tk.BOTH, expand=True)
        self.table_wrap = wrap
        self.findings_frame = tk.Frame(wrap, bg=t.card)
        self.findings_frame.pack(fill=tk.BOTH, expand=True)
        scroll = ttk.Scrollbar(self.findings_frame, orient=tk.VERTICAL)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree = ttk.Treeview(self.findings_frame, columns=[c[0] for c in COLUMNS], show="headings",
                                 selectmode="browse", yscrollcommand=scroll.set, height=8)
        scroll.configure(command=self.tree.yview)
        for key, title, width, anchor in COLUMNS:
            self.tree.heading(key, text=title, command=lambda k=key: self.sort_by(k))
            self.tree.column(key, width=int(width * s.scale), anchor=anchor, stretch=False, minwidth=40)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        for priority in ("NOW", "NEXT", "NEVER", "ERROR"):
            self.tree.tag_configure(priority, foreground=s.priority_text_color(priority))
        round_corners(wrap, 10, t.border, t.bg, fill={"tl": t.border, "tr": t.card, "bl": t.card, "br": t.card})
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Configure>", self._fit_columns, add="+")
        self._build_asset_table(wrap)

    def _build_asset_table(self, wrap):
        s, t = self.style, self.style.theme
        self.assets_frame = tk.Frame(wrap, bg=t.card)       # shown instead of the findings table in "By asset" mode
        scroll = ttk.Scrollbar(self.assets_frame, orient=tk.VERTICAL)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.asset_tree = ttk.Treeview(self.assets_frame, columns=[c[0] for c in ASSET_COLUMNS], show="headings",
                                       selectmode="browse", yscrollcommand=scroll.set, height=8)
        scroll.configure(command=self.asset_tree.yview)
        for key, title, width, anchor in ASSET_COLUMNS:
            self.asset_tree.heading(key, text=title, command=lambda k=key: self.sort_assets_by(k))
            self.asset_tree.column(key, width=int(width * s.scale), anchor=anchor, stretch=key == "top", minwidth=40)
        self.asset_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        for priority in ("NOW", "NEXT", "NEVER", "ERROR"):
            self.asset_tree.tag_configure(priority, foreground=s.priority_text_color(priority))
        self.asset_tree.bind("<<TreeviewSelect>>", self._on_select_asset)

    def _build_details(self):
        s, t = self.style, self.style.theme
        self.details = card(self.body, s, "Details", pady=(12, 0))
        # Claim the space before the expanding table does, so a short window shrinks the table and never the details.
        self.details.master.pack_configure(side=tk.BOTTOM, before=self.table_wrap)
        # Long details scroll inside a limited height, so they can never push the results table out of view.
        self.detail_scroll = ScrollFrame(self.details, t.card, max_height=int(DETAILS_MAX_HEIGHT * s.scale))
        self.detail_scroll.pack(fill=tk.X)
        area = self.detail_scroll.body
        self.detail_title = tk.Label(area, text="Select a row to see why.", font=s.font(10, "bold"),
                                     bg=t.card, fg=t.text, anchor="w")
        self.detail_title.pack(fill=tk.X)
        self.detail_chips = FlowFrame(area, t.card)
        self.detail_chips.pack(fill=tk.X, pady=(6, 0))
        self.detail_text = tk.Label(area, text="", font=s.font(10), bg=t.card, fg=t.muted, anchor="w",
                                    justify="left")
        self.detail_text.pack(fill=tk.X, pady=(6, 0))
        wrap_to_width(self.detail_text)
        self.detail_refs_title = tk.Label(area, text="REFERENCES FROM CISA", font=s.font(9, "bold"), bg=t.card,
                                          fg=t.accent, anchor="w")
        self.detail_refs = ReferenceList(area, s, self.ctx.open_reference, compact=True, limit=REFERENCE_LIMIT)
        self.detail_adv_title = tk.Label(area, text="ICS ADVISORIES FROM CISA", font=s.font(9, "bold"), bg=t.card,
                                         fg=t.accent, anchor="w")
        self.detail_adv = AdvisoryList(area, s, self.ctx.open_reference, compact=True, max_steps=4)

    # ---- loading ----
    def open_file(self):
        """Ask for a CSV file and score it in the background."""
        path = self.ctx.open_file("Select a CSV of vulnerabilities", [("CSV files", "*.csv"), ("All files", "*.*")])
        if path:
            self.load(path)

    def load(self, path):
        """Score a CSV file in the background and show the results."""
        self._run(path)

    def load_inventory(self):
        """Ask for an asset inventory CSV, load it, and score the open findings file again with it."""
        path = self.ctx.open_file("Select an asset inventory CSV", [("CSV files", "*.csv"), ("All files", "*.*")])
        if path:
            self._run(self.state.path or None, inventory_path=path)

    # ---- importing scanner exports ----
    def import_scanner(self):
        """Ask for scanner export files, read them in the background, then show what would be imported."""
        paths = self.ctx.open_files("Select scanner exports (Nessus, Tenable, OpenVAS, Nozomi, Dragos)",
                                    gui_import.EXPORT_TYPES)
        if not paths:
            return

        def job(_cancel, report):
            report("Reading the scanner export...")
            return scanimport.read_exports(paths)

        def done(result, error):
            self._import_read(paths, result, error)

        if not self.ctx.worker.start(job, done, self._progress):
            self.ctx.info("Batch import", "Another task is still running. Wait for it to finish or cancel it.")
            return
        self._busy(True)

    def _busy(self, working):
        """Show or hide the progress row and the buttons that must not be pressed meanwhile."""
        if not self.frame.winfo_exists():
            return
        if working:
            for control in (self.open_button, self.import_button, self.inventory_button, self.inventory_clear_button):
                set_enabled(control, False)
            self.progress_row.pack(fill=tk.X, pady=(8, 0), after=self.toolbar)
            self.progress_bar.start(12)
        else:
            self.progress_bar.stop()
            self.progress_row.pack_forget()
            set_enabled(self.open_button, True)
            set_enabled(self.import_button, True)
            set_enabled(self.inventory_button, True)
            self._update_inventory_label()

    def _import_read(self, paths, raw, error):
        self._busy(False)
        if self.ctx.worker.cancel_event.is_set():
            return
        if error:
            self.ctx.error("Scanner import", error)
            return
        choice = gui_import.ask_import(self.frame, self.style, raw, self.ctx.open_file)
        if choice is not None:
            self._save_import(paths, choice)

    def _save_import(self, paths, choice):
        """Ask where to save the findings (and the inventory), write them, and open them in this view."""
        result, ctx = choice.result, self.ctx
        types = [("CSV files", "*.csv"), ("All files", "*.*")]
        findings_path = ctx.save_file("Save the imported findings", "findings.csv", types)
        if not findings_path:
            return
        inventory_path = ""
        if result.assets:
            inventory_path = ctx.save_file("Save the asset inventory (its new assets need their criticality and "
                                           "exposure filled in)", "inventory.csv", types)
        inputs = [p for p in (*paths, choice.aliases, choice.existing_inventory) if p]
        outputs = [p for p in (findings_path, inventory_path) if p]
        clash = any(_same_file(out, other) for out in outputs for other in inputs)
        if clash or (inventory_path and _same_file(findings_path, inventory_path)):
            ctx.error("Scanner import", "That would replace a file the import reads from (or the other file being "
                                        "saved). Your exports, aliases and inventory are never overwritten: choose "
                                        "another name.")
            return
        new = 0
        try:
            scanimport.write_atomically(findings_path, lambda p: scanimport.write_findings(p, result))
            if inventory_path:
                counts = []
                scanimport.write_atomically(inventory_path, lambda p: counts.append(
                    scanimport.write_inventory(p, result, choice.existing_inventory or None)))
                new = counts[0][0]
        except (OSError, ValueError) as error:
            ctx.error("Scanner import", str(getattr(error, "strerror", None) or error))
            return
        if new:
            ctx.info("Scanner import", f"Saved {len(result.findings):,} findings and an inventory with {new:,} new "
                                       f"asset{'s' if new != 1 else ''}.\n\nNo scanner knows an asset's criticality, "
                                       "exposure or controls, so those columns are empty for the new assets: open the "
                                       "inventory in a spreadsheet, fill them in, then press Load inventory\u2026 "
                                       "again to rank the findings. Until then they show as not scored.")
        self._run(findings_path, inventory_path=inventory_path or None)

    def clear_inventory(self):
        """Stop using the inventory and score the open findings file again without it."""
        if self.state.inventory is not None:
            self._run(self.state.path or None, clear_inventory=True)

    def _run(self, path, inventory_path=None, clear_inventory=False):
        """Do the background work for opening a file, loading an inventory, or clearing it (all in one job)."""
        ctx, settings, data_dir = self.ctx, self.ctx.settings, self.ctx.data_dir
        known, current = ctx.threat_data, self.state.inventory
        changed = bool(inventory_path) or clear_inventory

        def job(_cancel, report):
            inv = current
            if inventory_path:
                report("Reading the inventory...")
                inv = inventory.load(inventory_path)
            elif clear_inventory:
                inv = None
            if path is None:
                return [], None, inv
            report("Reading the file...")
            data = known
            if batch.has_cve_column(path) and data is None:
                report("Loading threat data...")
                data = threatdata.ThreatData.load(data_dir)
            report("Scoring...")
            items = batch.process_file(path, settings, data if batch.has_cve_column(path) else None, inv)
            return items, data, inv

        done = lambda result, error: self._loaded(path, result, error, changed, bool(inventory_path))  # noqa: E731
        if not ctx.worker.start(job, done, self._progress):
            ctx.info("Batch import", "Another task is still running. Wait for it to finish or cancel it.")
            return
        for control in (self.open_button, self.inventory_button, self.inventory_clear_button):
            set_enabled(control, False)
        self.progress_row.pack(fill=tk.X, pady=(8, 0), after=self.toolbar)
        self.progress_bar.start(12)

    def _progress(self, message):
        if self.frame.winfo_exists():
            self.progress_label.configure(text=message)

    def _loaded(self, path, result, error, inventory_changed=False, inventory_fresh=False):
        alive = self.frame.winfo_exists()
        if alive:
            self.progress_bar.stop()
            self.progress_row.pack_forget()
            set_enabled(self.open_button, True)
            set_enabled(self.inventory_button, True)
            self._update_inventory_label()
        if self.ctx.worker.cancel_event.is_set():
            return
        if error:
            self.ctx.error("Batch import failed", error)
            return
        items, data, inv = result
        if inventory_changed:
            self.state.inventory = inv
            if alive:
                self._update_inventory_label()
            if inventory_fresh and inv.problems:
                self._warn_about_inventory(inv)
        if path is None:
            return
        if data is not None and self.ctx.threat_data is None:
            self.ctx.threat_data = data
            if data.warnings:
                self.ctx.warn("Threat data", "\n\n".join(data.warnings))
        if not items:
            self.ctx.info("Batch import", "The file has a header but no data rows.")
            return
        state = self.state
        state.path, state.items, state.data = path, items, data if any(i.cve for i in items) else None
        state.ranks = {id(item): rank for rank, item in enumerate((i for i in items if i.result), start=1)}
        state.sort_key, state.sort_desc, state.filter = "rank", False, "all"
        state.summaries, state.unassigned = None, ()
        state.asset_sort_key, state.asset_sort_desc = "rollup", False
        self._apply_comparison()
        self.ctx.status_changed()
        if alive:
            self.refresh()

    def _update_inventory_label(self):
        inv = self.state.inventory
        self.inventory_label.configure(text=inv.summary() if inv is not None else
                                       "No inventory loaded (optional: fills in asset criticality, exposure and "
                                       "controls from an asset_id column)")
        set_enabled(self.inventory_clear_button, inv is not None)

    def _warn_about_inventory(self, inv):
        """Tell the person about inventory rows that could not be used; they are never guessed at."""
        shown = inv.problems[:8]
        more = f"\n...and {inv.skipped + len(inv.duplicates) - len(shown)} more" if len(inv.problems) > 8 else ""
        listing = "\n".join(f"\u2022 {p}" for p in shown)
        self.ctx.warn("Asset inventory", f"Some inventory rows were not used:\n\n{listing}{more}")

    # ---- filtering, sorting, display ----
    def set_filter(self, key):
        """Show only one bucket, or all rows."""
        self.state.filter = key
        self.refresh()

    def _on_destroy(self, event):
        if event.widget is self.frame and self._search_job:
            self.frame.after_cancel(self._search_job)
            self._search_job = None

    def _search_changed(self, *_args):
        if self._search_job:
            self.frame.after_cancel(self._search_job)
        self._search_job = self.frame.after(SEARCH_DELAY_MS, self.apply_search)

    def apply_search(self):
        """Filter by the text in the search box now."""
        self._search_job = None
        self.state.search = self.search_var.get().strip().lower()
        self.refresh()

    def sort_by(self, key):
        """Sort by a column; clicking the same column again reverses it."""
        state = self.state
        state.sort_desc = (not state.sort_desc) if state.sort_key == key else False
        state.sort_key = key
        self.refresh()

    def visible(self):
        """Return the items passing the filter and search, in display order."""
        state = self.state
        rows = [i for i in state.items if (state.filter == "all" or i.priority == state.filter)
                and (not state.search or state.search in _text(i))]
        keys = {"rank": lambda i: state.ranks.get(id(i), 10 ** 9), "id": lambda i: i.id.lower(),
                "asset": lambda i: i.asset_id.lower(),
                "cve": lambda i: i.cve, "name": lambda i: i.name.lower(),
                "priority": lambda i: -explain.URGENCY.get(i.priority, -1),
                "change": lambda i: CHANGE_ORDER.get(self._change_kind(i), 9),
                "score": lambda i: i.result.score if i.result else -1.0, "cvss": lambda i: i.cvss or -1.0,
                "source": lambda i: i.threat_sources.lower()}
        rows.sort(key=keys[state.sort_key], reverse=state.sort_desc)
        return rows

    def refresh(self):
        """Redraw the counters, headings, table and details from the current state."""
        state, t = self.state, self.style.theme
        self._show_mode()
        self._update_compare_label()
        if state.mode == "assets":
            self._refresh_assets()
            return
        counts = batch.summarize(state.items)
        counts["all"] = len(state.items)
        for key, (box, number) in self.counters.items():
            number.configure(text=str(counts.get(key, 0)))
            selected = state.filter == key
            box.configure(highlightbackground=t.accent if selected else t.border)
            recolor_corners(box, 10, t.accent if selected else t.border, t.bg, ring_width=2, fill=t.card)
        for key, title, _w, _a in COLUMNS:
            arrow = HEADING_ARROWS[state.sort_desc] if key == state.sort_key else ""
            self.tree.heading(key, text=title + arrow)
        # The Asset column only appears when the file has asset ids, so ordinary files keep the room.
        has_assets = any(i.asset_id for i in state.items)
        self.tree.configure(displaycolumns=[c[0] for c in COLUMNS if (c[0] != "asset" or has_assets)
                                            and (c[0] != "change" or state.comparison is not None)])
        self._fit_columns()
        self.tree.delete(*self.tree.get_children())
        shown = self.visible()
        index_of = {id(item): n for n, item in enumerate(state.items)}
        for item in shown:
            index = index_of[id(item)]
            rank = state.ranks.get(id(item), "")
            symbol = PRIORITY_SYMBOLS[item.priority]
            score = f"{item.result.score:.2f}" if item.result else ""
            cvss = f"{item.cvss:.1f}" if item.result else item.cvss_raw
            source = item.threat_sources if item.result else item.error
            change = state.comparison.changes.get(id(item)) if state.comparison is not None else None
            self.tree.insert("", tk.END, iid=str(index), tags=(item.priority,),
                             values=(rank, item.id, item.asset_id, item.cve, item.name, f"{symbol} {item.priority}",
                                     change.text if change else "", score, cvss, source))
        self._update_file_label()
        self.count_label.configure(text=f"Showing {len(shown)} of {len(state.items)}" if state.items else "")
        set_enabled(self.export_button, bool(state.items))
        self._clear_details()
        if shown:
            self.tree.selection_set(str(index_of[id(shown[0])]))

    def _update_file_label(self):
        """Describe the open file: its name, row count, the threat data used, and whether it is out of date."""
        state = self.state
        if not state.items:
            self.file_label.configure(text="No file loaded")
            return
        scored = next((i for i in state.items if i.result), None)
        outdated = scored is not None and scored.result.profile != self.ctx.settings.describe()
        self.file_label.configure(
            text=f"{os.path.basename(state.path)}  ·  {len(state.items)} rows"
            + (f"  ·  {state.data.versions()}" if state.data else "")
            + ("  ·  scored with different scoring settings; open the file again to re-score" if outdated else ""),
            fg=self.style.theme.warn if outdated else self.style.theme.muted)

    def _show_mode(self):
        """Show the table, counters and button that belong to the current mode."""
        state = self.state
        assets = state.mode == "assets"
        if assets:
            self.findings_frame.pack_forget()
            self.assets_frame.pack(fill=tk.BOTH, expand=True)
            self.counter_boxes.pack_forget()
            self.mode_note.pack(side=tk.LEFT, fill=tk.X, expand=True)
        else:
            self.assets_frame.pack_forget()
            self.findings_frame.pack(fill=tk.BOTH, expand=True)
            self.mode_note.pack_forget()
            self.counter_boxes.pack(side=tk.LEFT, before=self.mode_control)
            self.mode_note.configure(text="")
        self.export_button.configure(text="Export asset roll-up" if assets else "Export ranked CSV")

    def _fit_columns(self, _event=None):
        """Share the room left over by the fixed-width columns between Name and Threat source, so the table always
        fits the window instead of clipping its last column (Tk widens columns but never shrinks them)."""
        available = self.tree.winfo_width() - 6
        if available <= 1:
            return
        shown = self.tree.cget("displaycolumns")
        fixed = sum(int(width * self.style.scale) for key, _title, width, _anchor in COLUMNS
                    if key in shown and key not in FLEXIBLE_COLUMNS)
        room = max(available - fixed, sum(MIN_FLEXIBLE.values()))
        name = max(MIN_FLEXIBLE["name"], int(room * NAME_SHARE))
        self.tree.column("name", width=name)
        self.tree.column("source", width=max(MIN_FLEXIBLE["source"], room - name))

    def _clear_details(self):
        self.detail_title.configure(text="Select a row to see why." if self.state.items else
                                    "Open a CSV file to score it. Required columns: cvss (or cvss_vector), asset, "
                                    "exposure (or asset_id with an inventory), and threat (or cve). A scanner "
                                    "export (Nessus, Tenable, OpenVAS, Nozomi, Dragos): use Import scan\u2026")
        self.detail_chips.set_items([])
        self.detail_text.configure(text="")
        self._show_references(())
        self._show_advisories(None)

    def _on_select(self, _event):
        selection = self.tree.selection()
        if not selection:
            return
        item = self.state.items[int(selection[0])]
        label = " · ".join(part for part in (item.id, item.cve, item.name) if part) or f"Line {item.line}"
        self.detail_title.configure(text=f"{label}  (source line {item.line})")
        if item.result:
            chips = [chip(self.detail_chips, self.style, f.label, f.direction)
                     for f in explain.sorted_factors(item.result.factors)]
            if item.from_inventory:
                chips.append(chip(self.detail_chips, self.style, f"From inventory: {item.asset_id[:24]}", "neutral"))
            self.detail_chips.set_items(chips)
            lines = [f"Action: {item.result.action}", ""] + [f"• {r}" for r in item.result.reasons]
            if item.cvss_version:
                lines += ["", f"CVSS vector: {item.cvss_vector} (CVSS {item.cvss_version}, base score {item.cvss:.1f})"]
                if item.cvss_environmental is not None:
                    lines.append(f"Environmental score: {item.cvss_environmental:.1f}, shown for comparison; the "
                                 "priority uses the base score.")
            change = self.state.comparison.changes.get(id(item)) if self.state.comparison else None
            if change is not None and change.text:
                was = change.previous
                score = f", ordering score {was.score:.2f}" if was is not None and was.score is not None else ""
                lines += ["", f"Compared with the previous export: {change.text}"
                              + (f" (it was {was.priority}{score})" if was is not None and change.kind != compare.SAME
                                 else "") + "."]
            if item.advisories and item.advisories[0].fix_text:
                lines += ["", f"CISA {item.advisories[0].id}: {item.advisories[0].fix_text} (context only)."]
            if item.asset_id:
                taken = ", ".join(item.from_inventory) or "nothing"
                lines += ["", f"Asset {item.asset_id}: {taken} filled in from the inventory"
                              + ("; the other values are from the file." if item.from_inventory else ".")]
            lines += ["", f"Scoring settings: {item.result.profile}"]
        else:
            self.detail_chips.set_items([chip(self.detail_chips, self.style, "Not scored", "error")])
            lines = [f"• {part}" for part in item.error.split("; ")]
            if item.cvss_vector:
                lines += ["", f"CVSS vector as given: {item.cvss_vector}"]
        self.detail_text.configure(text="\n".join(lines))
        self._show_references(item.references)
        self._show_advisories(item)
        self.detail_scroll.scroll_to_top()

    def _show_references(self, references):
        """Show the selected row's KEV references under the details, or nothing when it has none."""
        self.detail_refs_title.pack_forget()
        self.detail_refs.pack_forget()
        self.detail_refs.show(references)
        if references:
            self.detail_refs_title.pack(fill=tk.X, pady=(10, 4), before=self.detail_text)
            self.detail_refs.pack(fill=tk.X, before=self.detail_text)

    def _with_version_notes(self, item):
        """The row's advisories; if its asset has a vendor, product and version in the inventory, each says whether
        that version is inside the versions it lists (only for advisories that name that vendor and product)."""
        inv = self.state.inventory
        if not item.advisories or inv is None or not item.asset_id:
            return item.advisories          # (and no threat data is loaded for a file that has no CVE column)
        ics = self.ctx.get_threat_data().ics
        if ics is None:
            return item.advisories
        status, record = inv.lookup(item.asset_id)
        if status != "found" or not (record.vendor and record.product and record.version):
            return item.advisories
        noted = []
        for advisory in item.advisories:
            check = ics.check_advisory(advisory.id, record.vendor, record.product, record.version)
            noted.append(dataclasses.replace(advisory, version_note=check.note(record.version)) if check else advisory)
        return tuple(noted)

    def _show_advisories(self, item, advisories=None, total=None, title=ADVISORIES_TITLE):
        """Show the CISA ICS advisories that name the selected row's CVE (or the ones given, for an asset)."""
        self.detail_adv_title.pack_forget()
        self.detail_adv.pack_forget()
        if advisories is None:
            advisories = self._with_version_notes(item) if item is not None else ()
            total = item.advisory_count if item is not None else None
        self.detail_adv_title.configure(text=title)
        self.detail_adv.show(advisories, total)
        if advisories:
            self.detail_adv_title.pack(fill=tk.X, pady=(10, 4), before=self.detail_text)
            self.detail_adv.pack(fill=tk.X, before=self.detail_text)

    # ---- comparing with a previous export ----
    def compare_with(self):
        """Ask for a previous ranked export and compare the open findings with it."""
        path = self.ctx.open_file("Select a previous ranked CSV export", [("CSV files", "*.csv"), ("All files", "*.*")])
        if not path:
            return

        def job(_cancel, report):
            report("Reading the previous export...")
            rows, skipped = compare.load_previous(path)
            return os.path.basename(path), rows, skipped

        def done(result, error):
            if self.frame.winfo_exists():
                self.progress_bar.stop()
                self.progress_row.pack_forget()
                set_enabled(self.compare_button, True)
            if self.ctx.worker.cancel_event.is_set():
                return
            if error:
                self.ctx.error("Previous export", error)
                return
            self.state.previous = result
            self._apply_comparison()
            if self.frame.winfo_exists():
                self.refresh()
            skipped = result[2]
            if skipped:
                self.ctx.warn("Previous export", f"{skipped} row{'s' if skipped != 1 else ''} of the previous export "
                                                 "had no usable priority and were left out.")

        if not self.ctx.worker.start(job, done, self._progress):
            self.ctx.info("Batch import", "Another task is still running. Wait for it to finish or cancel it.")
            return
        set_enabled(self.compare_button, False)
        self.progress_row.pack(fill=tk.X, pady=(8, 0), after=self.toolbar)
        self.progress_bar.start(12)

    def clear_comparison(self):
        """Stop comparing with a previous export."""
        self.state.previous = self.state.comparison = None
        self.refresh()

    def _apply_comparison(self):
        """Compare the current findings with the previous export, if there is one. Never raises."""
        state = self.state
        if state.previous is None or not state.items:
            state.comparison = None
        else:
            label, rows, skipped = state.previous
            state.comparison = compare.compare(state.items, rows, label, skipped)
        if self.frame.winfo_exists():
            self._update_compare_label()

    def _change_kind(self, item):
        change = self.state.comparison.changes.get(id(item)) if self.state.comparison is not None else None
        return change.kind if change is not None else ""

    def _update_compare_label(self):
        state = self.state
        if state.previous is None:
            text = "No comparison \u00b7 see what changed since an earlier export"
        elif state.comparison is None:
            text = f"Previous export: {state.previous[0]}, {len(state.previous[1]):,} rows. Open a findings file."
        else:
            text = state.comparison.summary()
        self.compare_label.configure(text=text)
        set_enabled(self.compare_clear_button, state.previous is not None)
        set_enabled(self.resolved_button, state.comparison is not None and bool(state.comparison.resolved))

    def show_resolved(self):
        """List the findings that were in the previous export and are not in the current file."""
        comparison = self.state.comparison
        if comparison is None or not comparison.resolved:
            return
        shown = comparison.resolved[:RESOLVED_LISTED]
        lines = [f"\u2022 {row.label}  ({row.asset_id + ', ' if row.asset_id else ''}was {row.priority})"
                 for row in shown]
        more = len(comparison.resolved) - len(shown)
        if more:
            lines.append(f"...and {more} more")
        self.ctx.info("Resolved since the previous export",
                      f"{len(comparison.resolved)} finding{'s' if len(comparison.resolved) != 1 else ''} in "
                      f"{comparison.label} are not in the open file:\n\n" + "\n".join(lines))

    # ---- the per-asset roll-up ----
    def set_mode(self, mode):
        """Switch between the findings table and the per-asset roll-up."""
        if mode not in dict(MODES):
            return
        self.state.mode = mode
        if self.mode_var.get() != mode:
            self.mode_var.set(mode)
        self.refresh()

    def sort_assets_by(self, key):
        """Sort the asset table by a column; clicking the same column again reverses it."""
        state = self.state
        state.asset_sort_desc = (not state.asset_sort_desc) if state.asset_sort_key == key else False
        state.asset_sort_key = key
        self.refresh()

    def _summaries(self):
        state = self.state
        if state.summaries is None:
            state.summaries, state.unassigned = rollup.rollup(state.items)
        return state.summaries

    def visible_assets(self):
        """Return the asset summaries matching the search, in display order."""
        state = self.state
        rows = [s for s in self._summaries()
                if not state.search or state.search in s.asset_id.lower()
                or any(state.search in _text(i) for i in s.items)]
        keys = {"asset": lambda s: s.asset_id.casefold(), "worst": lambda s: -explain.URGENCY.get(s.worst, -1),
                "now": lambda s: s.counts[batch.NOW], "next": lambda s: s.counts[batch.NEXT],
                "never": lambda s: s.counts[batch.NEVER], "findings": lambda s: len(s.items),
                "score": lambda s: -1.0 if s.top_score is None else s.top_score,
                "top": lambda s: rollup.label(s.top).lower() if s.top else ""}
        if state.asset_sort_key in keys:
            rows.sort(key=keys[state.asset_sort_key], reverse=state.asset_sort_desc)
        return rows

    def _refresh_assets(self):
        state = self.state
        for key, title, _w, _a in ASSET_COLUMNS:
            arrow = HEADING_ARROWS[state.asset_sort_desc] if key == state.asset_sort_key else ""
            self.asset_tree.heading(key, text=title + arrow)
        self.asset_tree.delete(*self.asset_tree.get_children())
        shown = self.visible_assets()
        summaries = self._summaries()
        for index, summary in enumerate(shown):
            counts, top = summary.counts, summary.top
            self.asset_tree.insert(
                "", tk.END, iid=str(index), tags=(summary.worst,),
                values=(summary.asset_id, f"{PRIORITY_SYMBOLS[summary.worst]} {summary.worst}", counts[batch.NOW],
                        counts[batch.NEXT], counts[batch.NEVER], len(summary.items),
                        f"{summary.top_score:.2f}" if top else "", rollup.label(top) if top else "not scored"))
        self._shown_assets = shown
        self._update_file_label()
        urgent = sum(1 for s in summaries if s.worst == batch.NOW)
        note = f"{len(summaries)} assets · {urgent} with a NOW finding"
        if state.unassigned:
            count = len(state.unassigned)
            note += f" · {count} row{' has' if count == 1 else 's have'} no asset id (see Findings)"
        self.mode_note.configure(text=note if state.items else "")
        self.count_label.configure(text=f"Showing {len(shown)} of {len(summaries)}" if state.items else "")
        set_enabled(self.export_button, bool(summaries))
        self._clear_details()
        if shown:
            self.asset_tree.selection_set("0")

    def _on_select_asset(self, _event):
        selection = self.asset_tree.selection()
        if not selection or not getattr(self, "_shown_assets", None):
            return
        summary = self._shown_assets[int(selection[0])]
        counts = summary.counts
        self.detail_title.configure(text=f"Asset {summary.asset_id}: {len(summary.items)} finding"
                                         f"{'s' if len(summary.items) != 1 else ''}")
        chips = [chip(self.detail_chips, self.style, f"{counts[b]} {b}", d)
                 for b, d in ((batch.NOW, "raise"), (batch.NEXT, "neutral"), (batch.NEVER, "neutral")) if counts[b]]
        if counts["ERROR"]:
            chips.append(chip(self.detail_chips, self.style, f"{counts['ERROR']} not scored", "error"))
        self.detail_chips.set_items(chips)
        visit = summary.visit_items
        lines = []
        if visit:
            lines.append(f"Could be handled on one visit ({len(visit)} finding{'s' if len(visit) != 1 else ''}, "
                         "most urgent first):")
            ranks = self.state.ranks
            lines += [f"• #{ranks.get(id(i), '?')}  {rollup.label(i)}  ({i.priority}, score {i.result.score:.2f})"
                      for i in visit]
        else:
            lines.append("Nothing on this asset needs scheduling.")
        if counts[batch.NEVER]:
            more = "s" if counts[batch.NEVER] != 1 else ""
            never = f"{counts[batch.NEVER]} more finding{more} NEVER: no scheduled fix, re-check if conditions change."
            lines += ["", never]
        possible = self._possible_for(summary)
        shown = ()
        if possible is not None:
            lines += ["", *self._possible_lines(possible)]
            shown = possible.advisories
        self.detail_text.configure(text="\n".join(lines))
        self._show_references(())
        self._show_advisories(None, shown, possible.count if possible is not None else None, POSSIBLE_TITLE)
        self.detail_scroll.scroll_to_top()

    def _possible_for(self, summary):
        """The advisories that may apply to an asset, from its vendor and product in the inventory (or a message)."""
        inv = self.state.inventory
        status, record = inv.lookup(summary.asset_id) if inv is not None else ("missing", None)
        if status != "found":
            return None
        return rollup.possible_for_record(record, self.ctx.get_threat_data().ics)

    @staticmethod
    def _possible_lines(possible):
        who = f"{possible.vendor} {possible.product}"
        head = f"The inventory says this is a {who}. "
        if possible.count < 0:
            return [head + "The CISA ICS advisories are not loaded, so it cannot be checked: update them in Threat "
                    "data."]
        if not possible.vendor_known:
            return [head + f"No CISA advisory names the vendor '{possible.vendor}'; CISA may list it under another "
                    "name."]
        if not possible.count:
            return [head + "No CISA advisory names both that vendor and that product."]
        plural = "advisories" if possible.count != 1 else "advisory"
        if not possible.version:
            return [head + f"{possible.count} CISA {plural} name that vendor and product and may apply. This does "
                    "not know the version you run (add a version column to the inventory), so read each one."]
        if not possible.compared:
            return [head + f"{possible.count} CISA {plural} name that vendor and product and may apply. The version "
                    f"'{possible.version}' could not be read as a version number, so it was not compared: read each "
                    "advisory."]
        return [head + f"{possible.count} CISA {plural} name that vendor and product. For version "
                f"{possible.version}: {possible.affected} list it as affected, {possible.outside} list other "
                f"versions only, {possible.unknown} could not be compared. Those that list it come first. Being "
                "outside a listed range does not mean the asset is safe: read each advisory."]

    def export_current(self):
        """Export what the current view shows: the ranked findings or the per-asset roll-up."""
        if self.state.mode == "assets":
            self.export_assets()
        else:
            self.export()

    def export_assets(self):
        """Save the per-asset roll-up to a CSV file."""
        summaries = self._summaries()
        if not summaries:
            return
        out = self.ctx.save_file("Save the per-asset roll-up", "ot-triage-assets.csv",
                                 [("CSV files", "*.csv"), ("All files", "*.*")])
        if not out:
            return
        try:
            possible = {}
            if self.state.inventory is not None:
                possible = rollup.possible_advisories(summaries, self.state.inventory,
                                                      self.ctx.get_threat_data().ics)
            scanimport.write_atomically(out, lambda path: rollup.write_rollup(path, summaries, possible))
        except OSError as error:
            self.ctx.error("Export failed", str(error))
            return
        self.ctx.info("Exported", f"Saved {len(summaries)} assets to\n{out}")

    # ---- export ----
    def export(self):
        """Save the ranked results to a CSV file."""
        state = self.state
        if not state.items:
            return
        stem = os.path.splitext(os.path.basename(state.path))[0]
        out = self.ctx.save_file("Export ranked results", f"{stem}_ranked.csv", [("CSV files", "*.csv")])
        if not out:
            return
        try:
            scanimport.write_atomically(out, lambda path: batch.write_results(path, state.items, state.data,
                                                                              state.comparison))
        except OSError as error:
            self.ctx.error("Export failed", str(error))
            return
        self.ctx.info("Exported", f"Saved {len(state.items)} rows to\n{out}")
