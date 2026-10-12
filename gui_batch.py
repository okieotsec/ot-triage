"""The Batch view: score a CSV file, filter and search the ranked results, export them."""
import os
import tkinter as tk
from tkinter import ttk

import batch
import explain
import inventory
import threatdata
from gui_round import recolor_corners, round_corners
from gui_theme import PRIORITY_SYMBOLS
from gui_widgets import (
    AdvisoryList,
    FlowFrame,
    ReferenceList,
    ScrollFrame,
    button,
    card,
    chip,
    rounded_entry,
    set_enabled,
    wrap_to_width,
)

REFERENCE_LIMIT = 5
DETAILS_MAX_HEIGHT = 190
FILTERS = [("all", "All"), ("NOW", "Now"), ("NEXT", "Next"), ("NEVER", "Never"), ("ERROR", "Error")]
COLUMNS = [("rank", "#", 46, "center"), ("id", "ID", 80, "w"), ("asset", "Asset", 112, "w"),
           ("cve", "CVE", 124, "w"), ("name", "Name", 200, "w"),
           ("priority", "Priority", 96, "w"), ("score", "Score", 62, "center"), ("cvss", "CVSS", 54, "center"),
           ("source", "Threat source", 190, "w")]
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


def _text(item):
    return f"{item.id} {item.name} {item.cve} {item.asset_id} {item.error} {item.threat_sources}".lower()


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
        self.file_label = tk.Label(bar, text="No file loaded", font=s.font(9), bg=t.bg, fg=t.muted, anchor="w")
        self.export_button = button(bar, s, "Export ranked CSV", self.export, "secondary")
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
        self.counter_row.pack(fill=tk.X, pady=12)
        self.counters = {}
        for key, label in FILTERS:
            box = tk.Frame(self.counter_row, bg=t.card, highlightthickness=2, highlightbackground=t.border,
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
        self.count_label = tk.Label(self.counter_row, text="", font=s.font(10), bg=t.bg, fg=t.muted)
        self.count_label.pack(side=tk.RIGHT)

    def _build_table(self):
        s, t = self.style, self.style.theme
        wrap = tk.Frame(self.body, bg=t.card, highlightthickness=1, highlightbackground=t.border,
                        highlightcolor=t.border)
        wrap.pack(fill=tk.BOTH, expand=True)
        self.table_wrap = wrap
        scroll = ttk.Scrollbar(wrap, orient=tk.VERTICAL)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree = ttk.Treeview(wrap, columns=[c[0] for c in COLUMNS], show="headings", selectmode="browse",
                                 yscrollcommand=scroll.set, height=8)
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
        self.detail_adv = AdvisoryList(area, s, self.ctx.open_reference, compact=True)

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
                "score": lambda i: i.result.score if i.result else -1.0, "cvss": lambda i: i.cvss or -1.0,
                "source": lambda i: i.threat_sources.lower()}
        rows.sort(key=keys[state.sort_key], reverse=state.sort_desc)
        return rows

    def refresh(self):
        """Redraw the counters, headings, table and details from the current state."""
        state, t = self.state, self.style.theme
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
        self.tree.configure(displaycolumns=[c[0] for c in COLUMNS if c[0] != "asset" or has_assets])
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
            self.tree.insert("", tk.END, iid=str(index), tags=(item.priority,),
                             values=(rank, item.id, item.asset_id, item.cve, item.name, f"{symbol} {item.priority}",
                                     score, cvss, source))
        if state.items:
            scored = next((i for i in state.items if i.result), None)
            outdated = scored is not None and scored.result.profile != self.ctx.settings.describe()
            self.file_label.configure(
                text=f"{os.path.basename(state.path)}  ·  {len(state.items)} rows"
                + (f"  ·  {state.data.versions()}" if state.data else "")
                + ("  ·  scored with different scoring settings; open the file again to re-score" if outdated else ""),
                fg=self.style.theme.warn if outdated else self.style.theme.muted)
            self.count_label.configure(text=f"Showing {len(shown)} of {len(state.items)}")
        else:
            self.file_label.configure(text="No file loaded")
            self.count_label.configure(text="")
        set_enabled(self.export_button, bool(state.items))
        self._clear_details()
        if shown:
            self.tree.selection_set(str(index_of[id(shown[0])]))

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
                                    "exposure (or asset_id with an inventory), and threat (or cve).")
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

    def _show_advisories(self, item):
        """Show the CISA ICS advisories that name the selected row's CVE, or nothing when there are none."""
        self.detail_adv_title.pack_forget()
        self.detail_adv.pack_forget()
        advisories = item.advisories if item is not None else ()
        self.detail_adv.show(advisories, item.advisory_count if item is not None else None)
        if advisories:
            self.detail_adv_title.pack(fill=tk.X, pady=(10, 4), before=self.detail_text)
            self.detail_adv.pack(fill=tk.X, before=self.detail_text)

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
            batch.write_results(out, state.items, state.data)
        except OSError as error:
            self.ctx.error("Export failed", str(error))
            return
        self.ctx.info("Exported", f"Saved {len(state.items)} rows to\n{out}")
