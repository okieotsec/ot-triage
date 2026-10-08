"""The Threat data view: freshness of KEV and EPSS, user-started updates and offline import."""
import tkinter as tk
from tkinter import ttk

import threatdata
from gui_round import round_corners
from gui_widgets import ScrollFrame, button, card, chip, set_enabled

HOSTS = ("www.cisa.gov", "epss.empiricalsecurity.com")
CONFIRM_TEXT = ("This will download two public files over HTTPS from:\n\n" + "\n".join(f"  • {h}" for h in HOSTS)
                + "\n\nNothing else is sent or contacted. Continue?")


class ThreatUpdater:
    """Runs updates and imports in the background and remembers the last outcome, independent of any view."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.results, self.message = [], ""
        self.listeners = []
        self.confirmed = False

    @property
    def busy(self):
        """True while an update or import is running."""
        return self.ctx.worker.running

    def _notify(self):
        for listener in list(self.listeners):
            listener()

    def update(self, ask=True):
        """Download both sources. Returns False if cancelled by the user or another task is running."""
        if self.busy:
            return False
        if ask and not self.confirmed:
            if not self.ctx.confirm("Update threat data", CONFIRM_TEXT):
                return False
            self.confirmed = True
        data_dir = self.ctx.data_dir

        def job(cancel, report):
            return threatdata.update_from_network(data_dir, fetcher=threatdata.fetch, cancel=cancel, progress=report)

        return self._start(job)

    def import_files(self, kev_path, epss_path):
        """Import KEV and/or EPSS files chosen by the user."""
        if self.busy or not (kev_path or epss_path):
            return False
        data_dir = self.ctx.data_dir

        def job(_cancel, report):
            report("Checking the files...")
            return threatdata.import_from_files(kev_path or None, epss_path or None, data_dir)

        return self._start(job)

    def cancel(self):
        """Ask the running job to stop."""
        self.ctx.worker.cancel()

    def _start(self, job):
        self.message = "Starting..."
        started = self.ctx.worker.start(job, self._finished, self._progress)
        self._notify()
        return started

    def _progress(self, message):
        self.message = message
        self._notify()

    def _finished(self, results, error):
        self.results = results or [threatdata.SourceResult("update", False, f"Update failed: {error}")]
        self.message = ""
        self.ctx.reload_threat_data()
        self._notify()


class ThreatView:
    """Builds and updates the Threat data screen."""

    name = "threat"

    def __init__(self, ctx, parent):
        self.ctx, self.style = ctx, ctx.style
        t = self.style.theme
        if ctx.updater is None:
            ctx.updater = ThreatUpdater(ctx)
        self.updater = ctx.updater
        self.frame = tk.Frame(parent, bg=t.bg)
        self.scroll = ScrollFrame(self.frame, t.bg)
        self.scroll.pack(fill=tk.BOTH, expand=True)
        self.body = self.scroll.body
        self.body.configure(padx=28, pady=24)
        self._build()
        self.updater.listeners.append(self.refresh)
        self.frame.bind("<Destroy>", self._on_destroy)
        self.refresh()

    def _on_destroy(self, event):
        if event.widget is self.frame and self.refresh in self.updater.listeners:
            self.updater.listeners.remove(self.refresh)

    def _build(self):
        s, t = self.style, self.style.theme
        row = tk.Frame(self.body, bg=t.bg)
        row.pack(fill=tk.X)
        row.columnconfigure((0, 1), weight=1, uniform="cards")
        self.cards = {}
        for column, (name, title, host) in enumerate((("kev", "CISA KEV", HOSTS[0]), ("epss", "EPSS", HOSTS[1]))):
            outer = tk.Frame(row, bg=t.card, highlightthickness=1, highlightbackground=t.border,
                             highlightcolor=t.border)
            outer.grid(row=0, column=column, sticky="nsew", padx=(0, 14) if column == 0 else 0)
            tk.Label(outer, text=title.upper(), font=s.font(9, "bold"), bg=t.card, fg=t.accent).pack(
                anchor="w", padx=16, pady=(12, 4))
            top = tk.Frame(outer, bg=t.card)
            top.pack(fill=tk.X, padx=16)
            state_slot = tk.Frame(top, bg=t.card)
            state_slot.pack(side=tk.LEFT)
            version = tk.Label(top, text="", font=s.font(11, "bold"), bg=t.card, fg=t.text)
            version.pack(side=tk.LEFT, padx=10)
            detail = tk.Label(outer, text="", font=s.font(9), bg=t.card, fg=t.muted, anchor="w", justify="left")
            detail.pack(fill=tk.X, padx=16, pady=(8, 2))
            detail.bind("<Configure>", lambda e, w=detail: w.configure(wraplength=max(e.width - 4, 100)))
            tk.Label(outer, text=f"Source: {host}", font=s.font(9), bg=t.card, fg=t.muted, anchor="w").pack(
                fill=tk.X, padx=16, pady=(0, 14))
            round_corners(outer, 12, t.border, t.bg, fill=t.card)
            self.cards[name] = (state_slot, version, detail)

        update = card(self.body, s, "Update", pady=(14, 14))
        buttons = tk.Frame(update, bg=t.card)
        buttons.pack(fill=tk.X)
        self.update_button = button(buttons, s, "Update threat data", self.update)
        self.update_button.pack(side=tk.LEFT)
        self.import_button = button(buttons, s, "Import from files…", self.import_files, "secondary")
        self.import_button.pack(side=tk.LEFT, padx=8)
        tk.Label(buttons, text="Nothing is downloaded unless you press a button.", font=s.font(9), bg=t.card,
                 fg=t.muted).pack(side=tk.LEFT, padx=8)
        self.progress_row = tk.Frame(update, bg=t.card)
        self.progress_label = tk.Label(self.progress_row, text="", font=s.font(10), bg=t.card, fg=t.text)
        self.progress_label.pack(side=tk.LEFT)
        self.progress_bar = ttk.Progressbar(self.progress_row, mode="indeterminate", length=180,
                                            style="Busy.Horizontal.TProgressbar")
        self.progress_bar.pack(side=tk.LEFT, padx=10)
        self.cancel_button = button(self.progress_row, s, "Cancel", self.updater.cancel, "secondary")
        self.cancel_button.pack(side=tk.LEFT)
        tk.Label(update, text="LAST RESULT", font=s.font(9, "bold"), bg=t.card, fg=t.accent).pack(
            anchor="w", pady=(14, 4))
        self.results_box = tk.Frame(update, bg=t.card)
        self.results_box.pack(fill=tk.X)

        offline = card(self.body, s, "Offline use")
        text = tk.Label(offline, text=("The tool works fully offline. Download the two files on another computer, copy "
                                       "them here, and use Import from files. They get the same checks as a "
                                       "download, and a bad file never replaces good data. Files are stored in your "
                                       "per-user data folder."), font=s.font(10), bg=t.card, fg=t.muted, anchor="w",
                        justify="left")
        text.pack(fill=tk.X)
        text.bind("<Configure>", lambda e: text.configure(wraplength=max(e.width - 4, 100)))

    # ---- behaviour ----
    def update(self):
        """Ask for confirmation the first time, then download both sources."""
        self.updater.update()

    def import_files(self):
        """Ask for a KEV file and an EPSS file (either may be skipped) and import them."""
        kev = self.ctx.open_file("Choose the KEV JSON file (cancel to skip)",
                                 [("JSON files", "*.json"), ("All files", "*.*")])
        epss = self.ctx.open_file("Choose the EPSS CSV file (cancel to skip)",
                                  [("EPSS files", "*.csv *.gz"), ("All files", "*.*")])
        self.updater.import_files(kev, epss)

    def refresh(self):
        """Redraw the source cards, the progress line and the last result."""
        if not self.frame.winfo_exists():
            return
        s, t = self.style, self.style.theme
        stale_days = self.ctx.settings.stale_days
        for status in self.ctx.status():
            slot, version, detail = self.cards[status.name]
            for child in slot.winfo_children():
                child.destroy()
            fresh = status.freshness(stale_days)
            if status.problem:
                label, direction = "Problem", "error"
            elif not status.loaded:
                label, direction = "Not loaded", "warn"
            elif fresh.stale:
                label, direction = "Stale", "warn"
            else:
                label, direction = "Fresh", "ok"
            chip(slot, s, label, direction).pack()
            if status.loaded:
                version.configure(text=("Catalog " if status.name == "kev" else "Model ") + status.version)
                noun = ("entry", "entries") if status.name == "kev" else ("score", "scores")
                count = f"{status.count:,} {noun[status.count != 1]}" if status.count else ""
                lines = [fresh.text.split(": ", 1)[-1].capitalize()]
                lines.insert(0, f"{'Released' if status.name == 'kev' else 'Scored'} {status.date}")
                if count:
                    lines.insert(1, count)
                detail.configure(text="  ·  ".join(lines))
                if fresh.stale:
                    detail.configure(text=detail.cget("text") + f"\nOlder than the {stale_days}-day limit. The tool "
                                                                  "keeps working with this copy; update when you can.")
            else:
                version.configure(text="")
                detail.configure(text=status.problem or "Nothing stored yet. Update or import the file. Until then, "
                                                        "CVE lookups cannot use this source.")
        busy = self.updater.busy
        set_enabled(self.update_button, not busy)
        set_enabled(self.import_button, not busy)
        if busy:
            self.progress_label.configure(text=self.updater.message)
            self.progress_row.pack(fill=tk.X, pady=(10, 0))
            self.progress_bar.start(12)
        else:
            self.progress_bar.stop()
            self.progress_row.pack_forget()
        for child in self.results_box.winfo_children():
            child.destroy()
        if not self.updater.results:
            tk.Label(self.results_box, text="No update has been run in this session.", font=s.font(10), bg=t.card,
                     fg=t.muted).pack(anchor="w")
        for result in self.updater.results:
            line = tk.Frame(self.results_box, bg=t.card)
            line.pack(fill=tk.X, pady=2)
            chip(line, s, "OK" if result.ok else "Failed", "ok" if result.ok else "warn").pack(side=tk.LEFT)
            message = tk.Label(line, text=" " + result.message, font=s.font(10), bg=t.card, fg=t.text, anchor="w",
                               justify="left")
            message.pack(side=tk.LEFT, fill=tk.X, expand=True)
            message.bind("<Configure>", lambda e, w=message: w.configure(wraplength=max(e.width - 4, 100)))
