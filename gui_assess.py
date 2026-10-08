"""The Assess view: assess one vulnerability, with CVE lookup, why-chips and a what-would-change panel."""
import tkinter as tk
from tkinter import ttk

import explain
from explain import SHORT_LABELS, AssessInputs
from gui_widgets import (Expander, FlowFrame, ScrollFrame, Segmented, ask_text, button, card, chip, field_label,
                         priority_badge, set_enabled)
from prioritizer import Asset, Controls, Exposure, Patch, Threat, parse_cvss
from threatdata import apply_threat_context, derive_threat, normalize_cve

STACK_BELOW = 900
EXPOSURE_HELP = ("Low means no routable path from IT or the internet, verified by testing, not assumed from a "
                 "firewall's existence. If you are unsure, choose Medium.")
THREAT_HELP = ("Filled in from local KEV and EPSS data when a CVE is looked up. Data can only raise the level; "
               "being absent from the data is never treated as safe. Changing it by hand asks for a reason.")
ASSET_HELP = ("Crown jewel: assets whose compromise would stop operations or endanger safety. Important: "
              "significant but not critical. Standard: everything else.")
CONTROLS_HELP = ("Strong: segmentation, virtual patching or allow-listing that actually stops the attack. Partial: "
                 "ACLs or monitoring only. Partial controls rank the item lower inside its bucket but never change "
                 "the bucket.")
PATCH_HELP = ("Pending means the vendor supports the product and a fix is on the way. End of life means no fix "
              "will ever ship.")


class AssessState:
    """The Assess inputs, kept apart from the widgets so a theme or text size change does not lose them."""

    def __init__(self, root):
        self.cve = tk.StringVar(root)
        self.cvss = tk.StringVar(root)
        self.threat = tk.StringVar(root, Threat.NONE.name)
        self.asset = tk.StringVar(root, Asset.STANDARD.name)
        self.exposure = tk.StringVar(root, Exposure.LOW.name)
        self.patch = tk.StringVar(root, Patch.AVAILABLE.name)
        self.controls = tk.StringVar(root, Controls.NONE.name)
        self.analyst = tk.BooleanVar(root, False)
        self.public = tk.BooleanVar(root, False)
        self.info = None
        self.looked_up = ""
        self.override = None


def _options(enum):
    """Return the choices for a segmented control, least concerning first."""
    return [(member.name, label) for member, label in SHORT_LABELS[enum].items()]


class AssessView:
    """Builds and updates the Assess screen."""

    name = "assess"

    def __init__(self, ctx, parent):
        self.ctx, self.style = ctx, ctx.style
        if ctx.assess_state is None:
            ctx.assess_state = AssessState(ctx.root)
        self.state = ctx.assess_state
        self.result = None
        self.versions = ""
        self._flash_job = None
        self._pending = None
        self.updating = False
        self.stacked = None
        self.frame = tk.Frame(parent, bg=ctx.style.theme.bg)
        self.scroll = ScrollFrame(self.frame, ctx.style.theme.bg)
        self.scroll.pack(fill=tk.BOTH, expand=True)
        body = self.scroll.body
        body.configure(padx=20, pady=20)
        self.left = tk.Frame(body, bg=ctx.style.theme.bg)
        self.right = tk.Frame(body, bg=ctx.style.theme.bg)
        body.columnconfigure(1, weight=1)
        self._build_inputs(self.left)
        self._build_results(self.right)
        self._traces = []
        for var in (self.state.cvss, self.state.asset, self.state.exposure, self.state.patch, self.state.controls,
                    self.state.analyst, self.state.public):
            self._traces.append((var, var.trace_add("write", self.update)))
        self._traces.append((self.state.cve, self.state.cve.trace_add("write", self._cve_edited)))
        self.frame.bind("<Destroy>", self._on_destroy)
        self.scroll.canvas.bind("<Configure>", self._on_resize, add="+")
        self._layout(wide=True)
        self.refresh()

    def _on_destroy(self, event):
        if event.widget is self.frame:
            for job in (self._flash_job, self._pending):
                if job:
                    self.frame.after_cancel(job)
            self._flash_job = self._pending = None
            for var, trace in self._traces:
                try:
                    var.trace_remove("write", trace)
                except tk.TclError:
                    pass

    # ---- layout ----
    def _on_resize(self, event):
        self._layout(wide=event.width >= STACK_BELOW)

    def _layout(self, wide):
        if wide == self.stacked:
            return
        self.stacked = wide
        self.left.grid_forget()
        self.right.grid_forget()
        if wide:
            self.left.grid(row=0, column=0, sticky="new", padx=(0, 20))
            self.right.grid(row=0, column=1, sticky="new")
            self.left.configure(width=380)
        else:
            self.right.grid(row=0, column=0, columnspan=2, sticky="new")
            self.left.grid(row=1, column=0, columnspan=2, sticky="new", pady=(14, 0))

    def _build_inputs(self, parent):
        s, t, state = self.style, self.style.theme, self.state
        vuln = card(parent, s, "Vulnerability")
        field_label(vuln, s, "CVE ID (optional)   Ctrl+L")
        row = tk.Frame(vuln, bg=t.card)
        row.pack(fill=tk.X)
        self.cve_entry = self._entry(row, state.cve, width=22)
        self.cve_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=5)
        self.cve_entry.bind("<Return>", lambda _e: self.lookup())
        button(row, s, "Look up", self.lookup, "secondary").pack(side=tk.LEFT, padx=(8, 0))
        self.cve_message = tk.Label(vuln, text="", font=s.font(9), bg=t.card, fg=t.muted, anchor="w", justify="left")
        self.cve_message.pack(fill=tk.X, pady=(4, 0))
        self.cve_chips = FlowFrame(vuln, t.card)
        self.cve_chips.pack(fill=tk.X, pady=(4, 0))

        field_label(vuln, s, "CVSS base score")
        row = tk.Frame(vuln, bg=t.card)
        row.pack(fill=tk.X)
        self.cvss_entry = self._entry(row, state.cvss, width=6, size=18, bold=True)
        self.cvss_entry.configure(justify="center")
        self.cvss_entry.pack(side=tk.LEFT, ipady=6)
        self.cvss_band = tk.Label(row, text="", font=s.font(10, "bold"), bg=t.card, fg=t.muted)
        self.cvss_band.pack(side=tk.LEFT, padx=12)
        self.cvss_hint = tk.Label(vuln, text="Enter a base score from 0.0 to 10.0", font=s.font(9), bg=t.card,
                                  fg=t.muted, anchor="w")
        self.cvss_hint.pack(fill=tk.X, pady=(4, 0))

        field_label(vuln, s, "Threat", THREAT_HELP)
        self.threat_control = Segmented(vuln, s, _options(Threat), state.threat, self._threat_clicked)
        self.threat_control.pack(fill=tk.X)
        self.threat_note = tk.Label(vuln, text="", font=s.font(9), bg=t.card, fg=t.muted, anchor="w", justify="left")
        self.threat_note.pack(fill=tk.X, pady=(6, 0))
        self.clear_override = button(vuln, s, "Clear override", self._clear_override, "secondary")
        self.analyst_check = self._check(vuln, "Analyst-confirmed exploitation", state.analyst)
        self.public_check = self._check(vuln, "Public exploit known", state.public)

        env = card(parent, s, "Asset & environment")
        field_label(env, s, "Asset criticality", ASSET_HELP)
        Segmented(env, s, _options(Asset), state.asset).pack(fill=tk.X)
        field_label(env, s, "Network exposure", EXPOSURE_HELP)
        Segmented(env, s, _options(Exposure), state.exposure).pack(fill=tk.X)

        rem = card(parent, s, "Remediation & mitigation")
        field_label(rem, s, "Patch status", PATCH_HELP)
        Segmented(rem, s, _options(Patch), state.patch).pack(fill=tk.X)
        field_label(rem, s, "Compensating controls", CONTROLS_HELP)
        Segmented(rem, s, _options(Controls), state.controls).pack(fill=tk.X)

    def _entry(self, parent, variable, width, size=11, bold=False):
        t, s = self.style.theme, self.style
        return tk.Entry(parent, textvariable=variable, width=width, font=s.font(size, "bold" if bold else "normal"),
                        bg=t.field, fg=t.text, insertbackground=t.text, relief="flat", highlightthickness=2,
                        highlightbackground=t.border, highlightcolor=t.accent)

    def _check(self, parent, text, variable):
        t = self.style.theme
        return tk.Checkbutton(parent, text=text, variable=variable, font=self.style.font(9), bg=t.card, fg=t.text,
                              selectcolor=t.field, activebackground=t.card, activeforeground=t.text, anchor="w",
                              highlightthickness=0, disabledforeground=t.muted)

    def _build_results(self, parent):
        s, t = self.style, self.style.theme
        result = card(parent, s, "Priority")
        top = tk.Frame(result, bg=t.card)
        top.pack(fill=tk.X)
        self.badge = priority_badge(top, s, "-")
        self.badge.pack(side=tk.LEFT, ipady=10)
        info = tk.Frame(top, bg=t.card)
        info.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=18)
        self.verdict = tk.Label(info, text="", font=s.font(16, "bold"), bg=t.card, fg=t.text, anchor="w")
        self.verdict.pack(fill=tk.X)
        self.subtitle = tk.Label(info, text="", font=s.font(10), bg=t.card, fg=t.muted, anchor="w", justify="left")
        self.subtitle.pack(fill=tk.X, pady=(4, 0))
        self.subtitle.bind("<Configure>", lambda e: self.subtitle.configure(wraplength=max(e.width - 4, 100)))
        score_row = tk.Frame(result, bg=t.card)
        score_row.pack(fill=tk.X, pady=(14, 4))
        tk.Label(score_row, text="Ordering score", font=s.font(9), bg=t.card, fg=t.muted).pack(side=tk.LEFT)
        self.score_label = tk.Label(score_row, text="", font=s.font(10, "bold"), bg=t.card, fg=t.text)
        self.score_label.pack(side=tk.RIGHT)
        self.score_bar = ttk.Progressbar(result, maximum=10, style="Score.Horizontal.TProgressbar")
        self.score_bar.pack(fill=tk.X)
        tk.Label(result, text="Ranks items within a bucket; it does not decide the bucket.", font=s.font(8),
                 bg=t.card, fg=t.muted).pack(anchor="w", pady=(4, 0))
        self.chips = FlowFrame(result, t.card)
        self.chips.pack(fill=tk.X, pady=(12, 0))
        self.reasoning = Expander(result, s, "Show reasoning")
        self.reasoning.pack(fill=tk.X, pady=(8, 0))
        self.reasoning_text = tk.Label(self.reasoning.body, text="", font=s.font(10), bg=t.card, fg=t.text,
                                       anchor="w", justify="left")
        self.reasoning_text.pack(fill=tk.X)
        self.reasoning_text.bind("<Configure>",
                                 lambda e: self.reasoning_text.configure(wraplength=max(e.width - 4, 100)))

        action = card(parent, s, "Recommended action")
        self.action_label = tk.Label(action, text="", font=s.font(11), bg=t.card, fg=t.text, anchor="w", justify="left")
        self.action_label.pack(fill=tk.X)
        self.action_label.bind("<Configure>", lambda e: self.action_label.configure(wraplength=max(e.width - 4, 100)))

        what = card(parent, s, "What would change this?")
        self.whatif = tk.Frame(what, bg=t.card)
        self.whatif.pack(fill=tk.X)

        row = tk.Frame(parent, bg=t.bg)
        row.pack(fill=tk.X)
        self.copy_button = button(row, s, "Copy summary", self.copy_summary)
        self.copy_button.pack(side=tk.LEFT)
        self.markdown_button = button(row, s, "Copy as Markdown", self.copy_markdown, "secondary")
        self.markdown_button.pack(side=tk.LEFT, padx=8)
        self.copy_message = tk.Label(row, text="", font=s.font(9), bg=t.bg, fg=t.ok)
        self.copy_message.pack(side=tk.LEFT, padx=8)

    # ---- behaviour ----
    def focus_cve(self):
        """Put the cursor in the CVE field."""
        self.cve_entry.focus_set()
        self.cve_entry.selection_range(0, tk.END)

    def focus_first(self):
        """Put the cursor in the first useful field."""
        (self.cvss_entry if not self.state.cvss.get() else self.cve_entry).focus_set()

    def _cve_edited(self, *_args):
        state = self.state
        try:
            same = normalize_cve(state.cve.get()) == state.looked_up
        except ValueError:
            same = False
        if state.info is not None and not same:
            state.info, state.looked_up, state.override = None, "", None
            self.update()

    def lookup(self):
        """Look the CVE up in the local data and fill in the threat level."""
        state, t = self.state, self.style.theme
        text = state.cve.get().strip()
        if not text:
            state.info, state.looked_up, state.override = None, "", None
            self.refresh()
            return
        try:
            cve = normalize_cve(text)
        except ValueError as error:
            self.cve_message.configure(text=str(error), fg=t.error)
            return
        data = self.ctx.get_threat_data()
        state.info, state.looked_up, state.override = data.lookup(cve), cve, None
        state.cve.set(cve)
        state.looked_up = cve
        self.refresh()

    @property
    def auto_threat(self):
        """True when KEV or EPSS data decides the threat level."""
        info = self.state.info
        return info is not None and (info.kev_loaded or info.epss_loaded)

    def _decision(self, with_override=True):
        state = self.state
        override, reason = state.override if (with_override and state.override) else (None, "")
        return derive_threat(state.info, self.ctx.settings, analyst_confirmed=state.analyst.get(),
                             public_exploit=state.public.get(), override=override, override_reason=reason)

    def _threat_clicked(self):
        state = self.state
        if not self.auto_threat:
            self.refresh()
            return
        chosen = Threat[state.threat.get()]
        base = self._decision(with_override=False).level
        if chosen is base:
            state.override = None
        else:
            reason = ask_text(self.frame, self.style, "Override threat level",
                              f"The threat data says {base.name}. Why are you setting it to {chosen.name}? "
                              "The reason is recorded in the summary.", "Override")
            if reason is None:
                self.refresh()
                return
            state.override = (chosen, reason)
        self.refresh()

    def _clear_override(self):
        self.state.override = None
        self.refresh()

    def _set(self, variable, value):
        if variable.get() != value:
            variable.set(value)

    def update(self, *_args):
        """Schedule one redraw, however many inputs changed in this event-loop turn."""
        if self._pending is None and self.frame.winfo_exists():
            self._pending = self.frame.after_idle(self.refresh)

    def refresh(self):
        """Recompute and redraw everything from the current inputs now."""
        if self._pending is not None:
            self.frame.after_cancel(self._pending)
            self._pending = None
        if self.updating:
            return
        self.updating = True
        try:
            self._update()
        finally:
            self.updating = False

    def _update(self):
        t, state = self.style.theme, self.state
        self._update_threat_controls()
        raw = state.cvss.get().strip()
        self._update_cvss_band(raw)
        if not raw:
            self._idle("Waiting for input", "Enter a CVSS base score to calculate a priority.")
            return
        try:
            cvss = parse_cvss(raw)
        except ValueError as error:
            self.cvss_entry.configure(highlightbackground=t.error, highlightcolor=t.error)
            self.cvss_hint.configure(text=str(error), fg=t.error)
            self._idle("Invalid input", str(error), error=True)
            return
        self.cvss_entry.configure(highlightbackground=t.border, highlightcolor=t.accent)
        self.cvss_hint.configure(text="Enter a base score from 0.0 to 10.0", fg=t.muted)
        decision = self._decision() if self.auto_threat else None
        threat = decision.level if decision else Threat[state.threat.get()]
        inputs = AssessInputs(cvss, threat, Asset[state.asset.get()], Exposure[state.exposure.get()],
                              Controls[state.controls.get()], Patch[state.patch.get()])
        result = inputs.run(self.ctx.settings)
        if decision:
            result = apply_threat_context(result, decision, state.info)
        self.result = result
        self.versions = self.ctx.versions() if decision else ""
        self._show_result(result, inputs, decision)

    def _update_threat_controls(self):
        state, t = self.state, self.style.theme
        self.clear_override.pack_forget()
        if self.auto_threat:
            decision = self._decision()
            self._set(state.threat, decision.level.name)
            sources = "; ".join(decision.sources)
            self.threat_note.configure(text=f"Auto: {sources}.", fg=t.muted)
            if state.override:
                self.threat_note.configure(text=f"Manual override: {state.override[1]}. Data said "
                                                f"{self._decision(with_override=False).level.name}.", fg=t.warn)
                self.clear_override.pack(anchor="w", pady=(6, 0))
            for check in (self.analyst_check, self.public_check):
                check.configure(state="normal")
                check.pack(anchor="w", pady=(6, 0))
        else:
            self.threat_note.configure(text="Manual: choose the level yourself, or look up a CVE.", fg=t.muted)
            for check in (self.analyst_check, self.public_check):
                check.pack_forget()
        self._update_cve_chips()

    def _update_cve_chips(self):
        info, s, t = self.state.info, self.style, self.style.theme
        items = []
        if info is None:
            self.cve_message.configure(text="" if not self.state.cve.get().strip() else
                                       "Press Enter or Look up to check the local KEV and EPSS data.", fg=t.muted)
        elif not (info.kev_loaded or info.epss_loaded):
            self.cve_message.configure(text="No threat data is loaded, so nothing was looked up. Open Threat data "
                                            "to update or import it. This does not mean the CVE is safe.", fg=t.warn)
        else:
            self.cve_message.configure(text="", fg=t.muted)
            if info.kev_loaded:
                items.append(chip(self.cve_chips, s, "In CISA KEV" if info.kev else "Not in CISA KEV",
                                  "raise" if info.kev else "neutral"))
            else:
                items.append(chip(self.cve_chips, s, "KEV not loaded", "warn"))
            if info.epss_loaded:
                if info.percentile is None:
                    items.append(chip(self.cve_chips, s, "No EPSS score", "neutral"))
                else:
                    high = info.percentile >= self.ctx.settings.epss_percentile_cutoff
                    items.append(chip(self.cve_chips, s, f"EPSS {info.percentile * 100:.0f}th percentile",
                                      "raise" if high else "neutral"))
            else:
                items.append(chip(self.cve_chips, s, "EPSS not loaded", "warn"))
        self.cve_chips.set_items(items)

    def _update_cvss_band(self, raw):
        try:
            value = parse_cvss(raw)
        except ValueError:
            self.cvss_band.configure(text="")
            return
        label, direction = explain.cvss_band(value)
        self.cvss_band.configure(text=label, fg=self.style.direction(direction))

    def _idle(self, headline, sub, error=False):
        t = self.style.theme
        self.result = None
        self.badge.configure(text="!" if error else "-", bg=t.field, fg=t.error if error else t.muted)
        self.verdict.configure(text=headline)
        self.subtitle.configure(text=sub)
        self.score_bar.configure(value=0)
        self.score_label.configure(text="")
        self.action_label.configure(text="")
        self.chips.set_items([])
        self.reasoning_text.configure(text="")
        self._set_whatif([])
        for b in (self.copy_button, self.markdown_button):
            set_enabled(b, False)

    def _show_result(self, result, inputs, decision):
        s = self.style
        bg, fg = s.bucket(result.priority)
        headline, sub = explain.HEADLINES[result.priority]
        self.badge.configure(text=result.priority, bg=bg, fg=fg)
        self.verdict.configure(text=headline)
        self.subtitle.configure(text=sub)
        s_style = ttk.Style(self.frame)
        s_style.configure("Score.Horizontal.TProgressbar", background=bg, lightcolor=bg, darkcolor=bg)
        self.score_bar.configure(value=result.score)
        self.score_label.configure(text=f"{result.score:.2f} / 10")
        self.action_label.configure(text=result.action)
        self.chips.set_items([chip(self.chips, s, f.label, f.direction)
                              for f in explain.sorted_factors(result.factors)])
        lines = [f"• {r}" for r in result.reasons] + ["", *result.inputs, f"Scoring settings: {result.profile}"]
        if self.versions:
            lines.append(f"Threat data: {self.versions}")
        self.reasoning_text.configure(text="\n".join(lines))
        found = explain.what_would_change(inputs, self.ctx.settings)
        self._set_whatif(explain.what_if_lines(found), found)
        for b in (self.copy_button, self.markdown_button):
            set_enabled(b, True)

    def _set_whatif(self, lines, found=None):
        t, s = self.style.theme, self.style
        for child in self.whatif.winfo_children():
            child.destroy()
        coloured = {}
        if found is not None:
            for change in found.less_urgent + found.more_urgent:
                coloured[f"{change.priority} {change.text}"] = change.priority
        for line in lines:
            row = tk.Frame(self.whatif, bg=t.card)
            row.pack(fill=tk.X, pady=2)
            priority = coloured.get(line)
            if priority:
                word, rest = line.split(" ", 1)
                arrow = "▲" if explain.URGENCY[priority] > explain.URGENCY[found.current] else "▼"
                tk.Label(row, text=f"{arrow} {word}", font=s.font(10, "bold"), bg=t.card,
                         fg=s.priority_text_color(priority)).pack(side=tk.LEFT)
                text = rest
            else:
                text = line
            label = tk.Label(row, text=" " + text, font=s.font(10), bg=t.card, fg=t.text if priority else t.muted,
                             anchor="w", justify="left")
            label.pack(side=tk.LEFT, fill=tk.X, expand=True)
            label.bind("<Configure>", lambda e, w=label: w.configure(wraplength=max(e.width - 4, 100)))

    # ---- copying ----
    def copy_summary(self):
        """Copy the plain-text summary."""
        if self.result:
            self.ctx.copy(explain.summary_text(self.result, self.versions))
            self._flash("Summary copied")

    def copy_markdown(self):
        """Copy the Markdown summary."""
        if self.result:
            self.ctx.copy(explain.markdown_summary(self.result, self.versions))
            self._flash("Markdown copied")

    def _flash(self, text):
        self.copy_message.configure(text=f"✓ {text}")
        if self._flash_job:
            self.frame.after_cancel(self._flash_job)
        self._flash_job = self.frame.after(2000, lambda: self.copy_message.configure(text=""))

