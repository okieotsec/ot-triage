"""The About view: what the tool is, where its categories come from, and where to read more."""
import tkinter as tk

from gui_assess import EXPOSURE_HELP
from gui_widgets import ScrollFrame, card
from version import __version__

ATTRIBUTION = ("The Now / Next / Never categories come from Dragos' annual ICS/OT Cybersecurity Year in Review "
               "vulnerability analysis, which has used them since at least its 2020 report. Other OT practitioners "
               "use similar framing, such as Foxguard's \"Patch Now, Next, or Never.\" This tool adapts the idea "
               "with its own scoring rules; its definitions are not Dragos' and are documented in docs/POLICY.md.")
DOCUMENTS = [("README.md", "How to run the tool, the rules as implemented, and the batch CSV format"),
             ("docs/CVSS.md", "Pasting CVSS vectors, supported versions and how the scores were verified"),
             ("docs/POLICY.md", "The prioritization decisions and why they were made"),
             ("docs/THREAT_DATA.md", "KEV and EPSS data, offline updates and the safety checks"),
             ("docs/SETTINGS.md", "The adjustable scoring settings, their defaults and limits"),
             ("SECURITY_TEST_PLAN.md", "How the tool is security tested, with reports under reports/")]


class AboutView:
    """Builds the About screen."""

    name = "about"

    def __init__(self, ctx, parent):
        self.ctx, self.style = ctx, ctx.style
        t = self.style.theme
        self.frame = tk.Frame(parent, bg=t.bg)
        scroll = ScrollFrame(self.frame, t.bg)
        scroll.pack(fill=tk.BOTH, expand=True)
        scroll.body.configure(padx=28, pady=24)
        self._paragraphs(card(scroll.body, self.style, "About"), [
            (f"Vulnerability Prioritizer {__version__}", True),
            (("Rule-based Now / Next / Never triage. It works fully offline; the only network access is a "
              "threat-data update that you start yourself."), False),
            ("Low exposure: " + EXPOSURE_HELP, False)])
        self._paragraphs(card(scroll.body, self.style, "Where the categories come from"), [(ATTRIBUTION, False)])
        docs = card(scroll.body, self.style, "Documentation")
        docs.columnconfigure(1, weight=1)
        self.doc_names = []
        for row, (name, description) in enumerate(DOCUMENTS):
            label = tk.Label(docs, text=name, font=self.style.font(10, "bold"), bg=t.card, fg=t.text, anchor="w")
            label.grid(row=row, column=0, sticky="w", padx=(0, 18), pady=2)
            self.doc_names.append(label)
            text = tk.Label(docs, text=description, font=self.style.font(10), bg=t.card, fg=t.muted, anchor="w",
                            justify="left")
            text.grid(row=row, column=1, sticky="ew", pady=2)
            text.bind("<Configure>", lambda e, w=text: w.configure(wraplength=max(e.width - 4, 100)))

    def _paragraphs(self, box, paragraphs):
        t = self.style.theme
        for text, bold in paragraphs:
            label = tk.Label(box, text=text, font=self.style.font(11 if bold else 10, "bold" if bold else "normal"),
                             bg=t.card, fg=t.text if bold else t.muted, anchor="w", justify="left")
            label.pack(fill=tk.X, pady=(0, 8))
            label.bind("<Configure>", lambda e, w=label: w.configure(wraplength=max(e.width - 4, 100)))
