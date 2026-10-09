"""The About view: what the tool is, where its categories come from, and where to read more."""
import tkinter as tk

from gui_assess import EXPOSURE_HELP
from gui_brand import BRAND_NAME, LINKS, TAGLINE, wordmark
from gui_widgets import LinkLabel, ScrollFrame, card, wrap_to_width
from references import Reference
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
        about = card(scroll.body, self.style, "About")
        byline = tk.Frame(about, bg=t.card)
        byline.pack(fill=tk.X, pady=(0, 8))
        tk.Label(byline, text=f"OT Triage {__version__}  by", font=self.style.font(11, "bold"), bg=t.card, fg=t.text,
                 padx=0).pack(side=tk.LEFT)
        wordmark(byline, self.style, t.card, size=11).pack(side=tk.LEFT, padx=(5, 0))
        self._paragraphs(about, [
            (("Rule-based Now / Next / Never triage. It works fully offline; the only network access is a "
              "threat-data update that you start yourself."), False),
            ("Low exposure: " + EXPOSURE_HELP, False)])
        self._build_links(scroll.body)
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
            wrap_to_width(text)

    def _build_links(self, parent):
        """A card with the project's public links; each opens in the browser only when it is clicked."""
        t = self.style.theme
        box = card(parent, self.style, f"Made by {BRAND_NAME}")
        self._paragraphs(box, [(TAGLINE, False)])
        self.link_labels = []
        for name, url in LINKS:
            row = tk.Frame(box, bg=t.card)
            row.pack(fill=tk.X, pady=2)
            link = LinkLabel(row, self.style, name, lambda u=url, n=name: self.ctx.open_reference(Reference(n, u)))
            link.pack(side=tk.LEFT)
            tk.Label(row, text="  " + url.removeprefix("https://"), font=self.style.font(9), bg=t.card,
                     fg=t.muted).pack(side=tk.LEFT)
            self.link_labels.append(link)

    def _paragraphs(self, box, paragraphs):
        t = self.style.theme
        for text, bold in paragraphs:
            label = tk.Label(box, text=text, font=self.style.font(11 if bold else 10, "bold" if bold else "normal"),
                             bg=t.card, fg=t.text if bold else t.muted, anchor="w", justify="left")
            label.pack(fill=tk.X, pady=(0, 8))
            wrap_to_width(label)
