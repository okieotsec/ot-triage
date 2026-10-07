# Roadmap and design decisions

Approved 2026-10-07. This page records what is planned, in what order, and why.

## Order of work and why

1. **Baseline and Part 1 fixes** (done). A tagged baseline lets every later change be compared. The small fixes were done first because they are low risk.
2. **Policy decisions** (done, see [POLICY.md](POLICY.md)). The rules had to be settled before anything else was built on top of them.
3. **Scoring settings, core only (no screen yet).** The rule code takes its numbers from one settings object. This makes later features simple, and it makes the threat-data work and the new GUI use the same values. *(done: see [SETTINGS.md](SETTINGS.md))*
4. **Threat-data layer (KEV and EPSS), no screen yet.** Download, import from file, validation and storage come first, with the security checkpoint CP2 after it.
5. **New GUI, built once** on top of steps 3 and 4, then a settings tab. Building the GUI last avoids building it twice.

## Release phases

| Release | Contents | Security checkpoint |
| --- | --- | --- |
| v0.1 | Part 1 fixes, policy changes, README and policy docs | CP1 |
| v0.2 | Threat data (KEV and EPSS), offline import | CP2 (highest risk: network and file parsing) |
| v0.3 | Adjustable settings and the new GUI | CP3 |

The point of the phases is to publish something useful early. A tool this size can stall if everything must be finished first.

## Scoring settings: fewer knobs on purpose

Only a small set of values will be adjustable:

- the two CVSS lines (7.0 and 9.0),
- the EPSS cutoff for "likely exploited",
- the number of days before threat data is flagged as stale.

The rule structure, the 4.0 low-severity line, the ordering weights, and the partial-controls credit stay fixed. The 4.0 line is the CVSS standard's own "Medium" boundary, and the severity labels in the GUI come from the standard, so they must not be tunable.

**Why so few.** Every setting needs validation, can break the "worse input never lowers priority" guarantee when changed, and adds attack surface (a settings file is an input). A short list of documented settings is also easier to defend than a tool where everything can be changed.

## Threat data (KEV and EPSS): notes

- A CVE in the CISA KEV catalog means active exploitation. Absence from KEV, or a low EPSS score, never lowers a threat level.
- **EPSS measures the likelihood of exploitation activity, not whether a public exploit exists.** An EPSS-triggered "public" level will be labeled as "elevated EPSS" in the interface and rationale, so the tool never claims a public exploit exists when it does not.
- Updating is always started by the user (an optional check at startup stays off by default). An import-from-file option covers offline networks.
- Downloads use HTTPS only. The standard library follows redirects, including from HTTPS to plain HTTP, so a custom redirect handler is required. Decompressed size of the EPSS file is capped.

## GUI direction

**Framework: stay on ttk** (the standard Tkinter widgets, with the existing custom dark theme), and add a light theme through the same colour tokens. CustomTkinter was considered and rejected: it is a new dependency that appears to have had no release in a long time, which this project's own security plan flags, and the current look is already close to modern.

Planned improvements:

- A sidebar with Assess, Batch, Threat data, Settings and About, with Batch as a tab instead of a pop-up window.
- A status bar that always shows how fresh the KEV and EPSS data are, an Update button, and a "Custom scoring" badge when settings differ from defaults.
- Segmented buttons instead of dropdowns for inputs with 2 to 3 choices, so every option is visible. Short labels, with long descriptions as tooltips.
- Result card with colour-coded "why" chips (raising or lowering priority) and a "Show reasoning" expander.
- A "What would change this?" panel that re-runs the rules once per alternative single input and lists which change would move the bucket. This makes the logic easy to explain and trust.
- Batch view with clickable bucket counters as filters, a search box, sortable columns and tinted rows with text labels.
- Accessibility: contrast checked, colour never the only signal, keyboard shortcuts (Ctrl+1 to 4 for views), a sensible tab order, a font-size setting.
- Copy as Markdown for pasting into tickets.

## Security testing

Each phase ends with a checkpoint under `reports/`. The plan requires every tool to actually run, with output attached. Status so far:

- CP0 (baseline) and CP1 (after Part 1): all tools run, including gitleaks and osv-scanner.
- CP2 and CP3: pending.
