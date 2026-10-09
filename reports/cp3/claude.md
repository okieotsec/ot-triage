Reviewer: Claude Code (developer and reviewer)
Checkpoint / commit: CP3 / 8b6e399 (tag cp3, v0.3.0 candidate; branch gui-refresh)
Tools run (with versions): bandit 1.9.4, semgrep 1.179.0 (p/python, p/security-audit; 200 rules, 34 files), ruff 0.16.10 (E,F,W,S,B at line length 120), pip-audit 2.10.1 (requirements.txt and requirements-dev.txt), osv-scanner 2.5.1 (requirements-dev.txt), gitleaks 8.30.1 (25 commits), cyclonedx-bom 7.5.0, hypothesis 6.168.5, openssl 3.6.3 (test certificate), headless Chromium (mockup check), ImageMagick import (screenshots of the real app), grep for eval/exec/pickle/subprocess/yaml.load/shell=True/unverified TLS contexts
Tools not run (and why): mitmproxy and atheris (as at CP2: the local TLS server tests and hypothesis property tests were used instead); Excel (not available); screen readers (Tkinter has weak support; not attempted); a keyboard-only manual walk-through by a person and a real 1366x768 screen (this machine runs a tiling window manager that ignores requested window sizes, so narrow layouts were checked by logic tests and by forcing the layout in the real window)
Command deviations from the plan: osv-scanner 2.x syntax; malicious files generated on demand (see CP1 and CP2)

Tool results
- bandit: 0 findings (6,894 LOC including tests). reports/cp3/bandit.json
- semgrep: 0 findings, 0 errors. reports/cp3/semgrep.json
- ruff: clean. reports/cp3/ruff.json
- pip-audit: no known vulnerabilities (requirements.txt is empty; requirements-dev.txt holds hypothesis). reports/cp3/pip-audit*.json
- osv-scanner: no vulnerabilities for requirements-dev.txt. reports/cp3/osv-dev.json
- gitleaks: no leaks in 25 commits. reports/cp3/gitleaks.json
- SBOM: unchanged from CP2 (only pip from the clean venv). The GUI was built on ttk, so no dependency was added; the plan's concern about CustomTkinter did not arise.
- Tests: 324 pass without hypothesis, 339 with it, run with ResourceWarning treated as an error and with zero stray Tk errors or tracebacks in the output.
- Risky-call grep: no eval, exec, pickle, subprocess, os.system, yaml.load, shell=True or unverified TLS contexts in application code (subprocess appears only in the test that creates a throwaway certificate).

Dynamic testing (CP3 focus: settings file handling, new UI inputs, background work)
- The plan's malicious CSV set (all 22 files, including 1M rows, a 50 MB line, UTF-16, Latin-1, formula payloads and bad CVSS values) was pushed through the Batch view itself: each ends in a short message or a table, within the time limit, and the view stays usable.
- The 14 hostile settings files run at application start: each leaves the app on defaults with exactly one warning and no Custom scoring badge. Six hostile preference files behave the same.
- Hostile stored threat data (corrupt KEV and EPSS files) shows "problem" chips in the status bar, and a CVE lookup says no data is loaded instead of reporting the CVE as safe.
- Formula payloads appear as plain text in the table and are neutralized in the export (id, name, cve, action, rationale, threat_source).
- Background work: a load that finishes after the window was rebuilt still lands in the saved state; an update can be cancelled mid-download; a second job while one runs is refused politely; a job finishing after its view is gone does not crash.
- Settings entry: bad text (non-numbers, empty text, comma decimals, huge numbers, NaN, infinity, out-of-range values, lines too close together) is rejected field by field and cannot be saved. Save, restore defaults and failed writes are covered. Mutation checks of the key controls all fail the tests.
- Real-app visual review: screenshots of the running application were reviewed for Assess (dark, light, 130% text, forced narrow layout), Batch, Threat data, Settings (light, custom scoring) and About (dark and light).

Threat model update (section 3)
- New: appearance preferences file (ui.json), strict loader with fallback, 4 KB limit. New: background worker thread (no Tk calls from the thread; results return through a queue). New: file dialogs (the chosen path is only opened, never joined with other input). New: clipboard output (plain text, includes inputs, settings and data versions). New: optional update on start (off by default; ticking the box is the consent, and no confirmation is shown at launch).

Finding CP3-01
- Title: Background job callbacks could reach a destroyed view
- Severity: Low (error output and a lost result after a theme change during a load)
- Location: gui_batch.py (_progress, _loaded)
- Description: A progress or completion callback ran after the window had been rebuilt, touching widgets that no longer existed.
- Evidence / reproduction steps: TclError "invalid command name" during test teardown (test_a_load_that_finishes_after_a_rebuild_still_lands_in_the_state reproduces it).
- Recommended fix: Guard the callbacks and store the finished result in the saved state independent of the widgets (applied).
- Confidence: Confirmed
- Status: fixed and verified

Finding CP3-02
- Title: GUI tests made real network downloads
- Severity: Info (test isolation; no effect on the shipped application)
- Location: threatdata.py update_from_network, test_gui_threat.py
- Description: update_from_network bound fetcher=fetch as a default argument at definition time, so patching threatdata.fetch in tests had no effect and the view tests downloaded the real public KEV and EPSS files into temporary folders.
- Evidence / reproduction steps: A test run took 30 seconds and showed 1,734 real KEV entries instead of the test file's one.
- Recommended fix: The GUI now passes the fetcher at call time; every GUI test blocks the network so any attempt fails the test; cancel is forwarded to the download (applied). Confirmed afterwards that nothing was written to the real per-user settings or data folders.
- Confidence: Confirmed
- Status: fixed and verified

Finding CP3-03
- Title: Disabled primary buttons were nearly unreadable
- Severity: Low (accessibility)
- Location: gui_widgets.py button
- Description: A disabled button kept its accent colour with dim text, for example the Save button in the light theme.
- Evidence / reproduction steps: Screenshot of the Settings view in the light theme.
- Recommended fix: A distinct disabled look (set_enabled), with a contrast test of at least 3:1 for disabled text in both themes (applied).
- Confidence: Confirmed
- Status: fixed and verified

Finding CP3-04
- Title: Several visual and usability defects found only by looking at the real window
- Severity: Info
- Location: gui_assess.py, vuln_prioritizer_gui.py, gui_widgets.py, gui_about.py
- Description: Choices ran most to least concerning instead of the reverse; the header accent line covered only part of the width; the scrollbar was always shown; document names in About were truncated by a fixed-width column.
- Evidence / reproduction steps: Screenshots of the running application.
- Recommended fix: Fixed, each with a regression test, and the truncation test was mutation-checked (applied).
- Confidence: Confirmed
- Status: fixed and verified

Finding CP3-05
- Title: Scanner warning from a misleading parameter name
- Severity: Info
- Location: gui_context.py, vuln_prioritizer_gui.py
- Description: bandit B604 flagged the keyword argument shell=self (the window object, unrelated to subprocess).
- Evidence / reproduction steps: reports/cp3/bandit.json before the rename.
- Recommended fix: Renamed the parameter to app instead of suppressing the warning (applied).
- Confidence: Confirmed
- Status: fixed and verified

Finding CP3-06
- Title: Optional startup update downloads without a confirmation at launch
- Severity: Info
- Location: vuln_prioritizer_gui.py (App.__init__), gui_settings.py
- Description: When the user enables "Update threat data when the app starts", each launch contacts the two hosts without prompting.
- Evidence / reproduction steps: test_startup_update_runs_only_when_enabled.
- Recommended fix: None. The option is off by default, the label says so, and enabling it is the consent. The first manual update still shows the confirmation naming both hosts.
- Confidence: Confirmed
- Status: accepted by design

Finding CP3-07
- Title: Real-screen checks not done on a small display
- Severity: Info
- Location: n/a
- Description: The 1366x768 and narrow-window checks were not run on a real small screen because the tiling window manager ignores requested sizes.
- Evidence / reproduction steps: Requested window sizes were not honoured in screenshots.
- Recommended fix: Run the manual checklist in docs/GUI_TESTING.md on a small display before release (CP4).
- Confidence: Confirmed
- Status: open (carried to CP4)

Manual checklist (6.1), changes since CP2
- Input handling: Pass. Settings and preference text fields, files and the batch CSV all have limits, validation and clear messages; unexpected errors show a short message and the details stay on the terminal (tested).
- Network: Pass. Nothing is downloaded unless a button is pressed (or the startup option is on); the first update names both hosts and asks; updates can be cancelled; failures keep the previous copy.
- Files and storage: Pass. Settings and preferences are written atomically with user-only permissions; tests never touch the real folders.
- Output and integrity: Pass. Copied summaries, the reasoning panel and exports include inputs, scoring settings and KEV/EPSS versions; a Custom scoring badge is always shown when settings differ from the defaults, and batch results scored under older settings are flagged.
- Logic: Pass. The "what would change" panel is tested against the real rules; a CVE with no loaded data is never presented as safe.

Open items for CP4: run the manual checklist on a real small screen (CP3-07), re-run the full toolchain on the release candidate, write SECURITY.md, generate the final SBOM and archive all reports.
