Reviewer: Claude Code (developer and reviewer)
Checkpoint / commit: CP4 / 469bdbe (tags cp4 and v0.4.0-rc1)
Tools run (with versions): bandit 1.9.4, semgrep 1.179.0 (p/python, p/security-audit; 200 rules, 41 files), ruff 0.16.10 (E,F,W,S,B at line length 120), pip-audit 2.10.1 (requirements.txt and requirements-dev.txt), osv-scanner 2.5.1 (requirements-dev.txt), gitleaks 8.30.1 (31 commits, full history), cyclonedx-bom 7.5.0, hypothesis 6.168.5, openssl 3.6.3 (test certificate), Node.js 26.7.0 with FIRST's official CVSS calculators (verification only, pinned by SHA-256), ImageMagick import (screenshots of the running application), grep for eval/exec/pickle/os.system/yaml.load/shell=True/unverified TLS
Tools not run (and why): mitmproxy and atheris (as at CP2 and CP3: a local TLS server and hypothesis property tests were used instead); Excel (unavailable; LibreOffice was used for the export check at CP1); screen readers (Tkinter support is weak and was not attempted)
Command deviations from the plan: osv-scanner 2.x syntax; malicious files are generated on demand by malicious_cases.py instead of stored under tests/data/malicious/ (see CP1)

Tool results (all attached under reports/cp4/)
- bandit: 0 findings (8,956 LOC including tests). bandit.json
- semgrep: 0 findings, 0 errors. semgrep.json
- ruff: clean. ruff.json
- pip-audit: no known vulnerabilities for requirements.txt (empty: standard library only) or requirements-dev.txt (hypothesis). pip-audit*.json
- osv-scanner: no vulnerable packages (requirements-dev.txt). osv-dev.json
- gitleaks: no leaks in 31 commits. gitleaks.json
- SBOM: sbom/sbom.cdx.json regenerated; the component list is identical to CP3 (only pip, from the clean environment). No dependency was added at any checkpoint.
- Tests: 430 pass with the standard library only (tests-stdlib-only.log) and 448 with hypothesis (tests-with-hypothesis.log), both run with ResourceWarning treated as an error, with zero tracebacks or stray Tk errors in the output. The skipped tests are the ones that need the window manager to grant real keyboard focus.
- CVSS: all 110,160 possible base vectors (CVSS 3.0, 3.1 and 4.0) score identically to the official FIRST calculators, re-run at CP4 with the reference files pinned by SHA-256. cvss-official-verification.log
- Live data: an update from the real CISA and EPSS servers into a temporary folder succeeded in 1.5 s and validated today's real data (KEV 1,739 entries, EPSS 384,534 scores), with files 0600 in a 0700 folder. live-update-check.log. The project lead's own update through the application at 15:20 the same day also produced a valid stored copy.

Real-window checks (new at CP4)
- The running application was launched as a floating window at exact sizes (1366x700, 1024x640, 800x600, 700x560, which is the minimum) and captured; the Batch, Assess and Threat data views were reviewed at those sizes. This closes the part of CP3-07 that could not be done before (the window manager had ignored requested sizes).
- Keyboard reachability: for every view, the real Tk Tab order is walked and every interactive control is asserted to be on it (test_gui_app.KeyboardReachabilityTests, mutation-checked by making the choice controls unfocusable).

Finding CP4-01
- Title: Table and scrollbars showed the stock theme's colours in untreated states
- Severity: Low (visual and accessibility: beige borders and a light scrollbar on a dark interface)
- Location: gui_theme.py apply_ttk_styles
- Description: The clam theme's default border and scrollbar colours leaked through for the table field, and for a scrollbar with nothing to scroll (its disabled state), and for the progress bar's disabled state.
- Evidence / reproduction steps: A screenshot of the empty Batch view in a 1366x700 window; the pixels at the table edge were #9e9a91 and #eeebe7.
- Recommended fix: Theme every state, and add a test that no stock colour is returned for any applicable option and state in either theme (applied).
- Confidence: Confirmed
- Status: fixed and verified

Finding CP4-02
- Title: The narrow tab strip clipped its last tab at the minimum window width
- Severity: Low (usability)
- Location: vuln_prioritizer_gui.py _layout
- Description: With the keyboard hints shown, the five tabs were wider than 700 pixels, so "About" was cut off.
- Evidence / reproduction steps: A 700x560 window.
- Recommended fix: Hide the shortcut hints in the narrow layout; tested at every text size from 90% to 130% (applied).
- Confidence: Confirmed
- Status: fixed and verified

Finding CP4-03
- Title: Stale and loose text in the interface
- Severity: Info
- Location: gui_batch.py, gui_assess.py
- Description: The empty Batch hint still listed cvss as the only score column after the vector column was added, and empty message lines left visible gaps.
- Evidence / reproduction steps: Screenshots at 1366x700.
- Recommended fix: Updated the text, and made empty message lines collapse (applied; tested).
- Confidence: Confirmed
- Status: fixed and verified

Finding CP4-04
- Title: GUI tests could write to the real user's default folders
- Severity: Info (no leak was found; a safeguard was missing)
- Location: gui_testing.py
- Description: Tests use temporary folders, but nothing prevented an accidental write to a default settings, preferences or data path. When new files appeared in the real folders during CP4, a leak could not be ruled out on timing alone. Checking the contents showed they came from the project lead's own use of the application (a real update at 15:20 and a theme change at 15:21), and the full suite did not modify them.
- Evidence / reproduction steps: File timestamps and metadata (source URLs, today's real data); unchanged modification times across a full test run.
- Recommended fix: Run the GUI tests with HOME and the XDG folders pointing at a private temporary folder, with a test that proves it (applied).
- Confidence: Confirmed
- Status: fixed and verified

Finding CP3-07 (carried from CP3): disposition
- The small-screen part is now verified in real windows at exact sizes and the keyboard-reachability part by an automated Tab-order test. What remains is a person using a real keyboard for the manual checklist in docs/GUI_TESTING.md on their own screen. This is recommended before publishing but is not a security control.
- Status: closed with one residual manual step (below)

Manual checklist (6.1): final
- Input handling: Pass. Every file the tool reads has a size limit, encoding handling and strict validation: batch CSV, KEV JSON, EPSS CSV, settings, preferences and CVSS vectors. Errors are short messages; stack traces never reach the user. No eval, exec, pickle, subprocess or shell use in application code.
- Network: Pass. HTTPS only to two expected hosts; certificate and host name verification cannot be switched off from the interface or settings; at most 3 same-host redirects; timeouts, size and decompressed-size caps, a total deadline, truncation detection and cancel; nothing is downloaded unless the user starts an update (or ticks the opt-in startup option); proxy settings honoured.
- Files and storage: Pass. Atomic replacement after full validation; failed updates keep the previous copy; user-only permissions; no paths built from untrusted input.
- Output and integrity: Pass. Formula-safe CSV export for every text cell, including threat-data text and CVSS vectors; summaries and exports include inputs, scoring settings, CVSS vector and version, and KEV/EPSS versions; a Custom scoring badge is always shown; results scored under older settings are flagged.
- Logic: Pass. NaN, infinity, negative and out-of-range values are rejected everywhere; settings validation prevents inconsistent thresholds; a CVE with no data is never treated as safe; the monotonicity test holds under default and custom settings.

Exit criteria (section 9)
| Criterion | Evidence | Met |
| --- | --- | --- |
| All tools in section 5 ran successfully with output attached | bandit, semgrep, ruff, gitleaks, pip-audit, osv-scanner, SBOM: reports/cp4/ | Yes |
| No open Critical or High findings | None found at any checkpoint (3 Medium, 5 Low, 15 Info in total) | Yes |
| Every Medium finding fixed or accepted | CP0-01, CP1-01 and CP2-01 are fixed and verified | Yes |
| Full test suite, including the malicious file set, passes | 430 tests (standard library only) and 448 (with hypothesis) | Yes |
| SBOM generated and diffed against the previous checkpoint | sbom/sbom.cdx.json; component list identical to CP3 | Yes |
| No known vulnerabilities in dependencies, or each documented | None known; there are no third-party runtime dependencies | Yes |
| Final SBOM committed and attached to the release | sbom/sbom.cdx.json is committed; attach it when the release is created | Committed |
| SECURITY.md published | SECURITY.md (reporting method, supported versions, what is downloaded and from where, offline operation) | Yes, with a step for the maintainer (below) |
| README links to the SBOM and summarizes the security testing | README, Security section | Yes |
| This plan and all checkpoint reports archived in the repository | SECURITY_TEST_PLAN.md and reports/cp0 to reports/cp4 | Yes |

Steps for the project lead before publishing (not things the tool can do)
1. Enable GitHub's private vulnerability reporting on the repository, because SECURITY.md tells reporters to use it.
2. Run the manual checklist in docs/GUI_TESTING.md once on your own screen with a real keyboard.
3. Replace the git identity placeholder (the commits use a no-reply address) if you want your own name and address in the history, and decide whether the first public tag is v0.4.0-rc1 or v0.4.0.
4. Attach sbom/sbom.cdx.json to the release when it is created.
5. Have the independent reviewers (Codex and Gemini in the plan) run their own reports against the cp4 tag if you want the independent review the plan describes. Their reports would go in reports/cp4/<reviewer>.md; this report has not been compared with theirs.
