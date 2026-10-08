# Changelog

## 0.4.0 (release candidate)

- **Fixed:** the headline in the Priority card (for example "Schedule remediation") was cut off in medium-width windows; it now wraps onto a second line.
- **Fixed:** changing the threat level in the Assess view could show an extra "unexpected error (TclError)" box after the override reason prompt, because the dialog tried to take the keyboard grab before the window manager had shown it. The grab is now retried until the window is visible and can never raise.
- **CVSS vectors:** paste a CVSS 3.0, 3.1 or 4.0 vector in the Assess view to fill in the base score, or add a `cvss_vector` column to batch files. Scores match FIRST's official calculators for every possible base vector. See [docs/CVSS.md](docs/CVSS.md).
- **New GUI:** Assess, Batch, Threat data, Settings and About views with dark and light themes, a status bar showing threat data freshness, keyboard shortcuts, and a "What would change this?" panel.
- **Visual polish:** modern typeface, rounded cards, buttons, chips and inputs, a refined sidebar, and layouts that work down to a 700 px wide window.
- **Threat data:** CISA KEV and EPSS lookups from local files, user-started updates with progress and cancel, offline import, freshness warnings.
- **Adjustable scoring:** the two CVSS lines, the EPSS cutoff and the stale-data limit, with validation and a visible "Custom scoring" badge.
- **Rules updated** (see [docs/POLICY.md](docs/POLICY.md)): actively exploited, exposed crown jewels are NOW at any CVSS score; exposed crown jewels are never below NEXT; partial controls only affect the ranking score.
- **Security:** hostile-input handling for every file the tool reads, atomic user-only file writes, an HTTPS-only downloader with size, time and redirect limits, formula-safe CSV export, and a test that keeps invisible or look-alike characters out of the source. See [SECURITY.md](SECURITY.md).

## 0.1.0 (baseline)

- Rule-based Now / Next / Never prioritization with a GUI and CSV batch mode.
