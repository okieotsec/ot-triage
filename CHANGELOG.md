# Changelog

## 0.4.0 (release candidate)

- **References from CISA's notes:** the Assess view lists the links CISA adds to a KEV entry (advisories, vendor pages, BOD guidance) under Recommended action, each with its real domain. Links open in your browser only when you click them, only safe `https` links are clickable, and the copied summaries include them. See [docs/THREAT_DATA.md](docs/THREAT_DATA.md).
- **Fixed:** strong compensating controls did not lower the ordering score, so an item with strong controls could rank above the same item with partial controls (for example an actively exploited item already at NEXT). Strong controls now take 1.0 off the ordering score (partial still 0.5), and a test checks that better controls never rank higher. Buckets are unchanged. See [docs/POLICY.md](docs/POLICY.md), rule 4.
- **More from the KEV data:** the Batch Details box lists a row's CISA references (compact, with a scrolling area so long details never hide the table), the CSV export gains `references` and `forensic_triage` columns, and entries CISA flags for forensic triage get a neutral "Forensic triage advised" chip. None of these change a bucket or score.
- **Text size shortcuts:** Ctrl+plus, Ctrl+minus and Ctrl+0 make the whole interface larger or smaller (90% to 130%) or reset it, and the choice is remembered. This helps on window managers where resizing the window is awkward.
- **Clearer Windows certificate error:** on a fresh Windows install the EPSS download can fail with "unable to get local issuer certificate" because Windows has not installed a trusted root yet. The message now points to a verified fix in [docs/THREAT_DATA.md](docs/THREAT_DATA.md) (install Amazon Trust's published root, checked against its SHA-256). Certificate checking stays on.
- **Fixed:** in the Batch view the Details box could be cut off in shorter windows; the results table now gives up space first.
- **Fixed:** in the Batch view the loading progress bar could be squeezed out of sight by the results table in short windows; it now sits directly under the toolbar.
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
