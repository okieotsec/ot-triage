# Changelog

## 0.4.0 (release candidate)

- **References from CISA's notes:** the Assess view lists the links CISA adds to a KEV entry (advisories, vendor pages, BOD guidance) under Recommended action, each with its real domain. Links open in your browser only when you click them, only safe `https` links are clickable, and the copied summaries include them. See [docs/THREAT_DATA.md](docs/THREAT_DATA.md).
- **Changed:** looking up a CVE that is in CISA KEV now shows CISA's required action, the reference links and the KEV chips straight away, without waiting for a CVSS score. Only the priority itself needs the score, and it says so.
- **New name and branding:** the project is now **OT Triage by OkieOTSec** (it was "Vulnerability Prioritizer"). The window shows the OkieOTSec wordmark and a new icon (three bars in the result colours), the About page links to the project's website, GitHub, YouTube and X, and the light theme is now a warm cream. The entry point is `ot_triage_gui.py`, and the settings and data folders are now named `ot-triage` (an existing install should move its old `vuln-prioritizer` folders, or just download the threat data again).
- **Fixed:** a long message in the Assess inputs column (for example "No threat data is loaded") could make the column as wide as the message and push the results column off screen. All wrapping text now starts from a sensible width, and a test checks it.
- **Fixed:** a long sentence in front of a CISA link was shown as the link text; it is now shown as an explanation, with the domain as the link.
- **Code quality:** the lint rules are now listed explicitly in `ruff.toml` (bugs, security, import order, modern syntax, simplifications) and CI uses that file with a pinned ruff version. About 50 style findings were fixed; behaviour is unchanged (all tests pass and all 110,160 CVSS vectors still match FIRST's calculators).
- **Fixed (Windows):** a button stayed in its darker pressed colour after a click until the pointer moved; it now returns to normal at once.
- **Fixed:** pasting an enormous text into a text box could freeze the app on Windows (Tk becomes extremely slow showing megabytes on one line). Text boxes now refuse input beyond 2,000 characters immediately, and the CVSS vector box says so. Layout switches and the scrollbar also no longer flip back and forth in some window sizes, which made the interface stall on some systems.
- **License:** the project is released under the MIT License (see [LICENSE](LICENSE)).
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
