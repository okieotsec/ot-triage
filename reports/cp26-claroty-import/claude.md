Reviewer: Claude Code (developer and reviewer)
Checkpoint / commit: CP26 (Claroty xDome device-vulnerability pairs import) / branch claroty-import, before merge
Scope: a new reader for a file the project parses: the Claroty xDome device-vulnerability pairs report, as CSV. Files: scanimport.py (detect_format, _read_claroty, the only_confirmed option through read_export, read_exports and import_exports), ot_triage_import.py (--only-confirmed), gui_batch.py (dialog text), the fictional sample and its expected findings, the tests and the documents. No change to the ranking rules.
Tools run (with versions): the project's runner (ruff 0.16.10, bandit 1.9.4, semgrep, gitleaks), the full suite on a private virtual display, mutation checks on the new tests
Tools not run (and why): atheris (no new binary or archive parser; the CSV reader is the one every importer already uses), osv-scanner and pip-audit (no dependencies)

How it was made. The project lead obtained one demo export of the report as an Excel file and shared its content with the developer for guidance. It was used for the column names, the layout and the kinds of rows, and was then deleted at the lead's request. None of its content (device names, hostnames, addresses, ids) is in the repository: a search of every new and changed file for each device name, host name part and address in it found nothing. The sample is invented in the same plant ("Cedar Creek") and address ranges as the other samples.

Finding CP26-01
- Title: Claroty's own scores and exploitation flag must not decide a bucket, and must not be mistaken for the CVSS score
- Severity: Info (a design risk found before building, not a vulnerability)
- Location: the Claroty columns "CVSS V3 BASE SCORE" (a severity word), "CVSS V3 BASE SCORE POINTS" (the number), "ADJUSTED VULNERABILITY SCORE", "DEVICE RISK SCORE", "ACTIVELY EXPLOITED", "EPSS SCORE"
- Description: the export has three scores and a flag that look usable. Reading the severity word as a score gives no score; reading the adjusted or device score would put the vendor's opinion into a bucket; the exploitation flag is set on 39% of the demo rows. The policy (docs/POLICY.md and the earlier importers) is that a scanner's own scores, likelihoods and exploit fields are not used: the threat level comes from CISA KEV and EPSS data.
- What was done: only the numeric CVSS column is read (the word column is a fallback only if it holds a number); the other columns are never read. A test builds the same row with those columns quiet and loud and requires identical findings with no threat level set.
- Status: prevented by design and by test. Confidence: Confirmed.

Finding CP26-02
- Title: A row that names several CVEs shares one score
- Severity: Info
- Description: grouped advisories (several CVEs under one advisory name) carry one CVSS number for the group. Each CVE becomes its own finding with that number, which may overstate one of them.
- What was done: documented in docs/IMPORT.md; nothing is guessed per CVE.
- Status: accepted and documented. Confidence: Confirmed.

Finding CP26-03
- Title: "Potentially Relevant" rows
- Severity: Info
- Description: Claroty marks a device-vulnerability pair "Potentially Relevant" when it has not confirmed that the device is affected (252 of 525 rows in the demo). Dropping them would treat "not confirmed" as safe; keeping them silently would mix them in.
- What was done (owner's decision, 2026-10-15): they are kept, marked ` [potentially relevant]` at the end of the finding's name, counted in the summary note, and `--only-confirmed` leaves them out. The Import scan dialog keeps them (the option is command-line only for now).
- Status: fixed as decided. Confidence: Confirmed.

Behaviour details checked by tests
- The format is recognised only when Device Name, Vulnerability Name and CVEs are all present (a header with two of three is not Claroty).
- Skipped, and counted: a resolution date or a patch-install date (blank, N/A, "-" and "none" mean open); no device name.
- `patch` is `available` only for Patch Available or Version Upgrade Available without "Manufacturer Not Patching Model"; mitigation-only and contact-the-manufacturer rows are left empty.
- A row with no CVE is kept and needs a threat level like any other finding with no CVE; a missing or out-of-range score leaves the finding "not scored".
- Device addresses lose their "(Last known IP)" remark and are capped at four; they go to the inventory's name column. A device name that starts with a formula character is defused in the findings file. A long name plus the mark never exceeds the name limit.
- End to end: the sample imported, written, given a crown jewel / Low / strong inventory and ranked: every row with CVSS 7.0 or more is NEXT (CP24's floor), the 5.9 row is NEVER and the unscored row is an error naming the score.

Mutation checks (24 mutants, 24 caught after one test was added)
- Detection removed, relaxed to two of three columns (this one survived the first round and a test was added), resolution or install skip removed or widened, only-confirmed ignored or applied always, the mark removed or not truncated, the score column swapped or the number column dropped, the "not patching" exclusion removed, any remedy text called available, only patch called available, the address cap or the remark strip removed, only the first CVE kept, the CVE left out of the id (two findings collapse), the option not passed on in three places, the note replaced, the addresses dropped.

Suppressions added / removed: none.
SSDF practices touched: PW.1 (a design decision recorded before building), PW.5 (input checks: the shared reader, size and row limits, cleaned text), PW.8 (tests, mutation checks).

Release gate for this change
| Gate | Evidence | Pass |
| --- | --- | --- |
| Owner's decision recorded before the change | the owner's instruction of 2026-10-15 | Yes |
| No change to bucket logic or ordering scores | only a reader and an option on the import changed | Yes |
| No content of the source export in the repository | the search described above | Yes |
| Documents say what is and is not used | docs/IMPORT.md, samples/scanners/README.md, CHANGELOG | Yes |
| Full suite, runner | see the tail of this report | Yes |

Verification
- Full suite on a private virtual display: 1,164 tests; the first run had one failure, in the bundle test that runs the importer on the bundled samples (it used an option that adds a column the test's header check did not expect); the test was corrected and the bundle tests rerun and pass, and every other test passed in the full run. Runner: ruff, bandit, semgrep and gitleaks 0 findings; 49 suppressions, all in the baseline (none added). The raw tool output is not archived, as in CP23.
