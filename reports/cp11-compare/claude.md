Reviewer: Claude Code (developer and reviewer)
Checkpoint / commit: CP11 (comparing with a previous export) / branch compare-previous, before merge
Scope: compare.py (reads a previous ranked CSV and matches its rows with the current findings) and the Batch view's Compare with previous... button, Change column, details line, Show resolved... list, and two new export columns (`change`, `previous_priority`). The previous export is a new file the tool parses, so it is untrusted input. No network access, no change to scoring: a comparison never changes a priority or an ordering score.
Tools run (with versions): bandit 1.9.4 (27 application files, 6,091 LOC), semgrep 1.179.0 (p/python, p/security-audit), ruff 0.16.10, gitleaks (full history), the full suite (791 tests, including hypothesis fuzzing, on a private virtual display), 14 mutation checks, speed checks at the file limit
Tools not run (and why): osv-scanner and pip-audit (no dependencies); mitmproxy (no network code); atheris (hypothesis fuzzing of the loader and the matcher was used instead)

Tool results (attached under reports/cp11-compare/)
- bandit: 0 findings. semgrep: 0 findings, 0 errors. ruff: 0 findings. gitleaks: no leaks.

What was checked
- The loader: a UTF-8 CSV only; at most 25 MB and 50,000 rows; a `priority` column and one of id, cve or name are required; rows with an unknown priority are skipped and counted; scores outside 0 to 10, "nan" and non-numbers are ignored; every text cell is cleaned (control, invisible and direction characters removed) and limited to 300 characters; a byte-order mark and odd header case are accepted; a missing file, a folder, binary data and a wrong encoding give a clear message, never a crash. Property tests feed arbitrary text through the loader.
- The matcher: findings are recognised by id, then CVE and asset, then name and asset, ignoring case and extra spaces, and undoing the quote the export puts in front of formula-like cells. If more than one unused previous row could be the same finding, the finding is reported as "could not match" and none of those rows is used. A previous row is used at most once. Property tests show every finding gets exactly one change, no row is used twice, and matched plus resolved rows equal the previous rows.
- No effect on decisions: priorities and ordering scores are identical with and without a comparison (tested in the Batch view).
- A real export round-trips: comparing a batch with its own export gives "same" for every row and nothing resolved.
- Mutation checks (each made a test fail): moves reported in the wrong direction; case-sensitive matching; the export's formula quote not undone; an ambiguous match guessed; a previous row used twice; every previous row reported as resolved; the size limit, the row limit, the priority check, the score range and text cleaning removed; unscorable rows compared as if scored; the header requirement dropped; and the quadratic-time mutation below. All are caught.

Finding CP11-01
- Title: A previous export in which thousands of rows share one id made the comparison quadratic
- Severity: Low (a slow window, not a crash or a wrong result; it needs a hostile or odd file the person chose)
- Location: compare.py, the first version of the matcher
- Found by: a worst-case speed check I ran after the tests passed (5,000 identical ids took about 1 s, so 50,000 would take minutes)
- Cause: for every finding the matcher rebuilt the list of unused rows for each key it looked up.
- Status: fixed. The index now keeps, for each key, a dict of the rows not yet used, and removes a row from it when it is used, so a lookup never scans. The timing test now uses the real 50,000-row limit and requires the comparison to finish in 5 seconds (it takes about 0.1 s). A mutation that copies the candidates on every lookup is caught by it.

Speed at the limit: loading a 16 MB, 50,000-row export takes 0.6 s and comparing it with 50,000 findings 0.25 s.

Release gate for this feature
| Gate | Evidence | Pass |
| --- | --- | --- |
| No change to scoring | tests that priorities and scores are identical with and without a comparison | Yes |
| New input file is bounded and validated | limits, header checks and hostile-file tests, each with a mutation check | Yes |
| No guessing when a match is unclear | ambiguity tests, property tests | Yes |
| Worst-case speed is bounded | 50,000 identical ids compared in about 0.1 s; mutation caught | Yes |
| Static analysis clean | bandit, semgrep, ruff 0 findings; gitleaks clean | Yes |
| Documentation updated | README.md, docs/INVENTORY.md, CHANGELOG.md | Yes |
