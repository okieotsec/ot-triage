Reviewer: Claude Code (developer and reviewer)
Checkpoint / commit: CP10 (per-asset roll-up) / branch asset-rollup, before merge
Scope: rollup.py (grouping of already-scored rows by asset id, and a roll-up CSV export) and the Batch view's new By asset mode (a toggle, a second table, a details panel, an export button). No new input file, no new network access, no change to scoring: it only groups rows that were scored already. The one new output file is the roll-up CSV, which carries text from the user's own findings file.
Tools run (with versions): bandit 1.9.4 (26 application files, 5,806 LOC), semgrep 1.179.0 (p/python, p/security-audit), ruff 0.16.10, gitleaks (full history), the full suite (754 tests, including hypothesis fuzzing, on a private virtual display), 9 mutation checks, a speed check at the import limit
Tools not run (and why): osv-scanner and pip-audit (no dependencies); mitmproxy (no network code); atheris (hypothesis was used on the grouping instead)

Tool results (attached under reports/cp10-asset-rollup/)
- bandit: 0 findings. semgrep: 0 findings, 0 errors. ruff: 0 findings. gitleaks: no leaks.

What was checked
- Grouping: asset ids match without regard to letter case or surrounding white space (the first spelling is shown); rows with no asset id are set aside and counted, never merged into one made-up asset; every row lands in exactly one place (property test over generated rows, including formula-like and blank ids); the order never gets less urgent.
- Roll-up export: every text cell that could run as a spreadsheet formula (`=`, `+`, `-`, `@`, tab, carriage return) is prefixed, covering the asset id, the top finding and the list of findings; a long list is cut at 20 with a count of the rest. Tested with hostile ids.
- Speed at the import limit: 50,000 rows over 20,000 assets scored in 0.9 s, rolled up in 0.26 s, exported in 0.12 s (1.1 MB).
- Unscorable rows (for example an asset id missing from the inventory) still count toward their asset and show as "not scored"; an asset with only such rows sorts last and has no top finding.
- No effect on decisions: the view only reads rows that were scored already; the findings table, counters and export are unchanged (the existing tests all pass).
- The By asset mode survives a rebuild of the window (theme or text size change), switches back cleanly, and resets when a new file is opened.
- Mutation checks (each made a test fail): the worst bucket taken from the wrong end; asset ids matched case-sensitively; rows with no asset id merged into one asset; NEVER rows offered for the same visit; assets with fewer NOW rows ranked first; the top finding taken as the lowest scoring; export cells not protected from formulas; the finding list never cut; unscored rows counted as scored. All nine are caught.

Findings: none new. (While building the view, a drawing test used the old table frame and a keyboard test showed the toggle must stay reachable with no file loaded; both were test or design fixes made before merge.)

Release gate for this feature
| Gate | Evidence | Pass |
| --- | --- | --- |
| No change to scoring or the findings export | the full existing suite passes unchanged apart from one test pointed at the table's outer frame | Yes |
| Export is formula-safe | hostile-id tests and a mutation check | Yes |
| Works at the import limit | 50,000 rows, 20,000 assets in under 1.5 s | Yes |
| Static analysis clean | bandit, semgrep, ruff 0 findings; gitleaks clean | Yes |
| Documentation updated | README.md, docs/INVENTORY.md, CHANGELOG.md | Yes |
