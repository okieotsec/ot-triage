Reviewer: Claude Code (developer and reviewer)
Checkpoint / commit: CP5 (asset inventory import) / branch asset-inventory, before merge
Scope: the new file the tool parses (an asset inventory CSV), its join into batch scoring, and the Batch view changes. There is no new network code, so this checkpoint is a file-parsing checkpoint like CP1, not a network one like CP2.
Tools run (with versions): bandit 1.9.4 (27 files, 5,022 LOC), semgrep 1.179.0 (p/python, p/security-audit; 27 files), ruff 0.16.10 (the rule set in ruff.toml), gitleaks (full history), the unit, GUI and property-based tests, and the hostile-file tests in test_malicious.py
Tools not run (and why): osv-scanner and pip-audit (requirements.txt is empty, so there is nothing to scan; the SBOM still lists no third-party components); atheris and mitmproxy (no network code; hypothesis fuzzing and generated hostile files were used instead)

Tool results (all attached under reports/cp5-inventory/)
- bandit: 0 findings. bandit.json
- semgrep: 0 findings, 0 errors. semgrep.json
- ruff: 0 findings. ruff.json
- gitleaks: no leaks. gitleaks.json
- Tests: 570 pass, 1 skipped (a keyboard-focus test that skips itself when the window manager gives the test window no focus). The 25 inventory tests, 3 hostile-inventory tests (17 hostile files), 8 Batch GUI tests and a hypothesis fuzz test (200 random inventories) are new.

What was checked
- Size and row limits: 5 MB and 20,000 rows; an oversized file is refused before it is opened.
- Hostile content: empty file, header only, UTF-16, Latin-1, binary garbage, NUL bytes, an unterminated quote, old Mac line endings, a 300 KB cell, a 300 KB id, formula cells, control characters, direction-changing and invisible characters, one asset repeated 1,000 times, thousands of duplicate pairs, thousands of bad rows, ragged rows. Each loads with the bad rows skipped, or is refused with a readable ValueError; none raises anything else, and the list of reported problems is capped at 20.
- Matching and precedence: a value typed on the finding row always wins over the inventory (decision recorded with the project owner); an id missing from the inventory, duplicated, or without a value for a needed field is an error that says why, never a guess; matching ignores case and stray white space.
- Injection: asset ids and names from the inventory or the findings are cleaned of control and invisible characters, length-capped, and neutralised in the CSV export (a cell starting with = + - @ is prefixed with a quote).
- Privacy: the inventory is held in memory only, and its path is not stored in any settings or preferences file.
- Mutation checks (each made the tests fail): the inventory overriding a typed row value; using a duplicated id anyway; removing the size limit; not cleaning control characters from ids; dropping the explanation from the error for a missing inventory entry.
- CVSS reference check: unchanged and still passing (110,160 vectors identical to the FIRST calculators); no rule or bucket logic was changed, and test_prioritizer.py is unchanged.

Finding CP5-01
- Title: The shared text cleaner deleted line breaks and tabs instead of turning them into spaces
- Severity: Low (two words on either side of a line break were glued together, for example in a CISA note or an inventory name; no security impact)
- Location: references.clean
- Found by: the inventory test that cleans an id containing a line break
- Status: fixed (white space of any kind becomes a single space before other control characters are removed); regression test added in test_references.py

Finding CP5-02
- Title: A very large cell raised the CSV module's own error type, which the interface showed as an unhelpful message
- Severity: Info
- Location: inventory.load
- Status: fixed (csv errors and non-UTF-8 files become a clear ValueError message); tests added

Release gate for this feature
| Gate | Evidence | Pass |
| --- | --- | --- |
| No High or Critical findings open | two findings, both fixed | Yes |
| Static analysis clean | bandit, semgrep and ruff report 0 findings | Yes |
| Hostile-input tests pass | 17 hostile inventories plus 200 fuzzed ones | Yes |
| No new third-party dependency | requirements.txt is empty; tools/make_sbom.py output unchanged apart from the version | Yes |
| Documentation updated | docs/INVENTORY.md, README, SECURITY.md, docs/GUI_TESTING.md, CHANGELOG.md | Yes |
