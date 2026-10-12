Reviewer: Claude Code (developer and reviewer)
Checkpoint / commit: CP7 (security requirements for the environmental CVSS score) / branch security-requirements, before merge
Scope: a new function in cvss.py (with_requirements), three optional columns in the asset inventory file (a file the tool parses, covered by CP5), the optional selectors in the Assess view, and their use in Batch scoring and the export. No network code and no new dependency. The priority and the ordering score are unchanged; the environmental score is still shown for comparison only (decision recorded with the project owner, docs/POLICY.md).
Tools run (with versions): bandit 1.9.4 (29 files, 5,325 LOC), semgrep 1.179.0 (p/python, p/security-audit; 29 files), ruff 0.16.10 (the rules in ruff.toml), gitleaks (full history), the unit, GUI and property tests (run on a private virtual display), mutation checks
Tools not run (and why): osv-scanner and pip-audit (requirements.txt is empty, so there is nothing to scan); mitmproxy and atheris (no network code; generated hostile files and hypothesis fuzzing were used instead)

Tool results (all attached under reports/cp7-security-requirements/)
- bandit: 0 findings. bandit.json
- semgrep: 0 findings after finding CP7-01 was handled (see below). semgrep.json
- ruff: 0 findings. ruff.json
- gitleaks: no leaks. gitleaks.json
- Tests: 625 pass. New: 6 in test_cvss.py (including a check that applying requirements to vectors with their requirements removed gives the same score as FIRST's calculators for 3,000+ of the verified generated vectors), 9 in test_inventory.py, 7 in test_gui_assess.py, 3 hostile requirement files in test_malicious.py, and the fuzz test now includes the new columns.

What was checked
- Requirement values: low, medium and high in words and letters, any letter case and spacing, blank and "not defined" mean not stated; anything else skips that row with a message and loads the rest. A 300 KB value, control characters, direction-changing characters and spreadsheet formulas load safely or are refused cleanly.
- Precedence: a requirement the vector sets itself is never overridden by the interface or the inventory; the inventory only fills in what the vector leaves undefined.
- No effect on decisions: the priority, the ordering score and the base score are identical with and without requirements (tests in test_inventory.py and test_gui_assess.py).
- A finding with only a plain score has no vector to adjust and gets no environmental score; the interface says a vector is needed.
- Mutation checks (each made a test fail): a chosen requirement overriding one the vector sets; an invalid requirement letter accepted; inventory requirements never applied; "medium" read as "high" in the inventory (this one was not caught at first: a test that every accepted word means the right level was added, and the mutation is now caught).

Finding CP7-01
- Title: The new headless test runner passed its command-line argument to a subprocess without checking it
- Severity: Info (a developer tool run by the developer; no shell is used, so there was no way to inject a command)
- Location: tools/headless_tests.py
- Found by: semgrep (the other tools do not run in CI)
- Status: fixed. The one allowed argument (a stall limit in seconds) is now accepted only as 1 to 86,400 in ASCII digits and rebuilt as a plain number; anything else exits with a usage message. A test covers rejected inputs, including another script's digits, which the first version of the check wrongly accepted and my own test caught. The remaining semgrep match is suppressed on that one line with the reason beside it.

Release gate for this feature
| Gate | Evidence | Pass |
| --- | --- | --- |
| No change to bucket logic or the priority | test_prioritizer.py unchanged; tests that requirements never change a result | Yes |
| Environmental scores still match the official calculators | the 180,000-vector reference tests pass; requirements-applied scores equal the verified scores | Yes |
| Static analysis clean | bandit, semgrep and ruff report 0 findings | Yes |
| No new dependency or network access | requirements.txt empty | Yes |
| Documentation updated | docs/CVSS.md, docs/INVENTORY.md, README.md, docs/GUI_TESTING.md, CHANGELOG.md | Yes |
