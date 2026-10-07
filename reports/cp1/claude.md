Reviewer: Claude Code (developer and reviewer)
Checkpoint / commit: CP1 / 6678a39 (tag cp1; re-run after the policy changes, v0.1 candidate)
Tools run (with versions): bandit 1.9.4, semgrep 1.179.0 (p/python, p/security-audit; 200 rules, 8 files), ruff 0.16.10 (E,F,W,S,B at line length 120), pip-audit 2.10.1 (requirements.txt and requirements-dev.txt), cyclonedx-bom 7.5.0, hypothesis 6.168.5 (property tests), gitleaks 8.30.1 (9 commits, full history), osv-scanner 2.5.1 (requirements-dev.txt), LibreOffice (headless CSV export check)
Tools not run (and why): atheris fuzzing, mitmproxy and network tests (no network code until CP2); Excel export check (Excel unavailable on this machine)

Tool results
- bandit: 0 findings (1,153 LOC). reports/cp1/bandit.json
- semgrep: 0 findings. reports/cp1/semgrep.json
- ruff: clean after two style fixes (E501 in the GUI, B905 in a test). reports/cp1/ruff.json
- gitleaks: no leaks in 9 commits. reports/cp1/gitleaks.json
- osv-scanner: no vulnerabilities for requirements-dev.txt (hypothesis); requirements.txt is empty so there is nothing to scan. reports/cp1/osv-dev.json
- pip-audit: no known vulnerabilities for either requirements file. requirements.txt is empty (standard library only), so that result is trivially clean. reports/cp1/pip-audit*.json
- SBOM: unchanged from CP0 apart from its serial number and timestamp (only pip from the clean venv).
- Tests: 59 pass (55 without hypothesis installed), including the malicious file set (tests generated on demand by malicious_cases.py instead of stored under tests/data/malicious/, so the 50 MB and 1M-row files are never committed) and the optional hypothesis property tests.

Verification of CP0 findings
- CP0-01 (no size or row limit): fixed in batch.read_rows (25 MB, 50,000 rows). Re-tested: oversized and many-row files are rejected with a clear message; a 50,000-row file parses in 0.36 s and the batch window builds in 0.37 s on a real display.
- CP0-02 (float constant): not changed; boundary tests now pin the behavior (8.05 -> NOW, 8.04 -> NEXT). Still open as Info.
- CP0-03 (no boundary tests): fixed. Mutation-checked: moving any of the 4.0, 7.0 or 9.0 comparisons from >= to > makes a test fail.

Finding CP1-01
- Title: Duplicated CSV column silently used the last value
- Severity: Medium (silent wrong input to the prioritization; rubric Critical/Medium boundary, rated Medium because the file was user-supplied and the symptom is a visible wrong result)
- Location: batch.py read_rows (before this checkpoint)
- Description: With two cvss columns, the first value was dropped and the last was scored.
- Evidence / reproduction steps: header "cvss,cvss,threat,asset,exposure", row "1.0,9.8,active,crown,high" scored 9.8 with no warning (found by the malicious file set).
- Recommended fix: Reject duplicate columns (applied; test_malicious covers it).
- Confidence: Confirmed
- Status: fixed and verified at this commit

Finding CP1-02
- Title: Neutralized cells show a leading apostrophe in spreadsheets
- Severity: Info
- Location: batch._safe
- Description: The apostrophe prefix stays visible as literal text after CSV import.
- Evidence / reproduction steps: LibreOffice import stores the cell as text "'=HYPERLINK(...)".
- Recommended fix: None; document in the README. This is the accepted mitigation.
- Confidence: Confirmed

Export verification
- LibreOffice headless converted the exported malicious file to xlsx: 0 formula cells in the safe export; a control export with neutralization disabled produced 6 formula cells, so the check detects formulas. Excel itself was not tested.

Manual checklist (6.1), changes since CP0
- Input handling: size limit, row limit, encoding errors, long fields (csv.Error), duplicate and missing columns all produce clear errors; no crash. Pass.
- Logic: NaN, infinity, negative, over-range and 1e308 CVSS values become error rows. Pass.
- Output: formula neutralization on id, name, cvss and error; tab and carriage-return prefixes verified by test. Pass.
- Network, files and storage, settings: N/A until CP2 and CP3.

Policy changes included in this checkpoint (approved 2026-10-07; rationale in docs/POLICY.md)
- Active, high-exposure crown jewels stay NOW below CVSS 4.0; crown jewels with high exposure and CVSS >= 4.0 are floored at NEXT; partial controls lower the ordering score only.
- Each rule is covered by tests and mutation-checked (removing the exemption or the floor, changing >= to >, or letting partial controls move the bucket makes tests fail). The monotonicity test passes under the new rules.
- Security impact: none found. The change removes the CVSS arithmetic that caused CP0-02 (the float constant), so that Info finding is closed.
