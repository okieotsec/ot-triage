Reviewer: Claude Code (developer and reviewer)
Checkpoint / commit: CP0 / 096e1ad (tag baseline-cp0)
Tools run (with versions): bandit 1.9.4, semgrep 1.179.0 (p/python, p/security-audit; 200 rules), ruff 0.16.10 (E,F,W,S,B), pip-audit 2.10.1, cyclonedx-bom 7.5.0 (cyclonedx-py), manual grep for eval/exec/pickle/subprocess/yaml.load/urlopen
Tools run later (added after installation): gitleaks 8.30.1 over the history up to the baseline tag: no leaks (reports/cp0/gitleaks.json); osv-scanner 2.5.1 found no packages to scan (requirements.txt is empty)
Tools not run (and why): hypothesis, atheris, mitmproxy and the malicious file set (planned for CP1 and CP2; the app has no network code yet)

Tool results
- bandit: 0 findings (825 LOC). Output: reports/cp0/bandit.json
- semgrep: 0 findings, 0 errors. Output: reports/cp0/semgrep.json
- ruff: only E501 (line length), 97 at the default width of 88, 1 at 120. No S-rule findings. Output: reports/cp0/ruff.json
- pip-audit: no known vulnerabilities. requirements.txt is empty because the app uses only the standard library, so this result is trivially clean. Output: reports/cp0/pip-audit.json
- SBOM: sbom/sbom.cdx.json lists only `pip` from the clean venv. pip is installer tooling, not an app dependency, so the SBOM and requirements.txt differ by that one package.
- Manual grep: no eval, exec, pickle, subprocess, os.system, yaml.load, shell=True, or network calls.

Finding CP0-01
- Title: Batch import has no file size or row limit
- Severity: Medium (rubric: hang on a large file)
- Location: batch.py:90-109 (read_rows), vuln_prioritizer_gui.py:357-365 (Treeview insert)
- Description: read_rows loads every row into memory, and BatchWindow inserts every row into the table.
- Evidence / reproduction steps: A synthetic 1,000,000-row CSV loads through batch.process_file without error. A single field over 131072 bytes raises csv.Error, which the GUI already catches. The GUI hang with 1M rows was not run (no display session), so that part is inferred.
- Recommended fix: Cap file size and row count with a clear error message.
- Confidence: Likely

Finding CP0-02
- Title: Partial-credit constant is not exactly representable
- Severity: Info
- Location: prioritizer.py:41
- Description: PARTIAL_CVSS_CREDIT evaluates to 1.0499999999999998. All current threshold comparisons happen to round correctly, but exact-threshold behavior depends on float rounding.
- Evidence / reproduction steps: prioritize(8.05, PUBLIC, STANDARD, HIGH, PARTIAL) compares 7.000000000000001 against 7.0.
- Recommended fix: Use integer tenths or Decimal for threshold comparisons; add boundary tests.
- Confidence: Confirmed

Finding CP0-03
- Title: No boundary tests on CVSS thresholds
- Severity: Info
- Location: test_prioritizer.py
- Description: No test sits exactly on the 4.0, 7.0 or 9.0 lines, so >= versus > is not pinned.
- Evidence / reproduction steps: Reviewed the test file; no assertions at 6.9/7.0, 8.9/9.0 or 3.9/4.0.
- Recommended fix: Add boundary tests (Part 1 item 6).
- Confidence: Confirmed

Manual checklist (6.1)
- Input handling: partial. Encoding errors and malformed CSV are caught by the GUI; no size limit (CP0-01). No eval/exec/pickle/subprocess.
- Network: N/A (no network code yet).
- Files and storage: N/A for threat data and settings (not built). Export writes directly to the chosen path.
- Output and integrity: formula neutralization present (batch._safe) for id, name, cvss and error. Copy summary includes inputs. Settings and KEV/EPSS versions not applicable yet.
- Logic: CVSS validated for NaN, infinity and range in both parse_cvss and prioritize.
