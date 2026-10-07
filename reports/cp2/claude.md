Reviewer: Claude Code (developer and reviewer)
Checkpoint / commit: CP2 / d19aef3 (tag cp2)
Tools run (with versions): bandit 1.9.4, semgrep 1.179.0 (p/python, p/security-audit; 200 rules, 12 files), ruff 0.16.10 (E,F,W,S,B at line length 120), pip-audit 2.10.1, osv-scanner 2.5.1, gitleaks 8.30.1 (13 commits), cyclonedx-bom 7.5.0, hypothesis 6.168.5, openssl 3.6.3 (test certificate), manual grep for eval/exec/pickle/subprocess/yaml.load/shell=True/unverified TLS contexts
Tools not run (and why): mitmproxy (replaced by a local TLS server in test_threatdata.py that covers an untrusted certificate, a wrong host name, redirects, oversized and slow responses, timeouts, truncation and HTTP errors; no run through a real intercepting proxy was made); atheris coverage-guided fuzzing (optional in the plan; hypothesis property tests were run instead); Excel export check (Excel unavailable; LibreOffice was used at CP1)
Command deviations from the plan: osv-scanner 2.x syntax (see CP1); malicious files generated on demand by malicious_cases.py

Tool results
- bandit: 0 findings (2,949 LOC). reports/cp2/bandit.json
- semgrep: 0 findings, 0 errors. reports/cp2/semgrep.json
- ruff: clean. reports/cp2/ruff.json
- pip-audit: no known vulnerabilities for requirements.txt (empty) or requirements-dev.txt. reports/cp2/pip-audit*.json
- osv-scanner: no vulnerabilities for requirements-dev.txt. reports/cp2/osv-dev.json
- gitleaks: no leaks in 13 commits. reports/cp2/gitleaks.json
- SBOM: unchanged from CP1 (only pip from the clean venv). The application is still standard library only; no new dependency was added by the threat-data work.
- Tests: 147 pass without hypothesis, 160 with it (includes 53 threat-data tests, the local TLS server tests, the hostile KEV/EPSS/settings files, and property tests for both parsers, the CVE normalizer and threat derivation).
- Real data: the live KEV (1,734 entries) and EPSS (384,189 rows) files were downloaded from the real servers and pass validation. The EPSS address redirects once (HTTP 302, relative Location, same host), which the redirect handling supports. A real end-to-end update into a temporary folder succeeded in 2.2 s.

Mutation checks (scratch copy): removing each of these makes tests fail: redirect scheme and host checks, the up-front URL check, the streaming size cap, the overall deadline, the non-blocking read, the truncation check, TLS verification (default context), decompression cap, parsing before storing KEV or EPSS, the EPSS cutoff comparison, and KEV mapping to ACTIVE. Batch export neutralization of action, rationale, threat_source and threat_data, and the rule that the CSV threat value cannot lower the derived level, were mutation-checked too.

Finding CP2-01
- Title: Download deadline ignored by a slow-dripping server
- Severity: Medium (hang with a visible symptom; rubric Medium)
- Location: threatdata.py fetch (read loop)
- Description: The loop read with response.read(), which blocks until 64 KB arrive or the stream ends, so the overall deadline was only checked after the whole drip finished.
- Evidence / reproduction steps: A server sending one byte every 0.1 s for 10 s with deadline=1 returned after 10.0 s (found by test_enforces_the_overall_deadline_against_a_slow_drip during development).
- Recommended fix: Use read1() so each read returns after one underlying read (applied). The same test now finishes in about 1 s.
- Confidence: Confirmed
- Status: fixed and verified before this checkpoint

Finding CP2-02
- Title: A connection cut mid-download returned the partial body
- Severity: Low (the partial data would have failed validation, so nothing bad could be stored)
- Location: threatdata.py fetch
- Description: read1() returns an empty result on early EOF where read() would raise IncompleteRead, so a response shorter than its Content-Length was treated as complete.
- Evidence / reproduction steps: A server declaring Content-Length 100000 and sending 500 bytes returned 500 bytes without error (test_a_connection_cut_mid_download_is_a_clear_error).
- Recommended fix: Compare the received length with Content-Length and fail with a clear message (applied).
- Confidence: Confirmed
- Status: fixed and verified

Finding CP2-03
- Title: HTTPError responses were not closed
- Severity: Info
- Location: threatdata.py fetch
- Description: Caught HTTPError objects own a response and raised ResourceWarning when garbage collected.
- Evidence / reproduction steps: python -X dev run of the fetch tests.
- Recommended fix: error.close() (applied); the suite now passes with ResourceWarning treated as an error.
- Confidence: Confirmed
- Status: fixed and verified

Finding CP2-04
- Title: Loading EPSS costs about 100 MB of memory
- Severity: Info
- Location: threatdata.py parse_epss, ThreatData.load
- Description: All 384,189 scores are held in a dict. Measured from /proc: load 0.45 s, resident memory 24 MB before and 123 MB after, peak 206 MB while parsing.
- Evidence / reproduction steps: load of the real stored files in a fresh process.
- Recommended fix: None needed for a desktop tool; a more compact store is possible later if memory matters. Load is lazy, so users who never use a cve column never pay it.
- Confidence: Confirmed
- Status: accepted

Finding CP2-05
- Title: KEV text is stored with formula-leading characters intact
- Severity: Info
- Location: threatdata.py parse_kev, batch.write_results
- Description: Control characters are replaced when data is parsed, but a field such as requiredAction can begin with "=" if the source (or a tampered file) says so. It reaches the CSV export through the action cell.
- Evidence / reproduction steps: test_export_has_sources_versions_and_neutralizes_kev_text and test_exported_text_that_starts_like_a_formula_is_neutralized show the export prefixes such text with an apostrophe.
- Recommended fix: Neutralize at the output boundary, as done (action, rationale, threat_source, threat_data and cve cells now go through batch._safe). The GUI shows the text in Tk widgets, where formulas have no effect.
- Confidence: Confirmed
- Status: fixed in the export; design accepted

Manual checklist (6.1)
- Input handling: Pass. Size limits, encoding handling and schema validation exist for the batch CSV, KEV JSON, EPSS CSV and settings JSON. Parsing errors become messages, not stack traces, at the module level; the GUI has no Update or Import button yet, so GUI-level display of these errors is N/A until the GUI refresh (CP3). No eval, exec, pickle, subprocess or shell use in application code.
- Network: Pass. HTTPS only, certificates verified by default and not changeable from the UI or settings (the fetch function accepts a context only for tests; no application code passes one), redirects limited to 3 and to HTTPS on the same expected host, timeouts on every request, download and decompressed sizes capped, nothing downloaded unless a function is called (there is no startup check). The system proxy setting is honored (tested).
- Files and storage: Pass. Temp files come from tempfile in the target folder, replaced atomically only after validation; a failed update keeps the previous files (tested for download failure, invalid data, partial failure and a write error); files are 0600 and the folder 0700; no paths are built from untrusted input (import paths come from the user's file choice, and the stored source label is sanitized and shortened).
- Output and integrity: Pass for the batch export (inputs, settings profile, KEV and EPSS versions, formula neutralization of every text cell). Pending for the copied single-assessment summary, which gets a CVE field with the GUI refresh. The custom scoring badge is shown.
- Logic: Pass. NaN, infinity, negative and out-of-range values are rejected in CVSS, settings and EPSS data. A cve with no loaded data is never scored as "no known exploitation"; the row is reported as an error unless a threat value is given.

Policy confirmation needed from the project lead
- The EPSS cutoff default of 0.95 is provisional (docs/SETTINGS.md).
- The comparison is "at or above" the cutoff, slightly more cautious than the wording "above" in the design notes.
- Data is stored in the per-user data folder (not an app-local data/ folder) so it works when the app is installed read-only (docs/THREAT_DATA.md).
