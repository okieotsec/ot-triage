# Security Test Plan: Vulnerability Prioritizer

**Owner:** okieotsec (project lead, final approver)
**Reviewers:** Claude Code (developer and reviewer), OpenAI Codex (independent reviewer), Google Gemini (independent reviewer)
**Applies to:** every release checkpoint below

---

## 1. Purpose and rules of engagement

This plan defines how the application is security tested before each checkpoint is accepted. Every reviewer follows the same instructions and reports in the same format, so findings can be compared and verified.

1. **Work from the checkpoint's tagged commit.** Record the commit hash in your report.
2. **Review independently.** Do not read another reviewer's findings until your own report is submitted.
3. **Evidence over opinion.** Every finding needs a file and line, a reproduction or tool output, and a severity using the rubric in section 7. "This might be a problem" without evidence is logged as a question, not a finding.
4. **Run the tools; don't simulate them.** Tool output must come from an actual run and be attached. If you can't run a tool, say so in the report rather than describing what it would likely find.
5. **Don't fix while reviewing.** Report findings. Fixes are made by the developer in a separate change and re-verified (section 8).
6. **No sensitive data.** Use only the synthetic test data in `tests/data/` and public KEV and EPSS files. Never use employer or customer data.

---

## 2. Scope

**In scope**
- All application source: GUI, prioritization logic, batch import/export, settings, threat-data update and import, local data storage.
- All third-party Python packages and their transitive dependencies.
- Packaging and release artifacts.

**Out of scope**
- The security of CISA's and Empirical Security's servers themselves.
- The host operating system and Python interpreter, except where the app relies on them unsafely.

---

## 3. Threat model (summary)

Review this before testing and update it at each checkpoint.

| Asset / entry point | Threat | Example |
| --- | --- | --- |
| Batch CSV import | Malicious or malformed input | Huge file, bad encoding, formula payloads, unexpected columns |
| CSV export | Injection into downstream tools | Cell starting with `=`, `+`, `-`, `@` executes in Excel |
| Threat-data download | Tampered or hostile response | TLS bypass, redirect to another host, oversized or decompression-bomb `.gz`, malformed JSON/CSV |
| Threat-data import from file | Malicious local file | Same as above, plus path tricks |
| Settings file | Tampering or corruption | Out-of-range values, wrong types, extra keys, huge file |
| Local data folder | Unsafe file handling | Predictable temp files, partial writes, over-permissive file modes |
| Dependencies | Vulnerable or malicious packages | Known CVEs, typosquats, unpinned versions |
| Results | Integrity of the decision | Settings or data silently altering outcomes without being shown |

---

## 4. Checkpoints

A checkpoint is accepted only when its exit criteria (section 9) are met.

| ID | When | Focus |
| --- | --- | --- |
| CP0 | Now, before new features | Baseline: run the full toolchain on current code, generate the first SBOM, record known issues |
| CP1 | After Part 1 fixes | CSV export injection, input validation, test suite |
| CP2 | After threat data and updates (Part 4) | Network and file-parsing code; highest-risk checkpoint |
| CP3 | After settings and GUI refresh (Parts 5–6) | Settings file handling, new dependencies (e.g. CustomTkinter) |
| CP4 | Release candidate | Full regression of everything above, final SBOM, release gate |

---

## 5. Static analysis (SAST) and supply chain

Run at every checkpoint. Attach full output.

**Code analysis**
- `bandit -r <src> -f json -o reports/bandit.json`
- `semgrep scan --config p/python --config p/security-audit --json -o reports/semgrep.json`
- `ruff check <src>` (include the `S` rule set, which mirrors bandit)
- Secrets scan of the full git history: `gitleaks detect --source . --report-path reports/gitleaks.json`

**Dependencies (software composition analysis)**
- `pip-audit -r requirements.txt -f json -o reports/pip-audit.json`
- `osv-scanner --lockfile=requirements.txt --format json > reports/osv.json`
- For each third-party package, record: name, pinned version, license, maintainer activity (last release date), and why it's needed. Flag any package with no release in two years, a recent ownership change, or a name close to a popular package.
- Prefer the standard library where practical (e.g. `urllib` over adding a new HTTP library). Every new dependency needs a one-line justification in the review.
- Confirm dependencies are pinned with hashes (`pip-compile --generate-hashes` or equivalent) and install with `pip install --require-hashes`.

**SBOM**
- Generate a CycloneDX SBOM from the locked environment: `cyclonedx-py environment -o sbom/sbom.cdx.json` (in a clean virtual environment containing only the app's dependencies).
- Confirm every package in the SBOM appears in `requirements.txt` and vice versa.
- Compare against the previous checkpoint's SBOM and list anything added, removed, or upgraded.

---

## 6. Manual code review and dynamic testing

### 6.1 Manual review checklist
For each item, mark Pass, Fail (with a finding), or N/A.

**Input handling**
- [ ] All file inputs (CSV, KEV JSON, EPSS CSV, settings JSON) have size limits, encoding handling, and schema/column validation.
- [ ] Parsing errors are caught and shown to the user without crashing or exposing stack traces.
- [ ] No use of `eval`, `exec`, `pickle`, `yaml.load` without a safe loader, or `subprocess` with shell=True.

**Network**
- [ ] HTTPS only; TLS certificate verification is on and cannot be disabled from the UI or settings.
- [ ] Redirects are limited and stay on the expected hosts.
- [ ] Timeouts are set on every request.
- [ ] Download size is capped, and decompressed size of `.gz` files is capped.
- [ ] Nothing is downloaded unless the user starts an update (or has enabled the startup check).

**Files and storage**
- [ ] Temp files are created securely (`tempfile`), and the stored copy is replaced atomically only after validation passes.
- [ ] A failed update leaves the previous data in place.
- [ ] Data and settings files are written with user-only permissions where the OS supports it.
- [ ] No paths are built from untrusted input.

**Output and integrity**
- [ ] CSV export neutralizes formula-leading characters in every text cell.
- [ ] Exports and copied summaries include inputs, settings profile, and KEV/EPSS versions.
- [ ] Custom settings are always visibly indicated.

**Logic**
- [ ] Prioritization logic has no paths that ignore validation (e.g. NaN, infinity, negative values).
- [ ] Settings validation prevents inconsistent thresholds.

### 6.2 Dynamic testing
The app is a desktop tool, so dynamic testing means running it against hostile inputs and a hostile network.

**Malicious file test set** (build once under `tests/data/malicious/`, reuse at every checkpoint)
- Empty file, header only, 1 million rows, a single 50 MB line
- Wrong encoding (UTF-16, Latin-1), byte-order marks, null bytes
- Formula payloads in every text column (`=HYPERLINK(...)`, `+cmd`, `@SUM(...)`)
- Missing, extra, duplicated, and reordered columns
- CVSS values: `nan`, `inf`, `-1`, `10.1`, `1e308`, blank, text
- KEV JSON: malformed JSON, wrong types, deeply nested objects, a 500 MB file
- EPSS: missing header line, wrong columns, a `.gz` that expands to many gigabytes (decompression bomb)
- Settings JSON: wrong types, out-of-range values, inconsistent thresholds, extra keys, truncated file

Expected result for every case: a clear error message or safe fallback, no crash, no hang beyond the timeout, no partial data written.

**Fuzzing**
- Property-based tests with `hypothesis` for `parse_cvss`, the batch row parser, the settings loader, and the KEV/EPSS parsers.
- Optional: `atheris` coverage-guided fuzzing of the parsers for at least 30 minutes per parser at CP2 and CP4.

**Network testing** (CP2 and CP4)
- Route the app through `mitmproxy` with an untrusted certificate. Expected: the update fails with a clear TLS error.
- Serve hostile responses from a local test server: redirect to another host, oversized file, slow drip (tests timeouts), malformed content, HTTP 500. Expected: safe failure, previous data kept.
- Disconnect the network mid-download. Expected: safe failure, previous data kept.

**Export verification**
- Export results containing every formula payload and open the file in Excel and LibreOffice. Expected: payloads display as text and do not execute.

---

## 7. Severity rubric

| Severity | Meaning | Example |
| --- | --- | --- |
| Critical | Code execution, or silent wrong prioritization of real data | Unsafe deserialization; corrupted data changing buckets without warning |
| High | Bypass of a security control, or injection into downstream tools | TLS verification disabled; working CSV formula injection |
| Medium | Denial of service or integrity issue with a visible symptom | Crash or hang on a malformed file; partial data written after a failed update |
| Low | Hardening gap with limited impact | Missing size cap on a small local file; over-permissive file mode |
| Info | Best-practice note | Unpinned dev dependency; missing docstring on a security-relevant function |

Dependency CVEs are rated by their actual reachability in this app, with the reasoning stated.

---

## 8. Reporting and triage

**Each reviewer submits one report per checkpoint** at `reports/<checkpoint>/<reviewer>.md`:

```
Reviewer:
Checkpoint / commit:
Tools run (with versions):
Tools not run (and why):

Finding <ID>
- Title:
- Severity:
- Location: file:line
- Description:
- Evidence / reproduction steps:
- Recommended fix:
- Confidence: Confirmed / Likely / Needs verification
```

**Triage (project lead)**
1. Merge findings from all reviewers; de-duplicate.
2. Verify every finding by reproducing it. Findings that can't be reproduced are closed as "not reproduced," with a note.
3. Assign each confirmed finding: fix now, fix before release, or accept with documented reasoning.
4. After a fix, the reviewer who found it (or the lead) re-tests and marks it verified.

AI reviewers can produce plausible but incorrect findings. Nothing is fixed or accepted until it has been reproduced.

---

## 9. Exit criteria

**Each checkpoint**
- All tools in section 5 ran successfully with output attached.
- No open Critical or High findings.
- Every Medium finding is fixed or has a documented acceptance.
- The full test suite, including the malicious file set, passes.
- SBOM generated and diffed against the previous checkpoint.

**Release (CP4) additionally requires**
- No known vulnerabilities in dependencies, or each one documented as not reachable.
- Final SBOM (`sbom/sbom.cdx.json`) committed and attached to the release.
- `SECURITY.md` published with: how to report a vulnerability, supported versions, what data the app downloads and from where, and that it runs fully offline apart from user-started updates.
- README links to the SBOM and summarizes the security testing performed.
- This plan and all checkpoint reports archived in the repository.
