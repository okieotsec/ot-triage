Reviewer: Claude Code (developer and reviewer). No independent review.
Checkpoint / commit: CP21 (security process: NIST SSDF and MITRE SAF alignment) / branch security-framework-alignment, on top of f167ef0, before merge
Scope: no change to the application. New or changed: tools/security_checks.py (one-command scanner run, suppression inventory and gate, optional SAF conversion), test_security_checks.py, security/suppressions.baseline.json, .github/workflows (ci.yml changed; security.yml and release.yml new), .github/dependabot.yml, ruff.toml (one per-file rule), SECURITY.md, SECURITY_TEST_PLAN.md, docs/SECURITY_FRAMEWORKS.md, docs/RELEASING.md, README.md, CHANGELOG.md. The risks are a gate that passes when it should fail, archived output that leaks a path or third-party text, and workflows with more permission than they need.
Tools run (with versions): ruff 0.16.10, bandit 1.9.4, semgrep 1.180.0 (p/python, p/security-audit, metrics off), gitleaks (full history), MITRE SAF CLI 1.7.0, zizmor 1.30.1 (including `--persona pedantic`), the full suite (1,038 tests on a private virtual display, all pass), 8 mutation checks of the new gate
Tools not run (and why): osv-scanner and pip-audit (not applicable: no third-party dependency); atheris (no parser changed); the new GitHub workflows (CodeQL, Scorecard, dependency review, release attestation) have not run, because nothing was pushed; Heimdall (the SAF viewer) was not opened

Tool results (attached under reports/cp21-security-framework/)
- ruff, bandit, semgrep, gitleaks: 0 findings each. Suppressions: 50, all in the reviewed baseline. SAF: 0 failed results after the one suppressed semgrep result is left out (it is listed in suppressions.json).

What was checked
- Suppression review: all 50 in-source suppression comments were read. They are fixed-argument subprocess calls, URL opens restricted to https and checked hosts, an XML loader used only after DTDs and entities are refused, interface-only exceptions, and module-path setup in tools. Each has a stated reason or an obvious one. They are now the accepted baseline; a new or additional one fails the run.
- The gate fails when it should: 8 deliberate breakages of the new code (accept any increase, count markers inside strings, keep suppressed results, keep rule help text, leave an absolute path in the archive, treat a missing baseline as a pass, keep stale rule indexes, read only the first marker in a comment) were each caught by the new tests.
- SAF behaviour was observed, not assumed: `saf convert sarif2hdf` reads ruff, semgrep, gitleaks and bandit SARIF; `saf validate threshold` exits 1 on a file with failed results (tested on semgrep output with its suppressed results left in, which counted as 4 failures) and 0 on a clean one; the "compliance" percentage is 0 with no controls, so only the failed-results threshold is used.
- Workflows: zizmor reports no findings, pedantic persona included. Every action is pinned to a full commit that was resolved from the upstream tag (annotated tags were peeled to the commit). Top-level permissions are empty; each job asks only for what it needs; credentials are not persisted; the Scorecard job does not publish its results.
- The release workflow runs the same bundle command as docs/RELEASING.md; that command was run here and produced the zip and its checksum. It creates no release.
- Archived output: SARIF and HDF files keep only the rules that have results, drop rule help text, and replace the checkout's absolute path; the raw output is kept in a temporary folder that is deleted. The repository-wide test against names and home paths passes.

Findings

Finding CP21-01
- Title: SECURITY.md listed 0.4.x as the supported version while the application is 0.8.0
- Severity: Low
- Location: SECURITY.md (supported versions table)
- Description: the published support policy named a version four releases old, so a reporter could not tell what was supported.
- Evidence: SECURITY.md said "0.4.x | Yes"; version.py says 0.8.0.
- Recommended fix: updated to 0.8.x.
- Root cause and prevention: the file was not part of the release checklist and nothing compared it with the code. A test (`test_the_supported_version_in_security_md_is_the_current_minor_version`) now fails when they differ.
- Status: fixed. Confidence: Confirmed.

Finding CP21-02
- Title: CI did not run semgrep, and installed bandit unpinned
- Severity: Info
- Location: .github/workflows/ci.yml
- Description: the test plan lists semgrep at every checkpoint, but CI ran only ruff, bandit and gitleaks, so semgrep ran only when a person remembered to. An unpinned bandit can change results, or ship a bad release, without a code change.
- Root cause and prevention: the checkpoint tools and the CI tools had drifted apart with nothing comparing them. CI now runs semgrep, both tools are pinned, and the plan's section 5 says the two sets must match. Dependabot (pip) now proposes updates to requirements-dev.txt; the pins in the workflow file are still updated by hand.
- Status: fixed. Confidence: Confirmed.

Finding CP21-03
- Title: Archived tool output embedded third-party rule text and a home-folder path
- Severity: Low
- Location: tools/security_checks.py (first version of the SARIF step)
- Description: semgrep's SARIF holds its whole rule catalogue (about 700 KB) including help text with links. One link contained a path segment that the repository's home-folder hygiene test rejects, and the saf summary printed absolute paths from the machine it ran on.
- Evidence: the RuleTruss suite failed on the home-folder check on `reports/.../semgrep.hdf.json` during this checkpoint (the same runner is used in both projects). Nothing was committed.
- Root cause and prevention: tool output was archived verbatim. The runner now keeps raw output in a temporary folder and archives a trimmed, path-scrubbed copy; three tests cover the trimming, the renumbering and the scrubbing.
- Status: fixed. Confidence: Confirmed.

Finding CP21-04
- Title: The plan names two independent reviewers but no independent report is archived
- Severity: Info
- Location: SECURITY_TEST_PLAN.md header; reports/
- Description: every report in reports/ is by Claude Code. A reader of the plan could believe independent review has taken place.
- Recommended fix: the plan header, SECURITY.md and docs/SECURITY_FRAMEWORKS.md now say that no independent review has been done. The review itself is still open.
- Status: accepted as stated, open. Confidence: Confirmed.

Release gate for this change
| Gate | Evidence | Pass |
| --- | --- | --- |
| No change to the application | only documents, tools, tests and CI changed | Yes |
| Scanners clean | ruff, bandit, semgrep, gitleaks 0 findings | Yes |
| Full suite passes | 1,038 tests, private display | Yes |
| New gate tested | 10 tests, 8 mutation checks caught | Yes |
| Workflows audited | zizmor clean (pedantic) | Yes |
| Workflows proven on GitHub | not run | No: first push and first tagged release will show it |
| Release attestation verified | not run | No: record the result after the first tagged release |
| Independent review | none | No (open since the plan was written) |
