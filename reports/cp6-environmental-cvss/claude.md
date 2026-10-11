Reviewer: Claude Code (developer and reviewer)
Checkpoint / commit: CP6 (environmental CVSS scoring) / branch environmental-cvss, before merge
Scope: scoring code only (cvss.py), its display in the Assess and Batch views, and the export. No new file format, no network code and no new dependency, so the main risk is correctness, not input handling.
Decision recorded with the project owner (2026-10-11): the environmental score is shown next to the base score for comparison; the bucket and the ordering score continue to use only the base score. This is documented in docs/POLICY.md and docs/CVSS.md.
Tools run (with versions): bandit 1.9.4 (28 files, 5,165 LOC), semgrep 1.179.0 (p/python, p/security-audit; 28 files), ruff 0.16.10 (the rules in ruff.toml), gitleaks (full history), the unit, GUI and property tests, and FIRST's official calculators (see below)
Tools not run (and why): osv-scanner and pip-audit (requirements.txt is empty, so there is nothing to scan); mitmproxy and atheris (no network or file-format code)

Tool results (all attached under reports/cp6-environmental-cvss/)
- bandit: 0 findings. bandit.json
- semgrep: 0 findings, 0 errors. semgrep.json
- ruff: 0 findings. ruff.json
- gitleaks: no leaks. gitleaks.json
- Tests: 589 pass. New: 12 environmental scoring tests in test_cvss.py (including a re-check of all 180,000 generated vectors against the recorded FIRST results), 4 in test_batch.py, 3 in test_gui_assess.py and 1 in test_gui_batch.py.

Correctness against the official calculators
- FIRST's own calculators (cvsscalc30.js, cvsscalc31.js, and the v4.0 calculator's cvss_lookup.js, max_composed.js, max_severity.js and cvss_score.js, each pinned by SHA-256) scored 60,000 generated vectors per version that mix base, temporal or threat, environmental and supplemental metrics.
- Results: CVSS 3.0 environmental 59,994/59,994 identical; CVSS 3.1 59,999/59,999 identical; CVSS 4.0 60,012/60,012 identical. The base score of every one of these vectors is also identical to the reference, so extra metrics never change the base score.
- The 60,012 v4.0 vectors reach all 270 MacroVectors of the scoring table (the first 60,000 reach 258; 12 vectors with recorded numbers cover the rest).
- The vectors are derived from a hash of version and number, so the same set is rebuilt exactly on any machine; the recorded digests are in cvss_reference.json and the offline tests rebuild and re-check every one.
- Reproduce with: python3 tools/verify_cvss_against_reference.py (needs Node.js and a network connection).

Mutation checks (each made the tests fail)
- v3.1 changed-scope exponent 13 changed to 15; v3.0 exponent 15 changed to 13.
- High security requirement weight 1.5 changed to 1.4.
- Modified impact cap 0.915 changed to 0.9.
- v4.0 environmental metrics ignored.
- A security requirement (CR) not counted as an environmental metric.

Decision checks
- Vectors with and without environmental metrics give identical priorities, ordering scores and base scores (tested for 3.1 and 4.0, including modified metrics that would lower the score a lot).
- A vector with only temporal, threat or supplemental metrics (or environmental metrics set to X) produces no environmental score.
- The environmental line says in every place it appears that the priority uses the base score.

Findings
- None. The environmental scores matched the official calculators on the first full run.

Release gate for this feature
| Gate | Evidence | Pass |
| --- | --- | --- |
| Scores identical to the official calculators | 180,005 environmental scores identical (3.0, 3.1, 4.0) | Yes |
| No change to bucket logic | test_prioritizer.py unchanged; tests that environmental metrics never change a result | Yes |
| Static analysis clean | bandit, semgrep and ruff report 0 findings | Yes |
| No new dependency or network access | requirements.txt empty; no new imports outside the standard library | Yes |
| Documentation updated | docs/CVSS.md, docs/POLICY.md, README.md, docs/GUI_TESTING.md, CHANGELOG.md | Yes |
