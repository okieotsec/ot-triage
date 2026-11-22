Reviewer: Claude Code (developer and reviewer); the owner reviewed the changes, merged them and ran the release and its verification commands himself
Checkpoint / commit: CP29 (release 0.11.0: licence change, authorship statements, attestation) / tag v0.11.0 on the merge commit 7641d0bd5bcb1498feab029a011e7f0199cd3c91
Scope: the changes released as 0.11.0 (the AGPL-3.0-only licence and COPYRIGHT, the rewritten authorship and review statements and REVIEW.md, the contributing guide and templates, the browser demo already reported as CP28), the version bump (version.py, demo/rules.js, demo/golden.json, SECURITY.md, SBOM, CHANGELOG) and the verification of the release bundle. No change to the application's behaviour or to any rule.
Tools run (with versions): the full suite under the headless runner (1,150 tests ran, all passing, on the release branch and again from the merged tree); ruff 0.16.10 with this project's configuration; tools/make_demo_golden.py and tools/make_sbom.py to regenerate the demo's golden file and the SBOM (the SBOM changed only in the version and the licence id); on the pull requests, CI and Security workflows (ruff, bandit, semgrep, gitleaks, CodeQL, dependency review, zizmor), all green before each merge.
Tools not run (and why): tools/security_checks.py (no code change in this release; the same scanners ran in CI on both pull requests); atheris, osv-scanner and pip-audit (the application has no third-party dependency and no parser changed).

Release record
- Pull requests merged: the authorship and licence change, the contributing guide, and the release preparation (#60), in that order.
- Last MIT-licensed state: tag snapshot-2026-11-21 on commit 59cbd4ec774aa9d46bfe5b4f2a99f08ea0ec9c62, with a pre-release published from it and a copy archived at Software Heritage on 2026-11-21 (18:11 UTC), before the licence change merged.
- Release workflow: run 44975060082 on the tag v0.11.0, succeeded. It builds the bundle and attests it; it does not publish.
- Release published by the owner on 2026-11-22 (UTC) with the bundle, its checksum file and the SBOM.

Verification of the bundle (run by the owner on the downloaded files)
- `sha256sum -c ot-triage-0.11.0.zip.sha256`: OK. SHA-256 of the zip: 74b9b74fb02b30dbc6c8146c74dda67fb5b11612133a88d0fc0566a879945487.
- `gh attestation verify ot-triage-0.11.0.zip --repo okieotsec/ot-triage`: verification succeeded. One attestation matched the policy (predicate type https://slsa.dev/provenance/v1, source repository okieotsec/ot-triage, GitHub's token issuer); build and signer workflow `.github/workflows/release.yml@refs/tags/v0.11.0`.
- Rebuild of the bundle locally from the tag with `python3 tools/make_bundle.py` on the owner's machine: the SHA-256 is 74b9b74fb02b30dbc6c8146c74dda67fb5b11612133a88d0fc0566a879945487, identical to the checksum published by GitHub's workflow. The build is reproducible, as for 0.9.0.

Finding CP29-01
- Title: Comment lines in a changed test were longer than this project's line limit, so the lint job failed on the pull request
- Severity: Info
- Description: the comment above the name check in test_source_hygiene.py was wrapped for another repository's 140-character limit; this project's ruff.toml allows 120. The Lint and static analysis job failed (E501 on two lines).
- Root cause: the change was linted with the wrong repository's configuration, or not at all, before it was handed over.
- What was done: the comment was rewrapped; ruff passes with this project's configuration. Each repository is now linted with its own configuration before a change is staged.
- Code: `test_source_hygiene.py` (the name check).
- Why this severity: no effect on the application or on users; it stopped a merge until fixed, which is the check working (test plan, section 7: Info).
- Impact: none if fixed; the pull request could not merge while it failed.
- Status: fixed. Confidence: Confirmed.

Finding CP29-02
- Title: The check that no personal name or home path is in a file also read tool caches
- Severity: Info
- Description: the name check was widened to files with no suffix (LICENSE and COPYRIGHT, which the earlier version skipped). Run after ruff, it also read `.ruff_cache`, whose entries contain the working directory's path, and failed.
- Root cause: the widening dropped the implicit filter that the suffix list had given.
- What was done: folders that hold tool caches (`.git`, `__pycache__`, `.ruff_cache`, `.venv`, `.mypy_cache`, `.pytest_cache`, `.hypothesis`) are skipped; a probe file with the forbidden text in a file with no suffix still fails the test, so the widening is kept. The test now also requires COPYRIGHT to name the owner as the holder, and allows the name in that one file only.
- Code: `SKIPPED_FOLDERS` and `test_no_personal_name_or_home_folder_path_is_in_any_file_of_the_repository` in `test_source_hygiene.py`.
- Why this severity: it was a false failure of a safety test in a developer's checkout, with no effect on users (test plan, section 7: Info).
- Impact: a developer who had run the linter would have seen the test fail for no real reason.
- Status: fixed, tested. Confidence: Confirmed.

Finding CP29-03
- Title: This project has no privacy deny-list check of its own
- Severity: Info
- Description: the sibling project (RuleTruss) runs a privacy check before a push and in CI, using the owner's private deny-list. This project relies on the hygiene test only, which looks for the owner's name and home paths but not for anything on the private list (addresses, host names).
- What was done: nothing yet; it is recorded so the owner can decide whether to add the same check here.
- Code: none yet (`tools/` has no privacy check).
- Why this severity: a gap in a control, no known leak (test plan, section 7: Info).
- Impact: a private detail that is not a name or a home path could be committed without the hygiene test noticing.
- Status: open, waiting for the owner's decision. Confidence: Confirmed.

Observation, not investigated: this report and the earlier ones count test functions found in the test files (1,182 at the release commit, 1,181 at CP28); the headless runner reports 1,150 tests run. The difference of 32 was not investigated here.

Suppressions added: none.
Suppressions removed: none.
SSDF practices touched: PS.2 (the bundle's attestation verified for a second release), PS.3 (the release is archived and published from a verified tag), PS.1 (the last MIT-licensed state is pinned by a tag and archived off-site), PW.8 (the hygiene test and its tests), RV.3 (root causes recorded).

Root causes and prevention
- A repository's own lint configuration was not used (CP29-01): lint each repository with its own configuration before handing a change over.
- A widened check lost an implicit filter (CP29-02): the filter is now explicit, and a probe file shows the check still catches what it should.

Release gate for this release
| Gate | Evidence | Pass |
| --- | --- | --- |
| No change to the application or to any rule | only documents, the licence files, the version bump, the demo's version and golden file, and a test | Yes |
| Full suite and CI pass on the commit accepted | 1,150 tests ran and passed; CI and Security green on each pull request | Yes |
| The bundle was built by the workflow and its attestation verifies | run 44975060082; `gh attestation verify` succeeded | Yes |
| The published checksum matches the file | `sha256sum -c`: OK | Yes |
| A local rebuild matches the published checksum | the owner's rebuild from the tag gave the same SHA-256 | Yes |
