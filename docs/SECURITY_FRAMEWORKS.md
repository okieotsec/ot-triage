# Security frameworks: NIST SSDF and MITRE SAF

How OT Triage's security practice lines up with two public frameworks, what evidence backs each claim, and what is still open.

- **NIST SSDF** ([SP 800-218, version 1.1](https://csrc.nist.gov/projects/ssdf)) is a catalogue of secure software development practices.
- **MITRE SAF** ([Security Automation Framework](https://saf.mitre.org/framework/)) is a way to organise security automation into five capabilities: Plan, Harden, Validate, Normalize and Visualize.

**This is the developer's own assessment of a small project, written with AI assistance. It is not an audit, and nothing here is a certification or a claim of compliance.** Every status points at a file you can read. Where the repository cannot show something (a setting on GitHub, for example), the table says so. SSDF 1.2 is an initial public draft (December 2025) with no final version yet; this page follows 1.1 and will be re-mapped when 1.2 is final.

Last reviewed: 2026-10-14, checkpoint [CP21](../reports/cp21-security-framework/claude.md).

## How to read the status column

| Status | Meaning |
| --- | --- |
| Met | The practice is done and the evidence is in this repository. |
| Partly | Done in part. The gap is named in the last column. |
| Not yet | Planned, or added in CP21 but not yet proven in a real run. |
| N/A | Does not apply to a single-user desktop tool, with the reason. |

## NIST SSDF 1.1

### PO: Prepare the organization

| Practice | Status | Evidence | Open item |
| --- | --- | --- | --- |
| PO.1 Define security requirements | Met | [Test plan](../SECURITY_TEST_PLAN.md) sections 2 and 3 (scope and threat model); [SECURITY.md](../SECURITY.md) (what the app connects to, reads, writes, and does not cover) | Threat model is a table, not a data-flow diagram. |
| PO.2 Roles and responsibilities | Partly | Test plan header names the owner and the reviewers | One-person project. One independent AI review (OpenAI Codex, 2026-10-14) is archived unchanged in `reports/independent-review-codex/` and was triaged in CP23; Google Gemini has not been asked; **no human security audit has been done**. |
| PO.3 Supporting toolchains | Met | [ruff.toml](../ruff.toml), [CI](../.github/workflows/ci.yml), [security runner](../tools/security_checks.py), pinned tool versions in [requirements-dev.txt](../requirements-dev.txt) | CP21 added semgrep to CI (it was only run by hand), a weekly schedule and Dependabot for pip. |
| PO.4 Criteria for security checks | Met | Test plan sections 7 and 9 (severity rubric, exit criteria); each report ends with a release gate | None. |
| PO.5 Secure development environments | Partly | CI jobs have read-only tokens, do not persist credentials and pin every action to a commit; GUI tests run on a private virtual display; only synthetic data is used (plan rule 6) | Developer-machine and GitHub account settings cannot be seen from the repository: see the owner checklist below. |

### PS: Protect the software

| Practice | Status | Evidence | Open item |
| --- | --- | --- | --- |
| PS.1 Protect all forms of code | Partly | Changes go through pull requests; gitleaks scans the full history in CI; a source-hygiene test rejects hidden and look-alike characters | Branch protection and two-factor sign-in are GitHub settings: owner checklist. |
| PS.2 Verify release integrity | Met (0.9.0 on) | A published SHA-256 for every release; since 0.9.0 a [release workflow](../.github/workflows/release.yml) builds the bundle from the tag (and refuses a tag that does not match `version.py`) and records a signed build-provenance attestation; the 0.9.0 attestation was verified with `gh attestation verify` on 2026-10-14 and its checksum matched the independently built bundle | Releases before 0.9.0 have a checksum only. The workflow does not run the tests itself; branch protection and CI cover the commit. |
| PS.3 Archive and protect each release | Partly | Tags, the SBOM attached to each release ([sbom/sbom.cdx.json](../sbom/sbom.cdx.json)), every checkpoint report kept in [reports/](../reports/) | Provenance exists only from the first attested release on. |

### PW: Produce well-secured software

| Practice | Status | Evidence | Open item |
| --- | --- | --- | --- |
| PW.1 Design to meet security requirements | Met | Threat model in the test plan; design notes in [docs/](.) such as THREAT_DATA.md, IMPORT.md and SCANNER_IMPORT.md | None. |
| PW.2 Review the design | Partly | Each checkpoint report reviews the design of what changed | An independent AI review of the code exists (see PO.2); no human design review. |
| PW.4 Reuse well-secured software | Met | Python standard library only; the SBOM lists no third-party component | CVSS 4.0 tables from FIRST are credited in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md). |
| PW.5 Follow secure coding practices | Met | ruff's `S` and `B` rules, bandit and semgrep clean; strict parsing helpers (`jsonfile.py`); manual checklist in test plan section 6.1 | None. |
| PW.6 Configure build and interpreter settings | Partly | Tests run with `python -X dev -W error::ResourceWarning`; the bundle is plain source built reproducibly | There is no compile step; interpreter hardening flags are not otherwise used. |
| PW.7 Review and analyze code | Partly | Scanners at every checkpoint and in CI; manual checklist; since CP21, **every suppression comment is inventoried** and a new one fails the gate until it is reviewed ([baseline](../security/suppressions.baseline.json)); CodeQL added in CP21 | No human reviewer other than the owner. CodeQL results appear only once it runs on GitHub. |
| PW.8 Test executable code | Met | About 1,000 test functions; hostile-file set; hypothesis fuzzing of every parser; a local TLS server for the network code; mutation checks recorded in the reports (CP20: 32) | Atheris (coverage-guided fuzzing) has never been run; the plan now asks for it at release checkpoints or a recorded reason. |
| PW.9 Secure defaults | Met | Works offline; no update at start unless turned on; TLS verification cannot be disabled; size limits on every input | None. |

### RV: Respond to vulnerabilities

| Practice | Status | Evidence | Open item |
| --- | --- | --- | --- |
| RV.1 Find and confirm vulnerabilities continuously | Partly | Private vulnerability reporting ([SECURITY.md](../SECURITY.md)); Dependabot for Actions and pip; weekly CI and security workflows; CodeQL, Scorecard and dependency review (CP21) | Private reporting and code scanning must be switched on in the repository settings: owner checklist. |
| RV.2 Assess, prioritize and remediate | Met | Severity rubric and triage steps (plan sections 7 and 8); response targets published in SECURITY.md in CP21 | The targets are best effort, from one maintainer. |
| RV.3 Find root causes | Partly | Reports record findings fixed during the work and the test added for each (for example the CP20 development note); since CP21 the report template has a **Root cause and prevention** line | No periodic review of recurring classes of defect yet. |

## MITRE SAF

SAF describes five capabilities. OT Triage is a desktop application, so some of them have little to do here.

| Capability | What it means here | Status |
| --- | --- | --- |
| **Plan** | Security requirements: the threat model and scope in the test plan, and SECURITY.md. SAF's Vulcan tool authors STIG-style requirement documents for platforms; this project has no such platform baseline, so it is not used. | Met |
| **Harden** | SAF's hardening content configures deployed systems. There is no deployed system; the equivalent here is hardening the build pipeline: pinned actions, least-privilege tokens, zizmor, Scorecard, a seven-day Dependabot cooldown. | Met for the pipeline; N/A for hosts |
| **Validate** | Automated checks with a pass/fail gate: the test suite, the hostile-file set and the scanners. SAF's own validation uses InSpec profiles, which test the configuration of a host or service; there is none to test, so none is used. | Met |
| **Normalize** | [tools/security_checks.py](../tools/security_checks.py) writes SARIF for ruff, semgrep, gitleaks and bandit, and if the SAF CLI is installed converts each to the Heimdall Data Format (HDF) under `hdf/` in the checkpoint folder. | Met, optional |
| **Visualize** | `saf view summary` output is archived as `saf-summary.txt`; the `hdf/*.json` files open in SAF's Heimdall viewer. | Partly: Heimdall was not exercised in CP21 |

### Using the SAF CLI

The SAF CLI is optional. Nothing in the build, the tests or CI needs it, and the release gate does not depend on it.

```
npm install --prefix ~/.cache/saf @mitre/saf          # about 480 packages: keep it out of the project and out of CI
SAF_CLI=~/.cache/saf/node_modules/.bin/saf python tools/security_checks.py reports/cpNN-name
```

Without it the runner prints `saf (optional)  NOT RUN` and carries on. When present, it converts each SARIF file to HDF and runs `saf validate threshold -I "{failed.total.max: 0}"` on it.

Two things to know:

- **Suppressed results are removed before conversion.** semgrep reports in-source suppressions in its SARIF; SAF would count them as failures. They are not hidden: each one is in `suppressions.json` and must be in the reviewed baseline.
- **Ignore SAF's "compliance" percentage.** These tools report problems, not a list of controls, so with no findings SAF shows 0 controls and 0%. The threshold on failed results is the meaningful check.

## What the CI now does

| Check | Where | Frameworks |
| --- | --- | --- |
| Tests on Linux and Windows, Python 3.12 and 3.14, weekly | [ci.yml](../.github/workflows/ci.yml) | SSDF PW.8, RV.1 |
| ruff, bandit, semgrep (new) | ci.yml, lint job | PW.5, PW.7; SAF Validate |
| gitleaks over the full history | ci.yml, secrets job | PS.1 |
| zizmor: audits the workflows themselves | [security.yml](../.github/workflows/security.yml) | PO.5, PS.1; SAF Harden |
| CodeQL (Python) | security.yml | PW.7 |
| Dependency review on pull requests | security.yml | PW.4, RV.1 |
| OpenSSF Scorecard (results are not published) | security.yml | PO.5, PS.1 |
| Build and attest the release bundle | [release.yml](../.github/workflows/release.yml) | PS.2, PS.3 |
| Suppression gate, SARIF and HDF | `tools/security_checks.py` at each checkpoint | PW.7; SAF Normalize |

Every action is pinned to a full commit and the workflows pass `zizmor --persona pedantic` with no findings.

## Owner checklist: settings the repository cannot show

These are GitHub settings. Tick them on the repository's Settings pages and update this list; until then the related practices stay at Partly.

- [ ] Two-factor authentication on the account that owns the repository.
- [ ] A branch ruleset on `main`: pull request required, status checks required (Tests, Lint, Secret scan, Workflow audit, CodeQL), force pushes and deletion blocked.
- [ ] Private vulnerability reporting enabled (SECURITY.md already tells people to use it).
- [ ] Dependabot alerts and security updates, secret scanning and push protection enabled.
- [ ] Code scanning: use the CodeQL workflow in this repository, not GitHub's "default setup" as well.
- [ ] Actions settings: default token permission read-only, and "require actions to be pinned to a full-length commit SHA".
- [ ] Decide whether to publish Scorecard results (`publish_results` in security.yml is `false`) and whether to apply for the OpenSSF Best Practices badge, which is a free self-assessment.

## Open items, in order

1. ~~Make a release and verify its attestation (PS.2).~~ Done: 0.9.0, verified on 2026-10-14.
2. Obtain a human independent review (PO.2, PW.2, PW.7); an AI review (Codex) is done and archived.
3. Run Atheris on the parsers for a release candidate (PW.8).
4. Tick the owner checklist.
5. Re-map to SSDF 1.2 when NIST finalises it.

## Tools and licences

| Tool | Licence | Used for |
| --- | --- | --- |
| ruff | MIT | Lint and bandit-style rules |
| bandit | Apache-2.0 | Python security linting |
| semgrep (Community Edition) | LGPL-2.1-or-later | Pattern-based static analysis; rule packs are fetched at run time, with metrics off |
| gitleaks | MIT | Secret scanning |
| zizmor | MIT | GitHub Actions workflow audit |
| hypothesis | MPL-2.0 | Property-based fuzzing |
| cyclonedx-bom | Apache-2.0 | SBOM |
| MITRE SAF CLI | Apache-2.0 | Optional normalisation to HDF |
| CodeQL, OpenSSF Scorecard, dependency review, build-provenance attestation | GitHub-hosted services and open-source actions | Run only in GitHub Actions; CodeQL is free for public repositories |

None of these is shipped with the application or needed to run it.
