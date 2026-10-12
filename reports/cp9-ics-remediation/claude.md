Reviewer: Claude Code (developer and reviewer)
Checkpoint / commit: CP9 (what a CISA ICS advisory says about a fix) / branch ics-remediation, before merge
Scope: the advisory parser (icsadvisories.py) now also reads each vulnerability's CSAF `remediations` and reduces them to one letter per advisory and CVE; the stored index format moves to version 2; the status is shown in Assess (card, chip, a note under Patch status), Batch details, the copied summaries' reasoning, and a new `ics_remediation` export column. No new file, host or download: the same archive as CP8. Context only: the bucket, the ordering score and the Patch status input never change.
Tools run (with versions): bandit 1.9.4 (25 application files, 5,535 LOC), semgrep 1.179.0 (p/python, p/security-audit), ruff 0.16.10, gitleaks (full history), the full suite (727 tests, including hypothesis fuzzing, on a private virtual display), 9 mutation checks
Tools not run (and why): osv-scanner and pip-audit (no dependencies); mitmproxy (no network change)

Tool results (attached under reports/cp9-ics-remediation/)
- bandit: 0 findings. semgrep: 0 findings, 0 errors. ruff: 0 findings. gitleaks: no leaks.

What was checked
- Remediation data is untrusted: a remediation list that is not a list, items that are not objects, a category that is not text, and unknown categories are all ignored (status left blank), never trusted. The status is one of five fixed letters, and only fixed wording is ever shown; none of the advisory's free text (`details`, `url`) is read or kept.
- The stored index is validated as strictly as a download: version 2 only, the fix map must be an object, every key must be a CVE the advisory names, every value one of the five letters. A version 1 index is refused with the usual "update again" message.
- Each advisory keeps its own statement for a CVE (an older advisory can say "no fix" while a newer one says "vendor fix"), and a fix is attached to the right CVE when an advisory names several.
- No effect on decisions: tests show the same item with and without the advisory gives the same priority and ordering score, and that the note under Patch status does not change the Patch status.
- Mutation checks (each made a test fail): a partial fix reported as a full fix; "no fix planned" reported as "no fix yet"; mitigation-only and workaround not recognised; fix letters not validated in the stored index; a fix for a CVE the advisory does not name accepted; a fix attached to the wrong CVE; fixes lost from the stored index; a remediation value that is not a list trusted. All nine are caught.
- Real data: the 3,959 advisories carry 52,278 remediation entries in five categories (mitigation 31,426; vendor_fix 18,542; none_available 1,086; workaround 674; no_fix_planned 550), all of which the parser maps.

Findings: none new.

Notes
- The status describes the vendor's products as a whole, and a CVE can be fixed for some products and not others (letter P). The note under Patch status therefore says to check that the fix covers your own product and version, and never sets the field.

Release gate for this feature
| Gate | Evidence | Pass |
| --- | --- | --- |
| No change to bucket logic, ordering score or Patch status | tests with and without advisories; a test that the Patch status variable is untouched | Yes |
| Untrusted data is never shown as free text | only fixed wording is displayed; mutation and hostile-data tests | Yes |
| Stored index strictly validated | 8 new strictness cases, version 1 refused | Yes |
| Static analysis clean | bandit, semgrep, ruff 0 findings; gitleaks clean | Yes |
| Documentation updated | docs/THREAT_DATA.md, CHANGELOG.md | Yes |
