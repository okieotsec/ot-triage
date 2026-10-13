Reviewer: Claude Code (developer and reviewer)
Checkpoint / commit: CP16 (what the vendor says to do: the advisories' remediation text) / branch release-0.7.0, before merge
Scope: the CISA advisory index now also keeps, for each CVE of each advisory, the vendor's own remediation entries (kind, text, optional link); stored index version 4. Assess, the Batch details, the copied summaries and the CSV export show them. New text and links from a downloaded file now reach the screen, so this is a new trust boundary even though the archive and the parser already existed (CP8, CP9).
Tools run (with versions): bandit 1.9.4 (28 application files), semgrep 1.179.0 (p/python, p/security-audit), ruff 0.16.10, gitleaks (full history), the full suite (898 tests, including hypothesis fuzzing, on a private virtual display), 57 mutation checks, a real parse of the live CISA archive and screenshots of the real advisory on a private display
Tools not run (and why): osv-scanner and pip-audit (no dependencies); mitmproxy (no network change); atheris (hypothesis fuzzing and hostile-text tests were used instead)

Tool results (attached under reports/cp16-vendor-steps/)
- bandit: 0 findings. semgrep: 0 findings, 0 errors. ruff: 0 findings. gitleaks: no leaks.

What was checked
- What is kept: only remediation entries of a known kind (vendor fix, mitigation, workaround, none available, no fix planned) that have some text. Text is cleaned (control, invisible and unassigned characters removed, white space collapsed), cut at 400 characters with an ellipsis, repeats removed, at most 25 steps per CVE and 100 different steps per advisory.
- Links: kept only when `references.safe_https_url` accepts them (plain https, ordinary host, no user name, no numeric host, no port other than 443, now no white space) and they are at most 500 characters; otherwise the text is kept and the link dropped. A link opens only on a click, in the person's browser, and is shown with its real host name. Nothing is fetched.
- Display: step text is shown in plain labels (never interpreted); the Markdown summary escapes it with the same function used for KEV references, so `[x](javascript:...)`, tags and backticks stay inert; a test feeds all of these through Assess, Batch, both summaries and the export.
- Stored index: each row's step table and per-CVE positions are validated when loaded (kinds, text exactly clean and within the limit, links re-checked, positions whole numbers in range, no repeats, at most 25, only for CVEs the advisory names); each new bad-index case (wrong types, kinds, text, links, positions, counts) is refused by a test.
- Real data: the live archive (3,959 advisories) parses in 5.6 s, the index is 5.0 MB and reads back in 1.0 s with identical content; ICSA-26-281-01 (the example that prompted the feature) yields the same six steps CISA's page shows, with both HMS Networks links; of 13,610 CVE entries with steps, 104 have more than 25 (only the first 25 are kept) and no advisory has more than 100 different steps; 2,451 steps are cut at 400 characters and show an ellipsis. The 25-step limit is therefore a real cut for under 1% of entries; the advisory page on cisa.gov is always one click away and the lists say how many steps are left out.
- No effect on decisions: the steps are never read by the scoring; the Assess tests compare the badge, score and patch status before and after loading advisories with steps.
- Size: the index grew from about 2 MB to 5 MB (the cap for a stored index is 60 MB).
- Mutation checks (each made a test fail, after three weak spots were closed): unknown kinds kept; empty text kept; links not checked or not length-limited; repeats kept; step and table limits removed or off by one; text not cleaned, not cut, cut without an ellipsis or leaving a space; steps taken from the wrong CVE or lost on lookup or in the index; positions shifted; stored kind, text, link, position, count or CVE checks removed; an old index version accepted; summary and export mutations; widget mutations (limit ignored, count not shown, link not shown, link to the wrong address).

Finding CP16-01
- Title: The shared "plain https link" check accepted addresses containing white space
- Severity: Low (no effect on KEV references today, where an address is cut at the first space; it would have let a vendor link such as `https://host/a b` through)
- Location: references.safe_https_url
- Found by: the new test that offers hostile links as remediation URLs.
- Cause: the check required printable ASCII, and a space is printable.
- Status: fixed. Any white space makes the address unsafe, in the shared function and so for every link the tool offers; a regression test covers spaces, tabs, no-break spaces and new lines.

Observation (no finding): in Batch the details box keeps its fixed height (150 pixels), so the vendor's steps sit below the advisory line and need a scroll. Making the box taller squeezed the table at a normal window size, so it was left alone; Assess shows up to eight steps without scrolling.

Release gate for this feature
| Gate | Evidence | Pass |
| --- | --- | --- |
| No change to bucket logic, scores or patch status | tests compare badge, score and patch status with and without steps | Yes |
| Text from a downloaded file is shown as plain text and escaped in Markdown | hostile-text tests in Assess, Batch, summaries and export | Yes |
| Links are plain https, shown with their host, opened only on a click | link tests, bad-link index cases, CP16-01 fixed | Yes |
| Limits on size and count, with tests and mutation checks | step, table, text, link and cell limits | Yes |
| Works on the real data | live archive, ICSA-26-281-01 matches CISA's page | Yes |
| Static analysis clean | bandit, semgrep, ruff 0 findings; gitleaks clean | Yes |
| Documentation updated | docs/THREAT_DATA.md, SECURITY.md, README.md, CHANGELOG.md | Yes |
