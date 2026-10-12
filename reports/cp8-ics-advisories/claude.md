Reviewer: Claude Code (developer and reviewer)
Checkpoint / commit: CP8 (CISA ICS advisories) / branch ics-advisories, before merge
Scope: a new file the tool downloads and parses (icsadvisories.py): CISA's public CSAF repository archive (a tar.gz of about 12 MB holding about 3,960 OT advisory JSON files), reduced to a small stored index. Also the lookup, Assess card and chips, Batch Details, export column, copy summaries, Threat data view (third source, update and offline import), and the downloader's host list (now three hosts). Advisories are context only: the priority and the ordering score are unchanged (stated to the project owner before building; recorded in docs/POLICY.md).
Tools run (with versions): bandit 1.9.4 (25 application files, 5,467 LOC), semgrep 1.179.0 (p/python, p/security-audit), ruff 0.16.10, gitleaks (full history), the unit, GUI and hypothesis fuzz tests (716, run on a private virtual display), generated hostile archives at the real limits, 23 mutation checks, and one real end-to-end update against GitHub into a throwaway folder
Tools not run (and why): osv-scanner and pip-audit (requirements.txt is empty, nothing to scan); mitmproxy (the downloader is unchanged and already covered by the CP2 TLS tests; only the host list grew, and a test pins it); atheris (hypothesis fuzzing of every new parser was used instead)

Tool results (all attached under reports/cp8-ics-advisories/)
- bandit: 0 findings. bandit.json
- semgrep: 0 findings, 0 errors. semgrep.json
- ruff: 0 findings. ruff.json
- gitleaks: no leaks. gitleaks.json

What is new and what was checked
- Reading the archive: tarfile in streaming mode over a counting wrapper, so the bytes that come out of the gzip stream are limited to 600 MB whatever the entries claim. Entries are never extracted; only regular files whose names match .../csaf_files/OT/white/<year>/icsa(-ma)-YY-DDD-NN[a-z].json are opened. Links, devices, other folders, path-traversal names, upper-case names and names with extra characters are ignored.
- Each advisory is validated: valid JSON without duplicate keys or NaN, its own id equal to its file name, a title, valid dates, CVE ids that match exactly, a product tree bounded in size and depth. One bad advisory is skipped and counted; more than 10 (or 5%) means the format has probably changed and the whole update is refused.
- Output: only advisory number, a cleaned title (200 characters), up to five cleaned vendor names, two dates and the CVE list are kept. The link is built from the validated advisory number, never copied from the file, so a file cannot send anyone to another address. The stored index is re-validated on every load and must read back correctly before it replaces the previous one.
- Real data: the app's own downloader, run once against the live GitHub endpoint into a temporary folder, read 3,959 advisories naming 12,421 CVEs in 4.9 seconds with a 59 MB peak and an 868 KB stored index. Every constructed advisory address matched the Web Version address CISA gives in the file (apart from letter case and one legacy host).
- Tests: 53 in test_icsadvisories.py (including 5 hypothesis fuzz tests), 6 hostile-archive tests at the real limits in test_malicious.py (a gzip bomb of several hundred MB that is a few KB on disk, 100,000 empty entries, a header claiming a 3 GB file, hostile names and entry types, hostile advisory text, garbage in gzip and tar framing), 7 in test_batch.py, 6 in test_threatdata.py, 9 in test_gui_assess.py and 4 in test_gui_batch.py. Full suite: 716 pass.
- Mutation checks (each made a test fail): decompressed-size limit, entry limit, advisory limit and per-file size limit removed; entry folder check loosened; links and devices not skipped; id/file-name mismatch accepted; skip tolerance removed; titles not cleaned; link in upper case; medical advisories linked to the wrong section; host list widened; duplicate advisory accepted; index count and extra fields not checked; product-tree depth and per-advisory CVE limits removed; the stored index not re-checked; ordering lost; invalid CVE ids kept; three "matched loosely" variants; and advisories changing the ordering score. Two survived at first (an oversized-file test that failed for the wrong reason, and a missing test of the read-back check). Both tests were fixed and every mutation is now caught.

Finding CP8-01
- Title: Patterns that end in $ also match just before a trailing new line
- Severity: Info (nothing could reach a decision: a value with a trailing new line could never be looked up)
- Location: threatdata.py (CVE id, version and date patterns for KEV and EPSS) and, as first written, icsadvisories.py (entry names, advisory ids, CVE ids)
- Found by: my own hostile-name test while building CP8 (a name ending in a new line was accepted as a valid advisory file)
- Status: fixed. All of these now match the whole text exactly (fullmatch). Tests cover a trailing new line on entry names, advisory ids, CVE ids and the KEV and EPSS fields, and three mutation checks confirm they fail if the looser match returns.

Finding CP8-02
- Title: The archive as a whole is not signed
- Severity: Info (a trust limit, not a defect)
- Location: the ICS advisories download
- Found by: review of CISA's repository layout
- Status: accepted and documented. CISA signs each advisory with PGP, but the archive is not signed and the standard library cannot check PGP, so trust rests on HTTPS to GitHub, the same level as KEV and EPSS. Because of that the content is treated as untrusted and validated as above. Recorded in docs/THREAT_DATA.md and SECURITY.md.

Notes
- tarfile ends an entry name at a NUL byte, so "icsa-26-099-01.json" followed by a NUL is, to any tar tool, the name "icsa-26-099-01.json". The cut name goes through the same checks as any other, so this needed no change.
- The CISA CSAF repository has no licence file. The tool does not redistribute anything: it reads the archive on the user's machine and keeps only facts (advisory number, title, vendor names, dates, CVE list).
- An advisory that names no CVE is left out of the index, because there is nothing to look up.

Release gate for this feature
| Gate | Evidence | Pass |
| --- | --- | --- |
| No change to bucket logic or the ordering score | tests with and without the advisories loaded give identical results (Assess, Batch, a mutation that adds to the score is caught) | Yes |
| New downloaded file is bounded and validated | limits and checks above, each pinned by a test and a mutation check | Yes |
| Links cannot be redirected by the file | address built from the validated advisory number; test with a hostile reference in the file | Yes |
| Only the expected hosts are contacted | host list pinned by a test; non-HTTPS and other hosts refused | Yes |
| A failed update keeps the previous copy | tests for failed downloads, invalid data, cancel, a bad import and a bad read-back | Yes |
| Static analysis clean | bandit, semgrep and ruff report 0 findings; gitleaks clean | Yes |
| No new dependency | requirements.txt empty | Yes |
| Documentation updated | docs/THREAT_DATA.md, docs/POLICY.md, SECURITY.md, README.md, CHANGELOG.md | Yes |
