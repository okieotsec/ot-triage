Reviewer: Claude Code (developer and reviewer), closing two items of the independent AI review (reports/independent-review-codex/) that the project owner decided on 2026-10-15
Checkpoint / commit: CP25 (CP23-02 and the rest of CP23-05) / branch feed-rollback-and-file-checks, before merge
Scope: threatdata.py and icsadvisories.py (what a network update may replace), the new safefile.py, and every loader that read a file by name: batch.py, inventory.py, compare.py, jsonfile.py (settings and appearance preferences), threatdata.py (stored and imported threat data, the EPSS header). The scanner importer now calls the same helper.
Tools run (with versions): the project's runner (ruff 0.16.10, bandit 1.9.4, semgrep, gitleaks), the full suite on a private virtual display, mutation checks on the new tests
Tools not run (and why): atheris, osv-scanner and pip-audit (no new parser, no dependencies)

Decisions taken by the owner (2026-10-15): do both items, with the recommendation from CP23.

Finding CP23-02 (closed here)
- Title: A schema-valid older or truncated feed replaces the stored threat data
- What was done: a network update now compares the download with the stored copy of the same source. It is refused, and the stored copy kept, when its date is earlier (KEV release date, EPSS score date, newest advisory date) or when it has more than 20% fewer entries (exactly 20% is allowed). The message says which. A file chosen with Import from file is allowed, and the result carries a note saying it is older or smaller. Nothing is compared when no usable copy is stored, so a missing or damaged copy can always be replaced. The 20% line is one constant (MAX_SHRINK_PERCENT), documented in docs/THREAT_DATA.md.
- What it does not do: stop a hostile file that is newer and about the same size. That is the limit of trusting HTTPS to the named hosts without signatures, and SECURITY.md says so under Known limitations.
- Tests: test_feed_rollback.py (14 tests): older refused for KEV, EPSS and ICS; same and newer accepted; 79 of 100 refused and 80 of 100 accepted; both reasons together; one refused source does not block the other; first install and damaged copies not compared; the stored files unchanged after a refusal; a file import allowed with a note and an ordinary one without.
- Status: fixed. Confidence: Confirmed.

Finding CP23-05 (rest, closed here)
- Title: Input files opened by name, not proved to be regular files of limited size
- What was done: the helper that the scanner importer used moved to safefile.py (open_regular and read_regular) and every other loader now uses it: the findings file (read_rows, has_cve_column), the inventory, the previous export for Compare, the settings and appearance files (jsonfile.read_json), the stored and imported KEV, EPSS and ICS files (_read_capped) and the EPSS header. Each opens the file once without blocking, checks on the open file that it is a regular file and within its limit, and reads at most the limit plus one byte; a refusal closes the file again. A path that cannot be opened raises the same error as before.
- Behaviour change: a folder, a named pipe or a device given as a findings, inventory or previous-export file now gives the message "is not a regular file (a folder, a pipe or a device cannot be read)". A threat data file that is missing now reports the system's own message ("No such file or directory") instead of "is not a regular file".
- Tests: test_safefile.py (8 tests): a folder, a pipe and a device refused without blocking (each loader is run in a thread that must finish in 5 seconds), the name never measured (os.path.getsize and os.stat refused while each loader runs), the size judged on the open file, a file that grows after the check still held to the limit, the file closed again on refusal, every loader refusing an oversized file.
- Status: fixed. Confidence: Confirmed.

Mutation checks (26 mutants, 25 caught)
- Rollback: `<` changed to `<=` for the date and for the count, either check disabled, the strict flag ignored in the download path for KEV and EPSS and for ICS, the note removed, the stored-copy comparison removed for ICS, the ICS note dropped from the message: all caught.
- Files: the regular-file check removed, the size check removed, the close on refusal removed, the read cap removed, the non-blocking flag removed, and each of the seven loader call sites replaced with a plain open: all caught.
- Survivor (equivalent): `not stored.loaded` changed to `stored is None` in rollback_problems. A damaged stored copy has no date and no count, so nothing is compared either way; the check is kept for clarity.

Suppressions added / removed: none (the baseline stays at 49).
SSDF practices touched: PW.5 (input checks written once), PW.8 (tests, mutation checks), RV.3 (root causes), PS.2 (the integrity of the stored threat data against a replaced download).

Release gate for this change
| Gate | Evidence | Pass |
| --- | --- | --- |
| Owner's decision recorded before the change | the owner's instruction of 2026-10-15 | Yes |
| No change to bucket logic or ordering scores | only readers and the update guard changed | Yes |
| Documents say what the guard does and does not do | SECURITY.md, docs/THREAT_DATA.md, the test plan | Yes |
| Full suite, runner | see the tail of this report | Yes |

Verification
- Full suite on a private virtual display: 1,149 tests, all passing. Runner: ruff, bandit, semgrep and gitleaks 0 findings; 49 suppressions, all in the baseline (none added). The raw tool output is not archived, as in CP23.
