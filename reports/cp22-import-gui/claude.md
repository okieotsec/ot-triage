Reviewer: Claude Code (developer and reviewer)
Checkpoint / commit: CP22 (scanner import, phase 3: the Import scan button and preview in the Batch view) / branch scanner-import-gui, before merge
Scope: a new button in the Batch view, a preview window (gui_import.py) and a save-and-open flow (gui_batch.py), a multi-file chooser in the context (gui_context.py), and small changes in scanimport.py (reading is split from merging so the preview can merge again with other options; one shared atomic writer; summary text cleaned). It writes files the person chooses and opens them with the existing loaders; it scores nothing.
Tools run (with versions): bandit 1.9.4 (32 application files), semgrep 1.179.0 (p/python, p/security-audit), ruff 0.16.10, gitleaks (full history), the full suite (1,084 tests, including hypothesis fuzzing, on a private virtual display), 25 mutation checks, screenshots of the toolbar and the preview in both themes
Tools not run (and why): osv-scanner and pip-audit (no dependencies); mitmproxy (no network code); atheris (hypothesis fuzzing and hostile-file tests were used instead)

Tool results (attached under reports/cp22-import-gui/)
- bandit: 0 findings. semgrep: 0 findings, 0 errors. ruff: 0 findings. gitleaks: no leaks.

What was checked
- Nothing the import reads from is ever overwritten: the findings and the inventory cannot be saved over an export, the aliases file, the existing inventory, or each other, even when the files do not exist yet (compared as resolved paths); each case has a test and a mutation check, and the files' hashes are compared before and after.
- Writes are atomic: a failure half-way (a test makes the writer fail after writing part of a file) leaves neither the target nor a temporary file; the error is reported in a dialog.
- The preview works on a copy: merging again with other options never changes the reading; cancelling the preview or either save dialog writes nothing, loads nothing and shows no error (tests check files, state and dialogs); a bad aliases file is reported inside the preview and disables saving instead of closing it.
- Hostile text: file names and every line of the summary are cleaned before they reach a window or a terminal; the summary box is read-only; an export that cannot be read gives an error dialog and never opens the preview.
- Busy handling: while an export is read in the background the import, open and inventory buttons are disabled (a test holds the reader and checks) and come back afterwards; a second task is refused with the usual message.
- No effect on scoring: the findings the button saves are loaded by the same loader as any file, the ranking of an imported file equals the ranking of the same file loaded by hand (a test compares them), and new assets with no criticality or exposure show as not scored, with a message that says what to fill in.
- Layout: the new button fits in the toolbar at the default window size in both themes (the existing Batch tests, which check the layout, pass unchanged).
- Mutation checks: 25 changes (cancel handling, read errors, the save guards for each input, same-file detection, atomic writes, inventory extension, error reporting, the guidance message, disabling, and the preview's threat, aliases, accept and error handling). 15 were caught at once; 8 were gaps in the tests (cancelled dialogs checked only for missing output, not for errors; no test for aliases or the existing inventory as the save target; atomic writing not checked with a partial write; busy state not checked; an exception inside a window callback was logged by Tk, not raised, so the tests now collect callback errors and require none), closed and caught; 2 survivors were equivalent or unreachable changes.

Finding CP22-01
- Title: The import summary lines were not cleaned of control characters (file names)
- Severity: Info (no exposure in the shipped command line, which cleans each line when it prints it; it would have shown raw text in the new window)
- Location: scanimport.summary_lines
- Found by: the preview test with a file name containing an escape sequence.
- Status: fixed at the source: summary_lines now returns clean lines, so every caller (terminal or window) gets clean text; the test stays.

Development notes: the first test run also found that two output paths that do not exist yet were not recognised as the same file (the guard compared only existing files), now compared by resolved path when they do not exist; and a stray reformatting of an unrelated test file, caught by checking the diff and undone.

Release gate for this feature
| Gate | Evidence | Pass |
| --- | --- | --- |
| No change to bucket logic or scores | files go through the existing loaders; a test compares rankings | Yes |
| No input is ever overwritten | same-file guards with tests and mutation checks, hash comparisons | Yes |
| Failures leave no partial files | atomic writes, partial-write test | Yes |
| Hostile text is cleaned before display | file name and summary tests, read-only summary | Yes |
| Layout intact | existing Batch layout tests, screenshots in both themes | Yes |
| Static analysis clean | bandit, semgrep, ruff 0 findings; gitleaks clean | Yes |
| Documentation updated | docs/IMPORT.md, docs/SCANNER_IMPORT.md, README.md, CHANGELOG.md | Yes |
| Real exports checked | none available | No (open) |

Suppressions added / removed: none added (the one `noqa: E731` this branch had introduced was replaced by a plain function); none removed.
