Reviewer: Claude Code (developer and reviewer)
Checkpoint / commit: CP18 (scanner import, phase 1: Nessus, Tenable Vulnerability Management and OpenVAS CSV) / branch scanner-import-phase1, before merge
Scope: a new command, ot_triage_import.py, and a new module, scanimport.py, read scanner exports (new, untrusted input files that can be very large) and write the findings and inventory files OT Triage already reads. They change no scoring. They add a header-detected reader per format, an aliases file, a merge step, a writer for findings and a writer that extends an existing inventory.
Tools run (with versions): bandit 1.9.4 (31 application files), semgrep 1.179.0 (p/python, p/security-audit), ruff 0.16.10, gitleaks (full history), the full suite (1,016 tests, including hypothesis fuzzing, on a private virtual display), 44 mutation checks, a 400,000-row (62 MB) generated export for time and memory
Tools not run (and why): osv-scanner and pip-audit (no dependencies); mitmproxy (no network code at all, a test patches the downloader to fail if it is touched); atheris (hypothesis fuzzing and hostile-file tests were used instead)

Tool results (attached under reports/cp18-scanner-import-phase1/)
- bandit: 0 findings. semgrep: 0 findings, 0 errors. ruff: 0 findings. gitleaks: no leaks.

What was checked
- Header, not position: a file is recognised by its column names (case, spacing and underscores ignored); a header that is none of the three is refused with the start of the header in the message, and a recognised file missing a required column is refused too. Nothing is guessed.
- Never silent: resolved, fixed, informational and low-confidence rows are skipped and counted by reason; a finding with no score stays in the output with an empty score so OT Triage shows it as not scored; a finding with no CVE is counted as needing a threat level, and a threat level is only added when the person types one.
- Nothing invented: criticality, exposure and controls are never filled in; an existing inventory keeps every row, column and value, a blank name, vendor, product or version is filled from the scan and a value that is there is never replaced (a test compares the input file's hash before and after).
- Hostile input: files over 200 MB, over 1,000,000 rows, cells over 8 MB, binary files, empty files, directories and missing files are refused with a message; control and invisible characters (escape sequences, right-to-left marks) are removed; names are cut at 200 characters and asset ids at 100; spreadsheet formula cells are neutralised in everything written; the global CSV field size limit is put back after every read (a test checks it, even after an error).
- Files: an output is never written over an input (findings, inventory, aliases, any export), never replaced without --force, written atomically, and a failed import leaves no file and no temporary file; the printed summary is cleaned of control characters.
- Aliases: matched ignoring case, a chain (an alias that is itself an alias) and a name listed for two assets are refused, at most 100,000 aliases.
- Merging: same asset and CVE (or same asset and title with no CVE) becomes one finding, the highest score is kept, a patch status is kept if any report has one, the sources are listed (at most 6), and the order of first appearance is kept.
- Agreement with the plan: the three formats reproduce, byte for byte in content, the expected files that the throw-away prototype wrote for the fictional samples (a test compares them), and the output ranks through OT Triage exactly like a hand-written findings file with the same values.
- Time and memory: a 62 MB, 400,000-row export is read in about 4 seconds and refused cleanly at the 300,000-finding read limit after about 170 MB; before that limit existed it was read in full (see CP18-01).
- No real export has been tested. The formats are built from the vendors' public documentation and integrations (see docs/SCANNER_IMPORT.md); headers vary by product version, which is why the columns are found by name and why a real export from each tool is still wanted.
- Mutation checks: 44 changes to scanimport.py (each rule above: skips, score choice, CVE splitting, host fallback, quality threshold, patch status, detection, limits, aliases, merging, threat level, formula neutralising, inventory rules). 42 were caught at once; 1 pattern did not match (corrected and caught); 1 survivor is an equivalent change (the tab and carriage-return members of the formula set can never reach the start of a cell because text is cleaned first); and the file contains no other survivors.

Finding CP18-01
- Title: A huge export was read completely into memory before the limit on findings was checked
- Severity: Low (a large file used a lot of memory before being refused; nothing was written or wrong)
- Location: scanimport.import_exports and the two readers
- Found by: the time and memory run on a generated 400,000-row export: 331 MB at its peak before the "more than 50,000 findings" message.
- Cause: the limit on the number of findings was checked after merging, and merging needs everything in memory.
- Status: fixed. The readers stop as soon as 300,000 findings have been read from all the files together (a test covers one file, two files and both formats), which brings the peak to about 170 MB; the 50,000 limit still applies after merging, which is what the Batch view reads.

Release gate for this feature
| Gate | Evidence | Pass |
| --- | --- | --- |
| No change to bucket logic or scores | the importer writes only columns OT Triage already reads; a test ranks imported and hand-written rows alike | Yes |
| No invented values, no silent drops | counted skips, not-scored findings stay visible, threat level only when typed, inventory never overwritten | Yes |
| Hostile input and large files are bounded | size, row, cell, finding and alias limits, each tested; time and memory measured | Yes |
| Inputs never modified | hash tests, same-file checks, atomic writes | Yes |
| Static analysis clean | bandit, semgrep, ruff 0 findings; gitleaks clean | Yes |
| Documentation updated | docs/IMPORT.md, docs/SCANNER_IMPORT.md, README.md, SECURITY.md, CHANGELOG.md | Yes |
| Real exports checked | none available yet | No (open: planned with the owner's scrubbed exports) |
