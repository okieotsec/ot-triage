Reviewer: Claude Code (developer and reviewer)
Checkpoint / commit: CP12 (command line) / branch cli-mode, before merge
Scope: ot_triage_cli.py, a second entry point that runs the same ranking as the Batch view from the command line, and docs/CLI.md. It reads the same files (findings, inventory, previous export, settings, stored threat data) through the same parsers already covered by CP1 to CP11, and it can write two files (the ranked CSV and the asset roll-up). The only network use is the explicit --update flag, which calls the existing downloaders (hosts unchanged). New risks: overwriting a file by mistake, printing untrusted text to a terminal, exit codes that scripts rely on, and the update path.
Tools run (with versions): bandit 1.9.4 (28 application files, 6,269 LOC), semgrep 1.179.0 (p/python, p/security-audit), ruff 0.16.10, gitleaks (full history), the full suite (including 26 CLI tests and a run of the script as a separate process), 13 mutation checks
Tools not run (and why): osv-scanner and pip-audit (no dependencies); mitmproxy (the downloaders are unchanged and covered by CP2, CP8); atheris (no new parser)

Tool results (attached under reports/cp12-cli/)
- bandit: 0 findings. semgrep: 0 findings, 0 errors. ruff: 0 findings. gitleaks: no leaks.

What was checked
- Output files: an existing file is never replaced without --force; an input file (findings, inventory, previous export, or the other output) is never overwritten, even with --force (compared with samefile); output goes to a temporary file in the same folder and is moved into place, so a write that fails half-way leaves no partial file and does not damage an older one (tested with a writer that writes half a file and then fails).
- Terminal safety: every piece of text that comes from a file (names, ids, assets, messages) is cleaned and cut to 90 characters before it is printed, so escape sequences, a bell and direction characters in a hostile finding name cannot reach the terminal (tested with an ESC sequence, a title-setting sequence, BEL and a right-to-left override, and with a 500-character name).
- Exit codes: 0 done, 1 a file could not be used or an update alone failed, 2 wrong arguments (argparse), 3 --fail-on found a finding at or above the bucket; each is tested, including NEXT and NOW boundaries and the script run as its own process. Missing files, folders, empty files and binary data give one "error:" line and exit 1, never a traceback.
- Network: nothing is downloaded unless --update is given (a guard that fails any download is active in every test). --update alone exits 1 if any source failed; with a findings file it warns and ranks with the stored data.
- Same results as the application: the CLI uses batch.process_file, rollup and compare, so priorities, the export and the roll-up are the same code (a test compares the ranked order and a row's values).
- Mutation checks (each made a test fail): an existing output replaced without --force; an input file overwritable; file text printed with control characters; file text printed without a length limit; --fail-on NEXT ignoring NEXT; --fail-on never failing; a failed write leaving its partial file; output written directly instead of atomically; an update failure alone exiting zero; the downloader bound as a default again; --quiet still printing; the comparison not passed to the export; the inventory ignored. Twelve were caught at once; the atomic-write one survived until a test that writes half a file was added, and all thirteen are now caught.

Finding CP12-01
- Title: The downloaders bound the real network function as a default argument, so a test patch could not intercept it
- Severity: Info (a test-hygiene risk; the application always passed its downloader explicitly and no test touched the network by design)
- Location: threatdata.update_from_network and icsadvisories.update_from_network
- Found by: the new CLI tests: the first version of the --update tests ran for twelve seconds because it reached the real public servers (read-only requests to the same two public files the application uses, with the data going to a temporary folder).
- Status: fixed. Both functions now default to None and look the downloader up when called, so replacing threatdata.fetch in a test always works; the CLI also passes it explicitly. A test in each module pins this, and a mutation that restores the old binding is caught. All tests now run with no network.

Release gate for this feature
| Gate | Evidence | Pass |
| --- | --- | --- |
| Same priorities as the application | uses the same code; tests compare results | Yes |
| No network unless asked | a network guard in every test; explicit --update tests | Yes |
| Files are not overwritten or half-written | 5 tests and 3 mutation checks | Yes |
| Untrusted text cannot reach the terminal | hostile-text tests and 2 mutation checks | Yes |
| Exit codes are stable | tests for 0, 1, 2 and 3, and the script run as a process | Yes |
| Static analysis clean | bandit, semgrep, ruff 0 findings; gitleaks clean | Yes |
| Documentation updated | docs/CLI.md, README.md, CHANGELOG.md | Yes |
