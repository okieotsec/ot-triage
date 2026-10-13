Reviewer: Claude Code (developer and reviewer)
Checkpoint / commit: CP14 (the portable bundle and launcher) / branch portable-bundle, before merge
Scope: tools/make_bundle.py (builds ot-triage-<version>.zip and a .sha256 file from the files git tracks), OT Triage.pyw (a double-click launcher), docs/RELEASING.md and the README's Download and run section. No change to the application. The risks are what a published file contains (a leaked secret, a test fixture, a hostile path), whether it can be checked, and what the launcher does when something is wrong.
Tools run (with versions): bandit 1.9.4, semgrep 1.179.0 (p/python, p/security-audit), ruff 0.16.10, gitleaks (full history), the full suite (including 13 bundle tests that build, extract and run the bundle), 8 mutation checks
Tools not run (and why): osv-scanner and pip-audit (no dependencies); mitmproxy (no network code); atheris (no parser)

Tool results (attached under reports/cp14-bundle/)
- bandit: 0 findings (the first run flagged the partial path to git, fixed by resolving it with shutil.which). semgrep: 0 findings. ruff: 0 findings. gitleaks: no leaks.

What was checked
- Contents: only the modules the two entry points import (found by following their imports, so a new module cannot be forgotten), the launcher, the top-level documents, docs/, sbom/, the sample CSV files and a generated START-HERE.txt; 55 files, 0.7 MB. Tests, tools, security reports, repository settings and anything git does not track are excluded. A file that is needed but not tracked stops the build.
- Safety of the archive: every path is under one folder named for the version, with no absolute path, no "..", no backslash; files are not group or world writable.
- Reproducible: building twice gives identical bytes; entries are sorted, with fixed dates and modes, so anyone can rebuild from the tag and compare the checksum. The .sha256 file matches. (Windows does not record the executable bit, so a bundle built there differs in that one detail; this is documented.)
- It runs alone: the extracted bundle prints its version from the command line, ranks a sample file with its sample inventory, and every module in it imports with nothing else on the path.
- The launcher: it compiles; on a Python older than 3.12 it reports why (in a message box, or on the console when there is no Tk) instead of closing without a word, and a missing module gets the same treatment.
- Decision: no .exe. A frozen, unsigned executable looks like malware to many security products and asks people to run something they cannot read; plain source suits a security tool. Recorded in docs/RELEASING.md.
- Mutation checks (each made a test fail): tests bundled; imports (plain or from) not followed; reports bundled; untracked files allowed; files left unsorted; group- and world-writable modes; a wrong checksum file. One mutation (using real file times) is equivalent, because a zip entry's default date is already 1980-01-01, so there is nothing to catch.

Findings: none.

Release gate for this feature
| Gate | Evidence | Pass |
| --- | --- | --- |
| Nothing unintended is published | content tests; reports, tests and untracked files excluded | Yes |
| It can be verified | reproducible build, checksum file, documented | Yes |
| It runs on its own | extracted bundle runs the CLI and imports every module | Yes |
| The launcher fails visibly | old-Python test; message box or console | Yes |
| Static analysis clean | bandit, semgrep, ruff 0 findings; gitleaks clean | Yes |
| Documentation updated | README.md, docs/RELEASING.md, CHANGELOG.md | Yes |
