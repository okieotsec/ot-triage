Reviewer: Claude Code (developer and reviewer)
Checkpoint / commit: CP20 (scanner import, phase 2: Nozomi and Dragos exports) / branch scanner-import-ot-json, before merge
Scope: scanimport.py gains readers for a Nozomi `node_cves` export (JSON, and CSV with the same field names), and for a Dragos vulnerability-detections JSON export; they also write the OT assets' vendor, product and firmware version into the inventory. JSON is new untrusted input for the importer. The Nozomi fields follow Nozomi's published `node_cves` data model; the Dragos shape comes from third-party descriptions only. Both are labelled experimental.
Tools run (with versions): bandit 1.9.4 (31 application files), semgrep 1.179.0 (p/python, p/security-audit), ruff 0.16.10, gitleaks (full history), the full suite (1,062 tests, including hypothesis fuzzing, on a private virtual display), 32 mutation checks, a generated 102 MB Nozomi JSON file for time and memory
Tools not run (and why): osv-scanner and pip-audit (no dependencies); mitmproxy (no network code); atheris (hypothesis fuzzing and hostile-file tests were used instead)

Tool results (attached under reports/cp20-nozomi-dragos/)
- bandit: 0 findings. semgrep: 0 findings, 0 errors. ruff: 0 findings. gitleaks: no leaks.

What was checked
- JSON safety: the file is size-limited (100 MB, because it is read whole), decoded as UTF-8, and NaN, Infinity and duplicate keys are refused, using the same strict parsing as the threat data files; very deep nesting (100,000 levels) gives a clean "not a valid JSON file" message instead of a crash; a file that is JSON but not an export (an empty object, a scalar, wrong records) is refused; records that are not objects are skipped and counted.
- Detection by content: JSON is recognised by its first character and its records (a `host` and a `vulnerability` object for Dragos; `cve` with a node or asset field for Nozomi), never by the file name, and a CSV whose cells contain braces is still a CSV. A Nozomi CSV is recognised by its header (cve, a score column, a node or asset column).
- Resolved records: Nozomi `resolved` is read in every spelling a CSV or JSON may use (true, "true", "1", 1, "yes"); Dragos states resolved, closed, fixed and remediated are skipped in any case; both are counted. "mitigated" is not treated as closed, because a mitigation is not a fix.
- Vendor judgement is not used: Nozomi's likelihood, Dragos's own risk score and 0 to 5 severity, its exploit intelligence and its Purdue level are never read into a finding (tests look for them in the output), following the decisions recorded in docs/SCANNER_IMPORT.md.
- The score is the CVSS score only (Nozomi `cve_score`, Dragos `score.base`); text, out-of-range and missing values are left empty so the finding shows as not scored.
- The inventory gets vendor, product and firmware version from the OT tools (never replacing a value the person wrote); that is what the version comparison in By asset reads.
- Honest labelling: the summary prints a note on every Nozomi and Dragos file that it was read from a public description and not checked against a real export; the guide says the same; the release gate below keeps the open item.
- Opening a JSON file in Batch or as an inventory says it is JSON and gives the import command.
- Agreement with the plan: the importer reproduces every expected file of the independent prototype exactly, apart from the Nozomi titles (now the CVE summary, so the Name column says more than the CVE id); the sample result files in samples/scanners/ are now produced by the shipped importer.
- Time and memory: a 102 MB Nozomi file with 60,000 records is read in 6.7 s with a 404 MB peak, the largest the limit allows (see CP20-01).
- Mutation checks: 32 changes (resolved handling, CVE rules, asset choice, patch status, title, score alias, Dragos state and scale and CVE order, host rules, inventory facts, JSON size, NaN, duplicates, recursion, detection, row limit, non-records, notes, the JSON hint). 26 were caught at once; 5 were real gaps in the tests (CVE normalisation, the enumeration-over-reference order, NaN and duplicate keys placed where they matter, and the CSV note), closed and caught; 1 change was equivalent (it set a variable and then raised the same error).

Development note: the first run of the new tests found a real mistake in the code, not yet released: the "file is too large" error was caught by the handler for malformed JSON (both are ValueError) and reported as "not a valid JSON file". It is fixed and the test stays.

Finding CP20-01
- Title: A JSON export is read whole, so a large one needs about four times its size in memory
- Severity: Info (a resource use that is bounded and documented, not a weakness)
- Location: scanimport._load_json
- Found by: the time and memory run: 404 MB at the 100 MB limit.
- Reasoning: the standard library has no streaming JSON parser, and adding one would mean a dependency. The limit keeps the use bounded, a larger file is refused with advice to export in smaller pieces, and the XML and CSV readers, which can be larger, stream.
- Status: accepted and documented (docs/IMPORT.md).

Release gate for this feature
| Gate | Evidence | Pass |
| --- | --- | --- |
| No change to bucket logic or scores | only columns OT Triage already reads are written; vendor scores and intelligence are tested absent | Yes |
| Hostile JSON refused or bounded | NaN, duplicates, deep nesting, size, rows, wrong shapes, each tested | Yes |
| No invented values, no silent drops | counted skips, empty scores stay not scored | Yes |
| Honest about what is unverified | experimental label in the summary and the guide | Yes |
| Static analysis clean | bandit, semgrep, ruff 0 findings; gitleaks clean | Yes |
| Documentation updated | docs/IMPORT.md, docs/SCANNER_IMPORT.md, samples README, CHANGELOG.md | Yes |
| Real exports checked | none available | No (open) |
