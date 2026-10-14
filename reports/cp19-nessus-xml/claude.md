Reviewer: Claude Code (developer and reviewer)
Checkpoint / commit: CP19 (scanner import: Nessus v2 `.nessus` XML) / branch scanner-import-nessus-xml, before merge
Scope: scanimport.py gains a reader for Nessus v2 XML files, the first XML file the tool parses. XML is the classic source of entity-expansion ("billion laughs") and external-entity attacks, and a .nessus file can be hundreds of megabytes, so this is a new parser of untrusted input, not just another mapping.
Tools run (with versions): bandit 1.9.4 (31 application files), semgrep 1.179.0 (p/python, p/security-audit), ruff 0.16.10, gitleaks (full history), the full suite (1,035 tests, including hypothesis fuzzing, on a private virtual display), 27 mutation checks, a generated 115 MB Nessus file with 45,000 findings for time and memory
Tools not run (and why): osv-scanner and pip-audit (no dependencies); mitmproxy (no network code); atheris (hypothesis fuzzing and hostile-file tests were used instead)

Tool results (attached under reports/cp19-nessus-xml/)
- bandit: 0 findings. ruff: 0 findings. gitleaks: no leaks. semgrep: 1 finding at first (the standard library XML import, see CP19-01), 0 after the reviewed annotation.

What was checked
- Entity expansion and external entities: the standard library's expat parser is driven directly and any DTD or entity declaration stops the parse with a message ("declares a DTD or an entity"), before an entity can be defined or used. Tests feed it a billion-laughs file, an external-entity file that points at /etc/passwd, and a bare DOCTYPE; all are refused, through the library and through the command (no output file is written). Parameter entity parsing is also switched off.
- Streaming: the file is read in 1 MB pieces and each ReportItem is handled as it ends, so a large file is never held in memory; a test checks the parser is fed in pieces and told the file has ended. The text of a plugin's output (which can be megabytes) is never kept: only the CVE ids, the two score elements and a few host tags are read, each capped at 2,000 characters (a test feeds 30 million characters and checks the cap; a mutation check showed the cap guard needed a second call to be tested).
- Structure: the root must be NessusClientData_v2 (checked from the first element), nesting is limited to 24 levels, a file with no ReportHost is refused, a truncated or mismatched file gives a clean "not a valid XML file" message, a file is recognised as XML by its content (including after a byte order mark, and UTF-16) and not by its name.
- Meaning, from Tenable's published Nessus v2 file format document (2016): severity 0 is informational and is skipped; one finding per `cve` element; `cvss3_base_score` (newer than that document, read when present) before `cvss_base_score`; the host is the ReportHost name, or its host-ip tag; compliance checks (Policy Compliance family or `cm:` elements) are audits, not vulnerabilities, and are skipped and counted.
- Agreement with the plan: the sample .nessus gives exactly the findings recorded in samples/scanners/expected/nessus_xml.findings.csv; the same device in a Nessus CSV and a .nessus file merges into one finding with both sources listed.
- Opening a .nessus file in Batch or as an inventory now names it and gives the import command, like the CSV exports.
- Time and memory: a 115 MB file with 45,000 findings is read in 0.7 s with a 57 MB peak; a larger file is refused at 200 MB before it is opened.
- No real .nessus export has been tested; the format follows Tenable's document and the public descriptions of the newer elements.
- Mutation checks: 27 changes (DTD and entity refusal, parameter entities, depth, root, no-hosts, size, row and finding limits, text cap, skips, compliance rules, score order, CVE handling, host naming, XML and UTF-16 detection, chunked reading, the Batch hint). 23 were caught at once; 2 were real gaps in the tests (the text cap needed a second feed, and reading in pieces was not checked), closed and caught; 2 survivors are equivalent changes (an entity can only be declared inside a DOCTYPE, which is already refused, and parameter entities only exist inside one).

Finding CP19-01
- Title: The standard library XML parser is used for an untrusted file
- Severity: Info (semgrep's use-defused-xml rule; no weakness was found)
- Location: scanimport.py, the expat import and _read_nessus_xml
- Found by: semgrep, as expected.
- Reasoning: defusedxml is a third-party package and the tool has none. The attacks the rule is about all need a DTD or an entity declaration; the reader refuses both before they take effect, and tests prove it with real attack files.
- Status: accepted, with the semgrep rule suppressed on the import line and the reason written next to it.

Release gate for this feature
| Gate | Evidence | Pass |
| --- | --- | --- |
| No change to bucket logic or scores | only columns OT Triage already reads are written | Yes |
| Entity and DTD attacks refused | three attack files, library and command level | Yes |
| Large files bounded in memory and time | 115 MB / 45,000 findings: 0.7 s, 57 MB | Yes |
| No invented values, no silent drops | counted skips, compliance rule documented | Yes |
| Static analysis clean | bandit, semgrep (one reviewed suppression), ruff 0; gitleaks clean | Yes |
| Documentation updated | docs/IMPORT.md, docs/SCANNER_IMPORT.md, CHANGELOG.md | Yes |
| Real exports checked | none available | No (open) |
