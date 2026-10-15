# Independent security review of OT Triage 0.9.0

You are an independent security reviewer. You have no prior involvement with this project, and nothing you are told here
should be taken on trust: read the code and form your own view. Do not change any file. Report only what you can support.

## The project
OT Triage is a desktop application (Python 3.12+, standard library only, Tkinter) that helps OT/ICS security staff decide
which vulnerabilities to fix now, next or never. It runs offline, and downloads three public data sets only when the
person starts an update: CISA KEV, FIRST EPSS and the CISA ICS advisories archive. It reads files the person gives it
(findings CSV, an asset inventory CSV, scanner exports in several formats) and writes CSV files. It ships as a plain-source
zip. The repository is at the current directory; the release is tag v0.9.0.

## What to look at
Application code is the top-level `*.py` files that do not start with `test_` (the `tools/` folder is build tooling).
Please give most attention to:
1. Parsers of untrusted input: `scanimport.py` and `ot_triage_import.py` (Nessus CSV and XML, Tenable, OpenVAS, Nozomi JSON/CSV, Dragos JSON), `batch.py`, `inventory.py`, `compare.py`, `threatdata.py`, `icsadvisories.py` (a downloaded tar.gz archive), `references.py`, `versions.py`.
2. Network code: `threatdata.py` (fetch, TLS, redirects, size limits, host allow-list).
3. File writing: atomic writes, overwrite protection, spreadsheet-formula injection in exported CSV, path handling.
4. The GUI's handling of untrusted text and links (`gui_*.py`): links must only open on a click and only for safe addresses.
5. The CI and release workflows in `.github/workflows/` and the supply-chain claims in `SECURITY.md`.
6. Whether the scoring logic (`prioritizer.py`, `settings.py`, `cvss*.py`) can be made to give a wrong answer silently.

Threats to consider: a malicious or malformed input file; a hostile file name; resource exhaustion (memory, CPU, disk); a malicious
server response or archive; spreadsheet-formula injection; symlink or path tricks; unsafe defaults; secrets or personal data in the repository; weaknesses in the build and release process.

## How to work
- Form your findings from the code first. Afterwards you may read `SECURITY.md`, `SECURITY_TEST_PLAN.md`, `docs/` and `reports/` and say where your findings differ from them or where a documented claim is not supported by the code.
- You may run the test suite if your sandbox allows it. Do not use the network except to read this repository.
- Treat the previous reports as claims to check, not as evidence.

## What to return (one Markdown document)
1. A one-paragraph overall opinion, including your confidence and how much of the code you actually read.
2. A list of findings, most severe first. For each: a title; severity (Critical, High, Medium, Low, Info); the file and line; what is wrong; how it could be triggered (a concrete input or scenario); the likely impact; a suggested fix; and your confidence (Confirmed, Likely, Possible).
3. Documented claims you found to be wrong or unsupported.
4. Areas you did not review, and anything you could not verify.
5. If you found nothing in an area, say so and what you checked, rather than leaving it out.
