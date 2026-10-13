Reviewer: Claude Code (developer and reviewer)
Checkpoint / commit: CP17 (version-aware advisory matching) / branch version-aware-matching, before merge
Scope: the advisory index now also keeps the products and versions each advisory lists as known affected (stored index version 5); a new module, versions.py, reads the free-text version ranges CISA writes and compares an asset's version with them; the asset inventory gains an optional `version` column; By asset, the Batch details, and the roll-up export show the result. The version text comes from a downloaded file and from a file the person chose, and the result is shown to the person as a pointer, so wrong answers matter more than missing ones.
Tools run (with versions): bandit 1.9.4 (29 application files), semgrep 1.179.0 (p/python, p/security-audit), ruff 0.16.10, gitleaks (full history), the full suite (949 tests, including hypothesis fuzzing, on a private virtual display), 56 mutation checks, a real parse and real comparisons on the live CISA archive (3,959 advisories), screenshots on a private display
Tools not run (and why): osv-scanner and pip-audit (no dependencies); mitmproxy (no network change); atheris (hypothesis fuzzing and hostile-text tests were used instead)

Tool results (attached under reports/cp17-version-aware/)
- bandit: 0 findings. semgrep: 0 findings, 0 errors. ruff: 0 findings. gitleaks: no leaks.

What was checked
- The answer is three-valued and never guesses: a version is inside a listed range (True), outside (False), or it cannot be said (None). None is returned for text the parser does not understand, for a version it cannot read as a number, and for two versions that differ only in a qualifier such as SP2. At the advisory level, "inside" needs one listed range that holds; "outside" needs every listed range for the product to be understood and none to hold; anything else is "could not be compared".
- It is never worded as safe: the "outside" sentence says "outside the listed affected versions ... read the advisory anyway", the roll-up column is only "how many list your version", and the documents say a clean result is not a verdict (the advisory may cover the version in words, the list may be incomplete, a different advisory may apply).
- Only listed products count: the asset's vendor must be one of the advisory's vendors and every word of its product must be in a listed product name; an advisory that matched only through its title is "no statement", not a guess.
- Real data: 93.7% of the 26,338 version texts in today's advisories are read (the rest are shapes such as `V3.1.x`, `7_until_7.1.2` or lists of exact versions, and are reported as could not be compared). Spot checks by eye against the listed ranges (an Advantech WebAccess 8.4.5 asset against 50 advisories) agree. Siemens SIMATIC (275 advisories) takes 0.14 s; 2,000 different checks take 0.09 s.
- Bounds: versions are limited to 120 characters, 8 numbers and 9 digits each; the range cache holds at most 20,000 texts (a test fills it past the limit); the index keeps at most 40 product and version entries per advisory (80 characters per version, 120 per product); a note is at most 200 characters; 10,000 listed product ids per vulnerability are read. Hostile asset versions (5,000 NUL characters, a 100,000-digit number) are reported as unreadable in no time.
- Stored index: every new field is validated when loaded (types, lengths, clean text, no repeats, at most 40), with 13 new bad-index cases; the index grows by about 1 MB (6.0 MB in all; the cap is 60 MB), and an older index is refused with the usual "update again" message.
- No effect on decisions: the inventory tests score the same asset with and without a version column; the By asset table is the same with and without versions.
- Export: the version cell is protected against spreadsheet formulas like the other text cells; the new `listing_your_version` column is blank when nothing was compared.
- Mutation checks: 56 changes to versions.py, the check code in icsadvisories.py and rollup.py. In the first run 10 survived: 7 were gaps in the tests (an exact version mixed with another bound, a long text with a number, one product word being enough, an unreadable range losing to an outside one, the ranges named not being limited or repeated, newest-first order within a group), each closed with a test and then caught; 3 were equivalent changes (a redundant branch, which was removed, and two guards that other checks already enforce, which were kept as defence in depth).

Finding: none new. One development slip is recorded for completeness: the first real-data run failed because the new module's name clashed with an existing function called `versions` in icsadvisories.py (the import was renamed), and the full suite then caught one regression of mine before the pull request, a Batch details change that loaded the threat data for files with no CVE column (fixed, and the existing test that guards it stayed).

Release gate for this feature
| Gate | Evidence | Pass |
| --- | --- | --- |
| No change to bucket logic, scores or the inventory's scoring fields | tests with and without a version column | Yes |
| Never claims safety; says "could not compare" instead of guessing | wording tests, three-valued comparison, 56 mutation checks | Yes |
| Hostile text and large inputs are bounded | limits on text, numbers, cache and index, with tests | Yes |
| Works on the real data | 93.7% of real version texts read; spot checks; timings | Yes |
| Static analysis clean | bandit, semgrep, ruff 0 findings; gitleaks clean | Yes |
| Documentation updated | docs/INVENTORY.md, docs/THREAT_DATA.md, CHANGELOG.md | Yes |
