Reviewer: Claude Code (developer and reviewer)
Checkpoint / commit: CP3 addendum for the CVSS vector feature, branch cvss-vector (the cp3 tag predates this feature)
Scope: the new CVSS vector parser and calculators (cvss.py, cvss4_tables.py), the Assess vector field, the batch cvss_vector column and export columns, the developer verification tool (tools/), and third-party data embedded from FIRST.
Tools run (with versions): ruff 0.16.10, bandit 1.9.4, semgrep 1.179.0 (p/python, p/security-audit; 41 files), gitleaks 8.30.1 (29 commits, no leaks), hypothesis 6.168.5, Node.js 26.7.0 with FIRST's official calculators (verification only), cyclonedx-bom 7.5.0
Tools not run (and why): pip-audit and osv-scanner were not re-run because no dependency changed (requirements files and the SBOM are unchanged; the application is still standard library only). A full CP4 run will repeat everything.

Results after the fixes below
- ruff, bandit, semgrep: 0 findings.
- Tests: 417 pass without hypothesis and 435 with it.
- Correctness: every possible base vector (2,592 for CVSS 3.0, 2,592 for 3.1 and 104,976 for 4.0) scores identically to the official FIRST calculators, re-run at the end with the downloaded reference files pinned by SHA-256.
- Mutation checks: 11 of 13 deliberate scoring and parsing faults were caught. The two that survived are equivalent mutants for base vectors, verified directly (0 of 2,592 v3.x and 0 of 104,976 v4.0 scores change).

Finding CVSS-01
- Title: Invisible and look-alike characters in test source files
- Severity: Low (a source-readability hazard of the "Trojan Source" kind; the characters were in test strings, not in application logic)
- Location: test_cvss.py, test_batch.py, test_gui_settings.py
- Description: Several hostile-input test strings that were meant to be written as escape sequences were saved as the literal characters: a right-to-left override (U+202E), a zero-width space, a byte-order mark, a Cyrillic capital A (identical in appearance to a Latin A), a fullwidth slash, an Arabic-Indic digit and a Cyrillic small izhitsa.
- Evidence / reproduction steps: bandit B613 flagged the right-to-left override; a character scan found the others.
- Recommended fix: Write them as escape sequences, and add a test that fails if any source file ever contains an invisible, direction-changing or unreviewed non-ASCII character (test_source_hygiene.py, mutation-checked by planting a hidden character).
- Confidence: Confirmed
- Status: fixed and verified

Finding CVSS-02
- Title: The verification tool downloads and runs reference JavaScript without pinning
- Severity: Low (manual developer tool, HTTPS only, fixed URLs, code runs in a Node vm context without file or network access, but "download and run" should still be pinned)
- Location: tools/verify_cvss_against_reference.py
- Description: The tool would have run whatever the upstream URLs served at the time.
- Evidence / reproduction steps: Code review.
- Recommended fix: Pin the SHA-256 of each downloaded file, abort on a mismatch with a message to review the upstream change, and test the pin list offline (applied). The files used for the recorded results were checked against what upstream serves today (unchanged).
- Confidence: Confirmed
- Status: fixed and verified

Finding CVSS-03
- Title: A parenthesised CVSS 2 vector was reported as "unsafe characters"
- Severity: Info (usability)
- Location: cvss.py parse_vector
- Description: The character check ran before the CVSS 2 detection, so a pasted vector such as (AV:N/AC:L/Au:N/C:P/I:P/A:P) got a confusing message.
- Evidence / reproduction steps: test_rejected_inputs_give_a_clear_message.
- Recommended fix: Detect CVSS 2 first (applied).
- Confidence: Confirmed
- Status: fixed and verified

Finding CVSS-04
- Title: After editing a valid vector into an invalid one, the message wrongly said the score was "typed below"
- Severity: Info (a misleading message; the result was still driven by a valid earlier score)
- Location: gui_assess.py apply_vector
- Description: The score box still held the previous vector's score, but the message said it had been typed by hand.
- Evidence / reproduction steps: test_breaking_a_valid_vector_says_the_score_is_still_from_the_previous_one.
- Recommended fix: Say that the score still comes from the previous vector (applied).
- Confidence: Confirmed
- Status: fixed and verified

Finding CVSS-05
- Title: A giant vector cell is stopped by the CSV layer, not the vector parser
- Severity: Info (safe by design)
- Location: batch.py read_rows
- Description: A single CSV field over 128 KB makes the whole file fail with a clear message before any vector parsing. A long cell below that limit reaches the parser, which rejects anything over 400 characters immediately and keeps error text short.
- Evidence / reproduction steps: test_a_giant_vector_cell_is_refused_by_the_csv_layer_before_any_parsing; a 5 MB cell is rejected in under a second.
- Recommended fix: None.
- Confidence: Confirmed
- Status: accepted by design

Finding CVSS-06
- Title: Third-party scoring data is embedded
- Severity: Info
- Location: cvss4_tables.py, THIRD_PARTY_NOTICES.md
- Description: The CVSS 4.0 lookup tables come from FIRST's calculator (BSD-2-Clause). They were generated mechanically from the upstream files, and the required license text is included and matches upstream exactly.
- Evidence / reproduction steps: diff of the notice against upstream LICENSE (only a trailing newline differs).
- Recommended fix: None; keep the notice with any distribution.
- Confidence: Confirmed
- Status: accepted

Checklist items affected (6.1)
- Input handling: Pass. The vector parser is strict (allow-listed characters, 400-character limit, known metrics and values only, no duplicates) and fuzzed with hypothesis; CVSS 2, unknown versions and malformed text give clear messages.
- Output and integrity: Pass. Conflicting score and vector values make an error row instead of a silent choice; the vector and version are recorded in summaries and exports; exported vector cells are formula-neutralized.
- Logic: Pass. Scores are exactly those of the official calculators for all base vectors.
