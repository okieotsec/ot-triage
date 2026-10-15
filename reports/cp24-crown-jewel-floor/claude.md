Reviewer: Claude Code (developer and reviewer); the findings were raised by the project owner while testing the Assess view
Checkpoint / commit: CP24 (high-CVSS crown jewel floor, action text, exposure check note) / branch independent-review-fixes, before merge
Scope: three changes to how the tool reaches and words a result: a new floor in prioritizer.py, the action text of a NEVER result, and a note (not a rule) built from the CVSS attack vector. Files: prioritizer.py, cvss.py, explain.py, batch.py, gui_assess.py, gui_batch.py, and the tests and documents that describe them.
Tools run (with versions): the project's runner (ruff 0.16.10, bandit 1.9.4, semgrep, gitleaks), the full suite on a private virtual display, mutation checks on the new tests
Tools not run (and why): atheris, osv-scanner and pip-audit (no new parsing and no dependencies)

Finding CP24-01
- Title: A crown jewel with a very high CVSS score could be NEVER
- Severity: Low (a policy weakness, not a vulnerability; the practical effect is a missed or late fix on the most important asset)
- Location: prioritizer.prioritize, the strong-controls step and the floor rules that follow it
- Description: CVSS 9.8, no known exploitation, crown jewel, Low exposure, strong controls, patch available gave NEVER. The base bucket was NEXT (the high-CVSS rule applies to any asset that is not Standard), strong controls lowered it one level, and the only floor for crown jewels needed High exposure. Two unchecked claims (Low exposure, strong controls) were enough to remove the item from every schedule.
- Evidence: reproduced with the inputs above; with no controls or partial controls the result was NEXT. Found by the project owner reading the result and the "What would change this" list.
- Root cause and prevention: the floors were written for the combinations that were thought about (decision 3: exposed crown jewels). No rule stated the principle behind them, that "never fix" must be hard to reach on the most important asset. Decision 5 states it (a crown jewel with CVSS of 7.0 or more is at least NEXT, at any exposure and with any controls), the tests enumerate every exposure, control and patch combination for it, and the boundary tests pin 6.9 and 7.0 and the setting that moves the line.
- Status: fixed, approved by the owner 2026-10-14 (POLICY.md decision 5). Ordering score is unchanged by the floor and strong controls still rank the item lower inside the bucket.
- Confidence: Confirmed.

Finding CP24-02
- Title: The recommended action contradicted a NEVER result
- Severity: Low (presentation)
- Location: prioritizer.prioritize (the action was chosen from the patch status only)
- Description: a NEVER result headed "No scheduled remediation" showed "Apply the patch" as the recommended action; with the patch pending or the device end of life it showed "Mitigate now..." or the replacement text next to NEVER.
- Evidence: reproduced from the same screen.
- Root cause and prevention: the action was computed before the bucket was final and never revisited. The action is now set after the last floor, and a test enumerates 0.0 to 9.8 across every threat, asset, exposure, controls and patch combination and requires "No scheduled fix" in the action exactly when the result is NEVER.
- Status: fixed (POLICY.md decision 6). Text only: no bucket or score changed.
- Confidence: Confirmed.

Design note (not a finding): the CVSS attack vector. The owner pointed out that a Low exposure choice is only as good as its verification, and that the vector says how a flaw is reached. A rule that moves the bucket from the vector would count the exposure input twice, so it was built as a note only: when the vector (or its modified attack vector) is Network and exposure is Low, Assess and Batch say that Low must be verified by testing. It is shown under the exposure control, in the reasoning and summaries, in the Batch details and in a new `exposure_check` export column. Tests prove the bucket, ordering score, action and rationale are identical with and without the note. Decision 7.

Suppressions added / removed: none.
SSDF practices touched: PW.1 (design: the rule and its reason are written in POLICY.md), PW.8 (tests, mutation checks), RV.3 (root causes recorded).

Release gate for this change
| Gate | Evidence | Pass |
| --- | --- | --- |
| Policy change approved by the owner before it was built | the owner's instruction of 2026-10-14 | Yes |
| POLICY.md, README rules and CHANGELOG describe it, with the reason and what it replaced | decisions 5 to 7 | Yes |
| The only results that change are crown jewels with CVSS of 7.0 or more that were NEVER | the full-grid test and the old-versus-new comparison below | Yes |
| The note and the action text cannot change a bucket or an ordering score | tests in test_explain, test_batch, test_gui_assess | Yes |
| Full suite, runner and mutation checks | see the tail of this report | Yes |

Verification
- Old versus new engine over 2,673 combinations (11 scores from 0.0 to 10.0 across every threat, asset, exposure, controls and patch value): exactly 20 results differ, every one a crown jewel with CVSS of 7.0 or more going from NEVER to NEXT; nothing else changed (the comparison was run on the old and the new code and diffed).
- 12 mutation checks on the new tests, all caught: the floor removed, `>=` changed to `>`, crown jewel widened to every asset that is not standard, the threshold hard-coded instead of following the setting, the action override removed, one NEVER action reworded, the note shown for any exposure but High, shown without checking exposure, the modified attack vector ignored, the base attack vector ignored, the vector flag not recorded in Batch, the export column not written.
- Full suite on a private virtual display: 1,127 tests, all passing. Runner: ruff, bandit, semgrep and gitleaks 0 findings; 49 suppressions, all in the baseline (none added). The raw tool output is not archived, as in CP23.
