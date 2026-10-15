Reviewer: Claude Code (developer and reviewer); the decision was taken by the project owner
Checkpoint / commit: CP27 (important asset floor, exposure note wording) / branch friendlier-open-errors, before merge
Scope: one new floor in prioritizer.py (an important asset with CVSS of 9.0 or more is never NEVER) and a reworded exposure check note (explain.py). Documents: docs/POLICY.md decision 8, README rules, docs/SETTINGS.md, CHANGELOG. No other change to the ranking rules.
Tools run (with versions): the project's runner (ruff 0.16.10, bandit 1.9.4, semgrep, gitleaks), the full suite on a private virtual display, mutation checks on the new tests
Tools not run (and why): atheris, osv-scanner and pip-audit (no parser and no dependencies are involved)

Finding CP27-01
- Title: An important asset with a critical score could be NEVER on a controls claim alone
- Severity: Low (a policy weakness, found by the owner while testing; not a vulnerability)
- Location: prioritizer.prioritize, the strong-controls step
- Description: after CP24's floor for crown jewels, CVSS 9.8 / no known exploitation / important asset / Low exposure / strong controls was still NEVER, because strong controls lowered NEXT by one level. The only thing separating that item from a schedule was a claim, "strong controls", that nothing in the tool checks.
- Evidence: reproduced from the inputs above. The owner asked how other frameworks handle it. CVSS 3.1 lets a segmented component's Modified Attack Vector be scored Adjacent only when there is high confidence it is unavailable from the internet, and the example in its user guide moves a score from 6.4 to 5.4: a controls claim lowers a score, it does not remove the flaw. CISA's SSVC has no "never" outcome (its lowest, Track, keeps the item under review). IEC TR 62443-2-3 expects a deferred patch to be documented and justified with its compensating controls. A partner's description of Dragos's Never is "no realistic operational impact", which is about impact, not only controls (a secondary source).
- Root cause and prevention: CP24 stated the principle for crown jewels (a high score on the most important asset is never "never fix" because of unverified claims) but only for that asset class. Decision 8 applies the same principle with a higher bar to important assets (the "Critical" CVSS setting, 9.0 by default), and the tests enumerate every exposure, controls and patch combination at 9.0, 9.8 and 10.0.
- Status: fixed, approved by the owner 2026-10-15 (POLICY.md decision 8). Strong controls still lower the ordering score by 1.0. Confidence: Confirmed.

Effect (old engine against new, over 2,916 combinations: 12 scores from 0.0 to 10.0 across every threat, asset, exposure, controls and patch value): exactly 15 results change, every one an important asset with no known exploitation or a public exploit and CVSS of 9.0 or more going from NEVER to NEXT. Nothing else changes.

Exposure check note wording. The owner reworded the note: choosing Low exposure *asserts* isolation ("no IT or internet path reaches this device, for example air-gapped or fully segmented"), the risk is stated in plain words ("if an attacker gets into the OT network, any device that can route to this one could exploit it"), and the action is "confirm the isolation by testing, or choose Medium". Two details were corrected before adoption: a DMZ was not given as an example of isolation (it is reachable from both sides, so it contradicts the definition of Low), and "remote network exploit" became "exploited over a network" (the vector says network, not outside the plant). The last sentence, that the note does not change the priority, is kept: it is the promise that notes make. Tests in test_explain, test_batch and test_gui_assess pin the text.

Mutation checks (7, all caught): the floor removed, `>=` changed to `>`, the line hard-coded at 9.0 instead of following the setting, the line moved to the "High" setting (7.0), the floor widened to every asset that is not a crown jewel, and the reason and the factor removed.

Suppressions added / removed: none.
SSDF practices touched: PW.1 (a design decision recorded with its reasons), PW.8 (tests, mutation checks).

Release gate for this change
| Gate | Evidence | Pass |
| --- | --- | --- |
| Policy change approved by the owner before it was built | the owner's reply of 2026-10-15 | Yes |
| POLICY.md, README rules and CHANGELOG describe it, with the reason and what it replaced | decision 8 | Yes |
| The only results that change are important assets at CVSS 9.0 or more that were NEVER | the comparison above | Yes |
| Full suite, runner | see the tail of this report | Yes |

Verification
- Full suite on a private virtual display: 1,171 tests, all passing. Runner: ruff, bandit, semgrep and gitleaks 0 findings; 49 suppressions, all in the baseline (none added). The raw tool output is not archived, as in CP23.
