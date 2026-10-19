Reviewer: Claude Code (developer and reviewer); the project owner asked for the demo
Checkpoint / commit: CP28 (browser demo of the rules) / branch browser-demo, before merge
Scope: a new static page, demo/ (index.html, style.css, rules.js, app.js), and what keeps it honest: tools/make_demo_golden.py, demo/golden.json, demo/check_rules.js, tools/demo_ui_check.html and test_demo.py; a CodeQL job for JavaScript in .github/workflows/security.yml; documents (demo/README.md, README, SECURITY.md, docs/RELEASING.md, CHANGELOG). No change to the application or to any rule.
Tools run (with versions): the project's runner (ruff 0.16.10, bandit 1.9.4, semgrep, gitleaks), zizmor (pedantic) on the workflows, the full suite on a private virtual display, node 26 and a headless Chromium for the demo's own checks, mutation checks
Tools not run (and why): atheris, osv-scanner and pip-audit (the demo has no dependencies and parses nothing from outside); semgrep does not scan the JavaScript locally (CodeQL does, in CI)

Design in one paragraph. The rules are the product, so a second copy of them is the main risk (they changed twice in the days before this). The demo ports only the rules function and the "what would change this" lines to JavaScript. demo/golden.json holds what the Python rules answer for 2,916 inputs (every combination of the five choices at twelve scores, including 3.9, 4.0, 6.9, 7.0, 8.9 and 9.0): bucket, ordering score, action, reasons, factors, the what-would-change lines, the headlines and the exposure note. `node demo/check_rules.js` compares the JavaScript with it, and test_demo.py compares it with the Python rules, so a rule change that is not mirrored fails the suite. A version bump also fails until VERSION in rules.js and the golden file are updated, which makes the demo follow each release. Running the real Python in the browser (Pyodide) would remove the second copy but needs about 10 MB from a third-party CDN, which breaks the page's promise to load nothing from elsewhere.

Finding CP28-01
- Title: The demo is a second copy of the policy and could drift from it
- Severity: Info (a design risk found before building)
- Description: any rule change not mirrored in JavaScript would make the public demo give a different answer from the application.
- What was done: the golden-file comparison above, in both directions, plus the version check. The first run of the comparison found a real defect in the port (the factor chips sorted wrongly because `0 || 3` is 3 in JavaScript); the guard did its job.
- Status: mitigated by test. Confidence: Confirmed.

Finding CP28-02
- Title: A page on the public website must not collect, keep or load anything
- Severity: Info
- Description: the project's promise is that nothing about a person's assets leaves their machine. A web page could break it through a network call, storage, a third-party script or font, an inline script, or an HTML injection.
- What was done: a Content Security Policy (`default-src 'none'; script-src 'self'; style-src 'self'; base-uri 'none'; form-action 'none'`) in the page; the page has no inline script, no inline style and no event-handler attribute; the code writes to the page only with `textContent` (no innerHTML or similar) and uses no network, storage, cookie, navigation or dynamic-code API. test_demo.py checks each of these, that the only addresses in the published files are two links to the project's own repository, and that the page works in a headless browser. A CodeQL job for JavaScript was added to the Security workflow (a separate job, so the name of the existing required check is unchanged).
- Limitation: GitHub Pages cannot set HTTP headers, so the policy is a meta tag (which browsers enforce for these directives, but not frame-ancestors).
- Status: fixed, tested. Confidence: Confirmed.

Checks of the page itself
- The page was opened in a headless Chromium (no window) from a file and its answer read back; the five examples, the refusal of a score that is not a number between 0 and 10 ("abc", empty, "11", "-1", "NaN", "1e3"), the reading of a score to one decimal (6.96 is 7.0 and so on the High line, 6.94 is 6.9), the exposure note appearing and disappearing, and the bottom bar on narrow screens are driven by tools/demo_ui_check.html.
- Seen at desktop and phone width in the dark theme; the light theme uses the same layout with its own colours.

Mutation checks (27, all caught; one needed a stronger check first)
- rules.js: the High line, the Critical line, the important-asset floor removed, the crown-jewel floor `>=` to `>`, a score credit, a reason text, the end-of-life NEVER action, the exposure note shown at any exposure, the factor sort, the what-would-change search skipping a score, the version, the low-CVSS cap, the score rounding.
- app.js: the validation of the score, the rounding of the score to a tenth (this one survived until a check using 6.96 and 6.94 was added), the exposure note always visible, the bottom bar, the input and change listeners removed, an example changed, the action text replaced, innerHTML used.
- index.html: a policy widened to allow inline scripts, a stylesheet from another site, an inline event handler.
- prioritizer.py: the important-asset floor `>=` to `>` and a score credit changed (the golden file notices).

Suppressions added: 2 (`# noqa: S603` on the two subprocess calls in test_demo.py, which run node and a headless browser on this project's own files with fixed arguments, the same reason as the existing ones in test_import_cli.py and test_bundle.py). The baseline was refreshed to 51 entries; the only change is those two.
Suppressions removed: none.
SSDF practices touched: PW.1 (a design decision recorded with its reasons), PW.5 (input handling and safe output), PW.8 (tests, mutation checks), PS.1 (nothing is loaded from elsewhere).

Release gate for this change
| Gate | Evidence | Pass |
| --- | --- | --- |
| No change to the application or to any rule | only new files, a workflow job and documents | Yes |
| The demo gives the application's answers | 2,916 cases compared in both directions | Yes |
| The page loads, keeps and sends nothing | the policy and the checks above | Yes |
| Full suite, runner | see the tail of this report | Yes |

Verification
- Full suite on a private virtual display: 1,181 tests, all passing (the golden-file tool was then restructured so that its imports need no suppression, and test_demo, test_security_checks, test_bundle and test_source_hygiene were rerun and pass). Runner: ruff, bandit, semgrep and gitleaks 0 findings; 51 suppressions, all in the baseline (the two added are the ones named above, each now with its reason in the comment). zizmor (pedantic) on the workflows: no findings. The raw tool output is not archived, as in CP23.
