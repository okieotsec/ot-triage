# The OT Triage browser demo

A small page (`index.html`) that runs the OT Triage rules in the browser: six answers in, a bucket (NOW, NEXT or NEVER)
with the reasons, the recommended action and "what would change this?" out. It is for trying the idea in 30 seconds;
the application does the real work (threat lookups, scanner imports, whole files).

**What it does not do.** Nothing is sent, stored or logged, and the page loads nothing from another site: a Content
Security Policy in the page allows only its own files, there are no cookies, no storage and no network calls, and the
code writes to the page only with `textContent`. It uses the default settings and the answers you choose. Tests check
all of this (see `test_demo.py`).

## How it stays the same as the application

The rules exist twice, in `prioritizer.py` and in `rules.js`. `golden.json` is what keeps them equal:

* `tools/make_demo_golden.py` asks the Python rules for the bucket, the ordering score, the action, the reasons, the
  factors and the "what would change this" lines for 2,916 inputs (every combination of the five choices at twelve
  scores, including the lines of the rules, 4.0, 7.0 and 9.0, and a score either side of each).
* `node demo/check_rules.js` compares `rules.js` with it, and `test_demo.py` compares it with the Python rules, so a rule
  change that is not mirrored here fails the test suite. The test suite also drives the page in a headless browser
  (`tools/demo_ui_check.html`): the examples, the checks on the score box and the exposure note.
* After **any change to a rule**: change `rules.js` to match, run `python3 tools/make_demo_golden.py`, and run the tests.
  After **a version bump**: update `VERSION` in `rules.js` and regenerate the golden file.

## Files

| File | Published | Purpose |
| --- | --- | --- |
| `index.html`, `style.css`, `app.js` | yes | the page |
| `rules.js` | yes | the rules, a port of `prioritizer.py` and the "what would change this" part of `explain.py` |
| `golden.json` | no | the Python answers `rules.js` is checked against |
| `check_rules.js` | no | the comparison (`node demo/check_rules.js`) |

## Publishing

The demo is published on the OkieOTSec website, linked from the OT Triage projects page. With each release, copy the four
published files into the website repository's `ot-triage-demo/` folder and open a pull request there (see
[docs/RELEASING.md](../docs/RELEASING.md)). The page says which version of the rules it shows.
