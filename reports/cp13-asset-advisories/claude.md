Reviewer: Claude Code (developer and reviewer)
Checkpoint / commit: CP13 (advisories that may apply to an asset, by vendor and product) / branch vendor-product-match, before merge
Scope: the advisory index now also keeps product names (stored index version 3); `IcsData.match()` finds the advisories whose vendor and product words match an asset's; the asset inventory gains optional `vendor` and `product` columns (free text); the Batch By asset view, the roll-up export and the command line's `--assets` file show the result. The inventory and the advisory data are untrusted input already covered by CP5 and CP8; the new risks are free text from both sides meeting in a matcher, a larger stored index, and a result that could be mistaken for proof. It is context only: no priority or score is ever changed.
Tools run (with versions): bandit 1.9.4 (28 application files), semgrep 1.179.0 (p/python, p/security-audit), ruff 0.16.10, gitleaks (full history), the full suite (852 tests, including hypothesis fuzzing, on a private virtual display), 13 mutation checks, a real update and real matches against the live CISA repository, a speed check
Tools not run (and why): osv-scanner and pip-audit (no dependencies); mitmproxy (no network change); atheris (hypothesis fuzzing and hostile-name tests were used instead)

Tool results (attached under reports/cp13-asset-advisories/)
- bandit: 0 findings. semgrep: 0 findings, 0 errors. ruff: 0 findings. gitleaks: no leaks.

What was checked
- Matching rule: every word of the vendor must appear among an advisory's vendor names (legal endings such as Inc, GmbH and AG ignored) and every word of the product among its product names or title, all in the same advisory, ignoring case, punctuation, accents and order. A vendor and a product word of at least three characters are required, so "a", "A1" and "-" match nothing. A product alone never matches when the vendor is unknown, a vendor alone matches nothing, and a word that appears only in one of two multi-word vendors is not enough.
- It never claims more than it knows: the wording is "may apply ... does not know the version you run, so read each one"; a vendor that no advisory names gets "CISA may list it under another name" (for example Allen-Bradley and Rockwell Automation) instead of silence; if the advisories are not loaded it says to update them.
- Hostile input: names of 100,000 characters, NUL and right-to-left characters, emoji, and 10,000 repeated words are handled; words are limited to 12 per name and 40 characters each; the match cache is bounded (5,000 entries); product names from the advisories are cleaned, limited to 120 characters and 30 per advisory, and the stored index rejects anything else (the index validation grew accordingly).
- Speed: 20,000 different vendor and product pairs match in a few seconds (a test pins 10 s); building the word index takes 0.08 s on the real data; the real index is 1.65 MB and reloads in 0.12 s.
- Real data: the sample inventory (six fictional assets) matches 3 to 50 advisories each on the live CISA data, and the Allen-Bradley asset correctly finds that no advisory names its vendor.
- No effect on decisions: tests show an inventory with vendor and product columns scores exactly like one without, and the By asset table is the same with and without the advisories loaded.
- Export: the vendor and product cells are protected against spreadsheet formulas like every other text cell.
- Mutation checks (each made a test fail): accents splitting words; legal endings kept; any one vendor word enough; any one product word enough; short product words accepted; the vendor not required; newest not first; an unbounded cache; the title not searched; the vendor-known flag always true; product names not limited; stored products not validated; words not limited. Two survived at first (a multi-word vendor with one matching word, and an unknown vendor with a known product); tests were added and all thirteen are now caught.

Finding CP13-01
- Title: Text cut at a length limit could end in a space, so the stored advisory index failed its own check
- Severity: Low (a refused update, never bad data: the read-back check kept the previous copy, but the feature would not have updated against the live data)
- Location: icsadvisories._clean, used for titles (200 characters), vendor names (80) and product names (120)
- Found by: running the new code against the real CISA data before opening the pull request. The synthetic test advisories never had a name cut at exactly a space.
- Cause: the text was cleaned and then cut at the limit, and a cut inside a gap left a trailing space; the stored-index check requires text to equal its own cleaned form, so the index was refused with "bad products".
- Status: fixed. The cut is now trimmed (`[:limit].rstrip()`), and a regression test builds a title, a vendor and a product whose cut falls on a space, then reads the stored index back.

Release gate for this feature
| Gate | Evidence | Pass |
| --- | --- | --- |
| No change to bucket logic, scores or the inventory's scoring fields | tests with and without vendor and product columns | Yes |
| The result is worded as a pointer, not proof | wording tests; the three "nothing found" messages | Yes |
| Hostile names and large inputs are bounded | token, cache and size limits, each with a test and a mutation check | Yes |
| Works on the real data | live update and real matches; CP13-01 found and fixed | Yes |
| Static analysis clean | bandit, semgrep, ruff 0 findings; gitleaks clean | Yes |
| Documentation updated | docs/INVENTORY.md, docs/THREAT_DATA.md, README.md, CHANGELOG.md | Yes |
