## What this changes and why

## Checklist

- [ ] There is a test that fails without this change (new features and bug fixes need one).
- [ ] `python3 tools/headless_tests.py` passes and `ruff check .` is clean.
- [ ] No new runtime dependency, and no suppression comment without a reason.
- [ ] The README or the page in `docs/` and the `Unreleased` section of `CHANGELOG.md` are updated.
- [ ] If a rule in `prioritizer.py` changed: `demo/rules.js` and `demo/golden.json` are updated, and `docs/POLICY.md` records the decision.
- [ ] No real host names, addresses, scanner output or credentials anywhere (synthetic data only).
