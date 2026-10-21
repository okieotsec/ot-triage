# Contributing to OT Triage

Thank you for looking. OT Triage is a small, free, open-source project run by one maintainer on a best-effort basis, so
please be patient: issues and pull requests are usually answered within a week or two.

## Reporting a bug

Open an [issue](https://github.com/okieotsec/ot-triage/issues/new/choose) and pick **Bug report**. Say which version you
use (shown in the About view, or `python3 ot_triage_cli.py --version`), your operating system and Python version, what you did,
what you expected and what happened. A small input file that shows the problem helps most.

**Use synthetic data only.** Never attach real asset names, addresses, scanner exports, findings or credentials to an issue
or a pull request. If you need to show a shape, invent the data (the addresses 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24
and the name `example.com` are reserved for exactly this).

**Vulnerabilities are not reported in public issues.** Use GitHub's **Report a vulnerability** button on the Security tab,
as described in [SECURITY.md](SECURITY.md).

## Suggesting a change

Open an issue and pick **Feature request**. If your idea changes how an item is prioritized (a bucket, a score or a
rule), say so: the rules are the product, and a rule change is decided by the maintainer, written down in
[docs/POLICY.md](docs/POLICY.md) with its reason, and covered by tests before it is merged. A change to the ranking that is
not in the policy will not be accepted, however small.

## Sending a pull request

1. Fork the repository and make a branch from `main`.
2. Make the change, with the tests and documents below.
3. Open a pull request against `main` and fill in the checklist. A pull request is merged only after the checks have passed and
   the maintainer has reviewed it; changes are squash-merged.

### What a pull request needs

- **Tests.** Every new feature and every bug fix comes with a test that fails without the change. This is the project's test
  policy, and the reports in `reports/` show it being followed. The tests use the standard library's `unittest`: run
  `python3 tools/headless_tests.py` for everything (the window tests run on a private virtual display, so nothing opens on your
  screen), or `python3 -m unittest test_prioritizer` for one module. Do not run the window tests directly on your desktop.
- **No new runtime dependencies.** The application uses only the Python standard library, on purpose. Development tools
  (ruff, bandit, semgrep, hypothesis) are used for checking only and are pinned in `requirements-dev.txt`.
- **A clean linter.** `ruff check .` must pass with the rules in `ruff.toml`. Do not add a suppression comment (`noqa`,
  `nosec`, `nosemgrep`) without a reason written next to it; the security runner lists every suppression for review.
- **Documents.** Update the README or the page in `docs/` that describes what you changed, and add a line to the
  `Unreleased` section of `CHANGELOG.md`. A change a user can see needs a sentence a user can read.
- **The browser demo.** If you change a rule in `prioritizer.py`, change `demo/rules.js` to match and regenerate the golden file
  with `python3 tools/make_demo_golden.py`; the tests compare the two and fail if they differ (see
  [demo/README.md](demo/README.md)).
- **No personal or real data.** No real host names, addresses, people, scanner output or credentials in code, samples, tests,
  reports or commit messages.
- **Small and focused.** One change per pull request is much easier to review.

## Security checks

`python3 tools/security_checks.py reports/<name>` runs the scanners the project uses (ruff, bandit, semgrep, gitleaks and
others), compares every suppression comment with a reviewed baseline, and writes the results. Changes that touch how the
application reads files or the network should say in the pull request how they were checked; the test plan is
[SECURITY_TEST_PLAN.md](SECURITY_TEST_PLAN.md).

## Licence

By contributing you agree that your contribution is released under the project's [MIT licence](LICENSE). The OkieOTSec name
and logo are not part of that licence.
