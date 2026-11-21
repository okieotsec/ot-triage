# Contributing to OT Triage

Thank you for looking. OT Triage is a small, free, open-source project run by one maintainer on a best-effort basis, so
please be patient: issues are usually answered within a week or two.

**Code contributions (pull requests) are not being accepted at this time.** Bug reports, questions, ideas and review findings
are welcome as issues; see below.

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

## Code contributions

Pull requests from outside contributors are not being accepted for now. This is a small project whose one maintainer reads and
decides every change, and the terms for accepting outside code have not been settled. A pull request may be closed without
review; that is not a judgement of the change. If you have a fix in mind, describe it in an issue: the problem, where the code
goes wrong and what you would change. This page will say so before any outside code is accepted.

If you read the code and find a problem, an issue is welcome. A security problem goes through the private
**Report a vulnerability** button instead (see [SECURITY.md](SECURITY.md)).

## How changes are made in this project

These are the standards every change meets, whether the maintainer or an AI assistant working to the maintainer's direction
wrote it. The maintainer reviews each one before it is accepted.

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
- **Small and focused.** One change at a time is much easier to review.

## Security checks

`python3 tools/security_checks.py reports/<name>` runs the scanners the project uses (ruff, bandit, semgrep, gitleaks and
others), compares every suppression comment with a reviewed baseline, and writes the results. Changes that touch how the
application reads files or the network should say in the pull request how they were checked; the test plan is
[SECURITY_TEST_PLAN.md](SECURITY_TEST_PLAN.md).

## Licence

OT Triage is licensed under the GNU Affero General Public License v3.0 only (see [LICENSE](LICENSE) and
[COPYRIGHT](COPYRIGHT)). The OkieOTSec name and logo are not part of that licence. Because code contributions are not being
accepted, no contributor licence terms apply for now.
