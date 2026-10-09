# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.4.x | Yes (current release candidate and its fixes) |
| Older | No |

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**, not in a public issue.

- Use GitHub's **Report a vulnerability** button on the repository's **Security** tab (private vulnerability reporting).
- Include the version (shown in the About view), what you did, what you expected, and what happened. A sample input file that triggers the problem is the most useful thing you can send. Use synthetic data only; never send real vulnerability inventories.

This is a small project maintained on a best-effort basis. Reports are read as soon as practical, confirmed by reproducing them, and fixed in the supported version. See [SECURITY_TEST_PLAN.md](SECURITY_TEST_PLAN.md) section 8 for how findings are triaged.

## What the application connects to

The application works **fully offline**. It connects to the internet only when you ask it to update threat data (or if you have turned on the optional "Update threat data when the app starts" setting, which is off by default):

| Purpose | Address | Notes |
| --- | --- | --- |
| CISA Known Exploited Vulnerabilities catalog | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | Public file |
| EPSS scores | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` | Public file; redirects to a dated file on the same host |

- Those two hosts are the only ones the application will contact. Anything else, including redirects elsewhere, is refused.
- HTTPS only, with certificate and host name verification that cannot be turned off from the interface or the settings.
- No account, no telemetry, no analytics, no usage data, and no data about your vulnerabilities, assets or settings is ever sent. Only the two download requests above are made.
- System proxy settings (`HTTPS_PROXY`) are honoured.
- **Links from CISA's notes:** the Assess view lists the reference links CISA includes with a KEV entry. The application never fetches them. A link opens in your own web browser only when you click it (or press Enter on it), and the domain is always shown next to it. Because the notes come from a downloaded file they are treated as untrusted: only plain `https` links to an ordinary host name are clickable (no `http`, `javascript:`, `file:`, addresses with a user name or unusual port, IP addresses or look-alike characters). Anything else is shown as plain text and is never opened.
- Downloads are limited in size and time, validated completely before use, and replace the stored copy only on success. A failed update keeps the previous data.
- For networks with no internet access, download the two files elsewhere and use **Import from files**; they get the same checks.

## What the application reads and writes

- **Files you choose:** the CSV you open and the export you save. Cells that could run as spreadsheet formulas are neutralised on export.
- **Settings:** `settings.json` and `ui.json` in your user configuration folder; threat data and its metadata in your user data folder (see [docs/THREAT_DATA.md](docs/THREAT_DATA.md) and [docs/SETTINGS.md](docs/SETTINGS.md) for the locations). They are written atomically with user-only permissions, size-limited, and ignored (with a warning) if invalid.
- **Clipboard:** only when you press a copy button.

## What is not in scope

- The security of CISA's and Empirical Security's servers themselves.
- Your operating system and Python installation.
- Protection against a user who already has full control of your account: the settings and threat-data files are trusted to the extent that they are owned by you, although they are validated every time they are read.
- Multi-user or networked use: this is a single-user desktop tool, not a service.

## Known limitations

- Tkinter has weak screen reader support, so accessibility relies on keyboard use and contrast, not on assistive technology.
- CVSS 2 vectors are not supported, and only base scores are calculated (see [docs/CVSS.md](docs/CVSS.md)).

## How the application is tested

Security testing follows [SECURITY_TEST_PLAN.md](SECURITY_TEST_PLAN.md) and is archived under [reports/](reports/): static analysis (bandit, semgrep, ruff), secret scanning (gitleaks), dependency scanning (pip-audit, osv-scanner), a software bill of materials ([sbom/sbom.cdx.json](sbom/sbom.cdx.json)), hostile-input and fuzz tests, and tests against a local TLS server. The application uses only the Python standard library, so it has no third-party runtime dependencies.
