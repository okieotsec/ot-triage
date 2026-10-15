# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.9.x | Yes (the current release and its fixes) |
| Older | No |

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**, not in a public issue.

- Use GitHub's **Report a vulnerability** button on the repository's **Security** tab (private vulnerability reporting).
- Include the version (shown in the About view), what you did, what you expected, and what happened. A sample input file that triggers the problem is the most useful thing you can send. Use synthetic data only; never send real vulnerability inventories.

This is a small project maintained by one person on a best-effort basis. These are targets, not guarantees:

| Step | Target |
| --- | --- |
| Acknowledge your report | within 7 days |
| Confirm it by reproducing it, and tell you whether it is accepted | within 14 days |
| Fix a Critical or High issue in the supported version | within 30 days of confirmation |
| Fix a Medium issue | within 90 days of confirmation |
| Lower-severity issues | in a later release, or documented as accepted with the reason |

Severity follows the rubric in [SECURITY_TEST_PLAN.md](SECURITY_TEST_PLAN.md) section 7, and section 8 describes how findings are triaged: a finding is fixed or accepted only after it has been reproduced. When a fix is released, the report is published as a GitHub security advisory and you are credited if you wish. There is no bug bounty.

## What the application connects to

The application works **fully offline**. It connects to the internet only when you ask it to update threat data (or if you have turned on the optional "Update threat data when the app starts" setting, which is off by default):

| Purpose | Address | Notes |
| --- | --- | --- |
| CISA Known Exploited Vulnerabilities catalog | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | Public file |
| EPSS scores | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` | Public file; redirects to a dated file on the same host |
| CISA ICS advisories (CSAF) | `https://codeload.github.com/cisagov/CSAF/tar.gz/refs/heads/develop` | Public archive of CISA's advisory repository (about 12 MB); only the OT advisory files are read, and nothing is unpacked to disk |

- Those three hosts are the only ones the application will contact. Anything else, including redirects elsewhere, is refused.
- HTTPS only, with certificate and host name verification that cannot be turned off from the interface or the settings.
- No account, no telemetry, no analytics, no usage data, and no data about your vulnerabilities, assets or settings is ever sent. Only the three download requests above are made.
- System proxy settings (`HTTPS_PROXY`) are honoured.
- **Links from CISA's notes:** the Assess view lists the reference links CISA includes with a KEV entry. The application never fetches them. A link opens in your own web browser only when you click it (or press Enter on it), and the domain is always shown next to it. Because the notes come from a downloaded file they are treated as untrusted: only plain `https` links to an ordinary host name are clickable (no `http`, `javascript:`, `file:`, addresses with a user name or unusual port, IP addresses or look-alike characters). Anything else is shown as plain text and is never opened.
- Downloads are limited in size and time, checked for structure (types, sizes, counts and dates) before use, and replace the stored copy only on success. A failed update keeps the previous data. They are trusted only as far as HTTPS to the named hosts: the files are not signed, so a file that is well-formed but incomplete, or older than the stored copy, would be accepted (see Known limitations).
- **Advisory links:** the ICS advisory links in the Assess and Batch views are built from the validated advisory number and always point to `www.cisa.gov`; nothing in the downloaded file can change where one goes. They open in your own browser only when you click. The vendor's remediation steps shown under an advisory are the one place where a downloaded file supplies a link: it is kept only if it is a plain `https` address with an ordinary host name (no user name, no numeric host, no port other than 443, no white space), it is shown with its real host name, and it opens only when you click it, in your browser. The text is shown as plain text and escaped in the Markdown summary.
- For networks with no internet access, download the files elsewhere and use **Import from files**; they get the same checks.

## What the application reads and writes

- **Scanner exports:** `ot_triage_import.py` reads the Nessus, Tenable and OpenVAS exports you give it. They are untrusted: size, row and cell limits, a header that must be recognised by column name, cleaned and cut text, formula-safe output, and no overwriting of any input. It never uses the network and never scores (see [docs/IMPORT.md](docs/IMPORT.md)).
- **Files you choose:** the CSV you open, an optional asset inventory CSV, and the export you save. The inventory is size-limited and validated like the findings file, and its path is not remembered. Cells that could run as spreadsheet formulas are neutralised on export.
- **Settings:** `settings.json` and `ui.json` in your user configuration folder; threat data and its metadata in your user data folder (see [docs/THREAT_DATA.md](docs/THREAT_DATA.md) and [docs/SETTINGS.md](docs/SETTINGS.md) for the locations). They are written atomically with user-only permissions, size-limited, and ignored (with a warning) if invalid.
- **Clipboard:** only when you press a copy button.
- **Text boxes** refuse typed or pasted text beyond 2,000 characters, so a hostile or accidental huge paste cannot freeze the window.

## What is not in scope

- The security of CISA's and Empirical Security's servers themselves.
- Your operating system and Python installation.
- Protection against a user who already has full control of your account: the settings and threat-data files are trusted to the extent that they are owned by you, although they are validated every time they are read.
- Multi-user or networked use: this is a single-user desktop tool, not a service.

## Known limitations

- Tkinter has weak screen reader support, so accessibility relies on keyboard use and contrast, not on assistive technology.
- CVSS 2 vectors are not supported, and only base scores are calculated (see [docs/CVSS.md](docs/CVSS.md)).
- The CISA ICS advisories archive is trusted on HTTPS to GitHub only. CISA signs each advisory file with PGP, but the archive as a whole is not signed and the Python standard library cannot check PGP signatures, so the tool treats the content as untrusted and validates it (see [docs/THREAT_DATA.md](docs/THREAT_DATA.md)).

## Verifying a download

Each release has three attached files: the bundle (`ot-triage-<version>.zip`), its SHA-256 checksum and the SBOM.

- **Checksum:** `sha256sum -c ot-triage-<version>.zip.sha256` (on Windows: `certutil -hashfile ot-triage-<version>.zip SHA256`). This shows the file was not damaged in transit.
- **Provenance (releases made after the release workflow was added):** `gh attestation verify ot-triage-<version>.zip --repo okieotsec/ot-triage`. This shows the file was built from the repository's tag by its release workflow on GitHub's runners, using a signed attestation. Earlier releases have the checksum only.
- **Rebuild it yourself:** check out the tag and run `python3 tools/make_bundle.py` ([docs/RELEASING.md](docs/RELEASING.md)). The build fixes file order, dates and permissions, and for 0.9.0 the bundle built on GitHub's runner and one built on a developer's Linux machine had the same checksum; zip compression can differ between Python versions, so a very different environment may give different bytes.

## How the application is tested

Security testing follows [SECURITY_TEST_PLAN.md](SECURITY_TEST_PLAN.md) and is archived under [reports/](reports/): static analysis (bandit, semgrep, ruff, CodeQL), secret scanning (gitleaks), a review of every in-source suppression, an audit of the build workflows (zizmor), a software bill of materials ([sbom/sbom.cdx.json](sbom/sbom.cdx.json)), hostile-input and fuzz tests, and tests against a local TLS server. The same checks run in continuous integration and again every week. The application uses only the Python standard library, so it has no third-party runtime dependencies to scan.

The practices are mapped to the NIST Secure Software Development Framework and MITRE's Security Automation Framework in [docs/SECURITY_FRAMEWORKS.md](docs/SECURITY_FRAMEWORKS.md), including what is not yet done. That page is the developer's own assessment, not an audit or a certification. One independent review by an AI (OpenAI Codex, on release 0.9.0, 2026-10-14) has been run, archived unchanged in [reports/independent-review-codex/](reports/independent-review-codex/) and answered finding by finding in [reports/cp23-independent-review-fixes/](reports/cp23-independent-review-fixes/claude.md). It is not a human security audit, and none has been done yet.
