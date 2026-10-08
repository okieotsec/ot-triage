# Vulnerability Prioritizer

Rule-based Now / Next / Never triage for vulnerabilities, with a Tkinter GUI and CSV batch mode.
Pure standard library: no third-party dependencies. It works fully offline; the only network access is a threat-data update that you start yourself.

## Run

```
python3 vuln_prioritizer_gui.py     # GUI
python3 -m unittest                 # tests
```

## Inputs

| Input | Values |
| --- | --- |
| CVSS base score | 0.0 to 10.0 |
| Threat | Active exploitation in the wild, public exploit available, no known exploitation |
| Asset | Crown jewel, important, standard |
| Exposure | High (internet connected), medium, low |
| Patch | Available, pending (vendor supported), none ever (end of life) |
| Controls | None, partial, strong |

"Reachable" below means exposure is high or medium.

## Rules as implemented

For the reasoning behind each rule, see [docs/POLICY.md](docs/POLICY.md).

1. **Base bucket from threat**
   - Active exploitation: NOW if reachable or the asset is a crown jewel, otherwise NEXT.
   - Public exploit: NOW if exposure is high and CVSS >= 7.0, otherwise NEXT.
   - No known exploitation: NOW if CVSS >= 9.0 on a high-exposure crown jewel; NEXT if CVSS >= 7.0 and the item is reachable or not a standard asset; otherwise NEVER.
2. **Low severity cap**: an item with CVSS below 4.0 is capped at NEXT, except an actively exploited, high-exposure crown jewel, which stays at NOW.
3. **Patch available**: strong controls lower the bucket one level, but never below NEXT for actively exploited items.
4. **No patch (pending or end of life)**: with CVSS of 4.0 or more, the bucket is raised one level unless strong controls are in place. Strong controls withhold the raise but earn no additional downgrade. End-of-life items with CVSS of 7.0 or more are floored at NEXT, since they need a replacement plan.
5. **Exposed crown jewel floor**: a crown jewel with high exposure and CVSS of 4.0 or more is never below NEXT.
6. **Partial controls** never change the bucket. They lower the ordering score by 0.5.

The **ordering score** (0 to 10) only ranks items within a bucket; it never decides the bucket.

Two CVSS lines in these rules (7.0 and 9.0) can be adjusted within limits; see [docs/SETTINGS.md](docs/SETTINGS.md). Values shown above are the defaults.

**Low exposure** means no routable path from IT or the internet, verified by testing, not assumed from a firewall's existence.

## Batch CSV

Required columns: `cvss`, `asset`, `exposure`, and `threat` (or `cve`).
Optional columns: `id`, `name`, `patch` (default available), `controls` (default none).
An optional `cve` column looks the CVE up in local KEV and EPSS data (see [docs/THREAT_DATA.md](docs/THREAT_DATA.md)); with it, `threat` can be left blank.
Other columns are ignored. Header names accept common aliases, and enum cells accept short aliases or the full dropdown labels.

Import limits: 25 MB and 50,000 data rows. Files with duplicate columns are rejected. Exported CSVs prefix text cells that start with `=`, `+`, `-`, `@`, tab or carriage return with `'` so spreadsheets do not run them as formulas.

## Documentation

- [docs/POLICY.md](docs/POLICY.md): the prioritization decisions and why
- [docs/THREAT_DATA.md](docs/THREAT_DATA.md): KEV and EPSS threat data, offline updates and safety checks
- [docs/SETTINGS.md](docs/SETTINGS.md): adjustable settings, defaults, limits and file handling
- [docs/GUI_PROPOSAL.md](docs/GUI_PROPOSAL.md): proposed GUI refresh (open [docs/gui-mockup.html](docs/gui-mockup.html) in a browser)
- [docs/ROADMAP.md](docs/ROADMAP.md): planned work, order and design decisions

## Security testing

The test approach is defined in [SECURITY_TEST_PLAN.md](SECURITY_TEST_PLAN.md). Checkpoint reports are in `reports/`, and the SBOM is in `sbom/`.
