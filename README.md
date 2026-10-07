# Vulnerability Prioritizer

Rule-based Now / Next / Never triage for vulnerabilities, with a Tkinter GUI and CSV batch mode.
Pure standard library: no third-party dependencies, and no network access.

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

1. **Base bucket from threat**
   - Active exploitation: NOW if reachable or the asset is a crown jewel, otherwise NEXT.
   - Public exploit: NOW if exposure is high and CVSS >= 7.0, otherwise NEXT.
   - No known exploitation: NOW if CVSS >= 9.0 on a high-exposure crown jewel; NEXT if CVSS >= 7.0 and the item is reachable or not a standard asset; otherwise NEVER.
2. **Partial controls** reduce the CVSS used for the threshold checks above by 1.05 points (35% of the 3-point span from 7.0 to 10.0). The fractional credit only changes the outcome near a threshold, since buckets are discrete.
3. **Low severity cap**: an item whose (credit-adjusted) CVSS is below 4.0 is capped at NEXT.
4. **Patch available**: strong controls lower the bucket one level, but never below NEXT for actively exploited items.
5. **No patch (pending or end of life)**: with raw CVSS of 4.0 or more, the bucket is raised one level unless strong controls are in place. Strong controls withhold the raise but earn no additional downgrade. End-of-life items with raw CVSS of 7.0 or more are floored at NEXT, since they need a replacement plan.

The **ordering score** (0 to 10) only ranks items within a bucket; it never decides the bucket.

## Batch CSV

Required columns: `cvss`, `threat`, `asset`, `exposure`.
Optional columns: `id`, `name`, `patch` (default available), `controls` (default none).
Other columns are ignored. Header names accept common aliases, and enum cells accept short aliases or the full dropdown labels.

Import limits: 25 MB and 50,000 data rows. Files with duplicate columns are rejected. Exported CSVs prefix text cells that start with `=`, `+`, `-`, `@`, tab or carriage return with `'` so spreadsheets do not run them as formulas.

## Security testing

Checkpoint reports are in `reports/`, and the SBOM is in `sbom/`.
