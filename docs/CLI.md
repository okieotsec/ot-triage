# Command line

`ot_triage_cli.py` ranks a findings file without opening a window, with the same rules, scoring settings and threat data as the application. It is for scripts, scheduled jobs and quick checks.

```
python3 ot_triage_cli.py findings.csv -o ranked.csv
python3 ot_triage_cli.py findings.csv --inventory assets.csv --compare last_week.csv --assets by_asset.csv
python3 ot_triage_cli.py findings.csv --fail-on NOW        # exit code 3 if anything is NOW
python3 ot_triage_cli.py --update                          # download the threat data
```

| Option | What it does |
| --- | --- |
| `findings` | The findings CSV (see the README for its columns). |
| `-o`, `--output CSV` | Save the ranked results, the same file as **Export ranked CSV** in the application. |
| `-a`, `--assets CSV` | Save the per-asset roll-up (see [INVENTORY.md](INVENTORY.md)). |
| `-i`, `--inventory CSV` | An asset inventory that fills in asset, exposure and controls from an `asset_id` column. |
| `-c`, `--compare CSV` | A previous ranked export to compare with; the output gains `change` and `previous_priority` columns and the summary lists what was resolved. |
| `--settings JSON` | A scoring settings file. By default your saved settings are used, as in the application. |
| `--data-dir DIR` | The threat data folder. By default the per-user data folder the application uses. |
| `--update` | Download CISA KEV, EPSS and the CISA ICS advisories first. This is the only thing that uses the network. With no findings file it just updates. |
| `--top N` | Print the N top findings (default 10; 0 prints none). |
| `--fail-on NOW` or `NEXT` | Exit with code 3 if any finding is in that bucket or a more urgent one. |
| `--force` | Replace output files that already exist. |
| `-q`, `--quiet` | Print only errors. |
| `--version` | Print the version. |

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Done. |
| 1 | A file could not be used (the message says which and why), or `--update` alone failed. |
| 2 | Wrong arguments. |
| 3 | `--fail-on` found a finding at or above the chosen bucket. |

## Safety

- **Nothing is downloaded unless you give `--update`.** A file with a `cve` column is looked up in the stored data only; with no data stored, those rows are reported as not scored, never as safe.
- **Output files are never replaced silently.** An existing file is left alone unless you give `--force`, and an input file (the findings, the inventory, the previous export) is never overwritten, even with `--force`. Results are written to a temporary file and moved into place, so a failure leaves no half-written file and does not damage an older one.
- **Text from your files is cleaned before it is printed**, so a hostile finding name cannot send commands to your terminal (control and direction characters are removed, and long text is cut).
- **Exports are formula-safe**, like the application's.
- A scheduled job example (weekly, keeping each run to compare with the next):

```
python3 ot_triage_cli.py --update
python3 ot_triage_cli.py findings.csv -i assets.csv -c ranked_last.csv -o ranked_new.csv --force --fail-on NOW
cp ranked_new.csv ranked_last.csv
```
