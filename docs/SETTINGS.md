# Scoring settings

Only four values can be changed. Everything else (the rule structure, the 4.0 low-severity line, the ordering-score weights, and the partial-controls credit) is fixed on purpose. See [ROADMAP.md](ROADMAP.md) for why the list is short.

## The settings

| Setting | Default | Allowed range | What it does |
| --- | --- | --- | --- |
| `cvss_high` | 7.0 | 5.0 to 8.0 | CVSS score where a vulnerability counts as "High". Used by the public-exploit rule, the no-exploit rule and the end-of-life floor. |
| `cvss_critical` | 9.0 | 8.0 to 10.0 | CVSS score where a vulnerability counts as "Critical". Used by the exposed crown jewel rule for items with no known exploitation. |
| `epss_percentile_cutoff` | 0.95 | 0.5 to 0.999 | EPSS percentile above which exploitation is treated as likely. Used once threat data is added. |
| `stale_days` | 7 | 1 to 90 (whole days) | Days before downloaded threat data is flagged as stale. Used once threat data is added. |

`cvss_critical` must be at least 0.5 above `cvss_high`.

## Why these defaults

- **7.0 and 9.0:** these are the CVSS standard's own boundaries for High and Critical. Staying on them means the tool's idea of "high" matches the scores people already see in advisories.
- **Why the ranges stop where they do:** below 5.0, "High" would start to include Medium scores. Above 8.0, most High scores would no longer count. The Critical line stays between 8.0 and 10.0 for the same reason.
- **0.95 (EPSS):** the top 5% of EPSS scores. EPSS scores are mostly very low, so a high percentile keeps the "likely exploited" label meaningful. This default was accepted by the project lead on 2026-10-07. Revisit it after using real data.
- **7 days (stale):** the KEV catalog and EPSS scores change often, so a week-old copy is a reasonable limit for a warning. It is only a warning; the tool keeps working.

## What is deliberately not adjustable

| Fixed value | Why |
| --- | --- |
| The 4.0 low-severity line | It is the CVSS standard's boundary for "Medium", and several rules depend on it. |
| Ordering-score weights | They only rank items inside a bucket, so changing them cannot change a decision, only the order. |
| Controls credit (0.5 partial, 1.0 strong) | Same reason: it only affects ranking. See [POLICY.md](POLICY.md). |
| The rule structure | Settings change numbers, not logic. Active exploitation, exposure and strong controls always work the same way. |

## Where settings are stored

A JSON file in your user config folder:

| System | Location |
| --- | --- |
| Linux | `$XDG_CONFIG_HOME/vuln-prioritizer/settings.json` (usually `~/.config/vuln-prioritizer/settings.json`) |
| macOS | `~/Library/Application Support/vuln-prioritizer/settings.json` |
| Windows | `%APPDATA%\vuln-prioritizer\settings.json` |

The file is created with user-only permissions, and writes are atomic: a new file is written and checked, then swapped in, so a failed save keeps the previous file.

Example:

```json
{
  "version": 1,
  "cvss_high": 7.5,
  "cvss_critical": 9.0,
  "epss_percentile_cutoff": 0.95,
  "stale_days": 7
}
```

## What happens with a bad file

- **No file:** defaults are used, with no message.
- **Anything wrong with the file** (unreadable, too large, not valid JSON, wrong types, `true`/`false` instead of numbers, `NaN`, duplicate or unknown keys, values out of range, or lines too close together): the tool ignores the whole file, uses the defaults, and shows a warning that names the problem. It never crashes and never uses a partly valid file.
- The file is limited to 16 KB.

## Staying visible and reproducible

- When any value differs from the defaults, the main window shows a **Custom scoring** badge.
- Copied summaries, the batch detail pane and the batch CSV export (`scoring_settings` column) list the settings in effect, so a result can be reproduced.
- The rule explanations show the active lines. For example, a custom `cvss_high` of 7.5 shows "CVSS >= 7.5".

## Resetting

Use **Restore defaults…** on the Settings view (it asks for confirmation), delete the settings file, or call `settings.restore_defaults()`.

## Editing in the GUI

The Settings view shows each value with its description, default and allowed range. Values are checked as you type: a problem is shown next to the field in words and **Save** stays disabled until every value is valid. Appearance choices (theme, text size, update on start) are saved in a separate `ui.json` file next to `settings.json`.
