# Threat data (CISA KEV and EPSS)

The tool can look up a CVE in two public data sets and use what it finds as the **threat** input. It works fully offline. Internet access is needed only when you choose to update the data.

Decisions confirmed by the project lead on 2026-10-07: the EPSS cutoff defaults to 0.95, the comparison is "at or above", and data is stored in the per-user data folder.

## The two sources

| Source | What it tells you | Where it comes from |
| --- | --- | --- |
| **CISA KEV** (Known Exploited Vulnerabilities) | The CVE is being exploited in real attacks right now. | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |
| **EPSS** (Exploit Prediction Scoring System) | How likely the CVE is to see exploitation activity soon, as a probability and a percentile. | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` |

## How the threat level is decided

The first matching line wins.

1. The CVE is in **KEV**: threat is **Active exploitation**.
2. An analyst confirmed exploitation (manual input): **Active exploitation**.
3. A public exploit is known (manual input), **or** the EPSS percentile is at or above the cutoff (default 0.95): **Public exploit** level.
4. Otherwise: **No known exploitation**.

Rules that always hold:

- **Missing data never lowers the level.** Not being in KEV, a low EPSS score, or a data set that is not loaded at all is never treated as proof the CVE is safe. The explanation says when a data set was not loaded.
- **A manual input can only raise the level.** Batch CSV values in the `threat` column are treated this way. A deliberate downgrade needs a written reason, which is recorded in the explanation.
- **EPSS is not proof of a public exploit.** EPSS estimates likelihood of exploitation activity. When EPSS raises the level, the explanation says "Elevated EPSS (percentile ...)" instead of claiming an exploit exists. The rules treat that level the same way as a public exploit.
- The cutoff is **at or above** (so a percentile of exactly 0.95 counts). It can be changed; see [SETTINGS.md](SETTINGS.md).

KEV also adds context that never changes the bucket:

- **Required action:** CISA's required action is added to the recommended action.
- **Due date:** shown as context only.
- **Known ransomware campaign use:** ranks the item higher inside its bucket (the ordering score goes up by 0.5, to a maximum of 10).

## Updating

Nothing is downloaded unless you start an update. Two ways to update:

- **Download:** fetches both files over HTTPS.
- **Import from file:** for networks with no internet. Download the two files elsewhere, move them over, and import them. They go through exactly the same checks as a download.

Each source is handled on its own: if one fails, the other can still update, and the failed one **keeps its previous copy**. Data is checked in memory first and only written to disk if it passes.

## What is checked

| Check | KEV | EPSS |
| --- | --- | --- |
| Size limit | 25 MB | 50 MB download, 100 MB after decompression |
| Row or entry limit | 100,000 entries | 2,000,000 rows |
| Structure | Catalog version, release date, entry list, and `count` matching the entries (catches truncated files) | `#model_version:...,score_date:...` first line, then the header `cve,epss,percentile` |
| Each record | Valid CVE ID, valid dates, known ransomware field is `Known` or `Unknown`, text fields under 10,000 characters | Valid CVE ID, numbers between 0 and 1 |
| Duplicates | Rejected | Rejected |
| Odd content | Control characters in text are replaced with spaces; unknown extra fields are ignored | Not a number (`nan`, `inf`) is rejected |

Stored files are checked again every time they are loaded, so a file changed on disk cannot slip through.

## Download safety

- HTTPS only, and only to the two expected hosts. TLS certificates are always verified, and nothing in the app or its settings can turn that off.
- Redirects are allowed only to HTTPS on the same expected host, and at most 3. (The EPSS "current" address does redirect to a dated file on the same host.)
- Time limits: 20 seconds to connect or wait for data, and 2 minutes overall. A server that sends data very slowly is cut off at the overall limit.
- Size limits are enforced while downloading, not only at the end.
- The app's own proxy settings follow your system settings (`HTTPS_PROXY` and similar).

## Troubleshooting: "unable to get local issuer certificate" on Windows

On a fresh Windows install the EPSS download can fail with this message while the KEV download works. The EPSS server's certificate chain ends at Amazon's root certificate, cross-signed by *Starfield Services Root Certificate Authority - G2*. Windows installs some trusted roots only when first needed, and Python can only use roots that are actually in the machine's trusted store. Opening the address in a browser does **not** fix it, and certificate checking is never turned off.

This was reproduced and fixed on a new Windows 11 virtual machine. In an **Administrator** PowerShell:

```
Invoke-WebRequest https://www.amazontrust.com/repository/SFSRootCAG2.cer -OutFile $env:TEMP\SFSRootCAG2.cer
(Get-FileHash $env:TEMP\SFSRootCAG2.cer -Algorithm SHA256).Hash
```

The hash must be exactly `568D6905A2C88708A4B3025190EDCFEDB1974A606A13C6E5290FCB2AE63EDAB5`. If it is not, do not install the file. If it matches:

```
Import-Certificate -FilePath $env:TEMP\SFSRootCAG2.cer -CertStoreLocation Cert:\LocalMachine\Root
```

Then restart the app and update again. If it still fails, repeat with `AmazonRootCA1.cer` (SHA-256 `8ECDE6884F3D87B1125BA31AC3FCB13D7016DE7F57CC904FE1CB97C6AE98196E`). Both certificates are Amazon Trust's published root certificates (https://www.amazontrust.com/repository/). Importing them needs administrator rights; an ordinary Windows PC that has been used and updated normally usually already has them.

## Where the data is stored

| System | Location |
| --- | --- |
| Linux | `$XDG_DATA_HOME/vuln-prioritizer/data/` (usually `~/.local/share/vuln-prioritizer/data/`) |
| macOS | `~/Library/Application Support/vuln-prioritizer/data/` |
| Windows | `%LOCALAPPDATA%\vuln-prioritizer\data\` |

Files: `kev.json`, `epss.csv.gz` and `meta.json` (where and when each was retrieved, plus a checksum). Files are written with user-only permissions, using a temporary file that replaces the old copy only once the new one is complete.

## Freshness

The tool can report how old each source is and flag it as **stale** after the configured number of days (default 7). A stale warning never blocks anything.

## Batch CSV: the `cve` column

Add an optional `cve` column. Then:

- With data loaded, the `threat` cell can be left blank and the level comes from KEV and EPSS.
- A `threat` value can still be given. It can raise the level but never lower what the data says.
- With no data loaded and a blank `threat` cell, the row is reported as an error that says so. It is **not** scored as "no known exploitation".
- The export adds `cve`, `threat_source` (why the level was chosen) and `threat_data` (the KEV and EPSS versions used) columns, so results can be reproduced.

## In the GUI

- The **Threat data** view shows each source's version, dates, entry count and freshness, with **Update threat data** and **Import from files…** buttons. The first update shows exactly which two hosts will be contacted and asks for confirmation. Updates run in the background with a Cancel button.
- The **Assess** view has a CVE field. Press Enter or **Look up** to check the local data. The threat level is filled in with its source shown. Two checkboxes can only raise it, and changing it by hand asks for a written reason that appears in every summary.
- The **status bar** shows freshness at all times.
- **Settings** has an optional "Update threat data when the app starts" checkbox, off by default.

The same functions can be used from Python:

```python
import threatdata
print(threatdata.update_from_network())                       # download
print(threatdata.import_from_files("kev.json", "epss.csv.gz"))  # offline import
```
