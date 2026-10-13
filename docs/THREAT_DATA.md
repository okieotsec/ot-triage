# Threat data (CISA KEV, EPSS and CISA ICS advisories)

The tool can look up a CVE in three public data sets. KEV and EPSS decide the **threat** input; the CISA ICS advisories are shown as context only and never change the threat level, the bucket or the ordering score. It works fully offline. Internet access is needed only when you choose to update the data.

Decisions confirmed by the project lead on 2026-10-07: the EPSS cutoff defaults to 0.95, the comparison is "at or above", and data is stored in the per-user data folder.

## The sources

| Source | What it tells you | Where it comes from |
| --- | --- | --- |
| **CISA KEV** (Known Exploited Vulnerabilities) | The CVE is being exploited in real attacks right now. | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |
| **EPSS** (Exploit Prediction Scoring System) | How likely the CVE is to see exploitation activity soon, as a probability and a percentile. | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` |
| **CISA ICS advisories** | Which published CISA advisory for industrial control systems (ICSA) or medical devices (ICSMA) names the CVE: the advisory number, its title, the vendor and when it was last updated. | `https://codeload.github.com/cisagov/CSAF/tar.gz/refs/heads/develop` (CISA's public CSAF repository, about 12 MB) |

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

- **Download:** fetches the three files over HTTPS.
- **Import from file:** for networks with no internet. Download the files elsewhere, move them over, and import them. They go through exactly the same checks as a download. For the ICS advisories the file is the `.tar.gz` you get by opening the address in the table above in a browser.

Each source is handled on its own: if one fails, the others can still update, and the failed one **keeps its previous copy**. Data is checked in memory first and only written to disk if it passes.

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

## ICS advisories

CISA publishes every ICS advisory as a machine-readable CSAF file in its public repository. The tool downloads the repository as one archive, reads only the OT advisory files inside it, and keeps a small index (advisory number, title, up to ten vendor names, up to 30 product names, the dates, and the CVEs each advisory names; about 2 MB for all 3,959 advisories). The advisory files themselves are not kept.

- **Where it shows:** after you look up a CVE, the Assess view shows an **ICS advisories from CISA** card under the KEV references, and a chip ("In a CISA ICS advisory", "In 3 CISA ICS advisories" or "Not in a CISA ICS advisory"). The newest five advisories are listed, with a note when more name the CVE. In Batch, the Details box lists them for the selected row.
- **Links:** the advisory number is a link to its page on cisa.gov. The address is built from the advisory number after it has been checked, never copied from the downloaded file, so a hostile file cannot point you somewhere else. Nothing is opened until you click.
- **Context only:** a line in the reasoning and a neutral chip say the CVE is named in an advisory. The bucket and the ordering score never change. "Not in a CISA ICS advisory" only means CISA has not published one that names this CVE, not that the CVE is harmless.
- **What the advisory says about a fix:** each advisory lists, for every CVE, whether the vendor has a fix, only a mitigation or workaround, or nothing. The tool reduces that to one status per advisory and CVE: *vendor fix available*, *vendor fix for some products, none for others*, *no fix available yet*, *no fix planned*, or *mitigation or workaround only*. The status is shown beside the advisory, as a chip, in the reasoning, in the Batch details and in the `ics_remediation` export column (the newest advisory's status). Under **Patch status** in Assess a note says what the newest advisory says and which choice would fit, but **Patch status is never set for you**: the advisory covers the vendor's products and versions, and only you know which one you run. Like the rest of the advisory data it never changes the bucket or the ordering score.
- **Assets, from the inventory:** if the asset inventory has `vendor` and `product` columns, the Batch view's By asset mode lists the advisories that may apply to each asset (see [INVENTORY.md](INVENTORY.md)). This is a pointer to read, matched on words, and it never changes a priority.
- **Not loaded:** if the advisories have not been downloaded, the chip says "ICS advisories not loaded" so an empty result is never mistaken for "no advisory".
- **Copy summary and Copy as Markdown** list the advisories with their addresses. The **CSV export** adds an `ics_advisories` column (each advisory as `number: address`, separated by ` ; `, with "and N more" if some are left out), and `threat_data` names the advisories' date.
- **Freshness:** CISA adds advisories continuously, so the status bar shows how old your copy is and flags it stale after the configured number of days, like the other sources.

What is checked in the archive:

| Check | Limit |
| --- | --- |
| Download size | 60 MB (about 12 MB today) |
| Bytes read out of the archive, whatever its entries claim | 600 MB (a "gzip bomb" is stopped while it is being read) |
| Entries in the archive | 100,000 |
| Advisories | 20,000 (3,959 today); each file up to 8 MB; a product tree up to 20,000 nodes and 12 levels deep; up to 2,000 CVEs per advisory |
| Which entries are read | only regular files named like `.../csaf_files/OT/white/<year>/icsa-YY-DDD-NN.json` (an optional revision letter is allowed); links, devices, other folders and odd names are ignored, and nothing is ever extracted to disk |
| Each advisory | valid JSON without duplicate keys or `NaN`; its own id must match its file name; a title; valid dates; CVE ids must match exactly |
| Unreadable advisories | one is skipped and counted; more than 10 (or 5% of them) means the format has probably changed and the whole update is refused |
| Stored index | checked again every time it is loaded, and checked to read back correctly before it replaces the old one |

## References from the KEV notes

CISA's required action often says "see URL in Notes". The notes field holds those links (advisories, vendor pages, the BOD 26-04 guidance) as a list separated by semicolons, sometimes with a label such as `BOD 26-04:`.

- After you look up a CVE that is in KEV (even before you have entered a CVSS score; only the priority needs that), the Assess view shows a **References from CISA** card under Recommended action. Each link has its label (or its host name) and the real domain underneath, so you can see where it goes before you click.
- Clicking a link, or pressing Enter or Space while it has the keyboard focus, opens it in your default web browser. Nothing is opened or fetched automatically. If no browser can be opened, the address is copied to the clipboard instead.
- Only plain `https` links to an ordinary host name are clickable. Anything else in the notes (`http` links, odd ports, addresses with a user name, IP addresses, look-alike characters, other kinds of link) is shown as plain text and never opened. Invisible and control characters are removed.
- At most 12 references are shown, with duplicates removed.
- **Copy summary** and **Copy as Markdown** include the references, so a ticket carries the same links.
- **Batch:** when a row has a `cve` that is in KEV, the Details box under the table lists its references too (the first 5, with a note if there are more). Long details scroll inside the box, so they never push the results table out of view.
- **CSV export:** two columns are added at the end: `references` (each item as `label: address`, separated by ` ; `, as plain text) and `forensic_triage` (`Yes` or empty). Like every exported text cell they are neutralised so a spreadsheet cannot run them as a formula.

### Forensic triage

CISA's feed marks some entries `forensicTriage: Yes`. Those are entries where the BOD 26-04 guidance asks organisations to look for signs of compromise, not only to patch. The app shows a neutral **Forensic triage advised** chip and a line in the reasoning. Like the rest of the KEV context it never changes the bucket or the ordering score. The flag is read leniently: only the exact text `Yes` counts, and a missing or unexpected value just means "not flagged", so a change in CISA's wording can never make an update fail.

## Download safety

- HTTPS only, and only to the three expected hosts (`www.cisa.gov`, `epss.empiricalsecurity.com` and `codeload.github.com`). TLS certificates are always verified, and nothing in the app or its settings can turn that off.
- Redirects are allowed only to HTTPS on the same expected host, and at most 3. (The EPSS "current" address does redirect to a dated file on the same host.)
- Time limits: 20 seconds to connect or wait for data, and 2 minutes overall. A server that sends data very slowly is cut off at the overall limit.
- Size limits are enforced while downloading, not only at the end.
- The app's own proxy settings follow your system settings (`HTTPS_PROXY` and similar).
- **What the ICS advisories download is trusted on:** HTTPS to GitHub's servers, the same level of trust as the other two sources. CISA signs each advisory file with PGP, but the archive as a whole is not signed, and the Python standard library cannot check PGP signatures, so the tool does not verify them. The content is therefore treated as untrusted and checked as described above.

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
| Linux | `$XDG_DATA_HOME/ot-triage/data/` (usually `~/.local/share/ot-triage/data/`) |
| macOS | `~/Library/Application Support/ot-triage/data/` |
| Windows | `%LOCALAPPDATA%\ot-triage\data\` |

Files: `kev.json`, `epss.csv.gz` and `meta.json` (where and when each was retrieved, plus a checksum), and `ics_advisories.json` with `ics_meta.json` for the ICS advisories. Files are written with user-only permissions, using a temporary file that replaces the old copy only once the new one is complete.

## Freshness

The tool can report how old each source is and flag it as **stale** after the configured number of days (default 7). A stale warning never blocks anything.

## Batch CSV: the `cve` column

Add an optional `cve` column. Then:

- With data loaded, the `threat` cell can be left blank and the level comes from KEV and EPSS.
- A `threat` value can still be given. It can raise the level but never lower what the data says.
- With no data loaded and a blank `threat` cell, the row is reported as an error that says so. It is **not** scored as "no known exploitation".
- The export adds `cve`, `threat_source` (why the level was chosen) and `threat_data` (the KEV and EPSS versions used) columns, so results can be reproduced. It also adds `references` and `forensic_triage`, and `ics_advisories` (see above).

## In the GUI

- The **Threat data** view shows each source's version, dates, entry count and freshness, with **Update threat data** and **Import from files…** buttons. The first update shows exactly which three hosts will be contacted and asks for confirmation. Updates run in the background with a Cancel button.
- The **Assess** view has a CVE field. Press Enter or **Look up** to check the local data. The threat level is filled in with its source shown. Two checkboxes can only raise it, and changing it by hand asks for a written reason that appears in every summary.
- The **status bar** shows freshness at all times.
- **Settings** has an optional "Update threat data when the app starts" checkbox, off by default.

The same functions can be used from Python:

```python
import threatdata
print(threatdata.update_from_network())                       # download
print(threatdata.import_from_files("kev.json", "epss.csv.gz"))  # offline import
```
