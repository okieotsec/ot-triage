# Importing scanner exports

`ot_triage_import.py` turns a scanner's export into the two files OT Triage reads: a **findings CSV** and, if you want
one, an **asset inventory**. Then you rank them as usual, in the Batch view or with `ot_triage_cli.py`. The importer
only reads and writes files: it never uses the network, never scores anything, and never changes a file you give it.

```
python3 ot_triage_import.py scan.csv -o findings.csv
python3 ot_triage_import.py nessus.csv openvas.csv -o findings.csv --inventory-out inventory.csv
python3 ot_triage_import.py scan.csv -o findings.csv -i inventory.csv --inventory-out inventory.new.csv --aliases aliases.csv
```

## In the application

In the **Batch** view, **Import scan…** does the same without the command line:

1. Choose one or more scanner exports.
2. A preview shows what will be imported, what was skipped and why, and any note about a format that is still experimental. Here you can choose a threat level for findings with no CVE (the default is to leave it empty), an **aliases file** and your **existing inventory** (which is extended in a copy and never changed). The summary updates as you change them.
3. **Save and open…** asks where to save the findings and the inventory, writes them, and opens them in the view.

The import never overwrites a file it reads from (an export, the aliases file, your inventory) and never saves the findings and the inventory under the same name. The new assets have empty criticality, exposure and controls, because no scanner knows them: fill them in (a spreadsheet will do) and press **Load inventory…** again, and until then their findings show as not scored.

Opening a scanner export with **Open CSV…** or **Load inventory…** does not work (those read OT Triage's own files) and says so, with the import command, in the message.

Try it on the six files in the bundle: `python3 ot_triage_import.py sample_scan_nessus.csv sample_scan_openvas.csv
sample_scan.nessus sample_scan_nozomi.json sample_scan_dragos.json sample_scan_claroty.csv -o findings.csv --inventory-out inventory.csv`. They are fictional (every host, address and id is invented).

## What it reads

| Export | How to recognise it |
| --- | --- |
| **Nessus CSV** | Plugin ID, CVE, CVSS (v2 and/or v3), Risk, Host, Name ... |
| **Tenable Vulnerability Management CSV** | Asset Name, IPv4 Address, CVE, CVSSv3 Base Score, Severity, Plugin ID, Plugin Name, State ... |
| **OpenVAS / Greenbone CSV** | IP, Hostname, CVSS, Severity, QoD, NVT Name, CVEs, Result ID ... |
| **Claroty xDome device-vulnerability pairs CSV** | Device Name, Device IP, Vulnerability Name, CVEs, CVSS V3 Base Score Points, Manuf. Remediation Info, Vulnerability Relevance ... |
| **Nessus `.nessus` (v2 XML)** | an XML file whose root is `NessusClientData_v2`, with `ReportHost` and `ReportItem` elements |
| **Nozomi `node_cves`** *(experimental)* | JSON (`{"result": [...]}`) or a CSV exported from a `node_cves` query; fields `cve`, `cve_score`, `node_label`, `node_vendor`, `node_product_name`, `node_firmware_version`, `resolved` ... |
| **Dragos detections** *(experimental)* | JSON (`{"content": [...]}`), each record with a `host` and a `vulnerability` |

The format is found from the header, by column **name** and never by position, so the order of columns and the spelling
(`CVSS v3.0 Base Score`, `cvss_v3.0_base_score`) do not matter. A file whose header is not one of these is refused, with
the start of its header in the message, rather than guessed at. The Nozomi and Dragos readers are **experimental**: they follow Nozomi's published `node_cves` data model and third-party descriptions of the Dragos API, and have not been checked against a real export, so the summary says so each time. A file that does not look like them is refused, never guessed at. See [SCANNER_IMPORT.md](SCANNER_IMPORT.md).

## Claroty: what is used

The Claroty reader was written from one demo export of the *device-vulnerability pairs* report (saved as CSV UTF-8; an `.xlsx` file is not read, so open it in Excel and use **Save As → CSV UTF-8**). It is not experimental in the sense of the Nozomi and Dragos readers, which have never seen an export, but it has seen only one, so each run says so and another report layout may not be recognised.

* **One finding per device and CVE.** The device name is the asset (`DOMAIN\HOST` as Claroty writes it; use an aliases file to join it to the same device's name in another tool). A row that names several CVEs, as the grouped advisories do, becomes one finding for each, and each gets the **row's score**, which belongs to the whole advisory and may overstate a single CVE. The score is the number in *CVSS V3 Base Score Points*; the column of severity words is never read as a score.
* **The device's addresses** (up to four, without "Last known IP") go into the inventory's `name` column, to help you write the aliases file.
* **Skipped:** rows with a resolution date or a patch-install date. A row with no CVE is kept, and needs a threat level like any other finding with no CVE.
* **"Potentially Relevant" rows** (Claroty has not confirmed that the device is affected) are **kept and marked** with ` [potentially relevant]` at the end of the finding's name, and the summary counts them. Leaving them out would treat "not confirmed" as safe. `--only-confirmed` leaves them out (the Import scan dialog keeps them).
* **`patch` is `available`** when *Manuf. Remediation Info* says *Patch Available* or *Version Upgrade Available* and does not say *Manufacturer Not Patching Model*. Mitigation-only rows and *Contact Manufacturer* rows are left empty.
* **Not used, on purpose:** Claroty's device risk score, its adjusted vulnerability score, its **Actively Exploited** flag and its EPSS column. As for every scanner, the threat level comes from CISA KEV and EPSS data (and your own analyst flags), never from a scanner's own opinion; the same rule keeps Dragos's and Nozomi's exploit fields out. The export has no criticality, exposure, vendor, product or version, so the inventory it writes still needs the first three from you, and the version check has nothing to compare.

## What it writes

* **The findings CSV** has `id`, `asset_id`, `name`, `cve`, `cvss`, `patch` and `source_tool` (which OT Triage ignores).
  There is one row per CVE, so a plugin that names three CVEs becomes three findings, each of which can be looked up
  in KEV and EPSS. The score is the CVSS v3 score if the export has one, otherwise v2; a missing or invalid score is left
  empty, and OT Triage then shows the finding as **not scored**, with the reason. `patch` is `available` only where the
  export clearly says a vendor fix exists (OpenVAS Solution Type *VendorFix*, Claroty *Patch Available* or *Version Upgrade Available*); it is never guessed.
* **The inventory** (`--inventory-out`) lists the assets the scan saw. With `--inventory` (your existing one) the result
  is that file **plus** a row for each new asset: your rows, columns and values are kept as they are, and a blank name,
  vendor, product or version is filled in from the scan but a value you wrote is never replaced. New assets have empty
  criticality, exposure and controls: **no scanner knows those**, so they are for you to fill in. OT Triage reports a
  finding on an asset with no criticality or exposure as not scored, so nothing is ranked on a guess.

## Nozomi and Dragos: what is used

* **Nozomi.** Nozomi publishes the fields of its `node_cves` query, and its consoles export a query's results as CSV or Excel; the importer reads the JSON a query returns (`{"result": [...]}`) and a CSV with the same field names as columns (save an Excel export as CSV first). One finding per record: the CVE, `cve_score` as the score, the CVE summary as the title, and `available` as the patch status when a hotfix is named (Nozomi fills the hotfix fields for Windows assets only). The node's label (or asset id) is the asset, and its vendor, product name and firmware version go to the inventory, which feeds the version comparison. Records with `resolved` true are skipped. `likelihood` is **not** used.
* **Dragos.** One finding per detection: the host's name is the asset, the vulnerability's CVE (from `enumeration`, then `reference`) and `score.base` (the CVSS base score) are the finding, and the host's vendor, hardware model and firmware version go to the inventory. Detections whose state is resolved, closed, fixed or remediated are skipped. Dragos's own risk score, its 0 to 5 severity, its exploit intelligence and the Purdue level are **not** used: they are shown nowhere and decide nothing, like every vendor's own priority.
* A detection with no CVE, or with no `score.base`, is kept and shows as not scored (a CVE with no score could be filled from CISA's advisory data; that option is planned and off by default).

## What it skips

Every skipped row is counted and named in the summary, never dropped silently:

* Nessus and Tenable: findings whose risk or severity is *None* or *Info*, and findings whose state is *Fixed* or
  *Resolved*.
* OpenVAS: *Log* entries, results with no score, and results whose **Quality of Detection** is below `--min-qod`
  (default 70, Greenbone's own default for hiding low-confidence detections; `--min-qod 0` keeps everything).
* Claroty: rows with a resolution date or a patch-install date (and, with `--only-confirmed`, rows marked *Potentially Relevant*).
* Rows with no host or asset name.
* `.nessus` files: items with severity 0 (informational), and **compliance checks** (items of the *Policy Compliance* family or with `cm:` elements), which are configuration audits, not vulnerabilities.

A `.nessus` file is read as a stream, so a large one is never held in memory, and the text of a plugin's output (which can be huge) is never kept. The severity and CVE rules are those of the CSV: one finding per `cve` element, the `cvss3_base_score` if present, otherwise `cvss_base_score`, and the host's name, or its `host-ip` tag if it has no name. A file that declares a DTD or an entity is **refused**: that is how XML entity-expansion attacks are made, and a scanner never writes one. The format follows Tenable's published description of the Nessus v2 file (the v3 score element is newer than that document and is read when present).

## Several tools, one device

The same device often has several names (an IP address in one tool, a host name in another) and the same flaw may be
reported by two tools. List the names in an **aliases file** and pass it with `--aliases`:

```
alias,asset_id
192.0.2.21,CC-HIST-01
cc-hist-01.example.com,CC-HIST-01
```

Every alias is replaced by its asset id (ignoring case), and a finding with the same asset and CVE (or, with no CVE,
the same title) reported twice becomes one: the highest score is kept, a patch status is kept if any report has one, and
`source_tool` lists the tools (`nessus+openvas`). Map every name straight to the asset id; a name that is itself an alias
is refused, and so is a name listed for two assets.

## Findings with no CVE

A finding with no CVE (default credentials, an open Telnet port) cannot get a threat level from KEV or EPSS, so OT Triage
asks for one: *threat: value is required*. That is the right behaviour, and the summary says how many findings need it. Either
add a `threat` column by hand, or choose a level for all of them with `--default-threat none|public|active`. The level is
never assumed.

## Limits and safety

* Files up to 200 MB and 1,000,000 rows are read row by row; a single cell may be up to 8 MB (Nessus "Plugin Output"
  can be large). The result may have at most 50,000 findings, which is what the Batch view reads.
* Text is cleaned (control and invisible characters removed) and cut to a length, and cells that could run as spreadsheet
  formulas are neutralised in what is written, like every export of this tool.
* An output file is never replaced without `--force`, an input file never, and a failed import leaves no half-written file.
* Exit codes: 0 done, 1 a file could not be used, 2 wrong arguments.

The scoring is not touched: an imported file is ranked by the same rules as one you wrote yourself.
