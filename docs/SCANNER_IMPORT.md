# Importing scanner exports: research and plan

Status: **a plan, not a feature.** Nothing here is implemented. The sample files and the results are in
[samples/scanners/](../samples/scanners/README.md); a throw-away prototype produced them, so every mapping below has
been run, not only written down.

## Recommendation

Build it in three steps, smallest and best documented first, and keep the importers as a thin layer that only writes
the CSVs OT Triage already reads. Scoring does not change.

1. **Nessus / Tenable CSV and OpenVAS CSV, plus the merge step** (aliases and duplicates). These have public field
   documentation and many public examples, and the merge step is where most of the real value, and risk, is.
2. **Nessus `.nessus` XML, Nozomi and Dragos JSON.** The OT tools also give vendor, product and firmware version, which
   fills the inventory and feeds the version comparison added in 0.8.0.
3. **A button in Batch** ("Import scanner export...") over the same code, plus the command line (`ot_triage_cli.py
   import`).

Claroty xDome and Tenable OT Security are **not** planned yet: I found no public description of their export fields
(only integration pages that name endpoints), and I will not guess a format. They need a real export (below).

## What was found

| Tool | Export | Public documentation | Confidence in the sample |
| --- | --- | --- | --- |
| Nessus (classic) | CSV report | Tenable's plugin attribute names; the 13-column layout is long established | medium: headers vary by version (`CVSS`, `CVSS v2.0 Base Score`, `CVSS v3.0 Base Score`) |
| Nessus | `.nessus` v2 XML | Tenable's published file format description (2010) and the API documentation | medium: the structure is stable, newer plugin attributes are added over time |
| Tenable Vulnerability Management | findings CSV | Tenable documents every export field and its CSV key | high for the field names, medium for the exact header text of the UI download |
| OpenVAS / Greenbone | CSV | community posts show the header; a newer layout adds Quality of Detection after Severity | medium: the layout changed between releases |
| Nozomi (Guardian / Vantage) | `node_cves` query response (JSON) | the vendor's API reference is behind a login; integration pages describe the query | medium-low: the shape is known from third-party importers, not from the vendor |
| Dragos Platform | vulnerability detections (JSON) | the vendor's API reference is behind a login; integration pages describe the privileges and endpoints | medium-low, as for Nozomi |
| Claroty xDome | devices and device-vulnerability relations (API) | integration pages name the endpoints; no field list is public | none: no sample written |
| Tenable OT Security | not found | only Security Center and Vulnerability Management pages came up | none: no sample written |

The Nozomi and Dragos files look like **API responses**, not what a console's Export button writes. That matters: an
air-gapped plant may only be able to use the button.

## Design

A pipeline of four small steps, each testable on its own:

1. **Read** one export into plain rows (a bounded reader per format: size and row limits like the other importers).
2. **Normalise** into findings (`id, asset_id, name, cve, cvss, patch`) and assets (`asset_id, name, vendor, product,
   version`).
3. **Merge**: resolve aliases to one asset id and collapse the same CVE on the same asset (highest score kept, every
   source tool listed).
4. **Write** a findings CSV and an inventory (new assets added, existing rows never overwritten), with the same
   atomic-write and no-overwrite rules as the command line.

Rules that follow from the project's policy and its security stance (and the decisions below):

* **Scoring is untouched.** An importer only fills the columns OT Triage reads. The scanner's own severity word is
  never used (Dragos, for one, has its own 0 to 5 scale, which is not a CVSS score and must not be read as one).
* **No silent drops, no invented values.** Resolved or fixed findings are skipped and counted; informational rows
  without a score are skipped and counted; a finding with no score stays in the file with an empty score so OT Triage
  shows it as **not scored**, with the reason.
* **Untrusted input.** Hostile text, formula cells, embedded new lines, huge files; for XML, refuse any file that declares
  a DTD or entities (the standard library's parser can be abused by entity expansion), and read it incrementally.
* **Asset facts a scanner cannot know stay empty.** Criticality, exposure and controls are for a person (or an
  existing inventory) to fill in.

### Mapping

| Tool | asset_id | cve (one row per CVE) | cvss | patch | skipped | vendor / product / version |
| --- | --- | --- | --- | --- | --- | --- |
| Nessus CSV | Host | CVE | CVSS v3 if present, else v2 | blank | Risk None / Info | none |
| Nessus XML | `ReportHost name` | each `cve` element | `cvss3_base_score`, else `cvss_base_score` | blank | severity 0 | none |
| Tenable VM | Asset Name (IPv4 as alias) | CVE | CVSSv3 Base Score | blank | State Fixed / Resolved; severity Info | none |
| OpenVAS | IP (host name as the name) | CVEs (comma separated) | CVSS | `available` for Solution Type VendorFix | Severity Log; CVSS 0; QoD below a threshold | none |
| Nozomi | `node_label`, else `asset_id` | `cve` | `cve_score` (may arrive as text) | `available` when `latest_hotfix` is set | `resolved: true`; no CVE | node_vendor / node_product_name / node_firmware_version |
| Dragos | `host.name` | `enumeration` or `reference` | `score.base` | blank | state resolved | host.vendor / hardware.model / hardware.firmware_version |

## What prototyping showed

These are the real problems; the sample files are built to hit each one.

1. **The same device has several names.** The Nessus file knows `192.0.2.21`, Tenable knows `CC-HIST-01`, and one OpenVAS
   host appears once with a host name and once without. Without an alias table the same device becomes three assets
   and every finding is counted two or three times (29 findings became 25 after merging, and the assets 18 became 14).
   The plan: an optional `aliases` file (`alias, asset_id`), and for network scanners the IP as the default key.
2. **The same CVE arrives from two tools.** Merge on (asset, CVE), keep the highest score, record both sources.
3. **A plugin with several CVEs** is one row in some exports and one row per CVE in others; the importer splits
   them so each CVE can be looked up in KEV and EPSS.
4. **Findings with no CVE** (default credentials, an open Telnet port) cannot get a threat level from KEV or EPSS, so OT
   Triage says `threat: value is required`. That is correct behaviour, but it needs a decision (below).
5. **Findings with no score** (Tenable's "SMB Signing not required", a Dragos detection with only its own score) are
   left as not scored. For CVEs, the score exists in CISA's own advisory files (see below).
6. **Embedded new lines** in OpenVAS and Nessus cells break naive importers; the samples contain them.
7. **Resolved findings** must not reopen: Nozomi `resolved`, Dragos `state`, Tenable `State`.
8. **Purdue level 0 is a real level** and a missing level is not level 0 (Dragos leaves the field out when unknown).
   We do not use it, but a future "exposure" suggestion must not confuse the two.
9. **Exports change with the product version.** Match columns by name with aliases, report which columns were found,
   and refuse a file that lacks the ones that matter instead of guessing by position.

## Decisions

Agreed with the owner on 2026-10-13. Only the first changes what a result can say; it is off unless asked for.

1. **A score for CVEs the export does not score: opt-in.** The CISA advisory data already in the tool carries a CVSS score
   per CVE. With the option on, it is used only for a row that has no score of its own (a score in the file is never
   overridden), only when every advisory for that CVE gives the same score (if they disagree, the row stays not scored),
   and the row's reasoning says where the number came from ("score taken from ICSA-..."). Off by default.
2. **Vendor exploit intelligence is context only.** Dragos's exploit flags and Nozomi's likelihood are shown the way the CISA
   advisories are (a chip and a line in the details) and never set the threat level. KEV and EPSS are public and can be
   checked by anyone; a proprietary feed cannot, and it overlaps with KEV. Revisit with real exports.
3. **Findings with no CVE stay not scored by default.** OT Triage already says a threat level is required. The import
   summary says how many findings need one, and an explicit `--default-threat <level>` option (the value must be typed,
   never assumed) is available for people who want one.
4. **OpenVAS: follow Greenbone's own default** of hiding detections with a Quality of Detection below 70. The summary says how
   many rows were hidden, and the threshold can be changed.
5. **Aliases live in a separate file first** (`alias, asset_id`), so the inventory format people already use does not
   change. An inventory column can follow if the file proves itself. Network scanners key devices by IP by default.

## Phases

| Phase | Work | Security checkpoint |
| --- | --- | --- |
| 1 | Nessus/Tenable CSV and OpenVAS CSV readers, the merge step, the command line | CP18: hostile CSV, size limits, formula cells, header drift |
| 2 | `.nessus` XML (no DTD), Nozomi and Dragos JSON, vendor/product/version into the inventory | CP19: XML entity expansion, deep JSON, huge numbers, hostile text |
| 3 | Batch button, preview of what will be imported and what was skipped | CP20: the same checks through the window, no change to scoring |

Each phase ends with real-export checks (below), mutation checks on the mapping rules, and the usual release gate.

## What I need from you

A real export is the only way to know an importer reads what the product actually writes. For any tool you can reach,
**one small export** is enough (even three rows), scrubbed before it leaves your hands:

* Replace host names, IP addresses, MAC addresses, serial numbers, user names and any site or zone names that identify
  a place; keep the vendor, product, firmware version and CVE ids.
* Keep the file exactly as the tool wrote it otherwise (same header, same quoting) and tell me the product and version.
* Nothing goes into the repository without your say-so, and real data stays out of it: the repository only ever gets
  fictional files like the ones in `samples/scanners/`.

## Sources

* Tenable, [findings export fields and CSV keys](https://docs.tenable.com/vulnerability-management/Content/Explore/export-findings-csv-keys.htm)
  and [export file formats](https://developer.tenable.com/docs/export-file-formats)
* Greenbone community, [CSV report format change](https://forum.greenbone.net/t/csv-report-format-change/18589) and
  [CSV report from OpenVAS](https://forum.greenbone.net/t/csv-report-from-openvas/5542)
* Integration pages describing the Nozomi, Dragos and Claroty APIs (no vendor reference was public):
  [Axonius, Nozomi](https://docs.axonius.com/docs/nozomi-networks-guardian),
  [Sumo Logic, Dragos](https://help.sumologic.com/docs/send-data/hosted-collectors/cloud-to-cloud-integration-framework/dragos-source),
  [runZero, Dragos](https://help.runzero.com/docs/dragos/index.md),
  [Elastic, Claroty xDome](https://www.elastic.co/docs/reference/integrations/claroty_xdome),
  [Tenable, Claroty connector](https://docs.tenable.com/exposure-management/Content/connectors/claroty-connector.htm)
* DefectDojo's importer documentation was read for how others handle severity scales, resolved records and the Purdue
  level; none of its test files or code were used (see the licence note in the sample README).
