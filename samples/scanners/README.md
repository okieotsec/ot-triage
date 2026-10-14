# Fictional scanner exports

Made-up exports in the shape of six scanner formats, for designing and testing a future import feature (see
[docs/SCANNER_IMPORT.md](../../docs/SCANNER_IMPORT.md)). The importer (`ot_triage_import.py`, see [docs/IMPORT.md](../../docs/IMPORT.md)) reads all six of them, and copies of the small ones ship in the portable bundle as `sample_scan_*`.

**Everything is invented**: the plant ("Cedar Creek"), the hosts, the addresses (only the ranges reserved for
documentation: 192.0.2.0/24, 198.51.100.0/24, `example.com`), the plugin and result ids, the dates and the summaries.
Vendor and product names, CVE ids and CVSS scores are real public facts used for illustration; the pairing of a CVE with
a device is for the demonstration and says nothing about any real system. None of the files are copied from another
project: they were written for this repository, from the field names the tools' public documentation and
integrations describe.

| Folder | Format | Shape followed |
| --- | --- | --- |
| `nessus/classic.csv` | Nessus CSV report | the classic columns (Plugin ID, CVE, CVSS, Risk, Host ... Plugin Output), one row per CVE, with embedded new lines |
| `nessus/export.nessus` | Nessus v2 XML | `NessusClientData_v2`, `ReportHost` with `HostProperties`, `ReportItem` with one `cve` element per CVE |
| `tenable/vm_export.csv` | Tenable Vulnerability Management findings CSV | the display names of Tenable's documented export fields (Asset Name, IPv4 Address, CVE, CVSSv3 Base Score, VPR, State ...) |
| `openvas/report.csv` | OpenVAS / Greenbone results CSV | the layout with the Quality of Detection column |
| `nozomi/node_cves.json` | Nozomi `node_cves` query response | `{"result": [...]}`, each record carrying its own asset context |
| `dragos/detections.json` | Dragos vulnerability detections | `{"content": [...]}`, each detection carrying its host and its vulnerability |

The headers of real exports vary with the product version, so treat these as representative, not authoritative. Real
exports are still needed to check an importer (see the plan).

## What an importer would produce

* `expected/<tool>.findings.csv`: the findings in OT Triage's own CSV (`id, asset_id, name, cve, cvss, patch`, plus a
  `source_tool` column that OT Triage ignores). `expected/all.findings.csv` is the six together.
* `expected/inventory.skeleton.csv`: the assets the scanners saw, with the vendor, product and version the OT tools
  report, and **empty** criticality, exposure and controls, which no scanner knows and a person has to fill in.
* `merge/`: the same devices appear under different names (an IP, a host name, an asset name), so an alias table maps
  them to one asset id, and the same CVE reported by two tools on one asset becomes one finding.
  `merged.findings.csv` and `merged.inventory.csv` are the result, the inventory filled in the way a person at the plant
  might.
* `result/`: what OT Triage itself makes of the merged files (`python3 ot_triage_cli.py merge/merged.findings.csv
  --inventory merge/merged.inventory.csv -o ranked.csv -a assets.csv`), run on the threat data of 2026-10-08. Open
  `ranked.csv` for the ranking with reasons and `assets.csv` for the per-asset view, including how many CISA advisories
  list each asset's firmware version. Later threat data gives different numbers.

The files in `expected/`, `merge/` and `result/` were produced by `ot_triage_import.py` and `ot_triage_cli.py` themselves (they were first written by a throw-away prototype, and the importer reproduces them exactly, apart from the title of the Nozomi findings, which the importer takes from the CVE summary).
