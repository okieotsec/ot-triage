# Asset inventory

Typing the asset's criticality, exposure and controls on every finding is slow and easy to get wrong. An asset
inventory is a CSV that lists your assets once; findings then point to an asset with an `asset_id` and the tool fills in
the rest.

An inventory only supplies values for inputs the tool already has (asset criticality, exposure, controls). It does not
change any rule: a finding scores exactly as if you had typed the same values by hand. The sample files
`sample_inventory.csv` and `sample_findings_with_assets.csv` use fictional assets.

## How to use it

1. In **Batch**, press **Load inventory...** and choose your inventory CSV. (You can do this before or after opening the findings file.)
2. Open your findings CSV. It needs an `asset_id` column, and it no longer needs `asset` or `exposure` columns.
3. Rows that name an asset in the inventory take that asset's values. Select a row and the **From inventory** chip and the Details text say which values came from the inventory.

Loading, replacing or clearing the inventory scores the open findings file again straight away.

## Several findings on one asset

Many findings can point to the same `asset_id`; only the inventory must list each asset once. Every finding is scored on its own, using the asset's values from the inventory plus the finding's own CVSS, CVE, threat and patch status, so one asset can have findings in different buckets. All findings are ranked together in one list.

When the file has asset ids, the Batch table shows an **Asset** column. Click its heading to sort by asset and group each asset's findings together, or type an asset id in the search box to see only that asset's findings. The `sample_findings_multiple_per_asset.csv` file has 15 findings on six assets to try this (load `sample_inventory.csv` first).

## The inventory file

| Column | Meaning | Accepted header names |
| --- | --- | --- |
| `asset_id` (required) | Matches a finding's `asset_id` | `asset_id`, `assetid`, `asset_tag`, `id` |
| `name` | A readable name (display only) | `name`, `asset_name` |
| `criticality` | `crown jewel` / `important` / `standard` | `criticality`, `asset_criticality`, `asset` |
| `exposure` | `high` / `medium` / `low` | `exposure`, `network_exposure` |
| `controls` | `none` / `partial` / `strong` | `controls`, `compensating_controls`, `mitigations` |
| `confidentiality`, `integrity`, `availability` | How much each matters for the asset: `low` / `medium` / `high` (blank = not stated) | the same names, `*_requirement`, or `CR`, `IR`, `AR` |

At least one of criticality, exposure, controls or the three requirement columns is needed. Values accept the same short names as the findings file. A blank cell means "the inventory does not say", and nothing is guessed.

## Security requirements (optional)

The three requirement columns feed only the **CVSS environmental score** (see [CVSS.md](CVSS.md)). For a finding that has a `cvss_vector`, the asset's requirements are applied to the vector wherever the vector does not set them itself, and the environmental score is worked out from the result. They never change the priority. A finding with only a plain `cvss` score has no vector to adjust, so it gets no environmental score. Try `sample_findings_environmental.csv` with `sample_inventory.csv`.

## Rules for matching

- **A value on the finding row always wins.** The inventory only fills in cells the row leaves blank, because an analyst's entry on a row is deliberate.
- Matching ignores letter case and stray spaces, so `plc-01` finds `PLC-01`.
- **No guessing.** If a finding names an `asset_id` that is not in the inventory, and the row does not have the values itself, it shows as an error that says so. The same happens when no inventory is loaded.
- **Duplicates are never used.** If the same `asset_id` appears twice, the tool cannot know which entry is right, so neither is used, the inventory warning lists it, and findings that need it show an error.
- A row with an unrecognised value (for example exposure `sideways`) is skipped and listed in a warning; the rest of the inventory still loads.

## Safety

The inventory is read like every other file: at most 5 MB and 20,000 rows, UTF-8 only, control and invisible characters removed from ids and names, and bad rows skipped and reported, never guessed at. Nothing is sent anywhere, and the inventory's path is not remembered between runs. The export gains two columns, `asset_id` and `from_inventory` (which values came from the inventory), and neutralises spreadsheet formulas as usual.

## Vendor and product (optional)

Two optional columns, `vendor` and `product` (aliases: `manufacturer`, `make`, `model`, `product_name`), say what each asset is. They are used only to point at **CISA ICS advisories that may apply**; they never feed the scoring, so adding them cannot change any priority. An inventory with only `asset_id`, `vendor` and `product` is valid.

- **Where it shows:** in the Batch view's **By asset** mode, selecting an asset lists the advisories that may apply to it (the newest five, links to cisa.gov, with the total), or says plainly that none was found. The roll-up export gains `vendor`, `product`, `possible_advisories` and `newest_possible_advisory` columns, and the command line's `--assets` file has them too. They need the ICS advisories to be downloaded (Threat data).
- **How it matches:** an advisory matches when every word of the vendor appears among its vendor names and every word of the product appears among its product names or its title, ignoring case, punctuation, accents, order and endings such as Inc, GmbH and AG. A vendor and a product word of at least three characters are needed. So `Siemens AG` / `S7-1500` finds the advisories for the SIMATIC S7-1500, and an asset with only a vendor, or a product like `A1`, matches nothing.
- **What it means:** a pointer to read, never proof. It does not know the version you run, and advisories use the vendor's own names: if the inventory says `Allen-Bradley` and CISA writes `Rockwell Automation`, nothing matches and the tool says that no advisory names that vendor. Check each advisory against your product and version.

## Version (optional)

A third optional column, `version` (aliases: `firmware`, `firmware_version`, `fw_version`, `software_version`, `sw_version`), says which firmware or software version the asset runs, as you write it: `3.11.0`, `V2.9.4`, `Firmware 7.20.56`. With a vendor, a product and a version, the tool compares the version with the versions each matching advisory lists as affected. Like the other two, it never feeds the scoring.

- **What you see:** in **By asset**, the asset's details count how many advisories list your version as affected, how many list other versions only, and how many could not be compared; the advisories listing your version come first, each with a line such as *Version check: your version V2.9.4 is inside a listed affected range (<2.9.9)*. In Batch's Findings view, a row whose asset has a vendor, product and version gets the same line under each advisory that names that vendor and product. The roll-up export (and the command line's `--assets` file) gains `version` and `listing_your_version` columns.
- **How it compares:** the advisories write versions as free text: `<=Firmware_3.11.0`, `vers:intdot/>=4.0|<5.2`, `>= 6.02 | <= 6.05`, `V7.1 and prior`, `vers:all/*`. The tool reads these common shapes (about 94% of what CISA publishes today) and compares the numbers, so 3.9 is below 3.10. When the text is not one it understands, or two versions differ only in a qualifier such as `SP2`, it says it **could not compare** instead of guessing.
- **What it means:** a pointer to read, never proof, and never a clean bill of health. "Outside the listed versions" means this advisory's list does not include your number; the advisory may cover it in words the tool did not read, the vendor's own list may be incomplete, and a different CVE or advisory may apply. The version is only as good as the inventory, and a version the tool cannot read as a number (`banana`) is reported as not compared.

## The per-asset view

With a findings file that has an `asset_id` column (with or without an inventory), the Batch view's **By asset** button groups the findings by asset. OT assets are usually patched in short outage windows, so the question is often "what is on this asset?", not only "what is the worst finding?".

- **The table:** one row per asset: its worst bucket, how many NOW, NEXT and NEVER findings it has, how many findings in all, the highest ordering score, and the top finding. Assets with a NOW finding come first, then those with more NOW and NEXT findings. Click a heading to sort; the search box matches asset ids and anything in their findings.
- **Matching:** asset ids match without regard to letter case or surrounding white space; the first spelling seen is shown. Rows with no asset id are not merged into one made-up asset: the note above the table says how many there are, and they stay in the Findings view.
- **The details:** selecting an asset lists the findings that call for action (NOW and NEXT) in ranked order, as the set that could be handled on one visit, and says how many are NEVER (no scheduled fix). A row that could not be scored (for example an `asset_id` that is not in the inventory) still counts toward its asset, as "not scored".
- **Export:** **Export asset roll-up** saves one row per asset (`asset_id`, `worst_priority`, `now`, `next`, `never`, `errors`, `findings`, `visit_together`, `top_ordering_score`, `top_finding`, `finding_ids`). Like every export, text cells that could run as a spreadsheet formula are neutralised.
- **Nothing in this view changes a priority.** It only groups rows that were already scored.

## Comparing with a previous export

For a routine (a weekly scan, say) the useful question is often "what changed since last time?". In Batch, **Compare with previous…** asks for an earlier ranked CSV that was saved with **Export ranked CSV**.

- **The Change column** appears next to Priority: *New* (not in the previous export), *Up from NEXT* or *Down from NOW* (the bucket changed), *Same*, *Not comparable* (one of the two could not be scored) and *Could not match*. The line above the table counts them, and **Show resolved…** lists the findings that were in the previous export and are not in the open file. Click the Change heading to sort the new and worsened findings to the top.
- **How findings are recognised:** by `id` when both files have one; if that is missing or not unique, by CVE and asset; if that does not settle it, by name and asset. Case and extra spaces do not matter. If more than one previous row could be the same finding, the finding is reported as *Could not match* and none of those rows is used, rather than guessing.
- **Keeping it:** the previous export stays loaded while you open newer findings files, so each new scan is compared with the same baseline. **Clear** stops the comparison.
- **The export** gains `change` (`new`, `up`, `down`, `same`, `unscored` or `ambiguous`) and `previous_priority` columns, blank when no comparison is active. Resolved findings are not in the ranked export.
- **Safety:** the previous file is untrusted like every other file the tool reads. It is limited to 25 MB and 50,000 rows, rows with an unknown priority are skipped and counted, and text is cleaned. Nothing about a comparison changes a priority or an ordering score.

