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

## The inventory file

| Column | Meaning | Accepted header names |
| --- | --- | --- |
| `asset_id` (required) | Matches a finding's `asset_id` | `asset_id`, `assetid`, `asset_tag`, `id` |
| `name` | A readable name (display only) | `name`, `asset_name` |
| `criticality` | `crown jewel` / `important` / `standard` | `criticality`, `asset_criticality`, `asset` |
| `exposure` | `high` / `medium` / `low` | `exposure`, `network_exposure` |
| `controls` | `none` / `partial` / `strong` | `controls`, `compensating_controls`, `mitigations` |

At least one of criticality, exposure or controls is needed. Values accept the same short names as the findings file. A blank cell means "the inventory does not say", and nothing is guessed.

## Rules for matching

- **A value on the finding row always wins.** The inventory only fills in cells the row leaves blank, because an analyst's entry on a row is deliberate.
- Matching ignores letter case and stray spaces, so `plc-01` finds `PLC-01`.
- **No guessing.** If a finding names an `asset_id` that is not in the inventory, and the row does not have the values itself, it shows as an error that says so. The same happens when no inventory is loaded.
- **Duplicates are never used.** If the same `asset_id` appears twice, the tool cannot know which entry is right, so neither is used, the inventory warning lists it, and findings that need it show an error.
- A row with an unrecognised value (for example exposure `sideways`) is skipped and listed in a warning; the rest of the inventory still loads.

## Safety

The inventory is read like every other file: at most 5 MB and 20,000 rows, UTF-8 only, control and invisible characters removed from ids and names, and bad rows skipped and reported, never guessed at. Nothing is sent anywhere, and the inventory's path is not remembered between runs. The export gains two columns, `asset_id` and `from_inventory` (which values came from the inventory), and neutralises spreadsheet formulas as usual.
