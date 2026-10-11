# CVSS vectors and scores

The tool can work out the CVSS **base score** from a CVSS vector string, so you no longer have to look the score up and type it in. If the vector also describes your own environment, it works out the **environmental score** too and shows it next to the base score for comparison.

## What you can paste

| Version | Example |
| --- | --- |
| CVSS 3.0 | `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| CVSS 3.1 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| CVSS 4.0 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |

- **Not supported: CVSS 2.** Its vectors carry no version prefix. The tool says so and asks for the base score instead.
- Metrics may be in any order; the tool shows them in the standard order.
- The vector must be complete: every base metric has to be present. A vector is checked strictly (known metrics, valid values, no duplicates, letters, digits, `:`, `/` and `.` only, at most 400 characters), and anything else is rejected with a message that says why.

## The base score decides; the environmental score is for comparison

The **base score** is what the priority uses, and it never depends on anything but the base metrics. A vector that also includes temporal, threat, environmental or supplemental metrics gives exactly the same base score and the same priority as one without.

The **environmental score** adjusts the score to a particular deployment. It is worked out only when the vector sets at least one environmental metric:

| Version | Environmental metrics that count | Other metrics it uses |
| --- | --- | --- |
| 3.0 and 3.1 | Security requirements `CR`, `IR`, `AR`; modified base metrics `MAV`, `MAC`, `MPR`, `MUI`, `MS`, `MC`, `MI`, `MA` | Temporal `E`, `RL`, `RC`, as the standard's formula does |
| 4.0 | Security requirements `CR`, `IR`, `AR`; modified base metrics `MAV`, `MAC`, `MAT`, `MPR`, `MUI`, `MVC`, `MVI`, `MVA`, `MSC`, `MSI`, `MSA` (including the Safety value `S`) | Threat `E` |

A metric left as `X` (not defined) keeps its base value, and the 4.0 defaults (`CR`/`IR`/`AR` High, `E` Attacked) are applied, exactly as FIRST's calculators do. Temporal or threat metrics on their own do not produce an environmental score, and supplemental metrics are checked but never change a score.

**Why the priority does not use it.** The priority already has its own inputs for the same context: how critical the asset is, how exposed it is, and what controls protect it. Feeding an environmental score into the bucket as well would count the same facts twice, and it would be a policy change. So the environmental score is shown for comparison and nothing more. That decision can be revisited (see [POLICY.md](POLICY.md)).

To build an environmental vector, use FIRST's calculators (the CVSS 3.1 and 4.0 calculators at first.org) and paste the resulting vector string here.

## Why a vector is better than a typed score

- **The version is part of the vector.** The same CVE often has different scores under 3.1 and 4.0, and different organisations (the CNA, NVD, a vendor) may score it differently. A vector says which one you used, and the tool records it.
- **No typing mistakes.** Pasting beats copying a number by hand.
- **Reproducible.** Summaries and exports include the vector, the version and the score.

The score bands used by the rules (Low below 4.0, Medium below 7.0, High below 9.0, Critical from 9.0) are the same in 3.0, 3.1 and 4.0, so the rules treat scores from any supported version in the same way. The scores themselves still differ between versions, so use one version consistently across a batch.

## In the Assess view

Paste a vector into **CVSS vector (optional)**. After a short pause (or when you press Enter), the score box fills in and a message confirms the version and score. Details:

- If you then type a different score by hand, the vector no longer describes it, so the vector is cleared (and you are told).
- If you edit a valid vector into an invalid one, the message says the score below still comes from the previous vector.
- Clearing the vector keeps the score as a manual value.
- Copied summaries include the vector and version.
- If the vector sets environmental metrics, the **environmental score** appears under the base score and in the copied summaries, labelled "shown for comparison; the priority uses the base score".

## In batch CSV files

Add a **`cvss_vector`** column (the headers `vector` and `cvss_vector_string` also work). The `cvss` column then becomes optional.

| `cvss` | `cvss_vector` | Result |
| --- | --- | --- |
| blank or missing | valid | The score comes from the vector. |
| matches the vector's score | valid | Accepted. Differences in formatting such as `9.8` and `9.80` are fine. |
| different from the vector's score | valid | **Error row.** The tool never silently picks one of two conflicting values. |
| anything | invalid | **Error row**, even if `cvss` is valid. A bad vector is never ignored. |

The export gains `cvss_version` and `cvss_vector` columns, and a `cvss_environmental` column (blank unless the vector sets environmental metrics). The Details box shows the environmental score for a selected row.

## How the scores are calculated, and how that was checked

- **3.0 and 3.1** use the formulas of the CVSS specifications. **4.0** follows FIRST's reference calculator, including its lookup tables (see [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)).
- The code was checked against FIRST's own calculators for **every possible base vector**: all 2,592 for 3.0, all 2,592 for 3.1 and all 104,976 for 4.0. Every score is identical.
- **Environmental scores** were checked the same way on 60,000 generated vectors per version that mix base, temporal or threat, environmental and supplemental metrics (about 180,000 in all; the vectors are built from a hash, so the same set can be rebuilt anywhere). Every base and environmental score is identical, and for 4.0 the set reaches all 270 entries of the lookup table.
- The recorded results are in `cvss_reference.json`. The unit tests re-check a readable sample and an exhaustive fingerprint of all of these scores, without needing a network.
- To repeat the comparison against the official calculators yourself (needs Node.js and an internet connection): `python3 tools/verify_cvss_against_reference.py`.
- Version 4.0's table has 270 entries. Base vectors reach only 36 of them; the rest are used for threat and environmental scoring.

## Not covered

CVSS 2, a separate temporal or threat-only score (the CVSS-BT score), using the environmental score to decide the priority, building an environmental vector inside the tool (use FIRST's calculator and paste the result), and fetching scores from the internet (the tool never looks scores up; you provide the vector or score).
