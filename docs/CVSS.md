# CVSS vectors and scores

The tool can work out the CVSS **base score** from a CVSS vector string, so you no longer have to look the score up and type it in.

## What you can paste

| Version | Example |
| --- | --- |
| CVSS 3.0 | `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| CVSS 3.1 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| CVSS 4.0 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |

- **Not supported: CVSS 2.** Its vectors carry no version prefix. The tool says so and asks for the base score instead.
- Metrics may be in any order; the tool shows them in the standard order.
- The vector must be complete: every base metric has to be present. A vector is checked strictly (known metrics, valid values, no duplicates, letters, digits, `:`, `/` and `.` only, at most 400 characters), and anything else is rejected with a message that says why.

## Base score only

Only the **base score** is used.

- Temporal (CVSS 3.x), threat (4.0), environmental and supplemental metrics are accepted and checked, but they **never change** the score. A vector that includes them gives the same base score as one without.
- This matches the tool's input, which has always been "CVSS base score".

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

## In batch CSV files

Add a **`cvss_vector`** column (the headers `vector` and `cvss_vector_string` also work). The `cvss` column then becomes optional.

| `cvss` | `cvss_vector` | Result |
| --- | --- | --- |
| blank or missing | valid | The score comes from the vector. |
| matches the vector's score | valid | Accepted. Differences in formatting such as `9.8` and `9.80` are fine. |
| different from the vector's score | valid | **Error row.** The tool never silently picks one of two conflicting values. |
| anything | invalid | **Error row**, even if `cvss` is valid. A bad vector is never ignored. |

The export gains `cvss_version` and `cvss_vector` columns.

## How the scores are calculated, and how that was checked

- **3.0 and 3.1** use the formulas of the CVSS specifications. **4.0** follows FIRST's reference calculator, including its lookup tables (see [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)).
- The code was checked against FIRST's own calculators for **every possible base vector**: all 2,592 for 3.0, all 2,592 for 3.1 and all 104,976 for 4.0. Every score is identical.
- The recorded results are in `cvss_reference.json`. The unit tests re-check a readable sample and an exhaustive fingerprint of all 110,160 scores, without needing a network.
- To repeat the comparison against the official calculators yourself (needs Node.js and an internet connection): `python3 tools/verify_cvss_against_reference.py`.
- Version 4.0's table has 270 entries. Base vectors reach only 36 of them; the rest exist for threat and environmental scoring, which this tool does not compute.

## Not covered

CVSS 2, temporal, threat and environmental scoring, the CVSS-BT combined score, and fetching scores from the internet (the tool never looks scores up; you provide the vector or score).
