# Prioritization policy and rationale

This page explains **why** the rules work the way they do, in plain language. The exact rules, step by step, are in the [README](../README.md). The tests in `test_prioritizer.py` pin every rule below.

## What the buckets mean

| Bucket | Meaning |
| --- | --- |
| **NOW** | Act immediately: fix or mitigate right away. |
| **NEXT** | Schedule it into the next patch cycle (roughly 30 to 90 days). |
| **NEVER** | No scheduled fix. Re-check if conditions change. |

NEVER does not mean "safe". It means "not worth a scheduled fix under today's conditions".

## Guiding ideas

- **Exploitation beats severity.** A flaw attackers are using right now matters more than one with a high score that nobody is using.
- **Reachability matters.** A flaw an attacker cannot reach is much less urgent than one on an internet-facing system.
- **A score is not the whole story.** CVSS describes the flaw in general. It does not know your plant, your network, or what the asset controls.
- **Only real defenses lower the priority.** Controls that stop an attack lower it. Controls that only watch for an attack do not.

## Decisions (approved 2026-10-07)

### 1. Actively exploited, exposed crown jewels are NOW at any CVSS score

**Rule.** If a vulnerability is being actively exploited, sits on a crown jewel asset, and that asset has high exposure, the result is NOW even when the CVSS score is below 4.0. Everywhere else, a CVSS score below 4.0 still caps the result at NEXT.

**Why.** In industrial (OT) environments, CVSS often understates the real damage. A flaw scored low because it "only" causes a denial of service can still stop a production line, and a low score on its own should not delay the response when attackers are already using the flaw against an exposed, critical system.

**Why only this narrow case.** The cap exists so that low-severity noise does not flood the NOW list. Three conditions at once (active exploitation, crown jewel, high exposure) are rare, so the exception adds very little noise.

**What it replaced.** Before, CVSS 2.0 / active / crown jewel / high exposure was capped at NEXT.

**Still applies.** Strong compensating controls can still lower the result, but never below NEXT for an actively exploited item.

### 2. "Low exposure" has a strict definition

**Rule.** Low exposure means: *no routable path from IT or the internet, verified by testing, not assumed from a firewall's existence.* The GUI shows this text under the exposure dropdown.

**Why.** Several rules treat low exposure as a reason to wait. For example, an actively exploited flaw on a standard asset with low exposure is NEXT instead of NOW. That is only defensible if "low" is hard to claim. If people pick "low" because a firewall exists on a diagram, the tool will quietly under-prioritize real risk.

**What to do if you are unsure.** Choose medium. Medium counts as reachable, so it is treated cautiously.

### 3. An exposed crown jewel is never NEVER (when CVSS is 4.0 or higher)

**Rule.** A crown jewel asset with high exposure and CVSS of 4.0 or more is at least NEXT, even with no known exploitation and even with strong controls.

**Why.** Your most critical systems, reachable from the internet, are the places where "we will never fix this" is hardest to defend. NEXT puts the item on a schedule so someone has to make a conscious decision, instead of the item silently falling off the list.

**Why 4.0.** Below 4.0 the CVSS score is "Low" severity. The same cut-off already limits other rules, so one line stays easy to remember.

**Why strong controls do not lower it below NEXT.** Controls reduce the risk, but the asset is still both critical and exposed. The floor matches the one for actively exploited items.

**What it replaced.** Before, CVSS 5.0 / no known exploitation / crown jewel / high exposure was NEVER.

### 4. Controls lower the ranking; only strong controls can move the bucket

**Rule.** Partial controls (for example ACLs or monitoring only) lower the item's ordering score by 0.5 points so it ranks lower inside its bucket. They never move an item from one bucket to another. Strong controls lower the ordering score by 1.0 point, and (as described in the earlier rules) can also lower the bucket by one level.

**Why strong controls also lower the score.** Originally only partial controls changed the score, so an item with strong controls ranked *above* the same item with partial controls whenever strong controls could not move the bucket (for example an actively exploited item already at NEXT, which can never go lower). That was backwards: better protection must never rank an item higher. Strong controls actually stop attacks, so they earn twice the credit of partial ones. The score still only orders items inside a bucket and never decides the bucket, so this changes the order of a list, not any decision.

**Why.** Monitoring tells you an attack is happening. It does not stop it. ACLs that are only partly effective do not reliably stop it either. Moving an item to a less urgent bucket because of controls that may not hold would create false comfort. Strong controls (segmentation, virtual patching, allow-listing) do stop attacks, so they still lower the bucket by one level.

**What it replaced.** Before, partial controls subtracted a fixed 1.05 points from CVSS before the rules ran. That caused sudden jumps ("cliffs"): CVSS 7.5 dropped from NOW to NEXT, while CVSS 8.5 stayed at NOW. The number was hard to justify, and it also quietly changed outcomes at the 4.0 line. Treating partial controls as a ranking aid removes all of that.

**Trade-off.** Teams with solid partial controls will see more items in NOW than before. That is the cautious direction, and moving to strong controls (or patching) is how to reduce them.

### 5. A crown jewel with a high CVSS score is never NEVER (approved 2026-10-14)

**Rule.** A crown jewel asset with CVSS of 7.0 or more (the "High" line in the settings) is at least NEXT, at any exposure and with any compensating controls.

**Why.** Decision 3 only covered *exposed* crown jewels. A 9.8 on a crown jewel with Low exposure and strong controls was NEVER, because strong controls lowered NEXT by one level. That depends on two claims that nobody checks: that exposure really is Low, and that the controls really are strong. If either is wrong, "never fix" is the wrong answer on the most important asset. NEXT puts the item on a schedule so a person has to make a conscious decision, which is the same reason as decision 3.

**What stays the same.** Strong controls still lower the ordering score by 1.0, so the item ranks below the same item with no controls. Standard assets are not affected, important assets have their own, higher line (decision 8), and a crown jewel under 7.0 can still be NEVER.

**What it replaced.** Before, CVSS 9.8 / no known exploitation / crown jewel / low exposure / strong controls was NEVER.

### 6. The recommended action agrees with the bucket (approved 2026-10-14)

**Rule.** A NEVER result no longer says "Apply the patch". It says "No scheduled fix" and what to do at a routine opportunity: apply the patch with routine maintenance if convenient (patch available), apply the vendor's patch once it ships (pending), or keep the device isolated and include it in replacement planning (end of life). The wording only changes the text; the bucket and the ordering score are unchanged.

**Why.** The screen said "No scheduled remediation" and "Apply the patch" at the same time.

### 7. The CVSS vector reminds you to verify Low exposure; it does not decide the bucket (approved 2026-10-14)

**Rule.** When the vector's attack vector is Network (or the vector's modified attack vector says Network) and Network exposure is Low, Assess shows a note under the exposure control and adds an "Exposure check" line to the reasoning and the summaries, and Batch adds the line to the row's details and an `exposure_check` export column. The note says that Low must be verified by testing, and that any device that can reach the asset on the network could attack it.

**Why.** The attack vector says how the flaw is reached. A flaw that is attackable over a network is a reason to doubt a Low exposure that was assumed rather than tested (decision 2). A rule that moved the bucket from the vector would count the exposure input twice, so it is a note only. It can be made a rule later, with its own tests, once real exports show how often it matters.

### 8. An important asset with a critical CVSS score is never NEVER (approved 2026-10-15)

**Rule.** An important asset with CVSS of 9.0 or more (the "Critical" line in the settings) is at least NEXT, at any exposure and with any compensating controls. A standard asset has no such floor, and an important asset under 9.0 can still be NEVER.

**Why.** After decision 5 an important asset with a 9.8, Low exposure and strong controls was still NEVER, on the strength of one claim ("strong controls") that nothing in the tool checks. The frameworks that OT teams use do not let a controls claim make a flaw disappear: CVSS lets a segmented component's attack vector be scored as Adjacent only when there is high confidence it is unavailable from the internet, and the effect is modest; CISA's SSVC has no "never" outcome (its lowest one, Track, keeps the item under review); and IEC TR 62443-2-3 expects every deferred patch to be documented and justified with its compensating controls. NEXT puts the item on a schedule so a person has to decide, which is what those documents ask for. The bar is higher than for a crown jewel (9.0 instead of 7.0) because the asset matters less.

**What stays the same.** Strong controls still lower the ordering score by 1.0. The change reaches one corner only: important asset, no known exploitation, CVSS 9.0 or more, strong controls (without strong controls such an item is already NEXT).

**What it replaced.** Before, CVSS 9.8 / no known exploitation / important asset / low exposure / strong controls was NEVER.

## Things that deliberately do not decide a bucket

- **The CVSS attack vector** (decision 7). It adds a note when exposure is Low, nothing more.
- **The CVSS environmental score** (see [CVSS.md](CVSS.md)). It is shown next to the base score, but the bucket uses the base score only. The asset criticality, exposure and controls inputs already say the same things about your environment, and counting them twice would change the rules (approved 2026-10-11: show alongside, do not change the bucket). To make it drive the bucket, that has to be a deliberate policy change with its own rule and tests.
- **CISA ICS advisories** (see [THREAT_DATA.md](THREAT_DATA.md)). A CVE that a published CISA advisory names gets a neutral chip, a line in the reasoning and the advisory's link, but the bucket and the ordering score are unchanged. An advisory says a vendor and product are affected and what to do; it does not say the flaw is being exploited, so it adds context rather than urgency. KEV and EPSS already carry the exploitation signal. This was stated to the project owner before the feature was built; making advisories drive the bucket would be a deliberate policy change with its own rule and tests.

## Examples

Generated from the current rules.

| Situation | CVSS | Threat | Asset | Exposure | Controls | Patch | Result |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Active, exposed crown jewel, very low CVSS | 2.0 | Active | Crown | High | None | Available | **NOW** |
| Low CVSS, active, standard asset | 2.0 | Active | Standard | High | None | Available | **NEXT** |
| Exposed crown jewel, no exploit | 5.0 | None | Crown | High | None | Available | **NEXT** |
| Same, but only medium exposure | 5.0 | None | Crown | Medium | None | Available | **NEVER** |
| Exposed crown jewel, strong controls | 8.0 | None | Crown | High | Strong | Available | **NEXT** |
| Partial controls, public exploit | 7.5 | Public | Standard | High | Partial | Available | **NOW** |
| Same, no controls | 7.5 | Public | Standard | High | None | Available | **NOW** |
| Active, standard asset, low exposure | 9.0 | Active | Standard | Low | None | Available | **NEXT** |
| Active, crown jewel, low exposure | 9.0 | Active | Crown | Low | None | Available | **NOW** |
| High CVSS, no exploit, standard, low exposure | 8.0 | None | Standard | Low | None | Available | **NEVER** |
| Same, end-of-life device with strong controls | 8.0 | None | Standard | Low | Strong | End of life | **NEXT** |
| Active, reachable, strong controls | 9.0 | Active | Standard | High | Strong | Available | **NEXT** |
| High CVSS crown jewel, low exposure, strong controls | 9.8 | None | Crown | Low | Strong | Available | **NEXT** |
| Important asset, same inputs | 9.8 | None | Important | Low | Strong | Available | **NEXT** |
| Important asset just under the critical line | 8.9 | None | Important | Low | Strong | Available | **NEVER** |

## Properties the tests enforce

- **Monotonic:** making any single input worse (higher CVSS, stronger threat, more critical asset, more exposure, weaker controls, worse patch status) never lowers the priority.
- **Partial controls never change a bucket** for any combination of the other inputs.
- **Better controls never rank higher:** for every combination of the other inputs, the ordering score with no controls is at least the score with partial controls, which is at least the score with strong controls.
- **The CVSS environmental score never changes a priority or an ordering score**: vectors with and without environmental metrics give identical results.
- **CISA ICS advisories never change a priority or an ordering score**: the same item with and without the advisories loaded gives identical results.
- **Boundaries** sit exactly where documented: 4.0, 7.0 and 9.0 use "greater than or equal to".
- **The action agrees with the bucket:** for every combination of inputs, the action starts with "No scheduled fix" if and only if the result is NEVER.
- **A crown jewel with CVSS of 7.0 or more, and an important asset with CVSS of 9.0 or more, is never NEVER**, whatever the exposure, controls or patch status.

## When to revisit

- If you see many NOW results caused only by decision 1, check whether "high exposure" and "crown jewel" are being chosen too freely.
- If partial controls turn out to be reliable in your environment, move them to strong, or propose a documented rule for them.
