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

## Properties the tests enforce

- **Monotonic:** making any single input worse (higher CVSS, stronger threat, more critical asset, more exposure, weaker controls, worse patch status) never lowers the priority.
- **Partial controls never change a bucket** for any combination of the other inputs.
- **Better controls never rank higher:** for every combination of the other inputs, the ordering score with no controls is at least the score with partial controls, which is at least the score with strong controls.
- **Boundaries** sit exactly where documented: 4.0, 7.0 and 9.0 use "greater than or equal to".

## When to revisit

- If you see many NOW results caused only by decision 1, check whether "high exposure" and "crown jewel" are being chosen too freely.
- If partial controls turn out to be reliable in your environment, move them to strong, or propose a documented rule for them.
