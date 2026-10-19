// The OT Triage rules (docs/POLICY.md) for the browser demo. This is a port of prioritizer.py and of the "what would
// change this" part of explain.py. It must give exactly the answers the Python code gives: demo/golden.json holds
// the Python answers for thousands of inputs and `node demo/check_rules.js` (run by the test suite) compares them.
// It reads nothing, stores nothing and sends nothing.
(function (root) {
  "use strict";

  var VERSION = "0.10.0";
  var NOW = "NOW", NEXT = "NEXT", NEVER = "NEVER";
  var ORDER = [NOW, NEXT, NEVER];
  var URGENCY = {NOW: 2, NEXT: 1, NEVER: 0};
  var HIGH = 7.0, CRITICAL = 9.0;                         // the default CVSS lines (the real tool lets you adjust them)
  var PARTIAL_SCORE_CREDIT = 0.5, STRONG_SCORE_CREDIT = 1.0;
  var THREAT_PTS = {active: 10, public: 7, none: 3};
  var ASSET_PTS = {crown: 10, important: 7, standard: 3};
  var EXPOSURE_PTS = {high: 10, medium: 7, low: 3};

  // Enumerations in the order the Python code defines them, with the short labels the application uses.
  var FIELDS = [
    ["threat", "the threat", [["active", "Active"], ["public", "Public exploit"], ["none", "None"]]],
    ["asset", "the asset", [["crown", "Crown jewel"], ["important", "Important"], ["standard", "Standard"]]],
    ["exposure", "the exposure", [["high", "High"], ["medium", "Medium"], ["low", "Low"]]],
    ["patch", "the patch status", [["available", "Available"], ["pending", "Pending"], ["eol", "None (end of life)"]]],
    ["controls", "compensating controls", [["none", "None"], ["partial", "Partial"], ["strong", "Strong"]]]
  ];

  var HEADLINES = {
    NOW: ["Act immediately", "Remediate or mitigate right away."],
    NEXT: ["Schedule remediation", "Plan it into the next patch cycle (roughly 30-90 days)."],
    NEVER: ["No scheduled remediation", "Re-evaluate if conditions change."]
  };

  var NEVER_ACTIONS = {
    available: "No scheduled fix; apply the patch with routine maintenance if convenient",
    pending: "No scheduled fix; apply the vendor's patch with routine maintenance once it ships",
    eol: "No scheduled fix; keep the device isolated and include it in replacement planning"
  };

  var EXPOSURE_HINT = "The CVSS vector says this flaw can be exploited over a network. Choosing Low exposure asserts " +
    "that no IT or internet path reaches this device (for example, it is air-gapped or fully segmented), verified by " +
    "testing. If an attacker gets into the OT network, any device that can route to this one could exploit it. " +
    "Confirm the isolation by testing, or choose Medium. This note does not change the priority.";

  function fmt(value) {
    var text = value.toFixed(2).replace(/0+$/, "");
    return text.charAt(text.length - 1) === "." ? text + "0" : text;
  }

  function shift(priority, steps) {
    var index = ORDER.indexOf(priority) + steps;
    return ORDER[Math.max(0, Math.min(index, ORDER.length - 1))];
  }

  function factors(cvss, i, notes) {
    var list = [
      ["CVSS " + cvss.toFixed(1), cvss >= HIGH ? "raise" : cvss < 4.0 ? "lower" : "neutral"],
      {active: ["Actively exploited", "raise"], public: ["Public or likely exploit", "raise"],
        none: ["No known exploitation", "neutral"]}[i.threat],
      {crown: ["Crown jewel", "raise"], important: ["Important asset", "neutral"],
        standard: ["Standard asset", "neutral"]}[i.asset],
      {high: ["Exposure: High", "raise"], medium: ["Exposure: Medium", "raise"],
        low: ["Exposure: Low", "lower"]}[i.exposure],
      {available: ["Patch available", "neutral"], pending: ["Patch pending", "raise"],
        eol: ["End of life, no patch", "raise"]}[i.patch],
      {none: ["No controls", "neutral"], partial: ["Partial controls (ranking only)", "neutral"],
        strong: ["Strong controls", "lower"]}[i.controls]
    ];
    return list.concat(notes);
  }

  // i = {cvss, threat, asset, exposure, controls, patch}; returns {priority, score, reasons, action, factors}.
  function prioritize(i) {
    var cvss = i.cvss;
    if (!(cvss >= 0 && cvss <= 10)) { throw new RangeError("CVSS score must be between 0.0 and 10.0"); }
    var reachable = i.exposure === "high" || i.exposure === "medium";
    var exposedCrown = i.asset === "crown" && i.exposure === "high";
    var reasons = [], notes = [], priority, action;

    if (i.threat === "active") {
      if (reachable) {
        priority = NOW;
        reasons.push("Actively exploited and reachable from outside the asset's trust zone");
      } else if (i.asset === "crown") {
        priority = NOW;
        reasons.push("Actively exploited and the asset is a crown jewel");
      } else {
        priority = NEXT;
        reasons.push("Actively exploited, but low exposure and not a crown jewel");
      }
    } else if (i.threat === "public") {
      if (i.exposure === "high" && cvss >= HIGH) {
        priority = NOW;
        reasons.push("Public exploit, internet-exposed, and CVSS >= " + fmt(HIGH));
      } else {
        priority = NEXT;
        reasons.push("Public exploit available");
      }
    } else if (cvss >= CRITICAL && i.exposure === "high" && i.asset === "crown") {
      priority = NOW;
      reasons.push("Critical CVSS on an internet-exposed crown jewel, even without known exploitation");
    } else if (cvss >= HIGH && (reachable || i.asset !== "standard")) {
      priority = NEXT;
      reasons.push("High CVSS (>= " + fmt(HIGH) + ") with exposure or elevated asset value");
    } else {
      priority = NEVER;
      reasons.push("No known exploitation and low combined risk; re-evaluate if conditions change");
    }

    if (cvss < 4.0 && priority === NOW) {
      if (i.threat === "active" && exposedCrown) {
        reasons.push("Kept at NOW despite CVSS < 4.0: actively exploited, exposed crown jewel");
        notes.push(["Low-CVSS cap waived: exposed crown jewel", "raise"]);
      } else {
        priority = NEXT;
        reasons.push("Capped at NEXT: CVSS < 4.0");
        notes.push(["Capped at NEXT: CVSS below 4.0", "lower"]);
      }
    }

    if (i.patch === "available") {
      action = "Apply the patch";
      if (i.controls === "strong") {
        var lowered = shift(priority, 1);
        if (i.threat === "active" && lowered === NEVER) { lowered = NEXT; }
        if (lowered !== priority) {
          reasons.push("Lowered " + priority + " -> " + lowered + ": strong compensating controls");
          priority = lowered;
        }
      }
    } else {
      if (cvss >= 4.0) {
        if (i.controls === "strong") {
          reasons.push("No patch, but strong compensating controls: priority not raised");
        } else {
          var raised = shift(priority, -1);
          if (raised !== priority) {
            reasons.push("Raised " + priority + " -> " + raised + ": no patch and no effective compensating controls");
            priority = raised;
          } else {
            reasons.push("No patch and no effective compensating controls (already at highest urgency)");
          }
        }
      }
      if (i.patch === "pending") {
        action = "Mitigate now with compensating controls; monitor the vendor advisory and " +
          "patch as soon as the fix ships (re-evaluate on release)";
        reasons.push("Vendor-supported: exposure window is temporary");
      } else {
        action = "Isolate/segment and monitor; plan replacement or migration (no fix will ever ship)";
        reasons.push("End-of-life: exposure is permanent and accumulates over time");
        if (cvss >= HIGH && priority === NEVER) {
          priority = NEXT;
          reasons.push("Floored at NEXT: unpatchable device with CVSS >= " + fmt(HIGH) + " needs a replacement plan");
          notes.push(["Floored at NEXT: end of life", "raise"]);
        }
      }
    }

    if (exposedCrown && cvss >= 4.0 && priority === NEVER) {
      priority = NEXT;
      reasons.push("Floored at NEXT: internet-exposed crown jewel with CVSS >= 4.0");
      notes.push(["Floored at NEXT: exposed crown jewel", "raise"]);
    }
    if (i.asset === "crown" && cvss >= HIGH && priority === NEVER) {
      priority = NEXT;
      reasons.push("Floored at NEXT: crown jewel with CVSS >= " + fmt(HIGH) + ", whatever the exposure or controls");
      notes.push(["Floored at NEXT: high-CVSS crown jewel", "raise"]);
    }
    if (i.asset === "important" && cvss >= CRITICAL && priority === NEVER) {
      priority = NEXT;
      reasons.push("Floored at NEXT: important asset with CVSS >= " + fmt(CRITICAL) + ", whatever the exposure or controls");
      notes.push(["Floored at NEXT: critical-CVSS important asset", "raise"]);
    }
    if (priority === NEVER) { action = NEVER_ACTIONS[i.patch]; }

    var score = cvss * 0.3 + THREAT_PTS[i.threat] * 0.25 + ASSET_PTS[i.asset] * 0.25 + EXPOSURE_PTS[i.exposure] * 0.2;
    if (i.controls === "partial") {
      score -= PARTIAL_SCORE_CREDIT;
      reasons.push("Partial controls: ranked lower within the bucket; the bucket itself is unchanged");
    } else if (i.controls === "strong") {
      score -= STRONG_SCORE_CREDIT;
      reasons.push("Strong controls: ranked lower within the bucket, on top of any bucket change above");
    }
    score = Math.max(0, Math.min(10, score));
    return {priority: priority, score: Number(score.toFixed(2)), reasons: reasons, action: action,
      factors: factors(cvss, i, notes)};
  }

  function sortedFactors(list) {
    var order = {raise: 0, lower: 1, neutral: 2};
    function rank(f) { return f[1] in order ? order[f[1]] : 3; }
    return list.slice().sort(function (a, b) { return rank(a) - rank(b); });
  }

  function labelOf(field, value) {
    for (var f = 0; f < FIELDS.length; f++) {
      if (FIELDS[f][0] === field) {
        for (var m = 0; m < FIELDS[f][2].length; m++) {
          if (FIELDS[f][2][m][0] === value) { return FIELDS[f][2][m][1]; }
        }
      }
    }
    return value;
  }

  function copyWith(i, field, value) {
    var c = {cvss: i.cvss, threat: i.threat, asset: i.asset, exposure: i.exposure, controls: i.controls, patch: i.patch};
    c[field] = value;
    return c;
  }

  // The single input changes that would move the bucket, as the lines the application shows.
  function whatIfLines(i) {
    var current = prioritize(i).priority, more = [], less = [];
    function add(changed, text) {
      var change = {priority: changed, text: text};
      (URGENCY[changed] > URGENCY[current] ? more : less).push(change);
    }
    FIELDS.forEach(function (field) {
      field[2].forEach(function (member) {
        if (member[0] === i[field[0]]) { return; }
        var changed = prioritize(copyWith(i, field[0], member[0])).priority;
        if (changed !== current) { add(changed, "if " + field[1] + " were " + member[1]); }
      });
    });
    var here = Math.round(i.cvss * 10), t, changed;
    for (t = here + 1; t <= 100; t++) {
      changed = prioritize(copyWith(i, "cvss", t / 10)).priority;
      if (changed !== current) { add(changed, "if the CVSS score were at or above " + (t / 10).toFixed(1)); break; }
    }
    for (t = here - 1; t >= 0; t--) {
      changed = prioritize(copyWith(i, "cvss", t / 10)).priority;
      if (changed !== current) { add(changed, "if the CVSS score were at or below " + (t / 10).toFixed(1)); break; }
    }
    function byUrgency(a, b) {
      if (URGENCY[a.priority] !== URGENCY[b.priority]) { return URGENCY[b.priority] - URGENCY[a.priority]; }
      return a.text < b.text ? -1 : a.text > b.text ? 1 : 0;
    }
    more.sort(byUrgency);
    less.sort(byUrgency);
    var lines = less.concat(more).map(function (c) { return c.priority + " " + c.text; });
    if (!more.length && !less.length) {
      lines.push("No single change to one input moves this item.");
    } else if (!more.length && current === NOW) {
      lines.push("Already at the highest urgency, so nothing makes it more urgent.");
    }
    return {current: current, lines: lines, more: more, less: less};
  }

  // A reminder to verify Low exposure when the CVSS vector's attack vector is Network. It never changes a bucket.
  function exposureHint(networkAttackable, exposure) {
    return networkAttackable && exposure === "low" ? EXPOSURE_HINT : "";
  }

  var api = {VERSION: VERSION, FIELDS: FIELDS, HEADLINES: HEADLINES, EXPOSURE_HINT: EXPOSURE_HINT,
    prioritize: prioritize, sortedFactors: sortedFactors, whatIfLines: whatIfLines, exposureHint: exposureHint,
    labelOf: labelOf};
  if (typeof module === "object" && module.exports) { module.exports = api; } else { root.OTTriageRules = api; }
})(this);
