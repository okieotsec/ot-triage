// Compares demo/rules.js with demo/golden.json (what the Python rules answer). Run: node demo/check_rules.js
// Exit status 0 when every answer is identical, 1 otherwise.
"use strict";
const fs = require("fs");
const path = require("path");
const rules = require("./rules.js");
const golden = JSON.parse(fs.readFileSync(path.join(__dirname, "golden.json"), "utf8"));

let problems = 0, checked = 0;
function problem(message) {
  problems += 1;
  if (problems <= 20) { console.error("MISMATCH: " + message); }
}
function canonical(value) {
  if (Array.isArray(value)) { return "[" + value.map(canonical).join(",") + "]"; }
  if (value && typeof value === "object") {
    return "{" + Object.keys(value).sort().map(function (k) { return JSON.stringify(k) + ":" + canonical(value[k]); }).join(",") + "}";
  }
  return JSON.stringify(value);
}
function same(a, b) { return canonical(a) === canonical(b); }

if (rules.VERSION !== golden.version) {
  problem("rules.js is version " + rules.VERSION + " but the golden file is for " + golden.version);
}
if (!same(rules.HEADLINES, golden.headlines)) { problem("the headlines differ"); }
if (rules.EXPOSURE_HINT !== golden.exposure_hint) { problem("the exposure note differs"); }
if (rules.exposureHint(true, "low") !== golden.exposure_hint || rules.exposureHint(true, "medium") !== "" ||
    rules.exposureHint(false, "low") !== "") {
  problem("the exposure note is shown when it should not be, or not shown when it should");
}

Object.keys(golden.cases).forEach(function (key) {
  const parts = key.split("|");
  const input = {cvss: Number(parts[0]), threat: parts[1], asset: parts[2], exposure: parts[3], controls: parts[4],
    patch: parts[5]};
  const raw = golden.cases[key], got = rules.prioritize(input);
  const text = function (n) { return golden.strings[n]; };
  const want = {
    priority: raw.priority, score: raw.score, action: text(raw.action), reasons: raw.reasons.map(text),
    factors: raw.factors.map(function (f) { return [text(f[0]), f[1]]; }), what_if: raw.what_if.map(text)
  };
  checked += 1;
  const mine = {
    priority: got.priority, score: got.score, action: got.action, reasons: got.reasons,
    factors: rules.sortedFactors(got.factors), what_if: rules.whatIfLines(input).lines
  };
  Object.keys(want).forEach(function (field) {
    if (!same(mine[field], want[field])) {
      problem(key + ": " + field + "\n  python: " + JSON.stringify(want[field]) + "\n  js:     " + JSON.stringify(mine[field]));
    }
  });
});

if (problems) {
  console.error(problems + " difference(s) in " + checked + " cases: the demo rules no longer match the Python rules.");
  process.exit(1);
}
console.log("demo rules match the Python rules in all " + checked + " cases (version " + golden.version + ")");
