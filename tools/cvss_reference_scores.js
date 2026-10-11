// Usage: node cvss_reference_scores.js <vectors.json> <out.json>
// Scores every vector (base and environmental) with the official FIRST calculators, which must sit next to this script (the Python tool
// tools/verify_cvss_against_reference.py downloads them first).
const fs = require("fs"), vm = require("vm");
const [vectorsFile, outFile] = process.argv.slice(2);
const dir = __dirname;
function sandbox(files, extra = "") {
  const ctx = {}; vm.createContext(ctx);
  for (const f of files) vm.runInContext(fs.readFileSync(`${dir}/${f}`, "utf8"), ctx);
  if (extra) vm.runInContext(extra, ctx);
  return ctx;
}
const v31 = sandbox(["cvsscalc31.js"], "globalThis.api = CVSS31;").api;
const v30 = sandbox(["cvsscalc30.js"], "globalThis.api = CVSS;").api;
const v4 = sandbox(["cvss_lookup.js", "max_composed.js", "max_severity.js", "cvss_score.js"]);
const OPTIONAL4 = ["E","CR","IR","AR","MAV","MAC","MAT","MPR","MUI","MVC","MVI","MVA","MSC","MSI","MSA","S","AU","R","V","RE","U"];
const BASE4 = new Set(["AV","AC","AT","PR","UI","VC","VI","VA","SC","SI","SA"]);
function baseOnly4(vector) {
  const [prefix, ...parts] = vector.split("/");
  return [prefix, ...parts.filter(p => BASE4.has(p.split(":")[0]))].join("/");
}
function score4(vector) {
  const sel = {}; for (const m of OPTIONAL4) sel[m] = "X";
  for (const part of vector.split("/").slice(1)) { const [k, v] = part.split(":"); sel[k] = v; }
  const mv = v4.macroVector(sel);
  return v4.cvss_score(sel, v4.cvssLookup_global, v4.maxSeverity, mv);
}
const input = JSON.parse(fs.readFileSync(vectorsFile, "utf8")), out = {};
// Each result is [base score, environmental score]; for CVSS 4.0 the second is the score with every metric applied.
for (const vector of input) {
  if (vector.startsWith("CVSS:3.1/") || vector.startsWith("CVSS:3.0/")) {
    const r = (vector.startsWith("CVSS:3.1/") ? v31 : v30).calculateCVSSFromVector(vector);
    out[vector] = [Number(r.baseMetricScore), Number(r.environmentalMetricScore)];
  } else out[vector] = [score4(baseOnly4(vector)), score4(vector)];
}
fs.writeFileSync(outFile, JSON.stringify(out));
console.log("scored", Object.keys(out).length);
