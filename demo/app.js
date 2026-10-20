// The demo page: reads the six answers, runs the rules (rules.js) and shows the result.
// It uses no network, no storage and no cookies, and it writes to the page only with textContent.
(function () {
  "use strict";
  var R = window.OTTriageRules;

  var PRESETS = [
    {title: "Actively exploited, but only a CVSS 3.1, on an exposed crown jewel",
      v: {cvss: "3.1", threat: "active", asset: "crown", exposure: "high", patch: "available", controls: "none", vector: ""}},
    {title: "A 9.8 on a crown jewel you say is isolated, with strong controls",
      v: {cvss: "9.8", threat: "none", asset: "crown", exposure: "low", patch: "available", controls: "strong", vector: "network"}},
    {title: "An 8.9 on an important asset behind strong controls",
      v: {cvss: "8.9", threat: "none", asset: "important", exposure: "low", patch: "available", controls: "strong", vector: ""}},
    {title: "Actively exploited, but a standard asset nothing can reach",
      v: {cvss: "9.0", threat: "active", asset: "standard", exposure: "low", patch: "available", controls: "none", vector: ""}},
    {title: "A 9.8 on an end-of-life device",
      v: {cvss: "9.8", threat: "none", asset: "standard", exposure: "low", patch: "eol", controls: "none", vector: ""}}
  ];

  var form = document.getElementById("inputs");
  function $(id) { return document.getElementById(id); }

  function checked(name) {
    var box = form.querySelector('input[name="' + name + '"]:checked');
    return box ? box.value : "";
  }

  function fill(list, items, build) {
    list.textContent = "";
    items.forEach(function (item) { list.appendChild(build(item)); });
  }

  function listItem(text) {
    var li = document.createElement("li");
    li.textContent = text;
    return li;
  }

  function whatIfItem(line) {
    var li = document.createElement("li"), space = line.indexOf(" ");
    var bucket = document.createElement("strong");
    bucket.textContent = line.slice(0, space);
    if (["NOW", "NEXT", "NEVER"].indexOf(line.slice(0, space)) === -1) { return listItem(line); }
    li.appendChild(bucket);
    li.appendChild(document.createTextNode(line.slice(space)));
    return li;
  }

  function parseScore(text) {
    var value = Number(String(text).trim());
    if (String(text).trim() === "" || !isFinite(value) || value < 0 || value > 10) { return null; }
    return Math.round(value * 10) / 10;
  }

  function update() {
    var cvss = parseScore($("cvss").value);
    $("problem").hidden = cvss !== null;
    $("answer").hidden = cvss === null;
    ["action-card", "reasons-card", "whatif-card"].forEach(function (id) { $(id).hidden = cvss === null; });
    if (cvss === null) {
      $("problem").textContent = "Enter a CVSS base score from 0.0 to 10.0.";
      $("bar-badge").textContent = "";
      $("bar-badge").setAttribute("data-bucket", "");
      $("bar-text").textContent = "Enter a CVSS score";
      return;
    }
    var input = {cvss: cvss, threat: checked("threat"), asset: checked("asset"), exposure: checked("exposure"),
      controls: checked("controls"), patch: checked("patch")};
    var result = R.prioritize(input), what = R.whatIfLines(input);
    var headline = R.HEADLINES[result.priority];
    $("badge").textContent = result.priority;
    $("badge").setAttribute("data-bucket", result.priority);
    $("headline").textContent = headline[0];
    $("bar-badge").textContent = result.priority;
    $("bar-badge").setAttribute("data-bucket", result.priority);
    $("bar-text").textContent = headline[0];
    $("sub").textContent = headline[1];
    $("score").value = result.score;
    $("score-text").textContent = result.score.toFixed(2) + " / 10";
    fill($("chips"), R.sortedFactors(result.factors), function (f) {
      var li = listItem(f[0]);
      li.setAttribute("data-direction", f[1]);
      return li;
    });
    $("action").textContent = result.action;
    fill($("reasons"), result.reasons, listItem);
    fill($("whatif"), what.lines, whatIfItem);
    var hint = R.exposureHint($("vector").value === "network", input.exposure);
    $("exposure-note").textContent = hint;
    $("exposure-note").hidden = hint === "";
  }

  function apply(values) {
    $("cvss").value = values.cvss;
    $("vector").value = values.vector;
    ["threat", "asset", "exposure", "controls", "patch"].forEach(function (name) {
      var box = form.querySelector('input[name="' + name + '"][value="' + values[name] + '"]');
      if (box) { box.checked = true; }
    });
    update();
  }

  fill($("presets"), PRESETS, function (preset) {
    var button = document.createElement("button");
    button.type = "button";
    button.textContent = preset.title;
    button.addEventListener("click", function () { apply(preset.v); });
    return button;
  });
  form.addEventListener("input", update);
  form.addEventListener("change", update);
  form.addEventListener("submit", function (event) { event.preventDefault(); });
  $("version").textContent = R.VERSION;
  update();
})();
