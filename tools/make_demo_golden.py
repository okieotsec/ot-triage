"""Write demo/golden.json: what the Python rules answer for thousands of inputs, for the browser demo to match.

The demo (demo/rules.js) is a second copy of the rules, in JavaScript. This file is how the two are kept the same:
`node demo/check_rules.js` compares the JavaScript with it, and test_demo.py compares it with the Python rules, so a
rule change that is not mirrored in the demo fails the test suite.

Usage:  python3 tools/make_demo_golden.py          (rewrite demo/golden.json)
        python3 tools/make_demo_golden.py --check  (exit 1 if the file is not what the rules give now)
"""
import itertools
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "demo" / "golden.json"
# The lines of the rules (4.0, 7.0, 9.0) and a score on each side of each, plus the ends and some middles.
SCORES = [0.0, 2.0, 3.9, 4.0, 5.0, 6.9, 7.0, 8.0, 8.9, 9.0, 9.8, 10.0]


def build():
    """Return the golden data as a dict (the same every time for the same rules).

    Every text appears once in "strings" and the cases refer to it by position, which keeps the file small.
    """
    sys.path.insert(0, str(ROOT))      # the application's modules live next to the tools folder
    import explain
    from prioritizer import Asset, Controls, Exposure, Patch, Threat
    from version import __version__

    threats = {Threat.ACTIVE: "active", Threat.PUBLIC: "public", Threat.NONE: "none"}
    assets = {Asset.CROWN: "crown", Asset.IMPORTANT: "important", Asset.STANDARD: "standard"}
    exposures = {Exposure.HIGH: "high", Exposure.MEDIUM: "medium", Exposure.LOW: "low"}
    controls_names = {Controls.NONE: "none", Controls.PARTIAL: "partial", Controls.STRONG: "strong"}
    patches = {Patch.AVAILABLE: "available", Patch.PENDING: "pending", Patch.EOL: "eol"}
    strings, positions = [], {}

    def text(value):
        if value not in positions:
            positions[value] = len(strings)
            strings.append(value)
        return positions[value]

    cases = {}
    for cvss, threat, asset, exposure, controls, patch in itertools.product(
            SCORES, threats, assets, exposures, controls_names, patches):
        inputs = explain.AssessInputs(cvss, threat, asset, exposure, controls, patch)
        result = inputs.run()
        key = "|".join([f"{cvss:.1f}", threats[threat], assets[asset], exposures[exposure], controls_names[controls],
                        patches[patch]])
        cases[key] = {
            "priority": result.priority,
            "score": result.score,
            "action": text(result.action),
            "reasons": [text(r) for r in result.reasons],
            "factors": [[text(f.label), f.direction] for f in explain.sorted_factors(result.factors)],
            "what_if": [text(line) for line in explain.what_if_lines(explain.what_would_change(inputs))],
        }
    return {
        "version": __version__,
        "key": "cvss|threat|asset|exposure|controls|patch",
        "headlines": {k: list(v) for k, v in explain.HEADLINES.items()},
        "exposure_hint": explain.EXPOSURE_HINT,
        "strings": strings,
        "cases": cases,
    }


def render(data):
    """The text of the file: compact, with a fixed order, so a rule change shows as a clean diff."""
    return json.dumps(data, separators=(",", ":"), sort_keys=True, ensure_ascii=True) + "\n"


def main(argv):
    text = render(build())
    if "--check" in argv:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != text:
            print("demo/golden.json is out of date: run python3 tools/make_demo_golden.py", file=sys.stderr)
            return 1
        print("demo/golden.json is up to date")
        return 0
    OUTPUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)} ({len(text):,} bytes, {len(json.loads(text)['cases']):,} cases)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
