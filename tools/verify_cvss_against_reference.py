"""Check cvss.py against the official FIRST calculators for every possible base vector (developer tool).

Needs Node.js and an internet connection. It downloads FIRST's reference calculators into a temporary folder, scores
all 2,592 + 2,592 + 104,976 base vectors, and 60,000 vectors per version that also set temporal, threat, environmental
and supplemental metrics, with them, and compares each result with cvss.py. Use --refresh-fixtures to
rewrite cvss_reference.json, the recorded results that the offline unit tests use.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess  # nosec B404 - runs Node.js on files this tool just downloaded
import sys
import tempfile
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
from cvss_vectors import VERSIONS, all_vectors, environmental_vectors  # noqa: E402

import cvss  # noqa: E402

SOURCES = {
    "cvsscalc30.js": "https://www.first.org/cvss/calculator/cvsscalc30.js",
    "cvsscalc31.js": "https://www.first.org/cvss/calculator/cvsscalc31.js",
    **{name: f"https://raw.githubusercontent.com/FIRSTdotorg/cvss-v4-calculator/main/{name}"
       for name in ("cvss_lookup.js", "max_composed.js", "max_severity.js", "cvss_score.js")},
}
# SHA-256 of each reference file the recorded results were produced with. A mismatch stops the tool: either the
# upstream project changed (review it, then update these) or the download was tampered with.
PINNED_SHA256 = {
    "cvsscalc30.js": "382adaab554ceba55251eaa2550108bc81eea951427ad7cbdb961b8b67508c69",
    "cvsscalc31.js": "0f9b9d8000cbc0cc2201170bc9fcbab35a2c728746e52082cb88419db6b545eb",
    "cvss_lookup.js": "d533fe625d95e15b7b488a4bf93dab5f7df16b7e38b0c8ee01281d7b31a8165e",
    "max_composed.js": "be707cc82c17993a04a84e47b1a8aaa1d0d212b56852254659ce77fd7d959f63",
    "max_severity.js": "f838ecb41bfd5114456e7fa7df8a8449ca2735c176867886fa34bd011dee0b24",
    "cvss_score.js": "453ce6767b5c3939b51d1f21315f2649e47b5abeca674be287e94b524472a1bc",
}
FIXTURE = HERE.parent / "cvss_reference.json"


def check_pins():
    """Fail early if the pinned list and the download list ever drift apart."""
    if set(PINNED_SHA256) != set(SOURCES):
        raise SystemExit("PINNED_SHA256 and SOURCES list different files")


def digest(version, scores):
    """Return a SHA-256 over 'vector score' lines in the fixed order."""
    lines = "\n".join(f"{v} {scores[v]:.1f}" for v in all_vectors(version))
    return hashlib.sha256(lines.encode()).hexdigest()


def environmental_digest(rows):
    """Return a SHA-256 over 'vector base environmental' lines for vectors that set an environmental metric."""
    lines = "\n".join(f"{v} {base:.1f} {env:.1f}" for v, base, env in rows)
    return hashlib.sha256(lines.encode()).hexdigest()


def sample(version, scores):
    """Pick a readable, deterministic sample: one vector per v4 MacroVector, plus an even stride."""
    vectors = list(all_vectors(version))
    chosen = {v: scores[v] for v in vectors[:: max(1, len(vectors) // 300)]}
    if version == "4.0":
        seen = set()
        for vector in vectors:
            macro = cvss._macro_vector(cvss._selection(cvss.parse_vector(vector).metrics))
            if macro not in seen:
                seen.add(macro)
                chosen[vector] = scores[vector]
    return sorted(chosen.items())


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--refresh-fixtures", action="store_true", help="rewrite cvss_reference.json")
    args = parser.parse_args()
    check_pins()
    if not shutil.which("node"):
        sys.exit("Node.js is required to run the official calculators.")
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        for name, url in SOURCES.items():
            if not url.startswith("https://"):
                raise SystemExit(f"refusing non-HTTPS source {url}")
            # Fixed https:// URLs from SOURCES (checked above)
            with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310  # nosec B310  # nosem
                data = response.read()
            if hashlib.sha256(data).hexdigest() != PINNED_SHA256[name]:
                raise SystemExit(f"{name} differs from the pinned version; review the upstream change before using it")
            (work / name).write_bytes(data)
        shutil.copy(HERE / "cvss_reference_scores.js", work / "cvss_reference_scores.js")
        base_sets = {version: list(all_vectors(version)) for version in VERSIONS}
        env_sets = {version: environmental_vectors(version) for version in VERSIONS}
        vectors = [v for version in VERSIONS for v in (*base_sets[version], *env_sets[version])]
        (work / "vectors.json").write_text(json.dumps(vectors))
        subprocess.run(["node", "cvss_reference_scores.js", "vectors.json", "scores.json"], cwd=work,  # noqa: S607  # nosec B603 B607
                       check=True, env={**os.environ, "NODE_OPTIONS": ""})
        reference = json.loads((work / "scores.json").read_text())
    failed = False
    environmental_rows = {}
    for version in VERSIONS:
        mine = {v: cvss.parse_vector(v).score for v in base_sets[version]}
        wrong = [(v, reference[v][0], mine[v]) for v in mine if abs(reference[v][0] - mine[v]) > 1e-9]
        print(f"CVSS {version} base:          {len(mine) - len(wrong)}/{len(mine)} vectors identical to the official "
              "calculator")
        for row in wrong[:10]:
            print("   differs:", row)
        failed = failed or bool(wrong)
        parsed = {v: cvss.parse_vector(v) for v in env_sets[version]}
        wrong_base = [(v, reference[v][0], p.score) for v, p in parsed.items() if abs(reference[v][0] - p.score) > 1e-9]
        rows = [(v, reference[v][0], reference[v][1]) for v, p in parsed.items() if p.has_environmental]
        wrong_env = [(v, ref, parsed[v].environmental_score) for v, _base, ref in rows
                     if abs(ref - parsed[v].environmental_score) > 1e-9]
        print(f"CVSS {version} base (with extra metrics): {len(parsed) - len(wrong_base)}/{len(parsed)} identical")
        print(f"CVSS {version} environmental: {len(rows) - len(wrong_env)}/{len(rows)} vectors identical to the "
              "official calculator")
        for row in (wrong_base + wrong_env)[:10]:
            print("   differs:", row)
        failed = failed or bool(wrong_base) or bool(wrong_env)
        environmental_rows[version] = rows
    if args.refresh_fixtures and not failed:
        fixture = {"note": "Scores from the official FIRST calculators; regenerate with "
                           "tools/verify_cvss_against_reference.py", "counts": {}, "digests": {}, "samples": {},
                   "environmental": {}}
        for version in VERSIONS:
            scores = {v: reference[v][0] for v in base_sets[version]}
            fixture["counts"][version] = len(scores)
            fixture["digests"][version] = digest(version, scores)
            fixture["samples"][version] = sample(version, scores)
            rows = environmental_rows[version]
            fixture["environmental"][version] = {
                "vectors": len(env_sets[version]), "scored": len(rows), "digest": environmental_digest(rows),
                "samples": [[v, b, e] for v, b, e in rows[:: max(1, len(rows) // 150)]]}
        FIXTURE.write_text(json.dumps(fixture, indent=1) + "\n", encoding="utf-8")
        print(f"wrote {FIXTURE.name}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
