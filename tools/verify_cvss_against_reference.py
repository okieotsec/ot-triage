"""Check cvss.py against the official FIRST calculators for every possible base vector (developer tool).

Needs Node.js and an internet connection. It downloads FIRST's reference calculators into a temporary folder, scores
all 2,592 + 2,592 + 104,976 base vectors with them, and compares each result with cvss.py. Use --refresh-fixtures to
rewrite cvss_reference.json, the recorded results that the offline unit tests use.
"""
import argparse
import hashlib
import itertools
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
VERSIONS = ("3.0", "3.1", "4.0")


def all_vectors(version):
    """Yield every base vector of a version, in a fixed order."""
    base, _optional = cvss._allowed(version)
    names = list(base)
    for combo in itertools.product(*[base[name] for name in names]):
        yield f"CVSS:{version}/" + "/".join(f"{n}:{v}" for n, v in zip(names, combo, strict=True))


def check_pins():
    """Fail early if the pinned list and the download list ever drift apart."""
    if set(PINNED_SHA256) != set(SOURCES):
        raise SystemExit("PINNED_SHA256 and SOURCES list different files")


def digest(version, scores):
    """Return a SHA-256 over 'vector score' lines in the fixed order."""
    lines = "\n".join(f"{v} {scores[v]:.1f}" for v in all_vectors(version))
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
        vectors = [v for version in VERSIONS for v in all_vectors(version)]
        (work / "vectors.json").write_text(json.dumps(vectors))
        subprocess.run(["node", "cvss_reference_scores.js", "vectors.json", "scores.json"], cwd=work,  # noqa: S603, S607  # nosec B603 B607
                       check=True, env={**os.environ, "NODE_OPTIONS": ""})
        reference = json.loads((work / "scores.json").read_text())
    failed = False
    for version in VERSIONS:
        mine = {v: cvss.parse_vector(v).score for v in all_vectors(version)}
        wrong = [(v, reference[v], mine[v]) for v in mine if abs(reference[v] - mine[v]) > 1e-9]
        print(f"CVSS {version}: {len(mine) - len(wrong)}/{len(mine)} vectors identical to the official calculator")
        for row in wrong[:10]:
            print("   differs:", row)
        failed = failed or bool(wrong)
    if args.refresh_fixtures and not failed:
        fixture = {"note": "Scores from the official FIRST calculators; regenerate with "
                           "tools/verify_cvss_against_reference.py", "counts": {}, "digests": {}, "samples": {}}
        for version in VERSIONS:
            scores = {v: reference[v] for v in all_vectors(version)}
            fixture["counts"][version] = len(scores)
            fixture["digests"][version] = digest(version, scores)
            fixture["samples"][version] = sample(version, scores)
        FIXTURE.write_text(json.dumps(fixture, indent=1) + "\n", encoding="utf-8")
        print(f"wrote {FIXTURE.name}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
