"""Regenerate sbom/sbom.cdx.json, the CycloneDX software bill of materials for a release.

OT Triage uses only the Python standard library, so the honest SBOM has one component (the application itself) and no
third-party components. To prove that, the tool inspects a brand-new virtual environment with nothing installed.

Usage (needs the cyclonedx-bom package, which provides the cyclonedx-py command):

    python tools/make_sbom.py

The output is reproducible: running it again on the same version gives the same file.
"""
import json
import shutil
import subprocess  # nosec B404 - runs cyclonedx-py on a throwaway environment this tool creates
import sys
import tempfile
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from version import __version__  # noqa: E402

OUTPUT = ROOT / "sbom" / "sbom.cdx.json"
REPO = "https://github.com/okieotsec/ot-triage"
BOM_REF = f"pkg:github/okieotsec/ot-triage@{__version__}"


def find_cyclonedx():
    """Return the path of the cyclonedx-py command, looking next to this Python first."""
    beside = Path(sys.executable).parent / "cyclonedx-py"
    found = str(beside) if beside.exists() else shutil.which("cyclonedx-py")
    if not found:
        raise SystemExit("cyclonedx-py not found: pip install cyclonedx-bom")
    return found


def application_component():
    """Describe OT Triage itself, the one component of its own SBOM."""
    return {
        "type": "application",
        "bom-ref": BOM_REF,
        "name": "ot-triage",
        "version": __version__,
        "description": "Now / Next / Never triage for OT/ICS vulnerabilities",
        "supplier": {"name": "OkieOTSec", "url": ["https://okieotsec.com"]},
        "licenses": [{"license": {"id": "MIT"}}],
        "purl": BOM_REF,
        "externalReferences": [{"type": "vcs", "url": REPO},
                               {"type": "website", "url": "https://okieotsec.com/projects/"}],
    }


def build():
    """Return the SBOM as a dict."""
    with tempfile.TemporaryDirectory() as folder:
        env = Path(folder) / "empty"
        venv.create(env, with_pip=False)  # nothing is installed in it, on purpose
        raw = Path(folder) / "raw.json"
        command = [find_cyclonedx(), "environment", str(env / "bin" / "python"), "--of", "JSON", "--sv", "1.6",
                   "--output-reproducible", "-o", str(raw)]
        # A fixed command, run on a temporary folder this tool just created.
        subprocess.run(command, check=True)  # noqa: S603  # nosec B603
        bom = json.loads(raw.read_text(encoding="utf-8"))
    if bom.get("components"):
        raise SystemExit(f"the empty environment unexpectedly contains components: {bom['components']}")
    bom["metadata"]["component"] = application_component()
    bom["components"] = []
    bom["dependencies"] = [{"ref": BOM_REF, "dependsOn": []}]
    return bom


def main():
    """Write the SBOM file."""
    OUTPUT.parent.mkdir(exist_ok=True)
    OUTPUT.write_text(json.dumps(build(), indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)} for ot-triage {__version__}")


if __name__ == "__main__":
    main()
