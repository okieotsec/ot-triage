"""Build the portable bundle: ot-triage-<version>.zip, with the application, its documents and sample files.

The bundle holds only what a person needs to run OT Triage (no tests, tools or security reports) under one folder
named ot-triage-<version>. It is reproducible: the same files always give the same bytes, so its SHA-256 can be
checked by anyone who builds it from the same tag. The run-time modules are found by following the imports of the two
entry points, so a new module can never be left out.

Usage:  python tools/make_bundle.py [output folder]     (default: dist)
"""
import ast
import hashlib
import shutil
import subprocess  # nosec B404 - runs git ls-files, with fixed arguments
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from version import __version__  # noqa: E402

ENTRY_POINTS = ("ot_triage_gui", "ot_triage_cli", "ot_triage_import")
LAUNCHER = "OT Triage.pyw"
TOP_LEVEL_FILES = ("README.md", "CHANGELOG.md", "LICENSE", "SECURITY.md", "THIRD_PARTY_NOTICES.md", "requirements.txt",
                   LAUNCHER)
FOLDERS = ("docs/", "sbom/", "assets/")
SAMPLE_PREFIX = "sample_"
FIXED_TIME = (1980, 1, 1, 0, 0, 0)
START_HERE = f"""OT Triage {__version__}  -  an OkieOTSec project

To start the application:
  Windows : double-click "OT Triage.pyw" (needs Python 3.12 or newer from python.org, with Tcl/Tk, the default)
  Any     : python3 ot_triage_gui.py
Command line (no window): python3 ot_triage_cli.py findings.csv -o ranked.csv   (see docs/CLI.md)
From scanner exports: python3 ot_triage_import.py sample_scan_nessus.csv -o findings.csv   (see docs/IMPORT.md)

Try the sample files first: sample_findings_multiple_per_asset.csv with sample_inventory.csv.
Nothing is downloaded unless you start an update in the Threat data view (or give --update on the command line).
No third-party packages are needed. The bill of materials is in sbom/.
"""


def runtime_modules():
    """Return the names of the local modules the entry points need, by following their imports."""
    local = {p.stem for p in ROOT.glob("*.py")}
    found, todo = set(), list(ENTRY_POINTS)
    while todo:
        name = todo.pop()
        if name in found:
            continue
        found.add(name)
        for node in ast.walk(ast.parse((ROOT / f"{name}.py").read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                names = [node.module.split(".")[0]]
            else:
                continue
            todo.extend(n for n in names if n in local and n not in found)
    return sorted(found)


def tracked_files():
    """Return the files git tracks, so nothing untracked or ignored ever ends up in the bundle."""
    git = shutil.which("git")
    if not git:
        raise SystemExit("git was not found: the bundle is built from the files git tracks")
    out = subprocess.run([git, "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True,  # noqa: S603  # nosec B603
                         text=True).stdout
    return [name for name in out.split("\0") if name]


def bundle_files():
    """Return the sorted relative paths that go into the bundle."""
    tracked = set(tracked_files())
    wanted = {f"{name}.py" for name in runtime_modules()}
    wanted |= set(TOP_LEVEL_FILES)
    wanted |= {name for name in tracked if name.startswith(FOLDERS) or name.startswith(SAMPLE_PREFIX)}
    missing = sorted(name for name in wanted if name not in tracked)
    if missing:
        raise SystemExit(f"not tracked by git, so not bundled: {', '.join(missing)}")
    return sorted(wanted)


def build(output_folder):
    """Write the zip and its .sha256 file; return (zip path, hex digest)."""
    folder = Path(output_folder)
    folder.mkdir(parents=True, exist_ok=True)
    top = f"ot-triage-{__version__}"
    target = folder / f"{top}.zip"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        items = [(f"{top}/START-HERE.txt", START_HERE.encode("utf-8"), 0o644)]
        for name in bundle_files():
            mode = 0o755 if name.endswith((".py", ".pyw")) and (ROOT / name).stat().st_mode & 0o111 else 0o644
            items.append((f"{top}/{name}", (ROOT / name).read_bytes(), mode))
        for arcname, data, mode in sorted(items):
            info = zipfile.ZipInfo(arcname, FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100000 | mode) << 16
            archive.writestr(info, data, compresslevel=9)
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    (folder / f"{top}.zip.sha256").write_text(f"{digest}  {top}.zip\n", encoding="utf-8")
    return target, digest


def main():
    """Build the bundle and say where it is."""
    target, digest = build(sys.argv[1] if len(sys.argv) > 1 else ROOT / "dist")
    print(f"{target}\nsha256 {digest}")


if __name__ == "__main__":
    main()
