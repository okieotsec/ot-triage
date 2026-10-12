"""Run the whole test suite without opening a single window on your screen.

The GUI tests create real windows. On a desktop (and badly on a tiling window manager) that pops windows in and out
while you work. This script runs everything on a private virtual display (Xvfb) that nobody can see, which is also how
the project's CI runs them.

    python3 tools/headless_tests.py            # the whole suite
    python3 tools/headless_tests.py 900        # the same, with a stall limit of 900 seconds (default 600)

If Xvfb is not installed, the GUI tests are skipped (so nothing can appear on your screen) and the rest still run.
Install it with:  sudo pacman -S xorg-server-xvfb   (Arch)   or   sudo apt install xvfb   (Debian, Ubuntu)
"""
import os
import shutil
import subprocess  # nosec B404 - runs this project's own test runner
import sys
from pathlib import Path

RUNNER = Path(__file__).resolve().parent / "ci_run_tests.py"
SCREEN = "-screen 0 1280x1024x24"


def plan(platform, xvfb, environ, extra_args):
    """Decide how to run the tests; return (command, environment, message to show or None). Nothing is run here."""
    args = [sys.executable, "-X", "dev", "-W", "error::ResourceWarning", str(RUNNER), *extra_args]
    env = dict(environ)
    if platform != "linux":
        return args, env, None
    if xvfb:
        env["OT_TRIAGE_PRIVATE_DISPLAY"] = "1"
        return [xvfb, "-a", "-s", SCREEN, *args], env, None
    for name in ("DISPLAY", "WAYLAND_DISPLAY"):
        env.pop(name, None)
    return args, env, ("Xvfb is not installed, so the GUI tests are skipped (no window is opened). To run them "
                       "invisibly:\n  sudo pacman -S xorg-server-xvfb   (Arch)   or   sudo apt install xvfb   "
                       "(Debian, Ubuntu)")


def main():
    command, env, message = plan(sys.platform, shutil.which("xvfb-run"), os.environ, sys.argv[1:])
    if message:
        print(message, file=sys.stderr)
    return subprocess.run(command, env=env, check=False).returncode  # noqa: S603  # nosec B603


if __name__ == "__main__":
    sys.exit(main())
