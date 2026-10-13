#!/usr/bin/env python3
"""OT Triage on the command line: rank a findings CSV without opening a window.

    python3 ot_triage_cli.py findings.csv -o ranked.csv
    python3 ot_triage_cli.py findings.csv --inventory assets.csv --compare last_week.csv --assets by_asset.csv
    python3 ot_triage_cli.py --update            # download the threat data (the only thing that uses the network)

It uses the same rules, settings and threat data as the application. Nothing is downloaded unless --update is given.
Exit codes: 0 done, 1 a file could not be used, 2 wrong arguments, 3 --fail-on found something at or above that bucket.
"""
import argparse
import os
import sys
import tempfile
from pathlib import Path

import batch
import compare
import icsadvisories
import inventory
import rollup
import settings as scoring
import threatdata
from prioritizer import NEVER, NEXT, NOW
from references import clean
from version import __version__

EXIT_OK, EXIT_ERROR, EXIT_FAIL_ON = 0, 1, 3
SHOWN_TEXT_CHARS = 90


def shown(text):
    """Text from a file made safe to print: control characters (such as terminal escapes) are removed."""
    return clean(str(text))[:SHOWN_TEXT_CHARS]


def build_parser():
    """The command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="ot_triage_cli.py", description="Rank OT/ICS vulnerabilities into NOW, NEXT and NEVER.",
        epilog="Nothing is downloaded unless --update is given. Exit codes: 0 done, 1 a file could not be used, "
               "2 wrong arguments, 3 --fail-on found something at or above that bucket.")
    parser.add_argument("findings", nargs="?", help="the findings CSV to rank")
    parser.add_argument("-o", "--output", metavar="CSV", help="save the ranked results (like Export ranked CSV)")
    parser.add_argument("-a", "--assets", metavar="CSV", help="save the per-asset roll-up")
    parser.add_argument("-i", "--inventory", metavar="CSV", help="an asset inventory that fills in asset, exposure "
                                                                  "and controls from an asset_id column")
    parser.add_argument("-c", "--compare", metavar="CSV", help="a previous ranked export to compare with")
    parser.add_argument("--settings", metavar="JSON", help="scoring settings file (default: your saved settings)")
    parser.add_argument("--data-dir", metavar="DIR", help="threat data folder (default: the per-user data folder)")
    parser.add_argument("--update", action="store_true",
                        help="download CISA KEV, EPSS and the CISA ICS advisories first (the only network use)")
    parser.add_argument("--top", type=int, default=10, metavar="N", help="print the N top findings (default 10)")
    parser.add_argument("--fail-on", choices=(NOW, NEXT), help="exit with code 3 if any finding is at or above this "
                                                                "bucket (for scripts and scheduled jobs)")
    parser.add_argument("--force", action="store_true", help="replace output files that already exist")
    parser.add_argument("-q", "--quiet", action="store_true", help="print only errors")
    parser.add_argument("--version", action="version", version=f"OT Triage {__version__}")
    return parser


class CliError(Exception):
    """A problem to report to the person, which ends the run with exit code 1."""


def _check_output(path, inputs, force):
    """Refuse to overwrite an input file, or an existing file unless --force was given."""
    if not path:
        return
    for other in inputs:
        if other and os.path.exists(path) and os.path.exists(other) and os.path.samefile(path, other):
            raise CliError(f"{path} is also an input file; choose a different output name")
    if os.path.exists(path) and not force:
        raise CliError(f"{path} already exists (use --force to replace it)")


def _write_atomically(path, write):
    """Run write(temporary_path) and move the result into place, so a failure never leaves a half-written file."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, temp = tempfile.mkstemp(dir=directory, prefix=".ot-triage-", suffix=".part")
    os.close(fd)
    try:
        write(temp)
        os.replace(temp, path)
    except BaseException:
        try:
            os.remove(temp)
        except OSError:
            pass
        raise


def _update(data_dir, out, err):
    """Download the threat data; return True if every source updated."""
    # The downloader is passed in explicitly (not left as the functions' default), so tests can replace it
    results = threatdata.update_from_network(data_dir, fetcher=threatdata.fetch)
    results.append(icsadvisories.update_from_network(data_dir, fetcher=threatdata.fetch))
    for result in results:
        print(("ok: " if result.ok else "FAILED: ") + shown(result.message), file=out if result.ok else err)
    return all(r.ok for r in results)


def _summary(items, out):
    counts = batch.summarize(items)
    print(f"NOW {counts[NOW]} · NEXT {counts[NEXT]} · NEVER {counts[NEVER]} · not scored {counts['ERROR']}", file=out)


def _top(items, count, out):
    ranked = [i for i in items if i.result][:max(0, count)]
    if not ranked:
        return
    print("Top findings:", file=out)
    for rank, item in enumerate(ranked, start=1):
        asset = f"  [{shown(item.asset_id)}]" if item.asset_id else ""
        print(f"  {rank:>3}. {item.priority:<5} {item.result.score:5.2f}  {shown(rollup.label(item))}{asset}", file=out)


def run(args, out, err):
    """Do what the arguments ask; raise CliError for a problem. Return the exit code."""
    data_dir = Path(args.data_dir) if args.data_dir else threatdata.default_data_dir()
    if args.update:
        ok = _update(data_dir, out, err)
        if not args.findings:
            return EXIT_OK if ok else EXIT_ERROR
        if not ok:
            print("warning: some threat data could not be updated; the stored copy is used", file=err)
    if not args.findings:
        raise CliError("give a findings CSV to rank, or --update")
    _check_output(args.output, (args.findings, args.inventory, args.compare), args.force)
    _check_output(args.assets, (args.findings, args.inventory, args.compare, args.output), args.force)
    loaded = scoring.load(args.settings)
    for warning in loaded.warnings:
        print("warning: " + shown(warning), file=err)
    inv = inventory.load(args.inventory) if args.inventory else None
    if inv is not None:
        for problem in inv.problems[:5]:
            print("warning: inventory: " + shown(problem), file=err)
    data = threatdata.ThreatData.load(data_dir) if batch.has_cve_column(args.findings) else None
    if data is not None:
        for warning in data.warnings:
            print("warning: " + shown(warning), file=err)
    items = batch.process_file(args.findings, loaded.settings, data, inv)
    if not items:
        raise CliError("the file has a header but no data rows")
    comparison = None
    if args.compare:
        rows, skipped = compare.load_previous(args.compare)
        comparison = compare.compare(items, rows, os.path.basename(args.compare), skipped)
    if not args.quiet:
        print(f"OT Triage {__version__} · {shown(os.path.basename(args.findings))} · {len(items)} rows", file=out)
        _summary(items, out)
        if data is not None:
            print(f"Threat data: {shown(data.versions())}", file=out)
        print(f"Scoring settings: {'defaults' if loaded.settings.is_default else loaded.settings.describe()}", file=out)
        if inv is not None:
            print(f"Inventory: {shown(inv.summary())}", file=out)
        _top(items, args.top, out)
        if comparison is not None:
            print(shown(comparison.summary()), file=out)
            for row in comparison.resolved[:10]:
                print(f"  resolved: {shown(row.label)} (was {row.priority})", file=out)
            if len(comparison.resolved) > 10:
                print(f"  ...and {len(comparison.resolved) - 10} more resolved", file=out)
    if args.output:
        _write_atomically(args.output, lambda p: batch.write_results(p, items, data, comparison))
        if not args.quiet:
            print(f"Wrote {args.output}", file=out)
    if args.assets:
        summaries, _unassigned = rollup.rollup(items)
        _write_atomically(args.assets, lambda p: rollup.write_rollup(p, summaries))
        if not args.quiet:
            print(f"Wrote {args.assets} ({len(summaries)} assets)", file=out)
    if args.fail_on:
        levels = (NOW,) if args.fail_on == NOW else (NOW, NEXT)
        counts = batch.summarize(items)
        if any(counts[level] for level in levels):
            return EXIT_FAIL_ON
    return EXIT_OK


def main(argv=None, out=None, err=None):
    """Run the command line; return the exit code."""
    out, err = out or sys.stdout, err or sys.stderr
    args = build_parser().parse_args(argv)
    try:
        return run(args, out, err)
    except (CliError, compare.CompareError) as error:
        print("error: " + shown(error), file=err)
    except (ValueError, OSError) as error:
        message = error.strerror or error if isinstance(error, OSError) else error
        print("error: " + shown(message), file=err)
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
