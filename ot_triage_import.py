#!/usr/bin/env python3
"""Turn scanner exports into the findings (and inventory) files OT Triage ranks.

    python3 ot_triage_import.py nessus.csv openvas.csv -o findings.csv
    python3 ot_triage_import.py scan.csv -o findings.csv -i inventory.csv --inventory-out new.csv --aliases aliases.csv

It reads Nessus CSV, Tenable Vulnerability Management CSV and OpenVAS / Greenbone CSV exports (see docs/IMPORT.md). It
never uses the network, never changes an input file, and never scores anything: the files it writes are ranked by
ot_triage_cli.py or the Batch view with the same rules as any other findings file.
Exit codes: 0 done, 1 a file could not be used, 2 wrong arguments.
"""
import argparse
import sys

import scanimport
from ot_triage_cli import CliError, _check_output, _write_atomically
from references import clean
from version import __version__

EXIT_OK, EXIT_ERROR = 0, 1


def build_parser():
    """The command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="ot_triage_import.py", description="Turn scanner exports into findings and inventory files for OT Triage.",
        epilog="Reads Nessus, Tenable Vulnerability Management and OpenVAS CSV exports. Exit codes: 0 done, "
               "1 a file could not be used, 2 wrong arguments.")
    parser.add_argument("exports", nargs="+", metavar="EXPORT", help="one or more scanner export files (CSV)")
    parser.add_argument("-o", "--output", required=True, metavar="CSV", help="where to save the findings")
    parser.add_argument("-i", "--inventory", metavar="CSV", help="your existing asset inventory (never changed)")
    parser.add_argument("--inventory-out", metavar="CSV",
                        help="save an inventory: your existing one plus a row for each new asset the scan found")
    parser.add_argument("--aliases", metavar="CSV", help="a file with alias and asset_id columns: the names one device "
                                                         "goes by in different tools")
    parser.add_argument("--min-qod", type=int, default=scanimport.DEFAULT_MIN_QOD, metavar="N",
                        help=f"OpenVAS: skip detections with a Quality of Detection below N (default "
                             f"{scanimport.DEFAULT_MIN_QOD})")
    parser.add_argument("--default-threat", choices=scanimport.THREAT_LEVELS,
                        help="give findings with no CVE this threat level (otherwise they need one added by hand)")
    parser.add_argument("--force", action="store_true", help="replace output files that already exist")
    parser.add_argument("-q", "--quiet", action="store_true", help="print only errors")
    parser.add_argument("--version", action="version", version=f"OT Triage {__version__}")
    return parser


def run(args, out):
    """Do what the arguments ask; raise CliError or ScanImportError for a problem. Return the exit code."""
    inputs = (*args.exports, args.inventory, args.aliases)
    _check_output(args.output, inputs, args.force)
    _check_output(args.inventory_out, (*inputs, args.output), args.force)
    if args.inventory_out and args.inventory_out == args.output:
        raise CliError("the findings and the inventory need different file names")
    if not 0 <= args.min_qod <= 100:
        raise CliError("--min-qod must be between 0 and 100")
    aliases = scanimport.load_aliases(args.aliases) if args.aliases else None
    result = scanimport.import_exports(args.exports, aliases, args.min_qod, args.default_threat or "")
    if not result.findings:
        raise scanimport.ScanImportError("nothing to import: every row was skipped (see --help for what is skipped)")
    _write_atomically(args.output, lambda p: scanimport.write_findings(p, result))
    new = 0
    if args.inventory_out:
        counts = []
        _write_atomically(args.inventory_out,
                          lambda p: counts.append(scanimport.write_inventory(p, result, args.inventory)))
        new = counts[0][0]
    if not args.quiet:
        for line in scanimport.summary_lines(result, args.min_qod):
            print(" " * (len(line) - len(line.lstrip())) + clean(line)[:300], file=out)
        print(f"Wrote {args.output}", file=out)
        if args.inventory_out:
            print(f"Wrote {args.inventory_out} ({new} new assets: fill in their criticality, exposure and controls)",
                  file=out)
        elif result.assets and not args.inventory:
            print(f"{len(result.assets)} assets were seen; add --inventory-out to save them as an inventory", file=out)
    return EXIT_OK


def main(argv=None, out=None, err=None):
    """Run the importer; return the exit code."""
    out, err = out or sys.stdout, err or sys.stderr
    args = build_parser().parse_args(argv)
    try:
        return run(args, out)
    except (CliError, scanimport.ScanImportError) as error:
        print("error: " + clean(str(error))[:400], file=err)
    except (ValueError, OSError) as error:
        print("error: " + clean(str(error.strerror or error if isinstance(error, OSError) else error))[:400], file=err)
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
