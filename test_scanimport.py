import csv
import hashlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import batch
import scanimport as si
from prioritizer import NEVER, NEXT, NOW

try:
    from hypothesis import given
    from hypothesis import settings as hyp_settings
    from hypothesis import strategies as st
except ImportError:  # the property tests are optional
    given = None

SAMPLES = Path(__file__).parent / "samples" / "scanners"
NESSUS_HEAD = (
    "Plugin ID,CVE,CVSS v2.0 Base Score,CVSS v3.0 Base Score,Risk,Host,Protocol,Port,Name,Synopsis,"
    "Description,Solution,See Also,Plugin Output"
)
TENABLE_HEAD = (
    "Asset Name,IPv4 Address,Operating System,CVE,CVSSv3 Base Score,VPR,Severity,Plugin ID,Plugin Name,State,"
    "First Seen,Last Seen,Solution,Port,Protocol"
)
OPENVAS_HEAD = (
    "IP,Hostname,Port,Port Protocol,CVSS,Severity,QoD,Solution Type,NVT Name,Summary,Specific Result,NVT OID,"
    "CVEs,Task ID,Task Name,Timestamp,Result ID"
)


class Case(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def write(self, name, text, encoding="utf-8"):
        path = self.dir / name
        path.write_bytes(text.encode(encoding) if isinstance(text, str) else text)
        return path

    def nessus(self, *rows, head=NESSUS_HEAD, name="n.csv"):
        return self.write(name, head + "\n" + "\n".join(rows) + "\n")

    def read(self, path, **kwargs):
        findings, assets, report = si.read_export(path, **kwargs)
        return findings, assets, report

    @staticmethod
    def ids(findings):
        return [(f.asset_id, f.cve, f.cvss) for f in findings]


class SampleFileTests(Case):
    """The fictional exports in samples/scanners/ give exactly the findings recorded next to them."""

    CASES = (
        ("nessus/classic.csv", "nessus_csv"),
        ("tenable/vm_export.csv", "tenable_vm"),
        ("openvas/report.csv", "openvas"),
    )

    def test_each_sample_gives_the_expected_findings(self):
        for path, expected in self.CASES:
            with self.subTest(path):
                findings, _assets, _report = self.read(SAMPLES / path)
                got = [
                    {
                        "id": f.id,
                        "asset_id": f.asset_id,
                        "name": f.name,
                        "cve": f.cve,
                        "cvss": f.cvss,
                        "patch": f.patch,
                        "source_tool": f.source,
                    }
                    for f in findings
                ]
                with open(SAMPLES / "expected" / f"{expected}.findings.csv", newline="", encoding="utf-8") as fh:
                    self.assertEqual(got, list(csv.DictReader(fh)))

    def test_the_reports_say_what_was_skipped(self):
        reports = {p: self.read(SAMPLES / p)[2] for p, _ in self.CASES}
        self.assertEqual(reports["nessus/classic.csv"].skipped, {"informational (no risk)": 2})
        self.assertEqual(
            reports["tenable/vm_export.csv"].skipped, {"already fixed or resolved": 1, "informational (no risk)": 1}
        )
        self.assertEqual(reports["openvas/report.csv"].skipped, {"log entry or no score": 1})
        self.assertEqual(reports["openvas/report.csv"].format, "OpenVAS / Greenbone CSV")


class DetectionTests(Case):
    def test_each_header_is_recognised(self):
        self.assertEqual(si.detect_format(NESSUS_HEAD.split(",")), si.NESSUS)
        self.assertEqual(si.detect_format(TENABLE_HEAD.split(",")), si.TENABLE_VM)
        self.assertEqual(si.detect_format(OPENVAS_HEAD.split(",")), si.OPENVAS)
        self.assertEqual(si.detect_format(["plugin_id", "host", "risk", "name"]), si.NESSUS)
        self.assertEqual(si.detect_format(["  NVT NAME ", "cves"]), si.OPENVAS)

    def test_anything_else_is_refused_not_guessed(self):
        for header in (
            [],
            [""],
            ["id", "name", "cve", "cvss"],
            ["Plugin ID"],
            ["Host", "Risk"],
            ["IP", "CVSS"],
            ["Asset Name"],
            ["x"] * 50,
        ):
            with self.subTest(header=header):
                self.assertIsNone(si.detect_format(header))
        path = self.write("f.csv", "id,name,cve,cvss\n1,a,CVE-2024-0001,5\n")
        with self.assertRaisesRegex(si.ScanImportError, "not an export this tool knows"):
            self.read(path)

    def test_a_file_that_is_not_text_a_directory_or_missing_or_empty_is_refused_cleanly(self):
        for label, target in (
            ("binary", self.write("b.csv", b"\xff\xfe\x00\x01" * 50)),
            ("empty", self.write("e.csv", "")),
            ("directory", self.dir),
            ("missing", self.dir / "nope.csv"),
        ):
            with self.subTest(label), self.assertRaises(si.ScanImportError):
                self.read(target)


class NessusTests(Case):
    ROW = '97833,CVE-2017-0144,9.3,8.1,Critical,192.0.2.21,tcp,445,"MS17-010: SMB",syn,desc,fix,,"line one\nline two"'

    def test_one_row_per_cve_and_the_v3_score_wins(self):
        findings, assets, report = self.read(self.nessus(self.ROW, self.ROW.replace("0144", "0143").replace("8.1", "")))
        self.assertEqual(
            self.ids(findings), [("192.0.2.21", "CVE-2017-0144", "8.1"), ("192.0.2.21", "CVE-2017-0143", "9.3")]
        )
        self.assertEqual((report.rows, report.kept), (2, 2))
        self.assertEqual(list(assets), ["192.0.2.21"])

    def test_several_cves_in_one_cell_become_several_findings(self):
        row = self.ROW.replace("CVE-2017-0144", '"CVE-2017-0144, cve-2017-0143 CVE-2017-0144"')
        findings, _a, _r = self.read(self.nessus(row))
        self.assertEqual([f.cve for f in findings], ["CVE-2017-0144", "CVE-2017-0143"])

    def test_informational_and_fixed_rows_are_skipped_and_counted(self):
        rows = [self.ROW.replace("Critical", level) for level in ("None", "Info", "Informational")]
        _f, _a, report = self.read(self.nessus(*rows))
        self.assertEqual((report.kept, report.skipped), (0, {"informational (no risk)": 3}))
        head = NESSUS_HEAD + ",Vulnerability State"
        rows = [self.ROW + ",Fixed", self.ROW + ",Active", self.ROW + ",RESOLVED"]
        findings, _a, report = self.read(self.nessus(*rows, head=head))
        self.assertEqual((len(findings), report.skipped), (1, {"already fixed or resolved": 2}))

    def test_a_row_with_no_cve_or_no_score_is_kept_and_a_bad_score_is_left_empty(self):
        rows = [
            "1,,,,High,192.0.2.5,tcp,23,Default credentials,,,,,",
            "2,,,12.5,High,192.0.2.5,tcp,23,Odd score,,,,,",
            "3,,abc,-1,High,192.0.2.5,tcp,23,Words,,,,,",
            "4,,7.5,,High,192.0.2.5,tcp,23,v2 only,,,,,",
        ]
        findings, _a, _r = self.read(self.nessus(*rows))
        self.assertEqual(
            [(f.name, f.cve, f.cvss) for f in findings],
            [("Default credentials", "", ""), ("Odd score", "", ""), ("Words", "", ""), ("v2 only", "", "7.5")],
        )

    def test_the_host_falls_back_to_the_ip_address_and_a_row_with_no_host_is_skipped(self):
        head = "Plugin ID,CVE,CVSS,Risk,Host,IP Address,FQDN,Name"
        findings, assets, report = self.read(
            self.nessus(
                "1,,5,High,,192.0.2.9,plc.example.com,A",
                "2,,5,High,,,,B",
                "3,,5,High,192.0.2.7,192.0.2.8,pc.example.com,C",
                head=head,
            )
        )
        self.assertEqual([f.asset_id for f in findings], ["192.0.2.9", "192.0.2.7"])
        self.assertEqual(report.skipped, {"no host or asset name": 1})
        self.assertEqual([a.name for a in assets.values()], ["plc.example.com", "pc.example.com"])

    def test_header_spelling_and_order_do_not_matter_but_the_columns_do(self):
        head = "name,PLUGIN_ID,risk,host,cvss_v3.0 base score"
        self.assertEqual(si.detect_format(head.split(",")), si.NESSUS)
        findings, _a, _r = self.read(
            self.nessus("Thing,5,High,192.0.2.1,7.0", head="Name,Plugin ID,Risk,Host,CVSS v3.0 Base Score")
        )
        self.assertEqual(self.ids(findings), [("192.0.2.1", "", "7.0")])
        with self.assertRaisesRegex(si.ScanImportError, "needs a Plugin ID and a plugin name"):
            self.read(self.nessus("5,High,192.0.2.1", head="Plugin ID,Risk,Host"))

    def test_a_byte_order_mark_short_rows_blank_rows_and_embedded_new_lines_are_handled(self):
        text = "\ufeff" + NESSUS_HEAD + "\n\n" + self.ROW + "\n,,,,,,,,,,,,,\n1,CVE-2020-0001\n"
        findings, _a, report = self.read(self.write("bom.csv", text))
        self.assertEqual(report.rows, 2)
        self.assertEqual(self.ids(findings[:1]), [("192.0.2.21", "CVE-2017-0144", "8.1")])
        self.assertEqual(report.skipped, {"no host or asset name": 1})

    def test_text_is_cleaned_and_cut(self):
        long_name = "x" * 500
        findings, _a, _r = self.read(
            self.nessus(
                f'1,CVE-2020-0001,5,5,High,192.0.2.1,tcp,1,"{long_name}",,,,,',
                '2,,5,5,High,192.0.2.1,tcp,1,"a\x1b[31mb\u202ec",,,,,',
            )
        )
        self.assertEqual(len(findings[0].name), si.MAX_NAME_CHARS)
        self.assertEqual(findings[1].name, "a[31mbc")


class TenableTests(Case):
    ROW = "CC-HIST-01,192.0.2.21,Windows,CVE-2021-34527,8.8,9.6,High,151946,Print Spooler,Active,,,Patch,445,TCP"

    def tenable(self, *rows):
        return self.write("t.csv", TENABLE_HEAD + "\n" + "\n".join(rows) + "\n")

    def test_the_asset_name_is_the_asset_and_states_decide_what_is_skipped(self):
        rows = [
            self.ROW,
            self.ROW.replace("Active", "Fixed"),
            self.ROW.replace("Active", "New"),
            self.ROW.replace("Active", "Resurfaced"),
            self.ROW.replace("High", "Info"),
        ]
        findings, assets, report = self.read(self.tenable(*rows))
        self.assertEqual(len(findings), 3)
        self.assertEqual(list(assets), ["cc-hist-01"])
        self.assertEqual(report.skipped, {"already fixed or resolved": 1, "informational (no risk)": 1})
        self.assertTrue(findings[0].id.startswith("tenable:151946:CC-HIST-01:"))

    def test_without_an_asset_name_the_ip_is_used_and_the_v3_score_is_required_for_a_score(self):
        findings, _a, _r = self.read(self.tenable(self.ROW.replace("CC-HIST-01,", ",", 1).replace("8.8", "")))
        self.assertEqual(self.ids(findings), [("192.0.2.21", "CVE-2021-34527", "")])


class OpenvasTests(Case):
    ROW = (
        'IP4,host4,22,tcp,9.8,Critical,80,VendorFix,OpenSSH RCE,s,r,1.3.6.1,"CVE-2023-38408,CVE-2023-38409",t,T,ts,r-1'
    )

    def openvas(self, *rows, head=OPENVAS_HEAD):
        return self.write(
            "o.csv",
            head
            + "\n"
            + "\n".join(r.replace("IP4", "198.51.100.4").replace("host4", "h.example.com") for r in rows)
            + "\n",
        )

    def test_the_ip_is_the_asset_the_host_name_is_its_name_and_a_vendor_fix_means_available(self):
        findings, assets, _r = self.read(self.openvas(self.ROW))
        self.assertEqual(
            self.ids(findings), [("198.51.100.4", "CVE-2023-38408", "9.8"), ("198.51.100.4", "CVE-2023-38409", "9.8")]
        )
        self.assertEqual({f.patch for f in findings}, {"available"})
        self.assertEqual(assets["198.51.100.4"].name, "h.example.com")

    def test_other_solution_types_leave_the_patch_status_empty(self):
        for kind in ("Workaround", "Mitigation", "NoneAvailable", "WillNotFix", ""):
            with self.subTest(kind):
                findings, _a, _r = self.read(self.openvas(self.ROW.replace("VendorFix", kind)))
                self.assertEqual({f.patch for f in findings}, {""})

    def test_log_entries_and_unscored_results_are_skipped(self):
        rows = [
            self.ROW.replace("Critical", "Log"),
            self.ROW.replace("9.8", "0.0"),
            self.ROW.replace("9.8", ""),
            self.ROW.replace("9.8", "n/a"),
        ]
        findings, _a, report = self.read(self.openvas(*rows))
        self.assertEqual((findings, report.skipped), ([], {"log entry or no score": 4}))

    def test_the_quality_of_detection_threshold_applies_when_the_column_is_there(self):
        rows = [self.ROW.replace(",80,", f",{q},") for q in ("69", "70", "99", "", "high")]
        findings, _a, report = self.read(self.openvas(*rows), min_qod=70)
        self.assertEqual(len({f.id for f in findings}), 1 and len({f.id for f in findings}))
        self.assertEqual(report.skipped, {"quality of detection below 70": 1})
        _f, _a, report = self.read(self.openvas(*rows), min_qod=0)
        self.assertEqual(report.skipped, {})
        _f, _a, report = self.read(self.openvas(*rows), min_qod=100)
        self.assertEqual(report.skipped, {"quality of detection below 100": 3})
        old = OPENVAS_HEAD.replace("QoD,", "")
        row = self.ROW.replace(",80,", ",")
        findings, _a, report = self.read(self.openvas(row, head=old), min_qod=100)
        self.assertEqual((len(findings), report.skipped), (2, {}))

    def test_a_result_with_no_cve_is_kept(self):
        findings, _a, _r = self.read(self.openvas(self.ROW.replace('"CVE-2023-38408,CVE-2023-38409"', "")))
        self.assertEqual(self.ids(findings), [("198.51.100.4", "", "9.8")])

    def test_cves_are_found_in_messy_cells_and_other_text_is_ignored(self):
        findings, _a, _r = self.read(
            self.openvas(
                self.ROW.replace(
                    "CVE-2023-38408,CVE-2023-38409", "see cve-2023-38408; CVE-2023-38408 / CVE-2024-0001x CVE-12-1"
                )
            )
        )
        self.assertEqual([f.cve for f in findings], ["CVE-2023-38408", "CVE-2024-0001"])


class MergeTests(Case):
    def finding(self, asset, cve="CVE-2020-0001", cvss="5.0", patch="", source="nessus", name="Thing"):
        return si.Finding(f"{source}:{asset}:{cve}", asset, name, cve, cvss, patch, source)

    def result(self, *findings):
        found = si.ImportResult(findings=list(findings))
        for f in findings:
            found.assets.setdefault(f.asset_id.lower(), si.Asset(f.asset_id))
        return found

    def test_the_same_cve_on_the_same_asset_becomes_one_finding_with_the_highest_score(self):
        merged = si.merge(
            self.result(
                self.finding("A", cvss="5.0"),
                self.finding("a", cvss="9.0", source="openvas", patch="available"),
                self.finding("A", cvss="", source="tenable"),
            )
        )
        self.assertEqual(len(merged.findings), 1)
        only = merged.findings[0]
        self.assertEqual(
            (only.cvss, only.patch, only.source, merged.merged), ("9.0", "available", "nessus+openvas+tenable", 2)
        )

    def test_the_first_finding_keeps_its_id_and_name_and_order_is_kept(self):
        merged = si.merge(
            self.result(
                self.finding("A", cve="CVE-2020-0002"),
                self.finding("A"),
                self.finding("A", cve="CVE-2020-0002", source="x"),
            )
        )
        self.assertEqual([f.cve for f in merged.findings], ["CVE-2020-0002", "CVE-2020-0001"])
        self.assertEqual(merged.findings[0].id, "nessus:A:CVE-2020-0002")

    def test_findings_with_no_cve_merge_on_the_title(self):
        merged = si.merge(
            self.result(
                self.finding("A", cve="", name="Default credentials"),
                self.finding("A", cve="", name="DEFAULT credentials", source="openvas"),
                self.finding("A", cve="", name="Another"),
            )
        )
        self.assertEqual(len(merged.findings), 2)

    def test_different_assets_are_never_merged(self):
        self.assertEqual(len(si.merge(self.result(self.finding("A"), self.finding("B"))).findings), 2)

    def test_aliases_move_findings_and_assets_to_one_asset_id(self):
        result = self.result(
            self.finding("192.0.2.21"), self.finding("CC-HIST-01", source="tenable"), self.finding("H.EXAMPLE.COM")
        )
        result.assets["192.0.2.21"] = si.Asset("192.0.2.21", name="")
        result.assets["cc-hist-01"] = si.Asset("CC-HIST-01", name="Historian")
        aliases = {"192.0.2.21": "CC-HIST-01", "h.example.com": "CC-DMZ-04"}
        merged = si.merge(result, aliases)
        self.assertEqual([f.asset_id for f in merged.findings], ["CC-HIST-01", "CC-DMZ-04"])
        self.assertEqual((merged.renamed, merged.merged), (2, 1))
        self.assertEqual(sorted(a.asset_id for a in merged.assets.values()), ["CC-DMZ-04", "CC-HIST-01"])
        self.assertEqual(merged.assets["cc-hist-01"].name, "Historian")

    def test_the_threat_level_is_only_given_to_findings_with_no_cve_and_only_when_asked_for(self):
        merged = si.merge(self.result(self.finding("A", cve=""), self.finding("A", name="B")))
        self.assertEqual((merged.need_threat, [f.threat for f in merged.findings]), (1, ["", ""]))
        merged = si.merge(self.result(self.finding("A", cve=""), self.finding("A", name="B")), None, "none")
        self.assertEqual((merged.need_threat, [f.threat for f in merged.findings]), (0, ["none", ""]))

    def test_findings_with_no_score_are_counted(self):
        self.assertEqual(si.merge(self.result(self.finding("A", cvss=""), self.finding("B"))).not_scored, 1)

    def test_too_many_findings_are_refused_while_reading_not_after(self):
        rows = ["1,CVE-2020-0001,5,5,High,h,tcp,1,N,,,,,"] * 5
        path = self.dir / "raw.csv"
        path.write_text(NESSUS_HEAD + "\n" + "\n".join(rows) + "\n", encoding="utf-8")
        with mock.patch.object(si, "MAX_RAW_FINDINGS", 3), self.assertRaisesRegex(si.ScanImportError, "more than 3"):
            si.import_exports([path])
        openvas = self.dir / "raw_o.csv"
        openvas.write_text(
            OPENVAS_HEAD
            + "\n"
            + "\n".join(["1.2.3.4,h,22,tcp,9.8,High,80,,N,s,r,o,CVE-2020-0001,t,T,ts,r"] * 5)
            + "\n",
            encoding="utf-8",
        )
        with mock.patch.object(si, "MAX_RAW_FINDINGS", 3), self.assertRaisesRegex(si.ScanImportError, "more than 3"):
            si.import_exports([openvas])
        with mock.patch.object(si, "MAX_RAW_FINDINGS", 7), self.assertRaisesRegex(si.ScanImportError, "more than 7"):
            si.import_exports([path, path])

    def test_too_many_findings_are_refused(self):
        with mock.patch.object(si, "MAX_FINDINGS", 3), self.assertRaisesRegex(si.ScanImportError, "at most 3"):
            si.merge(self.result(*[self.finding(f"A{n}") for n in range(4)]))

    def test_an_invalid_default_threat_is_refused(self):
        with self.assertRaisesRegex(si.ScanImportError, "default threat"):
            si.import_exports([SAMPLES / "nessus/classic.csv"], None, 70, "high")


class ScannerHintTests(Case):
    """Opening a scanner export where a findings file or an inventory is expected says what it is and what to do."""

    FILES = ("sample_scan_nessus.csv", "sample_scan_openvas.csv")

    def test_batch_and_the_inventory_loader_name_the_export_and_the_command(self):
        import inventory

        here = Path(__file__).parent
        for name in self.FILES:
            for loader in (batch.process_file, inventory.load):
                with self.subTest(name, loader=loader.__module__), self.assertRaises(ValueError) as caught:
                    loader(here / name)
                message = str(caught.exception)
                self.assertIn("scanner export (", message)
                self.assertIn("python3 ot_triage_import.py", message)
                self.assertIn("docs/IMPORT.md", message)
                self.assertNotIn("Missing required column", message)

    def test_a_tenable_export_is_named_too_and_other_files_keep_their_old_messages(self):
        self.assertIn("Tenable Vulnerability Management CSV", si.scanner_hint(TENABLE_HEAD.split(",")))
        self.assertEqual(si.scanner_hint(["id", "name", "cve", "cvss"]), "")
        self.assertEqual(si.scanner_hint([]), "")
        plain = self.write("plain.csv", "id,name\n1,a\n")
        with self.assertRaisesRegex(ValueError, "Missing required column"):
            batch.process_file(plain)


class AliasFileTests(Case):
    def test_aliases_are_read_case_insensitively(self):
        path = self.write("a.csv", "alias,asset_id\n192.0.2.21,CC-HIST-01\nH.Example.com ,CC-DMZ-04\n,orphan\nx,\n")
        self.assertEqual(si.load_aliases(path), {"192.0.2.21": "CC-HIST-01", "h.example.com": "CC-DMZ-04"})

    def test_the_sample_aliases_file_is_valid(self):
        self.assertEqual(si.load_aliases(SAMPLES / "merge" / "aliases.csv")["192.0.2.21"], "CC-HIST-01")

    def test_a_chain_two_targets_or_a_wrong_header_is_refused(self):
        cases = {
            "chain": "alias,asset_id\nA,B\nB,C\n",
            "two targets": "alias,asset_id\nA,B\na,C\n",
            "header": "from,to\nA,B\n",
        }
        for label, text in cases.items():
            with self.subTest(label), self.assertRaises(si.ScanImportError):
                si.load_aliases(self.write(f"{label}.csv", text))

    def test_a_name_listed_twice_for_the_same_asset_is_fine_and_an_alias_of_itself_too(self):
        path = self.write("ok.csv", "alias,asset_id\nA,B\na,b\nB,B\n")
        self.assertEqual(si.load_aliases(path), {"a": "b", "b": "B"})

    def test_too_many_aliases_are_refused(self):
        with mock.patch.object(si, "MAX_ALIASES", 2), self.assertRaisesRegex(si.ScanImportError, "more than 2"):
            si.load_aliases(self.write("many.csv", "alias,asset_id\nA,X\nB,X\nC,X\n"))


class LimitTests(Case):
    def test_a_file_over_the_size_limit_is_refused_before_it_is_read(self):
        path = self.write("big.csv", NESSUS_HEAD + "\n")
        with mock.patch.object(si, "MAX_FILE_BYTES", 10), self.assertRaisesRegex(si.ScanImportError, "larger than"):
            self.read(path)

    def test_too_many_rows_are_refused(self):
        rows = ["1,,5,5,High,h,tcp,1,N,,,,," for _ in range(5)]
        path = self.write("rows.csv", NESSUS_HEAD + "\n" + "\n".join(rows) + "\n")
        with mock.patch.object(si, "MAX_INPUT_ROWS", 3), self.assertRaisesRegex(si.ScanImportError, "more than 3"):
            self.read(path)

    def test_a_large_cell_is_read_and_a_huge_one_is_refused(self):
        big = "x" * 300_000
        findings, _a, _r = self.read(self.write("cell.csv", NESSUS_HEAD + f'\n1,,5,5,High,h,tcp,1,N,,,,,"{big}"\n'))
        self.assertEqual(len(findings), 1)
        with (
            mock.patch.object(si, "MAX_FIELD_BYTES", 1000),
            self.assertRaisesRegex(si.ScanImportError, "not a valid CSV"),
        ):
            self.read(self.write("huge.csv", NESSUS_HEAD + f'\n1,,5,5,High,h,tcp,1,N,,,,,"{big}"\n'))

    def test_the_global_csv_limit_is_put_back(self):
        before = csv.field_size_limit()
        self.read(SAMPLES / "nessus/classic.csv")
        with self.assertRaises(si.ScanImportError):
            self.read(self.write("e.csv", ""))
        self.assertEqual(csv.field_size_limit(), before)


class WriteTests(Case):
    def imported(self, *paths, **kwargs):
        return si.import_exports(list(paths) or [SAMPLES / "nessus/classic.csv"], **kwargs)

    def test_the_findings_file_has_the_columns_ot_triage_reads(self):
        out = self.dir / "f.csv"
        si.write_findings(out, self.imported())
        with open(out, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            self.assertEqual(reader.fieldnames, si.FINDING_COLUMNS)
            self.assertEqual(len(list(reader)), 6)

    def test_a_threat_column_appears_only_when_a_default_was_given(self):
        for threat, header in (("", si.FINDING_COLUMNS), ("none", [*si.FINDING_COLUMNS[:-1], "threat", "source_tool"])):
            with self.subTest(threat):
                out = self.dir / f"f{threat}.csv"
                si.write_findings(out, self.imported(default_threat=threat))
                with open(out, newline="", encoding="utf-8") as fh:
                    self.assertEqual(next(csv.reader(fh)), header)

    def test_text_that_could_run_as_a_formula_is_defused(self):
        path = self.write(
            "f.csv", NESSUS_HEAD + '\n1,,5,5,High,=cmd|x,tcp,1,"+SUM(1)",,,,,\n2,,5,5,High,@h,tcp,1,"-2+3",,,,,\n'
        )
        out = self.dir / "o.csv"
        si.write_findings(out, si.import_exports([path]))
        with open(out, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual([(r["asset_id"], r["name"]) for r in rows], [("'=cmd|x", "'+SUM(1)"), ("'@h", "'-2+3")])

    def test_the_output_is_ranked_by_the_ranker_with_the_same_rules_as_any_findings_file(self):
        result = self.imported()
        out, inv = self.dir / "f.csv", self.dir / "i.csv"
        si.write_findings(out, result)
        si.write_inventory(inv, result)
        fill = {
            "192.0.2.21": ("crown jewel", "medium", "partial"),
            "192.0.2.22": ("important", "medium", "none"),
            "198.51.100.4": ("important", "high", "none"),
            "192.0.2.5": ("standard", "low", "none"),
        }
        with open(inv, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            rows = list(reader)
            columns = reader.fieldnames
        for row in rows:
            row["criticality"], row["exposure"], row["controls"] = fill[row["asset_id"]]
        with open(inv, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, columns, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        import inventory

        loaded = inventory.load(inv)
        plain = batch.process_file(out, inventory=loaded)
        # with no threat data a CVE row cannot get a threat level, exactly as for a findings file written by hand
        self.assertTrue(all(i.priority == "ERROR" and "threat: value is required" in i.error for i in plain))
        with open(out, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        with open(out, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, [*rows[0], "threat"], lineterminator="\n")
            writer.writeheader()
            writer.writerows(dict(r, threat="active") for r in rows)
        items = batch.process_file(out, inventory=loaded)
        by = {i.cve: i for i in items if i.cve}
        self.assertEqual(by["CVE-2019-0708"].priority, NOW)
        hand = self.write(
            "hand.csv", "id,asset_id,name,cve,cvss,threat\nX,192.0.2.22,Hand written,CVE-2019-0708,9.8,active\n"
        )
        again = batch.process_file(hand, inventory=loaded)[0]
        self.assertEqual(
            (by["CVE-2019-0708"].priority, by["CVE-2019-0708"].result.score), (again.priority, again.result.score)
        )
        self.assertIn(by["CVE-2017-0144"].priority, (NOW, NEXT, NEVER))


class InventoryTests(Case):
    def setUp(self):
        super().setUp()
        self.result = si.ImportResult(
            assets={
                "cc-plc-11": si.Asset("CC-PLC-11", "Filler PLC", "Siemens", "S7-1500", "V2.9.2"),
                "192.0.2.9": si.Asset("192.0.2.9", "", "", "", ""),
            }
        )
        self.result.findings = []

    def test_a_new_inventory_has_the_columns_a_person_fills_in(self):
        out = self.dir / "i.csv"
        self.assertEqual(si.write_inventory(out, self.result), (2, 0))
        with open(out, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(
            rows[0],
            {
                "asset_id": "CC-PLC-11",
                "name": "Filler PLC",
                "criticality": "",
                "exposure": "",
                "controls": "",
                "vendor": "Siemens",
                "product": "S7-1500",
                "version": "V2.9.2",
            },
        )
        self.assertEqual({k: v for k, v in rows[1].items() if v}, {"asset_id": "192.0.2.9"})

    def existing(self, text):
        return self.write("existing.csv", text)

    def test_an_existing_inventory_is_extended_never_overwritten_and_keeps_its_own_columns(self):
        path = self.existing(
            "asset_id,name,criticality,exposure,controls,Manufacturer,notes\n"
            "cc-plc-11,,crown jewel,low,strong,,keep me\nOTHER,Other,standard,low,none,Acme,\n"
        )
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        out = self.dir / "o.csv"
        self.assertEqual(si.write_inventory(out, self.result, path), (1, 1))
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)
        with open(out, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            rows = {r["asset_id"]: r for r in reader}
            header = reader.fieldnames
        self.assertEqual(
            header,
            ["asset_id", "name", "criticality", "exposure", "controls", "Manufacturer", "notes", "product", "version"],
        )
        self.assertEqual(
            {k: v for k, v in rows["cc-plc-11"].items() if v},
            {
                "asset_id": "cc-plc-11",
                "name": "Filler PLC",
                "criticality": "crown jewel",
                "exposure": "low",
                "controls": "strong",
                "Manufacturer": "Siemens",
                "notes": "keep me",
                "product": "S7-1500",
                "version": "V2.9.2",
            },
        )
        self.assertEqual(rows["OTHER"]["Manufacturer"], "Acme")
        self.assertEqual(rows["192.0.2.9"]["asset_id"], "192.0.2.9")

    def test_a_value_the_inventory_already_has_is_never_replaced(self):
        path = self.existing("asset_id,name,vendor,product,version\nCC-PLC-11,Mine,My vendor,My product,1.0\n")
        out = self.dir / "o.csv"
        self.assertEqual(si.write_inventory(out, self.result, path), (1, 0))
        with open(out, newline="", encoding="utf-8") as fh:
            row = next(csv.DictReader(fh))
        self.assertEqual(
            (row["name"], row["vendor"], row["product"], row["version"]), ("Mine", "My vendor", "My product", "1.0")
        )

    def test_the_result_loads_as_an_inventory_and_text_is_defused(self):
        self.result.assets["x"] = si.Asset("=x", "@name", "-v", "+p", "\tver")
        out = self.dir / "o.csv"
        si.write_inventory(out, self.result)
        import inventory

        loaded = inventory.load(out)
        self.assertEqual(len(loaded), 3)
        self.assertIn("'=x", out.read_text(encoding="utf-8"))

    def test_an_existing_inventory_without_an_asset_id_column_is_refused(self):
        with self.assertRaisesRegex(si.ScanImportError, "asset_id"):
            si.write_inventory(self.dir / "o.csv", self.result, self.existing("name,exposure\nA,high\n"))


class SummaryTests(Case):
    def test_the_summary_says_what_was_skipped_merged_and_needs_a_decision(self):
        result = si.import_exports(
            [SAMPLES / "nessus/classic.csv", SAMPLES / "tenable/vm_export.csv", SAMPLES / "openvas/report.csv"],
            si.load_aliases(SAMPLES / "merge" / "aliases.csv"),
        )
        text = "\n".join(si.summary_lines(result))
        self.assertIn("classic.csv: Nessus CSV, 8 rows, 6 findings kept", text)
        self.assertIn("  skipped 2: informational (no risk)", text)
        self.assertIn("reported more than once merged into another", text)
        self.assertIn("1 finding has no score in the export", text)
        self.assertIn("2 findings have no CVE, so a threat level is needed", text)

    def test_the_summary_uses_the_right_singular_and_plural(self):
        result = si.ImportResult(
            findings=[si.Finding("1", "A", "n")], assets={"a": si.Asset("A")}, not_scored=1, need_threat=1
        )
        text = "\n".join(si.summary_lines(result))
        self.assertIn("1 finding on 1 asset", text)
        self.assertIn("1 finding has no score", text)


if given is not None:

    class FuzzTests(Case):
        @hyp_settings(max_examples=150, deadline=None)
        @given(st.text(max_size=2000))
        def test_any_text_under_a_known_header_imports_or_is_refused_cleanly(self, body):
            for head in (NESSUS_HEAD, TENABLE_HEAD, OPENVAS_HEAD):
                path = self.dir / "fuzz.csv"
                path.write_text(head + "\n" + body, encoding="utf-8", errors="replace")
                try:
                    result = si.import_exports([path])
                except si.ScanImportError:
                    continue
                for f in result.findings:
                    self.assertTrue(f.asset_id.isprintable() and f.name.isprintable())
                    self.assertLessEqual(len(f.name), si.MAX_NAME_CHARS)
                    self.assertIn(f.cvss, [""] + [f"{v / 10:.1f}" for v in range(101)])
                out = self.dir / "fuzz_out.csv"
                si.write_findings(out, result)
                si.write_inventory(self.dir / "fuzz_inv.csv", result)
                io.StringIO("\n".join(si.summary_lines(result)))


if __name__ == "__main__":
    unittest.main()
