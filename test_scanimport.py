import csv
import hashlib
import io
import os
import tempfile
import threading
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
        ("claroty/device_vulns.csv", "claroty"),
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
        self.assertEqual(reports["claroty/device_vulns.csv"].skipped,
                         {"already resolved": 1, "patch already installed": 1})


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


def xml_item(
    plugin="97833",
    severity="3",
    name="MS17-010",
    cves=("CVE-2017-0144",),
    v2="9.3",
    v3="8.1",
    extra="",
    family="Windows",
):
    cve = "".join(f"<cve>{c}</cve>" for c in cves)
    scores = (f"<cvss_base_score>{v2}</cvss_base_score>" if v2 else "") + (
        f"<cvss3_base_score>{v3}</cvss3_base_score>" if v3 else ""
    )
    return (
        f'<ReportItem port="445" svc_name="cifs" protocol="tcp" severity="{severity}" pluginID="{plugin}" '
        f'pluginName="{name}" pluginFamily="{family}">{cve}{scores}{extra}'
        "<plugin_output>output</plugin_output></ReportItem>"
    )


def xml_host(name="192.0.2.21", items=(), tags=""):
    return f'<ReportHost name="{name}"><HostProperties>{tags}</HostProperties>{"".join(items)}</ReportHost>'


def xml_file(*hosts, root="NessusClientData_v2", head='<?xml version="1.0"?>'):
    return f'{head}<{root}><Policy><policyName>p</policyName></Policy><Report name="r" xmlns:cm="http://www.nessus.org/cm">{"".join(hosts)}</Report></{root}>'


class NessusXmlTests(Case):
    def xml(self, text, name="scan.nessus"):
        return self.write(name, text)

    def test_the_sample_gives_the_expected_findings_and_names_the_hosts(self):
        findings, assets, report = self.read(SAMPLES / "nessus/export.nessus")
        with open(SAMPLES / "expected" / "nessus_xml.findings.csv", newline="", encoding="utf-8") as fh:
            want = list(csv.DictReader(fh))
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
        self.assertEqual(got, want)
        self.assertEqual(
            (report.format, report.rows, report.kept, report.skipped),
            ("Nessus .nessus (v2 XML)", 4, 4, {"informational (no risk)": 1}),
        )
        self.assertEqual(sorted(assets), ["cc-hmi-03.example.com", "cc-sw-05.example.com"])

    def test_one_finding_per_cve_the_v3_score_wins_and_text_is_cleaned(self):
        text = xml_file(
            xml_host(
                "h1",
                [
                    xml_item(cves=("CVE-2017-0144", "cve-2017-0143", "CVE-2017-0144")),
                    xml_item(plugin="2", name="No&#8238; cve", cves=(), v2="7.5", v3=""),
                    xml_item(plugin="3", cves=("CVE-2020-0001",), v2="", v3=""),
                ],
            )
        )
        findings, _a, _r = self.read(self.xml(text))
        self.assertEqual(
            [(f.cve, f.cvss) for f in findings],
            [("CVE-2017-0144", "8.1"), ("CVE-2017-0143", "8.1"), ("", "7.5"), ("CVE-2020-0001", "")],
        )
        self.assertEqual(findings[2].name, "No cve")

    def test_informational_and_compliance_items_are_skipped_and_counted(self):
        compliance = xml_item(
            plugin="21157", name="Unix Compliance Checks", cves=(), v2="", v3="", family="Policy Compliance"
        )
        child = xml_item(plugin="5", cves=(), v2="", v3="", extra="<cm:compliance-result>FAILED</cm:compliance-result>")
        text = xml_file(xml_host("h1", [xml_item(severity="0"), compliance, child, xml_item(severity="1")]))
        findings, _a, report = self.read(self.xml(text))
        self.assertEqual(len(findings), 1)
        self.assertEqual(report.skipped, {"informational (no risk)": 1, "compliance check (not a vulnerability)": 2})

    def test_the_host_name_falls_back_to_its_ip_tag_and_a_host_with_neither_is_skipped(self):
        tags = '<tag name="host-ip">192.0.2.9</tag><tag name="host-fqdn">plc.example.com</tag><tag name="other">x</tag>'
        text = xml_file(
            xml_host("", [xml_item()], tags), xml_host("", [xml_item()]), xml_host("named", [xml_item()], tags)
        )
        findings, assets, report = self.read(self.xml(text))
        self.assertEqual([f.asset_id for f in findings], ["192.0.2.9", "named"])
        self.assertEqual(report.skipped, {"no host or asset name": 1})
        self.assertEqual([a.name for a in assets.values()], ["plc.example.com", "plc.example.com"])

    def test_a_byte_order_mark_an_undeclared_prefix_and_utf16_are_handled(self):
        findings, _a, _r = self.read(self.xml("\ufeff" + xml_file(xml_host("h1", [xml_item()]))))
        self.assertEqual(len(findings), 1)
        findings, _a, _r = self.read(
            self.write(
                "u16.nessus",
                xml_file(xml_host("h1", [xml_item()]), head='<?xml version="1.0" encoding="UTF-16"?>').encode("utf-16"),
            )
        )
        self.assertEqual(len(findings), 1)

    def test_the_plugin_output_is_never_kept(self):
        big = "x" * 5_000_000
        item = xml_item(extra=f"<description>{big}</description>").replace("output", big)
        findings, _a, _r = self.read(self.xml(xml_file(xml_host("h1", [item]))))
        self.assertEqual(len(findings), 1)
        reader = si._NessusXml(si.FileReport("x", "y"))
        reader.begin_text()
        for _ in range(3):
            reader.data("y" * 10_000_000)
        self.assertLessEqual(len("".join(reader.text)), si.MAX_XML_TEXT_CHARS)

    def test_a_doctype_or_an_entity_is_refused_so_nothing_can_expand(self):
        bomb = (
            '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY a "aaaaaaaaaa">'
            '<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>'
            "<NessusClientData_v2>&b;</NessusClientData_v2>"
        )
        external = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><NessusClientData_v2>&e;</NessusClientData_v2>'
        for label, text in (
            ("billion laughs", bomb),
            ("external entity", external),
            ("doctype only", '<?xml version="1.0"?><!DOCTYPE NessusClientData_v2><NessusClientData_v2/>'),
        ):
            with self.subTest(label), self.assertRaisesRegex(si.ScanImportError, "declares a DTD or an entity"):
                self.read(self.xml(text))

    def test_other_files_are_refused_cleanly(self):
        cases = {
            "wrong root": xml_file(xml_host("h1", [xml_item()]), root="Other"),
            "no hosts": xml_file(),
            "truncated": xml_file(xml_host("h1", [xml_item()]))[:-40],
            "not xml": "<html><body>hello</body></html>",
            "garbage": "<<<<",
            "mismatched": "<NessusClientData_v2><Report></NessusClientData_v2>",
        }
        for label, text in cases.items():
            with self.subTest(label), self.assertRaises(si.ScanImportError):
                self.read(self.xml(text))

    def test_deep_nesting_is_refused(self):
        deep = "<NessusClientData_v2>" + "<a>" * 200 + "</a>" * 200 + "</NessusClientData_v2>"
        with self.assertRaisesRegex(si.ScanImportError, "nested too deeply"):
            self.read(self.xml(deep))

    def test_limits_on_size_rows_and_findings_apply(self):
        text = xml_file(xml_host("h1", [xml_item(plugin=str(n)) for n in range(5)]))
        path = self.xml(text)
        with mock.patch.object(si, "MAX_FILE_BYTES", 100), self.assertRaisesRegex(si.ScanImportError, "larger than"):
            self.read(path)
        with mock.patch.object(si, "MAX_INPUT_ROWS", 3), self.assertRaisesRegex(si.ScanImportError, "more than 3"):
            self.read(path)
        with mock.patch.object(si, "MAX_RAW_FINDINGS", 3), self.assertRaisesRegex(si.ScanImportError, "more than 3"):
            self.read(path)

    def test_the_file_is_fed_to_the_parser_in_pieces_never_whole(self):
        calls = []
        real = si.expat.ParserCreate

        class Counting:
            def __init__(self):
                object.__setattr__(self, "inner", real())

            def __setattr__(self, name, value):
                setattr(self.inner, name, value)

            def __getattr__(self, name):
                return getattr(self.inner, name)

            def Parse(self, data, final=False):
                calls.append(len(data))
                return self.inner.Parse(data, final)

        items = [xml_item(plugin=str(n)) for n in range(400)]
        path = self.xml(xml_file(xml_host("h1", items)))
        with mock.patch.object(si, "XML_CHUNK_BYTES", 4096), mock.patch.object(si.expat, "ParserCreate", Counting):
            self.read(path)
        self.assertGreater(len(calls), 5)
        self.assertLessEqual(max(calls), 4096)
        self.assertEqual(calls[-1], 0)  # the parser is told the file has ended

    def test_a_large_file_is_read_in_pieces(self):
        items = [xml_item(plugin=str(n), cves=(f"CVE-2020-{n % 9000:04d}",)) for n in range(3000)]
        path = self.xml(xml_file(xml_host("h1", items)))
        with mock.patch.object(si, "XML_CHUNK_BYTES", 997):
            findings, _a, _r = self.read(path)
        self.assertEqual(len(findings), 3000)

    def test_a_csv_that_looks_like_text_is_not_mistaken_for_xml_and_xml_is_found_by_content_not_name(self):
        findings, _a, _r = self.read(self.write("scan.txt", xml_file(xml_host("h1", [xml_item()]))))
        self.assertEqual(len(findings), 1)
        findings, _a, _r = self.read(self.nessus("1,CVE-2020-0001,5,5,High,h,tcp,1,N,,,,,", name="scan.nessus"))
        self.assertEqual(len(findings), 1)

    def test_it_merges_with_the_csv_exports_of_the_same_scanner(self):
        csv_path = self.nessus("97833,CVE-2017-0144,9.3,8.1,Critical,192.0.2.21,tcp,445,MS17-010,,,,,")
        xml_path = self.xml(xml_file(xml_host("192.0.2.21", [xml_item()])))
        result = si.import_exports([csv_path, xml_path])
        self.assertEqual((len(result.findings), result.merged), (1, 1))
        self.assertEqual(result.findings[0].source, "nessus+nessus-xml")

    def test_opening_a_nessus_file_in_batch_or_as_an_inventory_says_what_it_is(self):
        import inventory

        path = self.xml(xml_file(xml_host("h1", [xml_item()])))
        for loader in (batch.process_file, inventory.load):
            with (
                self.subTest(loader.__module__),
                self.assertRaisesRegex(ValueError, r"scanner export \(Nessus .nessus"),
            ):
                loader(path)


NOZOMI_RECORD = {
    "id": "nc-1",
    "cve": "CVE-2023-28831",
    "cve_score": 7.5,
    "cve_summary": "A flaw in the firmware",
    "asset_id": "a-1",
    "node_label": "PLC-1",
    "node_vendor": "Siemens",
    "node_product_name": "S7-1500",
    "node_firmware_version": "V2.9.2",
    "latest_hotfix": "V2.9.7",
    "likelihood": 0.6,
    "resolved": False,
}


def dragos_record(vuln_id="vd-1", state="open", cve="CVE-2023-28831", base=7.5, name="PLC-1", **extra):
    host = {
        "id": "as-1",
        "name": name,
        "vendor": "Siemens",
        "hardware": {"model": "S7-1500", "firmware_version": "V2.8.1"},
    }
    vuln = {
        "id": vuln_id,
        "enumeration": cve,
        "reference": cve,
        "title": "A flaw",
        "state": state,
        "severity": 3,
        "dragos_score": 6.1,
        "intel": {"active_exploit": True},
    }
    if base is not None:
        vuln["score"] = {"base": base, "version": "3.1"}
    return {"host": host, "vulnerability": {**vuln, **extra}}


class NozomiTests(Case):
    def json(self, doc, name="n.json"):
        import json

        return self.write(name, json.dumps(doc))

    def test_the_sample_gives_findings_assets_and_an_experimental_note(self):
        findings, assets, report = self.read(SAMPLES / "nozomi/node_cves.json")
        self.assertEqual(report.format, "Nozomi node_cves (experimental)")
        self.assertEqual(report.note, si.EXPERIMENTAL_NOTE)
        self.assertEqual((report.rows, report.kept, report.skipped), (7, 5, {"already resolved": 1, "no CVE": 1}))
        self.assertEqual(
            [(f.asset_id, f.cve, f.cvss, f.patch) for f in findings][:2],
            [("CC-PLC-11", "CVE-2023-28831", "7.5", "available"), ("CC-GW-31", "CVE-2016-9361", "9.8", "available")],
        )
        plc = assets["cc-plc-11"]
        self.assertEqual((plc.vendor, plc.product, plc.version), ("Siemens", "S7-1500", "V2.9.2"))

    def test_every_documented_container_is_read(self):
        for doc in (
            {"result": [NOZOMI_RECORD]},
            {"results": [NOZOMI_RECORD]},
            {"data": [NOZOMI_RECORD]},
            [NOZOMI_RECORD],
        ):
            with self.subTest(type(doc).__name__):
                findings, _a, _r = self.read(self.json(doc))
                self.assertEqual(len(findings), 1)

    def test_resolved_records_are_skipped_in_every_spelling(self):
        for value, skipped in (
            (True, True),
            ("true", True),
            ("True", True),
            ("1", True),
            (1, True),
            (False, False),
            ("false", False),
            ("", False),
            (None, False),
            (0, False),
        ):
            with self.subTest(value=value):
                findings, _a, _r = self.read(self.json({"result": [dict(NOZOMI_RECORD, resolved=value)]}))
                self.assertEqual(len(findings), 0 if skipped else 1)

    def test_scores_may_arrive_as_text_and_bad_ones_are_left_empty(self):
        recs = [
            dict(NOZOMI_RECORD, id=f"n{i}", cve_score=score)
            for i, score in enumerate(("9.8", 7, "abc", 12, -1, None, ""))
        ]
        findings, _a, _r = self.read(self.json(recs))
        self.assertEqual([f.cvss for f in findings], ["9.8", "7.0", "", "", "", "", ""])

    def test_a_record_with_no_cve_or_several_or_no_asset_is_skipped_and_counted(self):
        recs = [
            dict(NOZOMI_RECORD, cve=""),
            dict(NOZOMI_RECORD, cve="CVE-2023-0001 CVE-2023-0002"),
            dict(NOZOMI_RECORD, node_label="", asset_id=""),
            dict(NOZOMI_RECORD, node_label="", id="x"),
            "text",
            5,
            None,
            [],
        ]
        findings, _a, report = self.read(self.json(recs))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].asset_id, "a-1")
        self.assertEqual(report.skipped, {"no CVE": 2, "no node label or asset id": 1, "not a record": 4})

    def test_the_patch_is_available_only_when_a_hotfix_is_named_and_the_name_is_the_summary(self):
        recs = [
            dict(NOZOMI_RECORD, id="a", latest_hotfix="", minimum_hotfix="KB1"),
            dict(NOZOMI_RECORD, id="b", latest_hotfix="", minimum_hotfix=""),
            dict(NOZOMI_RECORD, id="c", cve_summary=""),
        ]
        findings, _a, _r = self.read(self.json(recs))
        self.assertEqual([f.patch for f in findings], ["available", "", "available"])
        self.assertEqual((findings[0].name, findings[2].name), ("A flaw in the firmware", "CVE-2023-28831 on PLC-1"))

    def test_the_likelihood_never_reaches_the_findings(self):
        findings, _a, _r = self.read(self.json([NOZOMI_RECORD]))
        self.assertNotIn("0.6", repr(findings))

    def test_the_cve_is_normalised(self):
        findings, _a, _r = self.read(self.json([dict(NOZOMI_RECORD, cve="  cve-2023-28831 ")]))
        self.assertEqual(findings[0].cve, "CVE-2023-28831")

    def test_a_csv_export_of_the_same_fields_is_read_too(self):
        header = (
            "id,cve,cve_score,cve_summary,node_label,node_vendor,node_product_name,node_firmware_version,"
            "resolved,latest_hotfix"
        )
        rows = [
            "nc-1,CVE-2023-28831,7.5,A flaw,PLC-1,Siemens,S7-1500,V2.9.2,false,",
            "nc-2,CVE-2023-28831,7.5,A flaw,PLC-2,,,,true,",
            'nc-3,"CVE-2020-0001",9.8,"A, flaw",PLC-3,Moxa,NPort,1.0,,KB5',
        ]
        findings, assets, report = self.read(self.write("n.csv", header + "\n" + "\n".join(rows) + "\n"))
        self.assertEqual(report.format, "Nozomi node_cves (experimental)")
        self.assertEqual(report.note, si.EXPERIMENTAL_NOTE)
        self.assertEqual(
            [(f.asset_id, f.cve, f.patch) for f in findings],
            [("PLC-1", "CVE-2023-28831", ""), ("PLC-3", "CVE-2020-0001", "available")],
        )
        self.assertEqual(report.skipped, {"already resolved": 1})
        self.assertEqual(assets["plc-3"].vendor, "Moxa")
        self.assertEqual(findings[1].name, "A, flaw")

    def test_header_spelling_of_the_csv_does_not_matter(self):
        text = "CVE,Score,Node Label\nCVE-2020-0001,5,H\n"
        self.assertEqual(si.detect_format(["CVE", "Score", "Node Label"]), si.NOZOMI)
        findings, _a, _r = self.read(self.write("n.csv", text))
        self.assertEqual(self.ids(findings), [("H", "CVE-2020-0001", "5.0")])


class DragosTests(Case):
    def json(self, doc, name="d.json"):
        import json

        return self.write(name, json.dumps(doc))

    def test_the_sample_gives_findings_assets_and_an_experimental_note(self):
        findings, assets, report = self.read(SAMPLES / "dragos/detections.json")
        self.assertEqual(report.format, "Dragos detections (experimental)")
        self.assertEqual(report.note, si.EXPERIMENTAL_NOTE)
        self.assertEqual((report.rows, report.kept, report.skipped), (5, 4, {"already resolved": 1}))
        self.assertEqual(
            [(f.asset_id, f.cve, f.cvss) for f in findings],
            [
                ("CC-PLC-12", "CVE-2023-28831", "7.5"),
                ("CC-RTU-22", "CVE-2024-2617", "7.2"),
                ("CC-HMI-23", "CVE-2016-0854", ""),
                ("CC-ENG-24", "", ""),
            ],
        )
        self.assertEqual(assets["cc-plc-12"].product, "S7-1500")

    def test_every_documented_container_is_read(self):
        for doc in (
            {"content": [dragos_record()]},
            {"detections": [dragos_record()]},
            {"data": [dragos_record()]},
            {"results": [dragos_record()]},
            [dragos_record()],
        ):
            with self.subTest(type(doc).__name__):
                self.assertEqual(len(self.read(self.json(doc))[0]), 1)

    def test_closed_detections_are_skipped_and_other_states_kept(self):
        recs = [
            dragos_record(f"v{i}", state=s)
            for i, s in enumerate(("open", "Resolved", "CLOSED", "fixed", "remediated", "mitigated", "", None))
        ]
        findings, _a, report = self.read(self.json(recs))
        self.assertEqual(len(findings), 4)
        self.assertEqual(report.skipped, {"already resolved": 4})

    def test_the_score_is_the_cvss_base_and_dragos_own_scale_is_never_used(self):
        recs = [
            dragos_record("a", base=9.8),
            dragos_record("b", base=None),
            dragos_record("c", base="bad"),
            dragos_record("d", base=11),
        ]
        findings, _a, _r = self.read(self.json(recs))
        self.assertEqual([f.cvss for f in findings], ["9.8", "", "", ""])
        self.assertNotIn("6.1", repr(findings))

    def test_the_enumeration_wins_over_the_reference_when_both_name_a_cve(self):
        findings, _a, _r = self.read(self.json([dragos_record(enumeration="CVE-2020-0001", reference="CVE-2020-0002")]))
        self.assertEqual(findings[0].cve, "CVE-2020-0001")

    def test_the_cve_comes_from_enumeration_then_reference_and_may_be_absent(self):
        recs = [
            dragos_record("a", cve="CVE-2020-0001"),
            dragos_record("b", enumeration="", reference="CVE-2020-0002"),
            dragos_record("c", enumeration="CWE-79", reference="x"),
        ]
        findings, _a, _r = self.read(self.json(recs))
        self.assertEqual([f.cve for f in findings], ["CVE-2020-0001", "CVE-2020-0002", ""])

    def test_a_detection_without_a_host_or_a_name_is_skipped(self):
        recs = [
            dragos_record(name=""),
            {"host": {"name": "h"}, "vulnerability": []},
            {"vulnerability": {}},
            "x",
            dragos_record("ok"),
        ]
        recs[0]["host"]["id"] = ""
        findings, _a, report = self.read(self.json(recs))
        self.assertEqual([f.id for f in findings], ["dragos:ok"])
        self.assertEqual(
            report.skipped,
            {"no host name": 1, "not a detection (no host and vulnerability)": 2, "not a record": 1},
        )

    def test_missing_hardware_details_leave_the_asset_facts_empty(self):
        rec = dragos_record()
        del rec["host"]["hardware"]
        del rec["host"]["vendor"]
        _f, assets, _r = self.read(self.json([rec]))
        self.assertEqual((assets["plc-1"].vendor, assets["plc-1"].product, assets["plc-1"].version), ("", "", ""))

    def test_the_intelligence_and_the_purdue_level_never_reach_the_findings(self):
        rec = dragos_record()
        rec["host"]["pera_level"] = 0
        findings, _a, _r = self.read(self.json([rec]))
        self.assertNotIn("exploit", repr(findings).lower())
        self.assertNotIn("pera", repr(findings).lower())


class JsonSafetyTests(Case):
    def test_json_that_is_not_an_export_is_refused_cleanly(self):
        cases = {
            "empty object": "{}",
            "empty list": "[]",
            "scalar": "5",
            "no list": '{"a": 1}',
            "wrong records": '[{"x": 1}]',
            "truncated": '{"result": [',
            "nan": '{"result": [{"cve": "CVE-2020-0001", "node_label": "x", "cve_score": NaN}]}',
            "infinity": '{"result": [{"cve": "CVE-2020-0001", "node_label": "x", "cve_score": Infinity}]}',
            "duplicate keys": '{"result": [], "result": []}',
            "duplicate keys in a record": (
                '{"result": [{"cve": "CVE-2020-0001", "node_label": "x", "cve": "CVE-2020-0002"}]}'
            ),
            "not json": "[hello",
            "string": '"text"',
        }
        for label, text in cases.items():
            with self.subTest(label), self.assertRaises(si.ScanImportError):
                self.read(self.write(f"{label}.json", text))

    def test_deeply_nested_json_is_refused_not_crashed(self):
        # Some Python versions give up on 100,000 levels (an invalid file) and some read them (a list of lists that is
        # not an export); either way the answer is a clean refusal, never a crash.
        with self.assertRaises(si.ScanImportError):
            self.read(self.write("deep.json", "[" * 100_000 + "]" * 100_000))
        with self.assertRaisesRegex(si.ScanImportError, "not a valid JSON"):
            self.read(self.write("deep_open.json", "[" * 100_000))

    def test_the_size_and_row_limits_apply(self):
        import json

        path = self.write("n.json", json.dumps({"result": [NOZOMI_RECORD] * 5}))
        with mock.patch.object(si, "MAX_JSON_BYTES", 100), self.assertRaisesRegex(si.ScanImportError, "larger than"):
            self.read(path)
        with mock.patch.object(si, "MAX_INPUT_ROWS", 3), self.assertRaisesRegex(si.ScanImportError, "more than 3"):
            self.read(path)
        with mock.patch.object(si, "MAX_RAW_FINDINGS", 3), self.assertRaisesRegex(si.ScanImportError, "more than 3"):
            self.read(path)

    def test_hostile_text_is_cleaned_cut_and_defused(self):
        import json

        rec = dict(
            NOZOMI_RECORD,
            cve_summary="=cmd|' /c calc'!A1\x1b[31m" + "x" * 500,
            node_label="@evil\u202e",
            node_vendor="+v",
            node_firmware_version="-1",
        )
        findings, assets, _r = self.read(self.write("h.json", json.dumps([rec])))
        self.assertTrue(findings[0].name.startswith("=cmd"))
        self.assertLessEqual(len(findings[0].name), si.MAX_NAME_CHARS)
        self.assertNotIn("\x1b", findings[0].name)
        out = self.dir / "out.csv"
        si.write_findings(out, si.merge(si.ImportResult(findings=findings, assets=assets)))
        text = out.read_text(encoding="utf-8")
        self.assertIn("'=cmd", text)
        self.assertIn("'@evil", text)

    def test_json_is_found_by_content_not_by_name_and_a_csv_with_braces_is_still_a_csv(self):
        import json

        findings, _a, _r = self.read(self.write("export.txt", json.dumps([NOZOMI_RECORD])))
        self.assertEqual(len(findings), 1)
        csv_path = self.nessus('1,,5,5,High,h,tcp,1,"{not json}",,,,,')
        self.assertEqual(len(self.read(csv_path)[0]), 1)

    def test_opening_a_json_file_in_batch_or_as_an_inventory_says_what_to_do(self):
        import inventory

        path = self.write("n.json", '{"result": []}')
        for loader in (batch.process_file, inventory.load):
            with self.subTest(loader.__module__), self.assertRaisesRegex(ValueError, "This is a JSON file"):
                loader(path)

    def test_the_summary_carries_the_experimental_note_for_json_exports_only(self):
        result = si.import_exports([SAMPLES / "nozomi/node_cves.json", SAMPLES / "nessus/classic.csv"])
        text = "\n".join(si.summary_lines(result))
        self.assertEqual(text.count("note: read from a public description"), 1)
        self.assertIn("node_cves.json: Nozomi node_cves (experimental), 7 rows, 5 findings kept", text)

    def test_an_inventory_is_filled_from_the_ot_tools_and_the_threat_decisions_stay_the_same(self):
        result = si.import_exports([SAMPLES / "nozomi/node_cves.json", SAMPLES / "dragos/detections.json"])
        self.assertEqual(result.need_threat, 1)
        out = self.dir / "i.csv"
        self.assertEqual(si.write_inventory(out, result), (9, 0))
        with open(out, newline="", encoding="utf-8") as fh:
            rows = {r["asset_id"]: r for r in csv.DictReader(fh)}
        self.assertEqual(
            (
                rows["CC-PLC-11"]["vendor"],
                rows["CC-PLC-11"]["product"],
                rows["CC-PLC-11"]["version"],
                rows["CC-PLC-11"]["name"],
            ),
            ("Siemens", "S7-1500", "V2.9.2", ""),
        )
        self.assertEqual(
            {rows["CC-PLC-11"]["criticality"], rows["CC-PLC-11"]["exposure"], rows["CC-PLC-11"]["controls"]}, {""}
        )


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


class ReviewFixTests(Case):
    """Findings of the independent review of 0.9.0 (reports/independent-review-codex), each with its input."""

    def inventory_with_header(self, header):
        return self.write("inv.csv", f"asset_id,asset,{header}\nPLC-1,critical,x\n")

    def written_header(self, header):
        result = si.ImportResult(assets={"plc-1": si.Asset("PLC-1", "", "Siemens", "S7-1500", "V2.9.2")})
        out = self.dir / "out.csv"
        si.write_inventory(out, result, self.inventory_with_header(header))
        with open(out, newline="", encoding="utf-8") as fh:
            return next(csv.reader(fh))

    def test_a_formula_in_the_header_of_the_existing_inventory_is_defused(self):
        for lead in ("=", "+", "-", "@", "\t", "\r"):
            with self.subTest(lead=repr(lead)):
                cell = lead + 'HYPERLINK("https://attacker.example/collect","Inventory")'
                header = self.written_header('"' + cell.replace('"', '""') + '"')
                self.assertNotEqual(header[2][:1], lead, header)
                self.assertTrue(header[2].startswith("'"), header)
                self.assertEqual(header[:2], ["asset_id", "asset"])

    def test_a_plain_header_is_left_as_it_was_and_the_result_still_loads_as_an_inventory(self):
        import inventory

        self.assertEqual(self.written_header("notes")[:3], ["asset_id", "asset", "notes"])
        out = self.dir / "out.csv"
        si.write_inventory(out, si.ImportResult(assets={"plc-1": si.Asset("PLC-1")}), self.inventory_with_header("=x"))
        self.assertEqual(len(inventory.load(out)), 1)

    def test_a_cell_with_thousands_of_distinct_cves_is_read_in_time_proportional_to_its_size(self):
        import time

        cell = " ".join(f"CVE-2024-{10000 + n}" for n in range(40_000))
        started = time.monotonic()
        found = si._cves(cell)
        self.assertEqual(len(found), 40_000)
        self.assertLess(time.monotonic() - started, 3.0)    # about 11 s when every id was compared with all before it
        messy = "cve-2024-0001 CVE-2024-0001 CVE-2024-0001, cve-2024-0002"
        self.assertEqual(si._cves(messy), ["CVE-2024-0001", "CVE-2024-0002"])

    def test_a_pipe_or_a_device_is_refused_instead_of_blocking_for_ever(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("no named pipes on this system")
        pipe = self.dir / "scan.csv"
        os.mkfifo(pipe)
        outcome = []
        worker = threading.Thread(target=lambda: outcome.append(self.refusal(pipe)), daemon=True)
        worker.start()
        worker.join(5)
        self.assertFalse(worker.is_alive(), "reading a named pipe blocked")
        self.assertIn("not a regular file", outcome[0])
        if os.path.exists("/dev/zero"):
            self.assertIn("not a regular file", self.refusal("/dev/zero"))

    def refusal(self, path):
        with self.assertRaises(si.ScanImportError) as caught:
            si.read_export(path)
        return str(caught.exception)

    def test_a_folder_is_refused(self):
        self.assertTrue(self.refusal(self.dir))

    def test_a_file_that_grows_after_it_was_opened_is_still_held_to_the_limit(self):
        import json

        path = self.write("grow.json", json.dumps({"result": [NOZOMI_RECORD] * 5}))
        real = si._open_input

        def opened_when_small(target, binary, limit=None, advice="", **options):
            return real(target, binary, None, advice, **options)    # the size check passes, as if the file were small

        small = mock.patch.object(si, "_open_input", opened_when_small)
        refused = self.assertRaisesRegex(si.ScanImportError, "larger than")
        with mock.patch.object(si, "MAX_JSON_BYTES", 100), small, refused:
            self.read(path)
        xml = self.write("grow.nessus", xml_file(xml_host("h1", [xml_item(plugin=str(n)) for n in range(50)])))
        refused = self.assertRaisesRegex(si.ScanImportError, "larger than")
        with mock.patch.object(si, "MAX_FILE_BYTES", 500), small, refused:
            self.read(xml)

    def test_the_size_limit_is_decided_on_the_open_file(self):
        path = self.write("big.csv", NESSUS_HEAD + "\n" + "x" * 5000)
        with mock.patch.object(si, "MAX_FILE_BYTES", 1000), self.assertRaisesRegex(si.ScanImportError, "larger than"):
            self.read(path)
        good = self.nessus("1,CVE-2020-0001,5,5,High,h,tcp,1,N,,,,,")
        with mock.patch("os.path.getsize", side_effect=AssertionError("the name must not be measured")), mock.patch(
            "os.stat", side_effect=AssertionError("the name must not be measured")
        ):
            self.read(good)

    def test_a_json_file_is_read_with_a_cap_never_whole(self):
        import json

        reads = []

        class Spy(io.BytesIO):
            def read(self, size=-1):
                reads.append(size)
                return super().read(size)

        raw = json.dumps({"result": [NOZOMI_RECORD]}).encode()
        with mock.patch.object(si, "_open_input", lambda *a, **k: Spy(raw)):
            self.read(self.dir / "spy.json")
        self.assertEqual(reads[-1], si.MAX_JSON_BYTES + 1)          # after the two short looks at the start of the file
        self.assertNotIn(-1, reads)

    def test_a_refused_file_is_closed_again(self):
        # A regular file that opens and is then refused (a folder cannot even be opened on Windows)
        path = self.write("big.csv", "plugin id,name\n" + "1,x\n" * 50)
        with mock.patch.object(si, "MAX_FILE_BYTES", 10), mock.patch("os.close", wraps=os.close) as closer:
            self.assertIn("larger than", self.refusal(path))
        self.assertTrue(closer.called)


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
            for head in (NESSUS_HEAD, TENABLE_HEAD, OPENVAS_HEAD, ",".join(CLAROTY_HEAD)):
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


CLAROTY_HEAD = [
    "DEVICE NAME", "DEVICE IP", "VULNERABILITY NAME", "DEVICE RISK SCORE", "DEVICE RISK SCORE POINTS", "CVEs",
    "CVSS V3 BASE SCORE", "CVSS V3 BASE SCORE POINTS", "ADJUSTED VULNERABILITY SCORE",
    "ADJUSTED VULNERABILITY SCORE POINTS", "ACTIVELY EXPLOITED", "EPSS SCORE", "DEVICE-VULN. DETECTION DATE",
    "LAST UPDATED", "DEVICE-VULN. RESOLUTION DATE", "PATCH INSTALL DATE", "Device-Vuln. Relevance Reasons",
    "DEVICE-VULN. NOTES", "MANUF. REMEDIATION INFO", "MANUF. REMEDIATION SOURCE LINKS",
    "MANUF. REMEDIATION SOURCE COMMENTS", "REQUIRED ACTIONS", "VULNERABILITY RELEVANCE",
]


def claroty_row(**changes):
    """One Claroty row (a list in the header's order) with the given columns changed; keys use _ for spaces."""
    row = dict.fromkeys(CLAROTY_HEAD, "N/A")
    row.update({"DEVICE NAME": "PLANT\\HOST-1", "DEVICE IP": "192.0.2.10", "VULNERABILITY NAME": "CVE-2024-0001",
                "CVEs": "CVE-2024-0001", "CVSS V3 BASE SCORE": "High", "CVSS V3 BASE SCORE POINTS": "7.5",
                "MANUF. REMEDIATION INFO": "Patch Available", "VULNERABILITY RELEVANCE": "Confirmed"})
    for key, value in changes.items():
        row[key.replace("_", " ")] = value
    return [row[name] for name in CLAROTY_HEAD]


class ClarotyTests(Case):
    def file(self, *rows, name="c.csv"):
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(CLAROTY_HEAD)
        writer.writerows(rows)
        return self.write(name, buffer.getvalue())

    def test_the_header_is_recognised_and_a_findings_screen_explains_what_to_do(self):
        self.assertEqual(si.detect_format(CLAROTY_HEAD), si.CLAROTY)
        self.assertIn("Claroty xDome", si.scanner_hint(CLAROTY_HEAD))
        for other in (NESSUS_HEAD, TENABLE_HEAD, OPENVAS_HEAD):
            self.assertNotEqual(si.detect_format(other.split(",")), si.CLAROTY)
        for partial in (["Device Name", "CVEs"], ["Device Name", "Vulnerability Name"], ["Vulnerability Name", "CVEs"]):
            self.assertIsNone(si.detect_format(partial), partial)       # all three columns are needed
        with self.assertRaisesRegex(ValueError, "Claroty xDome"):
            batch.read_rows(self.file(claroty_row()))

    def test_the_sample_gives_findings_assets_and_a_note(self):
        findings, assets, report = self.read(SAMPLES / "claroty/device_vulns.csv")
        self.assertEqual(report.format, "Claroty xDome device-vulnerability pairs")
        self.assertEqual((report.rows, report.kept), (15, 14))
        self.assertIn("one Claroty report layout", report.note)
        self.assertIn("3 rows are 'potentially relevant'", report.note)
        self.assertEqual(len(findings), 14)
        self.assertEqual(assets["cedarcreek\\cc-eng-02"].name, "192.0.2.22, 192.0.2.122")

    def test_a_row_with_several_cves_becomes_one_finding_each_with_the_rows_score(self):
        findings, _a, _r = self.read(self.file(claroty_row(CVEs="CVE-2021-44228, cve-2021-45046, CVE-2021-44228",
                                                           CVSS_V3_BASE_SCORE_POINTS="10")))
        self.assertEqual([(f.cve, f.cvss) for f in findings], [("CVE-2021-44228", "10.0"), ("CVE-2021-45046", "10.0")])
        self.assertEqual(len({f.id for f in findings}), 2)

    def test_the_score_is_the_numeric_column_never_the_severity_word(self):
        findings, _a, _r = self.read(self.file(
            claroty_row(CVSS_V3_BASE_SCORE_POINTS="9.8", CVSS_V3_BASE_SCORE="Critical"),
            claroty_row(CVEs="CVE-2024-0002", CVSS_V3_BASE_SCORE_POINTS="N/A", CVSS_V3_BASE_SCORE="High"),
            claroty_row(CVEs="CVE-2024-0003", CVSS_V3_BASE_SCORE_POINTS="11"),
            claroty_row(CVEs="CVE-2024-0004", CVSS_V3_BASE_SCORE_POINTS="", CVSS_V3_BASE_SCORE="6.5")))
        self.assertEqual([f.cvss for f in findings], ["9.8", "", "", "6.5"])

    def test_a_row_with_no_cve_is_kept_for_a_threat_level_to_be_chosen(self):
        result = si.import_exports([self.file(claroty_row(CVEs="N/A", VULNERABILITY_NAME="CC-1 (bulletin)"))])
        self.assertEqual((len(result.findings), result.need_threat), (1, 1))
        self.assertEqual(si.import_exports([self.file(claroty_row(CVEs="N/A"))], default_threat="none").need_threat, 0)

    def test_resolved_and_patched_rows_are_skipped_and_blank_dates_are_open(self):
        for column, reason in (("DEVICE-VULN._RESOLUTION_DATE", "already resolved"),
                               ("PATCH_INSTALL_DATE", "patch already installed")):
            for value in ("09/20/2026 1:02 AM", "2026-09-20"):
                with self.subTest(f"{column} {value!r}"):
                    findings, _a, report = self.read(self.file(claroty_row(**{column: value})))
                    self.assertEqual((findings, report.skipped), ([], {reason: 1}))
            for value in ("N/A", "n/a", "", "-", " None "):
                with self.subTest(f"{column} {value!r}"):
                    self.assertEqual(len(self.read(self.file(claroty_row(**{column: value})))[0]), 1)

    def test_potentially_relevant_rows_are_marked_and_can_be_left_out(self):
        path = self.file(claroty_row(), claroty_row(CVEs="CVE-2024-0002", VULNERABILITY_NAME="CVE-2024-0002 (x)",
                                                    VULNERABILITY_RELEVANCE="Potentially Relevant"))
        kept = si.import_exports([path])
        self.assertEqual([f.name for f in kept.findings], ["CVE-2024-0001", "CVE-2024-0002 (x) [potentially relevant]"])
        only = si.import_exports([path], only_confirmed=True)
        self.assertEqual([f.cve for f in only.findings], ["CVE-2024-0001"])
        self.assertEqual(only.reports[0].skipped, {"not confirmed (potentially relevant)": 1})
        self.assertNotIn("potentially relevant'", only.reports[0].note)

    def test_the_mark_never_pushes_a_long_name_past_the_limit(self):
        findings, _a, _r = self.read(self.file(claroty_row(VULNERABILITY_NAME="A" * 500,
                                                           VULNERABILITY_RELEVANCE="Potentially Relevant")))
        self.assertLessEqual(len(findings[0].name), si.MAX_NAME_CHARS)
        self.assertTrue(findings[0].name.endswith("[potentially relevant]"))

    def test_a_patch_is_only_called_available_when_the_row_says_a_fix_exists(self):
        cases = {"Patch Available": "available", "Version Upgrade Available": "available",
                 "Patch Available, Version Upgrade Available": "available",
                 "Contact Manufacturer, Patch Available": "available",
                 "Mitigation: Restrict Traffic": "", "Contact Manufacturer": "", "N/A": "",
                 "Manufacturer Not Patching Model, Version Upgrade Available": ""}
        for text, expected in cases.items():
            with self.subTest(text):
                findings, _a, _r = self.read(self.file(claroty_row(**{"MANUF._REMEDIATION_INFO": text})))
                self.assertEqual(findings[0].patch, expected)

    def test_claroty_own_scores_and_flags_are_never_used(self):
        quiet = self.read(self.file(claroty_row()))[0]
        loud = self.read(self.file(claroty_row(DEVICE_RISK_SCORE="Critical", DEVICE_RISK_SCORE_POINTS="99",
                                               ADJUSTED_VULNERABILITY_SCORE="Critical",
                                               ADJUSTED_VULNERABILITY_SCORE_POINTS="9.9",
                                               ACTIVELY_EXPLOITED="Actively Exploited", EPSS_SCORE="100")))[0]
        self.assertEqual(quiet, loud)
        self.assertEqual(loud[0].threat, "")

    def test_ips_lose_their_remark_and_are_capped_at_four(self):
        ips = "192.0.2.1 (Last known IP), 192.0.2.1, 192.0.2.2, 192.0.2.3 (Last known IP), 192.0.2.4, 192.0.2.5"
        _f, assets, _r = self.read(self.file(claroty_row(DEVICE_IP=ips)))
        self.assertEqual(assets["plant\\host-1"].name, "192.0.2.1, 192.0.2.2, 192.0.2.3, 192.0.2.4")

    def test_an_alias_joins_the_claroty_name_to_another_tools_name(self):
        path = self.file(claroty_row(), claroty_row(CVEs="CVE-2024-0002"))
        result = si.import_exports([path], {"plant\\host-1": "HOST-1"})
        self.assertEqual(({f.asset_id for f in result.findings}, result.renamed), ({"HOST-1"}, 2))

    def test_the_imported_findings_are_ranked_by_the_ordinary_rules(self):
        import inventory

        result = si.import_exports([SAMPLES / "claroty/device_vulns.csv"])
        out, inv = self.dir / "f.csv", self.dir / "i.csv"
        si.write_findings(out, result)
        si.write_inventory(inv, result)
        with open(inv, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            rows, columns = list(reader), reader.fieldnames
        for row in rows:
            row["criticality"], row["exposure"], row["controls"] = "crown jewel", "low", "strong"
        with open(inv, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, columns, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        with open(out, newline="", encoding="utf-8") as fh:
            found = list(csv.DictReader(fh))
        with open(out, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, [*found[0], "threat"], lineterminator="\n")
            writer.writeheader()
            writer.writerows(dict(row, threat="none") for row in found)
        items = batch.process_file(out, inventory=inventory.load(inv))
        by = {(i.id.split(":")[-2], i.cve): i for i in items}
        # a crown jewel with CVSS 7.0 or more is never NEVER, even with Low exposure and strong controls (POLICY.md, 5)
        scored = [i for i in items if i.cvss is not None and i.cvss >= 7.0]
        self.assertEqual(len(scored), 12)
        self.assertEqual({i.priority for i in scored}, {NEXT})
        self.assertEqual(by[("CEDARCREEK\\CC-ENG-24", "")].priority, NEVER)          # CVSS 5.9, no CVE
        self.assertEqual(by[("CEDARCREEK\\CC-ENG-24", "CVE-2024-6387")].priority, "ERROR")   # the export has no score
        self.assertIn("cvss", by[("CEDARCREEK\\CC-ENG-24", "CVE-2024-6387")].error)

    def test_a_formula_in_a_claroty_cell_is_defused_in_the_findings_file(self):
        result = si.import_exports([self.file(claroty_row(DEVICE_NAME="=HYPERLINK(\"http://x.example\",\"y\")",
                                                          VULNERABILITY_NAME='@SUM(1)'))])
        out = self.dir / "f.csv"
        si.write_findings(out, result)
        text = out.read_text(encoding="utf-8")
        self.assertIn("'=HYPERLINK", text)
        self.assertIn("'@SUM", text)
        self.assertNotIn(",=HYPERLINK", text)


if __name__ == "__main__":
    unittest.main()
