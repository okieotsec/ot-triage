import csv
import gzip
import math
import os
import tempfile
import unittest

import batch
import cvss
import settings
import threatdata
import uiprefs
from prioritizer import NEVER, NEXT, NOW, Asset, Controls, Exposure, Patch, Threat, parse_cvss, prioritize

try:
    from hypothesis import given
    from hypothesis import settings as hyp_settings
    from hypothesis import strategies as st
except ImportError:  # hypothesis is an optional test dependency
    st = None

PRIORITIES = {NOW, NEXT, NEVER}


@unittest.skipIf(st is None, "hypothesis is not installed")
class PropertyTests(unittest.TestCase):
    if st is not None:
        @hyp_settings(max_examples=500, deadline=None)
        @given(st.text())
        def test_parse_cvss_returns_a_valid_score_or_value_error(self, text):
            try:
                value = parse_cvss(text)
            except ValueError:
                return
            self.assertTrue(math.isfinite(value) and 0.0 <= value <= 10.0)

        @hyp_settings(max_examples=500, deadline=None)
        @given(st.floats(min_value=0.0, max_value=10.0), st.sampled_from(list(Threat)), st.sampled_from(list(Asset)),
               st.sampled_from(list(Exposure)), st.sampled_from(list(Controls)), st.sampled_from(list(Patch)))
        def test_prioritize_outputs_are_valid(self, cvss, threat, asset, exposure, controls, patch):
            result = prioritize(cvss, threat, asset, exposure, controls, patch)
            self.assertIn(result.priority, PRIORITIES)
            self.assertTrue(0.0 <= result.score <= 10.0)

        @hyp_settings(max_examples=500, deadline=None)
        @given(st.dictionaries(st.sampled_from(["id", "name", "cvss", "threat", "asset", "exposure", "patch",
                                                "controls"]), st.text()))
        def test_score_row_never_raises(self, row):
            item = batch.score_row(2, row)
            self.assertIn(item.priority, PRIORITIES | {"ERROR"})

        @hyp_settings(max_examples=200, deadline=None)
        @given(st.text(), st.text(), st.text())
        def test_export_text_cells_are_formula_safe(self, ident, name, cvss):
            item = batch.score_row(2, {"id": ident, "name": name, "cvss": cvss})
            fd, out = tempfile.mkstemp(suffix=".csv")
            os.close(fd)
            try:
                batch.write_results(out, [item])
                with open(out, newline="", encoding="utf-8-sig") as fh:
                    rows = list(csv.DictReader(fh))
            finally:
                os.remove(out)
            for row in rows:
                for key in ("id", "name", "error", "cvss"):
                    self.assertFalse(row[key].startswith(tuple("=+-@\t\r")), (key, row[key]))

        @hyp_settings(max_examples=300, deadline=None)
        @given(st.binary(max_size=2048))
        def test_settings_loader_survives_arbitrary_bytes(self, data):
            with tempfile.TemporaryDirectory() as directory:
                path = os.path.join(directory, "settings.json")
                with open(path, "wb") as fh:
                    fh.write(data)
                result = settings.load(path)
            self.assertIsInstance(result.settings, settings.Settings)
            self.assertLessEqual(len(result.warnings), 1)

        @hyp_settings(max_examples=300, deadline=None)
        @given(st.dictionaries(st.text(max_size=20), st.one_of(st.none(), st.booleans(), st.integers(),
                                                                st.floats(), st.text(max_size=20),
                                                                st.lists(st.integers(), max_size=3)), max_size=8))
        def test_settings_from_dict_only_raises_value_error(self, data):
            try:
                result = settings.Settings.from_dict(data)
            except ValueError:
                return
            self.assertIsInstance(result, settings.Settings)

        @hyp_settings(max_examples=300, deadline=None)
        @given(st.floats(allow_nan=True, allow_infinity=True), st.floats(allow_nan=True, allow_infinity=True),
               st.floats(allow_nan=True, allow_infinity=True), st.integers())
        def test_settings_constructor_accepts_only_valid_values(self, high, critical, epss, days):
            try:
                result = settings.Settings(high, critical, epss, days)
            except ValueError:
                return
            self.assertTrue(5.0 <= result.cvss_high <= 8.0)
            self.assertTrue(result.cvss_high + settings.MIN_LINE_GAP <= result.cvss_critical <= 10.0)
            self.assertTrue(0.5 <= result.epss_percentile_cutoff <= 0.999)
            self.assertTrue(1 <= result.stale_days <= 90)

        KEV_SEED = (b'{"catalogVersion": "1", "dateReleased": "2024-01-02", "count": 1, "vulnerabilities": '
                    b'[{"cveID": "CVE-2024-0001", "vendorProject": "A", "product": "B", "vulnerabilityName": "C", '
                    b'"dateAdded": "2024-01-02", "requiredAction": "D", "dueDate": "", '
                    b'"knownRansomwareCampaignUse": "Known"}]}')
        EPSS_SEED = b"#model_version:v1,score_date:2026-10-07\ncve,epss,percentile\nCVE-2024-0001,0.1,0.2\n"

        @staticmethod
        def mutate(seed, position, replacement):
            position %= len(seed) + 1
            return seed[:position] + replacement + seed[position + 1:]

        @hyp_settings(max_examples=300, deadline=None)
        @given(st.binary(max_size=3000))
        def test_kev_parser_only_raises_threat_data_error(self, data):
            try:
                threatdata.parse_kev(data)
            except threatdata.ThreatDataError:
                pass

        @hyp_settings(max_examples=300, deadline=None)
        @given(st.integers(min_value=0, max_value=1000), st.binary(max_size=4))
        def test_kev_parser_survives_mutated_valid_files(self, position, replacement):
            try:
                threatdata.parse_kev(self.mutate(self.KEV_SEED, position, replacement))
            except threatdata.ThreatDataError:
                pass

        @hyp_settings(max_examples=300, deadline=None)
        @given(st.binary(max_size=3000), st.booleans())
        def test_epss_parser_only_raises_threat_data_error(self, data, compressed):
            try:
                threatdata.parse_epss(gzip.compress(data) if compressed else data)
            except threatdata.ThreatDataError:
                pass

        @hyp_settings(max_examples=300, deadline=None)
        @given(st.integers(min_value=0, max_value=1000), st.binary(max_size=4))
        def test_epss_parser_survives_mutated_valid_files(self, position, replacement):
            try:
                threatdata.parse_epss(self.mutate(self.EPSS_SEED, position, replacement))
            except threatdata.ThreatDataError:
                pass

        @hyp_settings(max_examples=300, deadline=None)
        @given(st.text(max_size=200))
        def test_normalize_cve_accepts_only_cve_ids(self, text):
            try:
                cve = threatdata.normalize_cve(text)
            except ValueError:
                return
            self.assertRegex(cve, r"^CVE-\d{4}-\d{4,}$")

        @hyp_settings(max_examples=300, deadline=None)
        @given(st.booleans(), st.one_of(st.none(), st.floats(0, 1)), st.booleans(), st.booleans(), st.booleans(),
               st.booleans())
        def test_more_evidence_never_lowers_the_threat_level(self, kev, percentile, kev_loaded, epss_loaded,
                                                             analyst, public):
            order = {Threat.NONE: 0, Threat.PUBLIC: 1, Threat.ACTIVE: 2}
            entry = threatdata.KevEntry("CVE-2024-0001", "", "", "", "2024-01-02", "", "", False) if kev else None
            info = threatdata.CveInfo("CVE-2024-0001", entry, None if percentile is None else 0.1, percentile,
                                      kev_loaded, epss_loaded)
            base = threatdata.derive_threat(info, settings.DEFAULT_SETTINGS, analyst, public).level
            for extra in ({"analyst_confirmed": True}, {"public_exploit": True}):
                kwargs = {"analyst_confirmed": analyst, "public_exploit": public}
                kwargs.update(extra)
                raised = threatdata.derive_threat(info, settings.DEFAULT_SETTINGS, **kwargs).level
                self.assertGreaterEqual(order[raised], order[base])
            missing = threatdata.derive_threat(None, settings.DEFAULT_SETTINGS, analyst, public).level
            self.assertGreaterEqual(order[base], order[missing])

        @hyp_settings(max_examples=500, deadline=None)
        @given(st.text(max_size=600))
        def test_cvss_parser_only_raises_value_error(self, text):
            try:
                vector = cvss.parse_vector(text)
            except ValueError:
                return
            self.assertTrue(0.0 <= vector.score <= 10.0)

        @hyp_settings(max_examples=500, deadline=None)
        @given(st.sampled_from(["3.0", "3.1", "4.0"]), st.integers(min_value=0, max_value=500),
               st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:/. ", max_size=6))
        def test_cvss_parser_survives_mutated_valid_vectors(self, version, position, replacement):
            seeds = {"3.0": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                     "3.1": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                     "4.0": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}
            seed = seeds[version]
            position %= len(seed) + 1
            text = seed[:position] + replacement + seed[position + 1:]
            try:
                vector = cvss.parse_vector(text)
            except ValueError:
                return
            self.assertEqual(cvss.parse_vector(vector.normalized).normalized, vector.normalized)
            self.assertEqual(cvss.parse_vector(vector.normalized).score, vector.score)

        @hyp_settings(max_examples=400, deadline=None)
        @given(st.data())
        def test_optional_metrics_never_change_a_cvss_base_score(self, data):
            version = data.draw(st.sampled_from(["3.0", "3.1", "4.0"]))
            base, optional = cvss._allowed(version)
            metrics = {name: data.draw(st.sampled_from(sorted(values))) for name, values in base.items()}
            plain = f"CVSS:{version}/" + "/".join(f"{n}:{v}" for n, v in metrics.items())
            chosen = data.draw(st.lists(st.sampled_from(sorted(optional)), unique=True, max_size=len(optional)))
            extras = "".join(f"/{name}:{data.draw(st.sampled_from(sorted(optional[name])))}" for name in chosen)
            self.assertEqual(cvss.parse_vector(plain + extras).score, cvss.parse_vector(plain).score)

        @hyp_settings(max_examples=300, deadline=None)
        @given(st.binary(max_size=2048))
        def test_preferences_loader_survives_arbitrary_bytes(self, data):
            with tempfile.TemporaryDirectory() as directory:
                path = os.path.join(directory, "ui.json")
                with open(path, "wb") as fh:
                    fh.write(data)
                result = uiprefs.load(path)
            self.assertIsInstance(result.prefs, uiprefs.UiPrefs)
            self.assertLessEqual(len(result.warnings), 1)

        @hyp_settings(max_examples=300, deadline=None)
        @given(st.dictionaries(st.text(max_size=12),
                               st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=8)), max_size=6))
        def test_preferences_from_dict_only_raises_value_error(self, data):
            try:
                uiprefs.UiPrefs.from_dict(data)
            except ValueError:
                pass


if __name__ == "__main__":
    unittest.main()
