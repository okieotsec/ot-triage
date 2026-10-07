import csv
import math
import os
import tempfile
import unittest

import batch
import settings
from prioritizer import Asset, Controls, Exposure, Patch, Threat, NOW, NEXT, NEVER, parse_cvss, prioritize

try:
    from hypothesis import given, settings as hyp_settings, strategies as st
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


if __name__ == "__main__":
    unittest.main()
