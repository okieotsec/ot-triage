import csv
import math
import os
import tempfile
import unittest

import batch
from prioritizer import Asset, Controls, Exposure, Patch, Threat, NOW, NEXT, NEVER, parse_cvss, prioritize

try:
    from hypothesis import given, settings, strategies as st
except ImportError:  # hypothesis is an optional test dependency
    st = None

PRIORITIES = {NOW, NEXT, NEVER}


@unittest.skipIf(st is None, "hypothesis is not installed")
class PropertyTests(unittest.TestCase):
    if st is not None:
        @settings(max_examples=500, deadline=None)
        @given(st.text())
        def test_parse_cvss_returns_a_valid_score_or_value_error(self, text):
            try:
                value = parse_cvss(text)
            except ValueError:
                return
            self.assertTrue(math.isfinite(value) and 0.0 <= value <= 10.0)

        @settings(max_examples=500, deadline=None)
        @given(st.floats(min_value=0.0, max_value=10.0), st.sampled_from(list(Threat)), st.sampled_from(list(Asset)),
               st.sampled_from(list(Exposure)), st.sampled_from(list(Controls)), st.sampled_from(list(Patch)))
        def test_prioritize_outputs_are_valid(self, cvss, threat, asset, exposure, controls, patch):
            result = prioritize(cvss, threat, asset, exposure, controls, patch)
            self.assertIn(result.priority, PRIORITIES)
            self.assertTrue(0.0 <= result.score <= 10.0)

        @settings(max_examples=500, deadline=None)
        @given(st.dictionaries(st.sampled_from(["id", "name", "cvss", "threat", "asset", "exposure", "patch",
                                                "controls"]), st.text()))
        def test_score_row_never_raises(self, row):
            item = batch.score_row(2, row)
            self.assertIn(item.priority, PRIORITIES | {"ERROR"})

        @settings(max_examples=200, deadline=None)
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


if __name__ == "__main__":
    unittest.main()
