import json
import unittest
from pathlib import Path

from version import __version__

ROOT = Path(__file__).resolve().parent
STANDARD_LIBRARY_ONLY = (ROOT / "requirements.txt").read_text(encoding="utf-8").strip() == ""


class SbomTests(unittest.TestCase):
    """The committed SBOM must describe this version and must stay free of third-party components."""

    def setUp(self):
        self.bom = json.loads((ROOT / "sbom" / "sbom.cdx.json").read_text(encoding="utf-8"))

    def test_it_is_a_cyclonedx_1_6_document(self):
        self.assertEqual((self.bom["bomFormat"], self.bom["specVersion"]), ("CycloneDX", "1.6"))

    def test_it_describes_this_version_of_the_application(self):
        component = self.bom["metadata"]["component"]
        self.assertEqual((component["name"], component["version"], component["type"]), ("ot-triage", __version__,
                                                                                         "application"))
        self.assertEqual(component["licenses"], [{"license": {"id": "MIT"}}])
        self.assertTrue(component["purl"].endswith(f"@{__version__}"))
        self.assertIn(__version__, component["bom-ref"], "regenerate it with tools/make_sbom.py after a version change")

    def test_it_lists_no_third_party_components_because_there_are_none(self):
        self.assertTrue(STANDARD_LIBRARY_ONLY, "requirements.txt must stay empty, or the SBOM must list what it adds")
        self.assertEqual(self.bom["components"], [])
        self.assertEqual(self.bom["dependencies"], [{"ref": self.bom["metadata"]["component"]["bom-ref"],
                                                     "dependsOn": []}])

    def test_it_carries_no_personal_information(self):
        text = json.dumps(self.bom).lower()
        for word in ("ja" + "red", "frit" + "ts", "/ho" + "me/"):
            self.assertNotIn(word, text)


if __name__ == "__main__":
    unittest.main()
