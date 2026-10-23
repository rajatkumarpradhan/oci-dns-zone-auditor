import json
import os
import tempfile
import unittest

from dns_audit import analysis, importer, model
from dns_audit.cli import main

EX = os.path.join(os.path.dirname(__file__), "..", "examples")


def export_text():
    with open(os.path.join(EX, "export.json"), encoding="utf-8") as f:
        return f.read()


class ConvertTests(unittest.TestCase):
    def test_fixture_converts(self):
        zone = importer.convert(json.loads(export_text()))
        self.assertEqual(zone["zone"], "example.com")
        self.assertEqual(len(zone["records"]), 8)
        r = zone["records"][0]
        self.assertEqual((r["name"], r["type"], r["ttl"], r["rdata"]),
                         ("example.com.", "NS", 86400, "ns1.p68.dns.oraclecloud.net."))

    def test_imported_zone_audits_clean(self):
        zone = model.load(importer.convert(json.loads(export_text())))
        self.assertEqual(analysis.analyze(zone), [])

    def test_unwrapped_shape(self):
        data = {"name": "example.com", "items": [
            {"domain": "example.com.", "rtype": "NS", "ttl": 300, "rdata": "ns1.vendor.net."}]}
        zone = importer.convert(data)
        self.assertEqual(zone["zone"], "example.com")
        self.assertEqual(len(zone["records"]), 1)

    def test_zone_name_normalised(self):
        data = {"name": "Example.COM.", "items": []}
        self.assertEqual(importer.convert(data), {"zone": "example.com", "records": []})

    def test_bad_top_level(self):
        for bad in ({"data": {"items": "x"}}, {"data": {}}, "text", 3, None):
            with self.subTest(bad=bad):
                with self.assertRaises(importer.ImportError):
                    importer.convert(bad)
        with self.assertRaises(importer.ImportError):
            importer.convert({"data": {"name": " ", "items": []}})


class ErrorTests(unittest.TestCase):
    TEXT = """{
 "data": {
  "name": "example.com",
  "items": [
   {"domain": "example.com.", "rtype": "NS", "ttl": 300, "rdata": "ns1.vendor.net."},
   {"domain": "www.example.com.", "ttl": 300, "rdata": "203.0.113.1"},
   {"domain": "mail.example.com.", "rtype": "A", "ttl": "300", "rdata": "203.0.113.2"},
   {"domain": "bad..name.", "rtype": "A", "ttl": 300, "rdata": "203.0.113.3"},
   {"rtype": "TXT", "ttl": 300, "rdata": "v=spf1 -all"}
 ]
 }
}"""

    def test_all_bad_rows_reported_with_lines(self):
        with self.assertRaises(importer.ImportError) as cm:
            importer.convert(json.loads(self.TEXT), self.TEXT)
        msg = str(cm.exception)
        self.assertIn("items[1] (line 6): rtype must be a valid record type token", msg)
        self.assertIn("items[2] (line 7): ttl must be an integer", msg)
        self.assertIn("items[3] (line 8): domain is not a valid DNS name", msg)
        self.assertIn("items[4] (line 9): domain must be a non-empty string", msg)
        self.assertNotIn("ns1.vendor.net", msg.split("\n")[0])

    def test_row_not_object(self):
        with self.assertRaises(importer.ImportError) as cm:
            importer.convert({"data": {"name": "example.com", "items": ["oops"]}})
        self.assertIn("items[0]: must be an object", str(cm.exception))

    def test_rdata_and_ttl(self):
        rows = [{"domain": "a.example.com.", "rtype": "A", "ttl": 300, "rdata": "  "},
                {"domain": "b.example.com.", "rtype": "A", "ttl": True, "rdata": "203.0.113.1"}]
        with self.assertRaises(importer.ImportError) as cm:
            importer.convert({"name": "example.com", "items": rows})
        msg = str(cm.exception)
        self.assertIn("items[0]: rdata must be a non-empty string", msg)
        self.assertIn("items[1]: ttl must be an integer", msg)


class CliTests(unittest.TestCase):
    def test_import_to_file_and_audit(self):
        src = os.path.join(EX, "export.json")
        with tempfile.TemporaryDirectory() as t:
            out = os.path.join(t, "zone.json")
            self.assertEqual(main(["import", src, "-o", out]), 0)
            with open(out, encoding="utf-8") as f:
                self.assertEqual(len(json.load(f)["records"]), 8)
            self.assertEqual(main([out, "--fail-on", "low"]), 0)

    def test_import_errors(self):
        with tempfile.TemporaryDirectory() as t:
            bad = os.path.join(t, "bad.json")
            open(bad, "w").write('{"data": {"name": "example.com", "items": [{"domain": "x.example.com."}]}}')
            self.assertEqual(main(["import", bad]), 1)
            self.assertEqual(main(["import", os.path.join(t, "none.json")]), 1)
            notjson = os.path.join(t, "x.json")
            open(notjson, "w").write("{oops")
            self.assertEqual(main(["import", notjson]), 1)

    def test_plain_run_unchanged(self):
        self.assertEqual(main([os.path.join(EX, "good.json")]), 0)
        self.assertEqual(main([os.path.join(EX, "risky.json"), "--fail-on", "high"]), 2)


if __name__ == "__main__":
    unittest.main()
