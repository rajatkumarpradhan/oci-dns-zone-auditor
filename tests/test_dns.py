import json
import os
import tempfile
import unittest

from dns_audit import analysis, model
from dns_audit.cli import main

EX = os.path.join(os.path.dirname(__file__), "..", "examples")

NS = [{"name": "@", "type": "NS", "ttl": 300, "rdata": "ns1.dns-vendor.net."},
      {"name": "@", "type": "NS", "ttl": 300, "rdata": "ns2.dns-vendor.net."}]


def zone(records, min_ttl=60, name="example.com"):
    return {"zone": name, "config": {"min_ttl": min_ttl}, "records": NS + records}


def rec(name, rtype, rdata, ttl=300):
    return {"name": name, "type": rtype, "ttl": ttl, "rdata": rdata}


def run(d):
    return analysis.analyze(model.load(d))


def rules(d):
    return {f.rule for f in run(d)}


class ExampleTests(unittest.TestCase):
    def test_good_is_clean(self):
        self.assertEqual(run(json.load(open(os.path.join(EX, "good.json"), encoding="utf-8"))), [])

    def test_risky_triggers_every_rule(self):
        d = json.load(open(os.path.join(EX, "risky.json"), encoding="utf-8"))
        self.assertEqual(rules(d), {f"DZ{n:03d}" for n in range(1, 12)})

    def test_sorted_by_severity(self):
        d = json.load(open(os.path.join(EX, "risky.json"), encoding="utf-8"))
        s = [analysis.SEV[f.severity] for f in run(d)]
        self.assertEqual(s, sorted(s))


class NameTests(unittest.TestCase):
    def test_canonicalisation(self):
        z = model.load(zone([rec("@", "A", "203.0.113.1"),
                             rec("WWW", "A", "203.0.113.2"),
                             rec("API.EXAMPLE.COM.", "A", "203.0.113.3")]))
        self.assertEqual([r.name for r in z.records[2:]],
                         ["example.com", "www.example.com", "api.example.com"])

    def test_wildcard_allowed_as_first_label_only(self):
        z = model.load(zone([rec("*", "A", "203.0.113.9")]))
        self.assertEqual(z.records[-1].name, "*.example.com")
        with self.assertRaises(model.ModelError):
            model.load(zone([rec("foo.*", "A", "203.0.113.9")]))


class RuleTests(unittest.TestCase):
    def test_cname_at_apex(self):
        self.assertIn("DZ001", rules(zone([rec("@", "CNAME", "elsewhere.example.net.")])))
        self.assertNotIn("DZ001", rules(zone([rec("www", "CNAME", "elsewhere.example.net.")])))

    def test_cname_coexistence(self):
        f = [x for x in run(zone([rec("www", "CNAME", "a.example.net."),
                                  rec("www", "TXT", "hello")])) if x.rule == "DZ002"]
        self.assertEqual(len(f), 1)                      # one finding per name, not per type pair
        self.assertEqual(f[0].severity, "high")
        self.assertNotIn("DZ002", rules(zone([rec("www", "CNAME", "a.example.net.")])))

    def test_private_addresses(self):
        for ip in ("10.0.0.5", "172.16.3.4", "192.168.1.1", "127.0.0.1", "169.254.1.1", "100.64.0.1"):
            with self.subTest(ip=ip):
                self.assertIn("DZ003", rules(zone([rec("h", "A", ip)])))
        self.assertIn("DZ003", rules(zone([rec("h", "AAAA", "fd00::1")])))
        # documentation prefixes are routable-looking on purpose: not in the leak ranges
        for ip in ("203.0.113.10", "192.0.2.1", "8.8.8.8"):
            with self.subTest(ip=ip):
                self.assertNotIn("DZ003", rules(zone([rec("h", "A", ip)])))
        self.assertNotIn("DZ003", rules(zone([rec("h", "A", "not-an-ip")])))

    def test_mx_without_spf(self):
        self.assertIn("DZ004", rules(zone([rec("@", "MX", "10 mail.example.com.")])))
        ok = zone([rec("@", "MX", "10 mail.example.com."), rec("@", "TXT", "v=spf1 -all"),
                   rec("_dmarc", "TXT", "v=DMARC1; p=reject")])
        self.assertNotIn("DZ004", rules(ok))

    def test_missing_dmarc(self):
        self.assertIn("DZ005", rules(zone([rec("@", "MX", "10 mail.example.com.")])))
        self.assertIn("DZ005", rules(zone([rec("@", "TXT", "v=spf1 -all")])))
        ok = zone([rec("@", "MX", "10 mail.example.com."), rec("_dmarc", "TXT", "v=DMARC1; p=reject")])
        self.assertNotIn("DZ005", rules(ok))
        # DMARC must live at _dmarc.<zone>, not anywhere else
        misplaced = zone([rec("@", "MX", "10 mail.example.com."), rec("_dmarc.www", "TXT", "v=DMARC1; p=reject")])
        self.assertIn("DZ005", rules(misplaced))

    def test_dangling_cloud_cname(self):
        self.assertIn("DZ006", rules(zone([rec("old", "CNAME", "myapp.herokuapp.com.")])))
        # target inside the zone is fine
        ok = zone([rec("api", "CNAME", "www.example.com."), rec("www", "A", "203.0.113.1")])
        self.assertNotIn("DZ006", rules(ok))
        # external but not a known cloud suffix: nothing to say offline
        self.assertNotIn("DZ006", rules(zone([rec("ext", "CNAME", "www.example.net.")])))

    def test_ttl_boundary(self):
        self.assertNotIn("DZ007", rules(zone([rec("a", "A", "203.0.113.1", ttl=60)])))
        f = [x for x in run(zone([rec("a", "A", "203.0.113.1", ttl=59)])) if x.rule == "DZ007"]
        self.assertEqual(f[0].evidence, {"ttl": 59, "min_ttl": 60})
        self.assertIn("DZ007", rules(zone([rec("a", "A", "203.0.113.1", ttl=120)], min_ttl=300)))

    def test_wildcard(self):
        self.assertIn("DZ008", rules(zone([rec("*", "A", "203.0.113.9")])))
        self.assertNotIn("DZ008", rules(zone([rec("www", "A", "203.0.113.9")])))

    def test_duplicates(self):
        two = zone([rec("d", "A", "203.0.113.5"), rec("d", "A", "203.0.113.5")])
        self.assertEqual(len([f for f in run(two) if f.rule == "DZ009"]), 1)
        three = zone([rec("d", "A", "203.0.113.5")] * 3)
        self.assertEqual(len([f for f in run(three) if f.rule == "DZ009"]), 2)
        # same name and type but different data is a normal rrset
        rrset = zone([rec("d", "A", "203.0.113.5"), rec("d", "A", "203.0.113.6")])
        self.assertNotIn("DZ009", rules(rrset))

    def test_no_apex_ns(self):
        self.assertIn("DZ010", rules({"zone": "example.com", "records": []}))
        self.assertNotIn("DZ010", rules(zone([])))


def zone_ns(records, expected=None, name="example.com"):
    cfg = {} if expected is None else {"expected_ns": expected}
    return {"zone": name, "config": cfg, "records": records}


class DelegationTests(unittest.TestCase):
    def test_exact_set_match_is_clean(self):
        d = zone_ns([rec("@", "NS", "ns1.dns-vendor.net."), rec("@", "NS", "ns2.dns-vendor.net.")],
                    ["ns1.dns-vendor.net", "ns2.dns-vendor.net"])
        self.assertNotIn("DZ011", rules(d))

    def test_extra_ns_flagged(self):
        d = zone_ns([rec("@", "NS", "ns1.dns-vendor.net."), rec("@", "NS", "ns2.dns-vendor.net."),
                     rec("@", "NS", "ns-old.other-provider.com.")],
                    ["ns1.dns-vendor.net", "ns2.dns-vendor.net"])
        f = [x for x in run(d) if x.rule == "DZ011"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "medium")
        self.assertIn("ns-old.other-provider.com", f[0].message)

    def test_missing_expected_ns_flagged(self):
        d = zone_ns([rec("@", "NS", "ns1.dns-vendor.net.")],
                    ["ns1.dns-vendor.net", "ns2.dns-vendor.net"])
        f = [x for x in run(d) if x.rule == "DZ011"]
        self.assertEqual(len(f), 1)
        self.assertIn("ns2.dns-vendor.net", f[0].message)

    def test_both_directions_flagged(self):
        d = zone_ns([rec("@", "NS", "ns1.dns-vendor.net."), rec("@", "NS", "typo.dns-vendor.net.")],
                    ["ns1.dns-vendor.net", "ns2.dns-vendor.net"])
        f = [x for x in run(d) if x.rule == "DZ011"]
        self.assertEqual(len(f), 2)

    def test_empty_expected_list_disables_rule(self):
        for cfg in (None, []):
            d = zone_ns([rec("@", "NS", "anything.example.net.")], cfg)
            self.assertNotIn("DZ011", rules(d))

    def test_matching_is_case_and_dot_insensitive(self):
        d = zone_ns([rec("@", "NS", "NS1.DNS-Vendor.NET.")], ["ns1.dns-vendor.net"])
        self.assertNotIn("DZ011", rules(d))
        d = zone_ns([rec("@", "NS", "ns1.dns-vendor.net")], ["NS1.DNS-Vendor.NET."])
        self.assertNotIn("DZ011", rules(d))

    def test_non_apex_ns_records_ignored(self):
        d = zone_ns([rec("@", "NS", "ns1.dns-vendor.net."), rec("sub", "NS", "elsewhere.example.net.")],
                    ["ns1.dns-vendor.net"])
        self.assertNotIn("DZ011", rules(d))


class ValidationTests(unittest.TestCase):
    def bad(self, m):
        d = zone([rec("a", "A", "203.0.113.1")])
        m(d)
        with self.assertRaises(model.ModelError):
            model.load(d)

    def test_errors(self):
        cases = [
            lambda d: d.update(zone=""),
            lambda d: d.update(zone="bad..name"),
            lambda d: d.update(config="x"),
            lambda d: d.update(config={"min_ttl": 0}),
            lambda d: d.update(config={"min_ttl": True}),
            lambda d: d.update(config={"expected_ns": "ns1.example.net"}),
            lambda d: d.update(config={"expected_ns": [""]}),
            lambda d: d.update(config={"expected_ns": ["bad..name"]}),
            lambda d: d.update(config={"expected_ns": [5]}),
            lambda d: d.update(records="x"),
            lambda d: d["records"].append("x"),
            lambda d: d["records"].append({"name": "a", "type": "A", "ttl": 300}),          # no rdata
            lambda d: d["records"].append({"name": "a", "type": "A", "rdata": "x"}),          # no ttl
            lambda d: d["records"].append({"name": "a", "type": "bogus type", "ttl": 1, "rdata": "x"}),
            lambda d: d["records"].append({"name": "a", "type": "A", "ttl": -1, "rdata": "x"}),
            lambda d: d["records"].append({"name": "a b", "type": "A", "ttl": 1, "rdata": "x"}),
        ]
        for i, m in enumerate(cases):
            with self.subTest(case=i):
                self.bad(m)


class CliTests(unittest.TestCase):
    def test_exit_codes(self):
        self.assertEqual(main([os.path.join(EX, "good.json")]), 0)
        self.assertEqual(main([os.path.join(EX, "good.json"), "--fail-on", "low"]), 0)
        self.assertEqual(main([os.path.join(EX, "risky.json"), "--fail-on", "high"]), 2)

    def test_report_and_errors(self):
        with tempfile.TemporaryDirectory() as t:
            out = os.path.join(t, "r.json")
            main([os.path.join(EX, "risky.json"), "--output", out])
            rep = json.load(open(out, encoding="utf-8"))
            self.assertIn("No DNS queries are made", rep["disclaimer"])
            self.assertEqual(rep["zone"], "risky-example.com")
            self.assertEqual(len(rep["findings"]), 13)
            self.assertEqual(sum(1 for f in rep["findings"] if f["rule"] == "DZ011"), 2)
            bad = os.path.join(t, "b.json")
            open(bad, "w").write("{oops")
            self.assertEqual(main([bad]), 1)
            self.assertEqual(main([os.path.join(t, "none.json")]), 1)


if __name__ == "__main__":
    unittest.main()
