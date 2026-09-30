# Copyright (c) 2026 KeelLinux maintainers
"""The diff model and the comparison, as pure functions

compare() takes a declared document and an Inspection and never touches
the disk, so these tests build both by hand and check one branch each:
the line shapes, the exit code precedence, the normalisation that keeps a
spelling difference from being drift, and the rule that a field inspect
could not infer is unknown rather than drifted.
"""

import unittest
from os.path import abspath, dirname, join

from helpers import spec  # noqa: F401

from keel import exits
from keel.diff import (
    DRIFT,
    NOT_COMPARED,
    NOT_DECLARED,
    SAME,
    UNKNOWN,
    Comparison,
    FieldDiff,
    compare,
    diff_root,
    report_lines,
    to_json,
)
from keel.diff.compare import (
    compare_section,
    flatten,
    normalize,
    unknown_reason,
)
from keel.diff.report import show
from keel.inspect import inspect_root
from keel.inspect.report import Inspection, inferred, missing

FIXTURES = join(dirname(abspath(__file__)), "fixtures", "inspect")
TURNKEY = join(FIXTURES, "turnkey")
KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyMaterialOnly admin@blog"


def inspection(spec_doc: dict, *findings) -> Inspection:
    return Inspection("/", "core", spec_doc, tuple(findings))


def by_field(comparison: Comparison) -> dict[str, FieldDiff]:
    return {field.field: field for field in comparison.fields}


class TestShow(unittest.TestCase):
    def test_every_value_kind_has_a_printable_form(self):
        self.assertEqual(show(None), "nothing")
        self.assertEqual(show(True), "true")
        self.assertEqual(show(False), "false")
        self.assertEqual(show(["a", 1]), "a, 1")
        self.assertEqual(show([]), "(empty)")
        self.assertEqual(show("blog"), "blog")


class TestFieldDiff(unittest.TestCase):
    def test_each_status_has_its_own_line_shape(self):
        self.assertEqual(FieldDiff("i.h", SAME, "a", "a").line(),
                         "i.h: same (a)")
        self.assertEqual(FieldDiff("i.h", DRIFT, "a", "b").line(),
                         "i.h: drift (declared a, observed b)")
        self.assertEqual(FieldDiff("i.h", DRIFT, "a").line(),
                         "i.h: drift (declared a, observed nothing)")
        self.assertEqual(FieldDiff("i.h", UNKNOWN, "a", None, "why").line(),
                         "i.h: unknown (declared a; not inferred: why)")
        self.assertEqual(FieldDiff("i.h", NOT_DECLARED, None, "b").line(),
                         "i.h: not declared (observed b)")
        self.assertEqual(FieldDiff("secrets", NOT_COMPARED,
                                   reason="never").line(),
                         "secrets: not compared (never)")

    def test_section_and_dict_form(self):
        field = FieldDiff("network.nameservers", SAME, ["::1"], ["::1"])
        self.assertEqual(field.section, "network")
        self.assertEqual(field.to_dict(), {
            "field": "network.nameservers", "section": "network",
            "status": "same", "declared": ["::1"], "observed": ["::1"],
            "reason": "", "note": "",
        })


class TestComparison(unittest.TestCase):
    def test_no_drift_exits_ok(self):
        result = Comparison("/", (FieldDiff("a", SAME, 1, 1),
                                  FieldDiff("secrets", NOT_COMPARED),
                                  FieldDiff("b", NOT_DECLARED, None, 2)))
        self.assertEqual(result.code, exits.OK)
        self.assertFalse(result.drift)
        self.assertFalse(result.incomplete)
        self.assertEqual(
            result.summary(),
            "diff: 1 same, 0 drift, 0 unknown, 1 not declared,"
            " 1 not compared; no drift",
        )

    def test_unknown_alone_exits_incomplete(self):
        result = Comparison("/", (FieldDiff("a", UNKNOWN, 1, None, "why"),))
        self.assertEqual(result.code, exits.INSPECT_INCOMPLETE)
        self.assertTrue(result.incomplete)
        self.assertTrue(result.summary().endswith(
            "; no drift, but declared fields could not be observed"))

    def test_drift_wins_over_unknown(self):
        result = Comparison("/", (FieldDiff("a", UNKNOWN, 1, None, "why"),
                                  FieldDiff("b", DRIFT, 1, 2)))
        self.assertEqual(result.code, exits.DRIFT_FOUND)
        self.assertTrue(result.drift)
        self.assertTrue(result.summary().endswith("; drift found"))


class TestFlattenAndNormalize(unittest.TestCase):
    def test_flatten_recurses_and_skips_null_values(self):
        found = dict(flatten("users", {
            "root": {"authorized_keys": [KEY]},
            "bob": None,
            "eve": {},
            "app": {"options": {"ip_bind": "[2001:db8::1]"}},
        }))
        self.assertEqual(found, {
            "users.root.authorized_keys": [KEY],
            "users.app.options.ip_bind": "[2001:db8::1]",
        })

    def test_keywords_and_domains_compare_case_insensitively(self):
        self.assertEqual(
            normalize("security.updates_at_first_boot", "FORCE"), "force"
        )
        self.assertEqual(normalize("hub.api_key", "SKIP"), "skip")
        self.assertEqual(normalize("instance.fqdn", "Blog.Example.org."),
                         "blog.example.org")
        self.assertEqual(normalize("tls.acme.domains", ["A.org", "b.org"]),
                         ("a.org", "b.org"))

    def test_addresses_compare_in_canonical_form(self):
        path = "network.interfaces.eth0.ipv6.address"
        self.assertEqual(normalize(path, "2001:DB8:0001::10/64"),
                         "2001:db8:1::10/64")
        self.assertEqual(normalize(path, "not-an-address"), "not-an-address")
        self.assertEqual(normalize("network.nameservers", ["2001:DB8::53"]),
                         ("2001:db8::53",))
        self.assertEqual(normalize("x.gateway", "FE80::1"), "fe80::1")

    def test_booleans_and_plain_values_keep_their_meaning(self):
        self.assertEqual(normalize("tls.acme.enabled", True), "true")
        self.assertEqual(normalize("tls.acme.enabled", False), "false")
        self.assertEqual(normalize("locale.lang", " en_US.UTF-8 "),
                         "en_US.UTF-8")
        self.assertEqual(normalize("x.method", "static"), "static")


class TestUnknownReason(unittest.TestCase):
    def test_the_most_specific_finding_wins(self):
        unknowns = {"users": "none at all", "users.root.authorized_keys":
                    "file absent"}
        self.assertEqual(unknown_reason("users.root.authorized_keys",
                                        unknowns), "file absent")
        self.assertEqual(unknown_reason("users.admin.authorized_keys",
                                        unknowns), "none at all")
        self.assertIsNone(unknown_reason("locale.lang", unknowns))

    def test_managed_by_is_unknown_together_with_the_interfaces(self):
        unknowns = {"network.interfaces": "no file"}
        self.assertEqual(unknown_reason("network.managed_by", unknowns),
                         "no file")
        self.assertIsNone(unknown_reason("network.managed_by", {}))


class TestCompare(unittest.TestCase):
    def test_same_drift_unknown_and_not_declared_in_one_document(self):
        declared = {
            "version": 1,
            "instance": {"hostname": "blog", "fqdn": "blog.example.org"},
            "locale": {"timezone": "Europe/Lisbon", "lang": "en_US.UTF-8"},
        }
        observed = {
            "instance": {"hostname": "shop"},
            "locale": {"timezone": "Europe/Lisbon"},
            "hub": {"api_key": "skip"},
        }
        result = compare(declared, inspection(
            observed,
            inferred("instance.hostname", "shop", "/etc/hostname"),
            missing("instance.fqdn", "no dotted name"),
            missing("instance.fqdn", "hostname -f not run"),
            missing("locale.lang", "no LANG"),
        ))
        fields = by_field(result)
        self.assertEqual(fields["instance.hostname"].status, DRIFT)
        self.assertEqual(fields["instance.fqdn"].status, UNKNOWN)
        self.assertEqual(fields["instance.fqdn"].reason,
                         "no dotted name; hostname -f not run")
        self.assertEqual(fields["locale.timezone"].status, SAME)
        self.assertEqual(fields["locale.lang"].status, UNKNOWN)
        self.assertEqual(fields["hub.api_key"].status, NOT_DECLARED)
        self.assertEqual(fields["hub.api_key"].observed, "skip")
        self.assertEqual(result.code, exits.DRIFT_FOUND)
        self.assertEqual([f.section for f in result.fields],
                         ["instance", "instance", "hub", "locale", "locale"])

    def test_a_declared_value_the_machine_lacks_is_drift_not_unknown(self):
        declared = {"tls": {"acme": {"enabled": True, "challenge": "dns-01",
                                     "domains": ["blog.example.org"]}}}
        observed = {"tls": {"acme": {"enabled": False}}}
        fields = by_field(compare(declared, inspection(
            observed, inferred("tls.acme.enabled", "false", "no dehydrated"),
        )))
        self.assertEqual(fields["tls.acme.enabled"].status, DRIFT)
        self.assertEqual(fields["tls.acme.challenge"].line(),
                         "tls.acme.challenge: drift (declared dns-01,"
                         " observed nothing)")
        self.assertEqual(fields["tls.acme.domains"].status, DRIFT)

    def test_a_feature_the_spec_turns_off_is_compared_at_the_switch_only(self):
        declared = {"tls": {"acme": {
            "enabled": False, "challenge": "http-01",
            "domains": ["forum2.keellinux.org"],
        }}}
        observed = {"tls": {"acme": {"enabled": False}}}
        result = compare(declared, inspection(
            observed,
            inferred("tls.acme.enabled", "false",
                     "/etc/dehydrated is not present"),
        ))
        fields = by_field(result)
        self.assertEqual(fields["tls.acme.enabled"].status, SAME)
        self.assertEqual(fields["tls.acme.challenge"].status, NOT_COMPARED)
        self.assertEqual(
            fields["tls.acme.domains"].line(),
            "tls.acme.domains: not compared (tls.acme is off in the spec"
            " (enabled is false), so what it governs is not compared; it"
            " takes effect when enabled becomes true)",
        )
        self.assertEqual(result.code, exits.OK)

    def test_consent_to_the_terms_is_never_compared(self):
        declared = {"tls": {"acme": {"enabled": True, "agree_tos": True,
                                     "domains": ["blog.example.org"]}}}
        observed = {"tls": {"acme": {"enabled": True,
                                     "domains": ["blog.example.org"]}}}
        result = compare(declared, inspection(
            observed,
            inferred("tls.acme.enabled", "true", "/etc/ssl/private/cert.pem"),
        ))
        field = by_field(result)["tls.acme.agree_tos"]
        self.assertEqual(field.status, NOT_COMPARED)
        self.assertIn("keeps no record of it", field.line())
        self.assertEqual(result.code, exits.OK)

    def test_the_switch_itself_drifts_when_the_machine_turned_it_on(self):
        declared = {"tls": {"acme": {"enabled": False,
                                     "domains": ["blog.example.org"]}}}
        observed = {"tls": {"acme": {"enabled": True, "challenge": "dns-01",
                                     "domains": ["blog.example.org"]}}}
        result = compare(declared, inspection(observed))
        fields = by_field(result)
        self.assertEqual(fields["tls.acme.enabled"].status, DRIFT)
        self.assertEqual(fields["tls.acme.domains"].status, NOT_COMPARED)
        self.assertEqual(fields["tls.acme.challenge"].status, NOT_DECLARED)
        self.assertEqual(result.code, exits.DRIFT_FOUND)

    def test_settings_declared_without_the_switch_are_not_compared(self):
        declared = {"tls": {"acme": {"domains": ["blog.example.org"]}}}
        result = compare(declared, inspection({"tls": {"acme": {
            "enabled": False}}}))
        fields = by_field(result)
        self.assertEqual(fields["tls.acme.domains"].status, NOT_COMPARED)
        self.assertIn("enabled is not declared",
                      fields["tls.acme.domains"].reason)
        self.assertEqual(fields["tls.acme.enabled"].status, NOT_DECLARED)
        self.assertEqual(result.code, exits.OK)

    def test_a_value_inspect_wrote_is_compared_despite_a_side_note(self):
        """The dhcp fixture: a v4tunnel stanza next to the dhcp one"""
        declared = {"network": {"managed_by": "host", "interfaces": {
            "eth0": {"ipv6": {"method": "dhcp"}}}}}
        observed = {"network": {"managed_by": "host", "interfaces": {
            "eth0": {"ipv6": {"method": "dhcp"}}}}}
        fields = by_field(compare(declared, inspection(
            observed,
            inferred("network.interfaces.eth0.ipv6", "dhcp", "/e/n/i"),
            missing("network.interfaces.eth0.ipv6",
                    "method v4tunnel has no spec equivalent"),
        )))
        self.assertEqual(fields["network.interfaces.eth0.ipv6.method"].status,
                         SAME)
        self.assertEqual(fields["network.managed_by"].status, SAME)

    def test_sections_without_a_trace_are_not_compared(self):
        declared = {
            "version": 1,
            "secrets": {"root_password": {"generate": True}},
            "app": {"email": "admin@example.org"},
            "first_login_wizard": True,
            "preseed": {"X": "1"},
            "hub": {"api_key": {"file": "/etc/keel/secrets/hub"}},
        }
        observed = {"hub": {"api_key": "skip"},
                    "app": {"domain": "blog.example.org"}}
        result = compare(declared, inspection(observed))
        self.assertEqual(
            [(f.field, f.status) for f in result.fields],
            [("secrets", NOT_COMPARED), ("app", NOT_COMPARED),
             ("hub.api_key", NOT_COMPARED), ("first_login_wizard",
                                              NOT_COMPARED),
             ("preseed", NOT_COMPARED)],
        )
        self.assertIn("never read", by_field(result)["hub.api_key"].reason)
        self.assertEqual(result.code, exits.OK)

    def test_absent_sections_on_both_sides_produce_nothing(self):
        result = compare({"version": 1}, inspection({"version": 1}))
        self.assertEqual(result.fields, ())
        self.assertEqual(result.summary(),
                         "diff: 0 same, 0 drift, 0 unknown, 0 not declared,"
                         " 0 not compared; no drift")


class TestCompareAgainstFixture(unittest.TestCase):
    """Specs that match and specs that drift on each observable section"""

    @classmethod
    def setUpClass(cls):
        cls.observed = inspect_root(TURNKEY)

    def matching(self) -> dict:
        return {
            "version": 1,
            "instance": {"hostname": "BLOG", "fqdn": "blog.example.org."},
            "network": {
                "managed_by": "file",
                "interfaces": {"eth0": {"ipv6": {
                    "method": "static", "address": "2001:DB8:1::10/64",
                    "gateway": "FE80::1"}}},
                "nameservers": ["2001:db8:1::53", "2001:db8:1::54",
                                "192.0.2.53"],
            },
            "tls": {"acme": {"enabled": True, "challenge": "dns-01",
                             "domains": ["blog.example.org",
                                         "www.blog.example.org"]}},
            "security": {"alerts": "admin@example.org",
                         "updates_at_first_boot": "FORCE"},
            "hub": {"api_key": "SKIP"},
            "users": {"admin": {"authorized_keys": [
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureAdminKeyMaterial"
                "Only000000000 admin@laptop"]}},
            "locale": {"timezone": "Europe/Lisbon", "lang": "en_US.UTF-8"},
        }

    def test_a_matching_spec_has_no_drift_and_lists_the_undeclared(self):
        result = compare(self.matching(), self.observed)
        self.assertEqual(result.count(DRIFT), 0)
        self.assertEqual(result.count(UNKNOWN), 0)
        self.assertEqual(result.count(SAME), 15)
        self.assertEqual(
            [f.field for f in result.fields if f.status == NOT_COMPARED],
            ["security.updates_at_first_boot"],
        )
        undeclared = [f.field for f in result.fields
                      if f.status == NOT_DECLARED]
        self.assertEqual(undeclared, [
            "network.interfaces.eth0.ipv4.method",
            "network.interfaces.eth1.ipv6.method",
            "network.interfaces.eth1.ipv4.method",
            "network.interfaces.eth1.ipv4.address",
            "network.interfaces.eth1.ipv4.gateway",
            "users.root.authorized_keys",
            "users.root.shell",
            "users.admin.shell",
            "users.admin.groups",
            "monitor.enabled",
        ])
        self.assertEqual(result.code, exits.OK)

    def test_each_section_drifts_on_its_own(self):
        edits = {
            "instance.hostname": ("instance", "hostname", "shop"),
            "network.nameservers": ("network", "nameservers",
                                    ["2001:db8:1::53"]),
            "tls.acme.challenge": ("tls", "acme", {"enabled": True,
                                                   "challenge": "http-01"}),
            "security.alerts": ("security", "alerts", "ops@example.org"),
            "hub.api_key": ("hub", "api_key", "SKIP "),
            "users.admin.authorized_keys": ("users", "admin",
                                            {"authorized_keys": [KEY]}),
            "locale.timezone": ("locale", "timezone", "Etc/UTC"),
        }
        for field, (section, key, value) in edits.items():
            with self.subTest(field=field):
                declared = self.matching()
                declared[section] = {**declared[section], key: value}
                result = compare(declared, self.observed)
                drifted = [f.field for f in result.fields
                           if f.status == DRIFT]
                if field == "hub.api_key":
                    self.assertEqual(drifted, [])
                    self.assertEqual(result.code, exits.OK)
                elif field == "tls.acme.challenge":
                    self.assertEqual(drifted, ["tls.acme.challenge"])
                    self.assertEqual(result.code, exits.DRIFT_FOUND)
                else:
                    self.assertEqual(drifted, [field])
                    self.assertEqual(result.code, exits.DRIFT_FOUND)

    def test_the_first_boot_field_never_drifts_whatever_it_declares(self):
        """updates_at_first_boot is an input the machine keeps no record of"""
        for value in ("skip", "force"):
            with self.subTest(value=value):
                declared = self.matching()
                declared["security"] = {**declared["security"],
                                        "updates_at_first_boot": value}
                result = compare(declared, self.observed)
                field = by_field(result)["security.updates_at_first_boot"]
                self.assertEqual(field.status, NOT_COMPARED)
                self.assertIn("95secupdates installs the pending security"
                              " updates once", field.reason)
                self.assertEqual(result.code, exits.OK)

    def test_diff_root_runs_the_collector_and_the_comparison(self):
        result = diff_root(self.matching(), TURNKEY)
        self.assertEqual(result.root, TURNKEY)
        self.assertEqual(result.count(DRIFT), 0)


class TestEmit(unittest.TestCase):
    def test_report_lines_end_with_the_summary(self):
        result = Comparison("/", (FieldDiff("a.b", SAME, 1, 1),))
        self.assertEqual(report_lines(result), [
            "a.b: same (1)",
            "diff: 1 same, 0 drift, 0 unknown, 0 not declared,"
            " 0 not compared; no drift",
        ])

    def test_json_carries_the_fields_the_counts_and_the_exit_code(self):
        import json

        result = Comparison("/", (
            FieldDiff("a.b", DRIFT, "x", None),
            FieldDiff("c.d", UNKNOWN, ["y"], None, "why"),
        ))
        document = json.loads(to_json(result, "/etc/keel/instance.yaml"))
        self.assertEqual(document["spec"], "/etc/keel/instance.yaml")
        self.assertEqual(document["root"], "/")
        self.assertEqual(document["fields"][0]["observed"], None)
        self.assertEqual(document["fields"][1]["declared"], ["y"])
        self.assertEqual(document["counts"], {
            "same": 0, "drift": 1, "unknown": 1, "not_declared": 0,
            "not_compared": 0,
        })
        self.assertEqual((document["drift"], document["incomplete"]),
                         (True, True))
        self.assertEqual(document["exit_code"], exits.DRIFT_FOUND)


class TestMonitorSwitch(unittest.TestCase):
    """keel#46: diff reads the monitor section the way apply acts on it"""

    OBSERVED = {"enabled": True, "checks": {"disk": {"warn": 80}}}

    def status(self, declared):
        found = {f.field: f.status
                 for f in compare_section("monitor", declared, self.OBSERVED,
                                          {})}
        return found["monitor.enabled"]

    def test_a_section_without_enabled_is_off_and_so_drift(self):
        self.assertEqual(self.status({"checks": {"disk": {"warn": 80}}}),
                         DRIFT)

    def test_no_section_is_not_declared_as_apply_leaves_it(self):
        self.assertEqual(self.status(None), NOT_DECLARED)

    def test_enabled_true_is_same(self):
        self.assertEqual(self.status({"enabled": True}), SAME)


if __name__ == "__main__":
    unittest.main()
