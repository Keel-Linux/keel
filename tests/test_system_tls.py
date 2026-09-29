# Copyright (c) 2026 KeelLinux maintainers
"""apply --system: tls.acme on a running machine (keel#35, part B)

The planner is pure. Whether a certificate is requested is decided from
the certificate in use, read as inspect reads it, so a second run after a
successful request finds nothing to do and Let's Encrypt is asked only
when the machine needs it.
"""

import unittest
from datetime import datetime, timezone
from os.path import abspath, dirname, join

from helpers import spec  # noqa: F401

from keel.inspect.tree import NOT_PRESENT, File
from keel.system.actions import Note, Refuse, Run, WriteFile
from keel.system.state import SystemState
from keel.system.tls import CRON, DOMAINS, WRAPPER, plan_tls

CERTS = join(dirname(abspath(__file__)), "fixtures", "certificates")
ABSENT = File("/x/absent", problem=NOT_PRESENT)
NOW = datetime(2026, 9, 29, tzinfo=timezone.utc)
BLOG = ["blog.example.org", "www.blog.example.org"]


def cert(name: str) -> File:
    with open(join(CERTS, f"{name}.pem")) as fob:
        return File("/x/etc/ssl/private/cert.pem", fob.read())


def domains_file(names) -> File:
    return File(f"/x/{DOMAINS}", "# written by keel apply --system\n"
                + " ".join(names) + "\n")


def state(**overrides) -> SystemState:
    values = dict(
        root="/", live=True, passwd=ABSENT, group=ABSENT, hosts=ABSENT,
        key_files={}, timezone=ABSENT, localtime_target=None,
        default_locale=ABSENT, locale_gen=ABSENT, generated=None,
        available=frozenset(("turnkey-make-ssl-cert", "systemctl", "chmod")),
        tls_cert=cert("self-signed"), acme_domains=ABSENT,
        acme_account=False, acme_wrapper=True, now=NOW,
    )
    values.update(overrides)
    return SystemState(**values)


def acme(**fields) -> dict:
    return {"acme": {"enabled": True, "challenge": "http-01",
                     "domains": BLOG, **fields}}


def actions(steps):
    return [a for step in steps for a in step.actions]


def runs(steps):
    return [a.argv for a in actions(steps) if isinstance(a, Run)]


class TestRequest(unittest.TestCase):
    def test_nothing_declared_plans_nothing(self):
        self.assertEqual(plan_tls({}, state()), [])
        self.assertEqual(plan_tls({"acme": {"domains": BLOG}}, state()), [])

    def test_a_self_signed_machine_writes_the_domains_and_requests(self):
        steps = plan_tls(acme(agree_tos=True), state())
        self.assertEqual(steps[0].field, "tls.acme")
        [domains] = [a for a in actions(steps) if isinstance(a, WriteFile)]
        self.assertEqual(domains.path, DOMAINS)
        self.assertEqual(domains.content.splitlines()[-1],
                         "blog.example.org www.blog.example.org")
        self.assertEqual(runs(steps), [(
            "/bin/bash", WRAPPER, "--log-info", "--challenge", "http-01",
            "--register",
        )])

    def test_a_certificate_that_carries_the_domains_is_left_alone(self):
        found = state(tls_cert=cert("acme-blog"),
                      acme_domains=domains_file(BLOG))
        steps = plan_tls(acme(), found)
        self.assertEqual(actions(steps), [Note(
            "unchanged (blog.example.org, www.blog.example.org, valid until"
            " 2039-01-01)")])

    def test_a_certificate_near_its_end_is_renewed(self):
        found = state(tls_cert=cert("acme-blog"),
                      acme_domains=domains_file(BLOG), acme_account=True,
                      now=datetime(2038, 12, 15, tzinfo=timezone.utc))
        self.assertEqual(len(runs(plan_tls(acme(), found))), 1)

    def test_an_expired_or_other_certificate_is_requested_again(self):
        for name in ("acme-expired", "acme-other"):
            found = state(tls_cert=cert(name), acme_account=True,
                          acme_domains=domains_file(BLOG))
            self.assertEqual(len(runs(plan_tls(acme(), found))), 1, name)

    def test_an_existing_account_needs_no_new_consent(self):
        found = state(acme_account=True)
        self.assertEqual(runs(plan_tls(acme(), found))[0][-1], "http-01")

    def test_no_account_and_no_consent_is_refused(self):
        steps = plan_tls(acme(), state())
        refusals = [a for a in actions(steps) if isinstance(a, Refuse)]
        self.assertEqual(len(refusals), 1)
        self.assertIn("agree_tos", refusals[0].summary)
        self.assertEqual(runs(steps), [])

    def test_dns_01_is_refused_with_its_reason(self):
        steps = plan_tls(acme(challenge="dns-01", agree_tos=True), state())
        [refusal] = [a for a in actions(steps) if isinstance(a, Refuse)]
        self.assertIn("dns-01", refusal.summary)
        self.assertIn("confconsole", refusal.summary)
        self.assertEqual(runs(steps), [])

    def test_enabled_without_domains_is_refused(self):
        steps = plan_tls({"acme": {"enabled": True}}, state())
        self.assertIsInstance(actions(steps)[0], Refuse)

    def test_without_confconsole_there_is_no_client(self):
        steps = plan_tls(acme(agree_tos=True), state(acme_wrapper=False))
        [refusal] = [a for a in actions(steps) if isinstance(a, Refuse)]
        self.assertIn("dehydrated-wrapper", refusal.summary)

    def test_a_scratch_tree_is_not_refused_what_it_would_never_request(self):
        found = state(root="/x", live=False, available=frozenset())
        steps = plan_tls(acme(challenge="dns-01"), found)
        self.assertFalse(any(isinstance(a, Refuse) for a in actions(steps)))

    def test_a_scratch_tree_writes_the_domains_and_requests_nothing(self):
        found = state(root="/x", live=False, available=frozenset())
        steps = plan_tls(acme(agree_tos=True), found)
        self.assertEqual(runs(steps), [])
        self.assertTrue(any(isinstance(a, WriteFile) for a in actions(steps)))
        self.assertTrue(any(isinstance(a, Note) and "not the live system"
                            in a.summary for a in actions(steps)))

    def test_domains_already_written_are_not_rewritten(self):
        found = state(acme_domains=domains_file(BLOG), acme_account=True)
        self.assertFalse(any(isinstance(a, WriteFile)
                             for a in actions(plan_tls(acme(), found))))


class TestTurnOff(unittest.TestCase):
    def test_false_over_an_issued_certificate_goes_back_to_self_signed(self):
        found = state(tls_cert=cert("acme-blog"),
                      acme_domains=domains_file(BLOG))
        steps = plan_tls({"acme": {"enabled": False}}, found)
        self.assertEqual(runs(steps), [
            ("chmod", "a-x", f"/{CRON}"),
            ("turnkey-make-ssl-cert", "--default", "--force"),
            ("systemctl", "try-restart", "nginx.service", "apache2.service",
             "lighttpd.service", "tomcat10.service", "tomcat11.service",
             "webmin.service"),
        ])

    def test_false_over_a_self_signed_certificate_is_unchanged(self):
        steps = plan_tls({"acme": {"enabled": False}}, state())
        self.assertEqual(actions(steps), [Note("unchanged (off)")])

    def test_false_on_a_scratch_tree_says_what_it_did_not_do(self):
        found = state(root="/x", live=False, tls_cert=cert("acme-blog"))
        steps = plan_tls({"acme": {"enabled": False}}, found)
        self.assertEqual(runs(steps), [])
        self.assertTrue(any("not the live system" in a.summary
                            for a in actions(steps)))


if __name__ == "__main__":
    unittest.main()
