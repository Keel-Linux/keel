# Copyright (c) 2026 KeelLinux maintainers
"""Validation of the monitor section (decision 0021)"""

import os
import tempfile
import unittest

from helpers import errors, spec

from keel.spec.validate_monitor import (
    NO_CHANNEL,
    alerts_address,
    validate_monitor,
    working_channels,
)

WEBHOOK = {"webhook": {"url": "https://hooks.example.org/keel"}}
ALERTS = {"alerts": "admin@example.org"}


def check(monitor, security=ALERTS, files=False):
    return validate_monitor(monitor, security, files)


class TestSection(unittest.TestCase):
    def test_absent_or_empty_is_valid(self):
        self.assertEqual(check(None), [])
        self.assertEqual(check({}), [])

    def test_not_a_mapping(self):
        self.assertEqual(check("on"), ["monitor: must be a mapping"])

    def test_unknown_keys_are_errors(self):
        self.assertIn("monitor.peers: unknown key", check({"peers": []}))

    def test_enabled_must_be_a_boolean(self):
        self.assertIn("monitor.enabled: must be true or false",
                      check({"enabled": "yes", "notify": WEBHOOK}))

    def test_the_decision_example_is_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            token = os.path.join(tmp, "token")
            with open(token, "w") as fob:
                fob.write("123:abc\n")
            os.chmod(token, 0o600)
            found = errors(
                "version: 1\n"
                "security:\n  alerts: admin@example.org\n"
                "monitor:\n"
                "  enabled: true\n"
                "  checks:\n"
                "    disk: {warn: 80, critical: 90}\n"
                "    inodes: {critical: 90}\n"
                "    memory: {warn: 85, for_minutes: 5}\n"
                "    swap: {warn: 50, for_minutes: 5}\n"
                "    cpu: {warn: 90, for_minutes: 10}\n"
                "    load_per_core: {warn: 2.0, for_minutes: 10}\n"
                "    network:\n"
                "      eth0: {link: true, max_mbit: 800, for_minutes: 5}\n"
                "  notify:\n"
                "    email: true\n"
                "    telegram:\n"
                '      chat_id: "-1001234567890"\n'
                f"      token: {{file: {token}}}\n"
                "    ntfy:\n"
                "      url: https://ntfy.example.org/keel-blog\n"
                f"      token: {{file: {token}}}\n"
                "    webhook:\n"
                "      url: https://hooks.example.org/keel\n"
                "    details: true\n"
            )
        self.assertEqual(found, [])

    def test_top_level_key_is_known_to_the_spec(self):
        self.assertEqual(errors("version: 1\nmonitor: {enabled: false}\n"),
                         [])


class TestChannels(unittest.TestCase):
    def test_enabled_without_notify_is_an_error(self):
        self.assertEqual(check({"enabled": True}), [NO_CHANNEL])

    def test_enabled_with_an_empty_channel_is_an_error(self):
        self.assertIn(NO_CHANNEL, check({"enabled": True,
                                         "notify": {"email": False}}))

    def test_disabled_without_a_channel_is_fine(self):
        self.assertEqual(check({"enabled": False}), [])

    def test_email_while_alerts_is_skip_is_an_error(self):
        found = check({"enabled": True, "notify": {"email": True}},
                      {"alerts": "skip"})
        self.assertIn("monitor.notify.email: security.alerts is skip or"
                      " absent, so there is no address to mail; set"
                      " security.alerts to an address, or email to false",
                      found)
        self.assertIn(NO_CHANNEL, found)

    def test_email_without_a_security_section_is_an_error(self):
        found = check({"notify": {"email": True}}, None)
        self.assertEqual(len(found), 1)
        self.assertIn("security.alerts is skip or absent", found[0])

    def test_email_with_an_address_is_a_working_channel(self):
        self.assertEqual(check({"enabled": True,
                                "notify": {"email": True}}), [])

    def test_alerts_address_reads_only_an_address(self):
        self.assertEqual(alerts_address(ALERTS), "admin@example.org")
        self.assertIsNone(alerts_address({"alerts": "SKIP"}))
        self.assertIsNone(alerts_address({"alerts": "not an address"}))
        self.assertIsNone(alerts_address({}))
        self.assertIsNone(alerts_address("skip"))

    def test_working_channels_in_order(self):
        notify = {"webhook": {"url": "x"}, "email": True,
                  "ntfy": {"url": "y"}, "telegram": {}}
        self.assertEqual(working_channels(notify, ALERTS),
                         ["email", "ntfy", "webhook"])
        self.assertEqual(working_channels("email", ALERTS), [])

    def test_notify_keys(self):
        found = check({"notify": {"sms": True, "email": "yes",
                                  "details": 1}})
        self.assertIn("monitor.notify.sms: unknown key", found)
        self.assertIn("monitor.notify.email: must be true or false", found)
        self.assertIn("monitor.notify.details: must be true or false", found)
        self.assertEqual(check({"notify": ["email"]}),
                         ["monitor.notify: must be a mapping"])

    def test_telegram(self):
        found = check({"notify": {"telegram": {"chat": 1}}})
        self.assertIn("monitor.notify.telegram.chat: unknown key", found)
        self.assertIn("monitor.notify.telegram.token: required, as a secret"
                      " reference", found)
        self.assertTrue(any("chat_id: must be a chat id" in one
                            for one in found))
        for chat_id in (True, "not a chat", None, 1.5):
            found = check({"notify": {"telegram": {
                "chat_id": chat_id, "token": {"file": "/x"}}}})
            self.assertEqual(len(found), 1, chat_id)
        for chat_id in (-1001234567890, "-1001234567890", "@keel_ops"):
            self.assertEqual(check({"notify": {"telegram": {
                "chat_id": chat_id, "token": {"file": "/x"}}}}), [])
        self.assertEqual(check({"notify": {"telegram": "t"}}),
                         ["monitor.notify.telegram: must be a mapping"])

    def test_a_token_is_never_generated(self):
        found = check({"notify": {"ntfy": {
            "url": "https://ntfy.example.org/k", "token": {"generate": True}}}})
        self.assertEqual(found, [
            "monitor.notify.ntfy.token: a token is issued by the service, so"
            " it is a file reference; a generated value is one nobody else"
            " knows"])

    def test_a_token_file_is_checked_when_asked(self):
        found = check({"notify": {"telegram": {
            "chat_id": 1, "token": {"file": "/nonexistent/token"}}}},
            files=True)
        self.assertEqual(found, ["monitor.notify.telegram.token:"
                                 " /nonexistent/token: secret file not"
                                 " found"])

    def test_ntfy_token_is_optional(self):
        self.assertEqual(check({"enabled": True, "notify": {"ntfy": {
            "url": "https://ntfy.example.org/keel"}}}), [])
        self.assertEqual(check({"notify": {"ntfy": 1}}),
                         ["monitor.notify.ntfy: must be a mapping"])
        self.assertIn("monitor.notify.ntfy.user: unknown key", check(
            {"notify": {"ntfy": {"url": "https://a.example", "user": "x"}}}))

    def test_urls_must_be_https_with_a_host_and_no_credentials(self):
        cases = {
            None: "required, an https URL",
            "": "required, an https URL",
            "http://ntfy.example.org/keel": "must be an https URL",
            "https:///keel": "must be an https URL",
            "https://ntfy.example.org/a b": "must not contain spaces",
            "https://[2001:db8::1/keel": "not a URL",
            "https://hooks.example.org:https/keel": "not a URL",
            "https://user:pass@hooks.example.org/":
                "must not carry credentials",
        }
        for url, message in cases.items():
            found = check({"notify": {"webhook": {"url": url}}})
            self.assertEqual(len(found), 1, url)
            self.assertIn(message, found[0])
        self.assertEqual(check({"notify": {"webhook": {
            "url": "https://[2001:db8::1]:8443/keel"}}}), [])
        self.assertEqual(check({"notify": {"webhook": []}}),
                         ["monitor.notify.webhook: must be a mapping"])
        self.assertIn("monitor.notify.webhook.token: unknown key", check(
            {"notify": {"webhook": {"url": "https://a.example",
                                    "token": {"file": "/x"}}}}))


class TestChecks(unittest.TestCase):
    def test_checks_must_be_a_mapping(self):
        self.assertEqual(check({"checks": []}),
                         ["monitor.checks: must be a mapping"])

    def test_unknown_check_and_key(self):
        found = check({"checks": {"gpu": {}, "disk": {"panic": 99},
                                  "memory": "85"}})
        self.assertIn("monitor.checks.gpu: unknown check", found)
        self.assertIn("monitor.checks.disk.panic: unknown key", found)
        self.assertIn("monitor.checks.memory: must be a mapping", found)

    def test_a_key_that_belongs_to_another_check_is_unknown(self):
        found = check({"checks": {"inodes": {"warn": 80},
                                  "disk": {"for_minutes": 5}}})
        self.assertIn("monitor.checks.inodes.warn: unknown key", found)
        self.assertIn("monitor.checks.disk.for_minutes: unknown key", found)

    def test_percentages(self):
        for value in (0, 100, 101, -1, "80", True):
            found = check({"checks": {"memory": {"warn": value}}})
            self.assertEqual(found, ["monitor.checks.memory.warn: must be a"
                                     " percentage above 0 and below 100"],
                             value)
        self.assertEqual(check({"checks": {"memory": {"warn": 85.5}}}), [])

    def test_load_is_a_positive_number_not_a_percentage(self):
        self.assertEqual(check({"checks": {"load_per_core": {"warn": 4}}}),
                         [])
        self.assertEqual(check({"checks": {"load_per_core": {"warn": 0}}}),
                         ["monitor.checks.load_per_core.warn: must be a"
                          " number above 0"])

    def test_disk_warn_below_critical_with_the_defaults_filled_in(self):
        self.assertEqual(check({"checks": {"disk": {"warn": 95}}}), [
            "monitor.checks.disk: warn (95) must be below critical (90)"])
        self.assertEqual(check({"checks": {"disk": {"warn": 70,
                                                    "critical": 70}}}),
                         ["monitor.checks.disk: warn (70) must be below"
                          " critical (70)"])
        self.assertEqual(check({"checks": {"disk": {"critical": 95}}}), [])

    def test_for_minutes_fits_monit_64_cycles(self):
        self.assertEqual(check({"checks": {"cpu": {"for_minutes": 64}}}), [])
        self.assertEqual(check({"checks": {"cpu": {"for_minutes": 65}}}), [
            "monitor.checks.cpu.for_minutes: at most 64: monit holds a"
            " condition for at most 64 cycles, and keel sets a cycle of"
            " 60 s"])
        for value in (0, 2.5, "5", False):
            self.assertEqual(
                check({"checks": {"cpu": {"for_minutes": value}}}),
                ["monitor.checks.cpu.for_minutes: must be a whole number of"
                 " minutes, at least 1"], value)


class TestNetwork(unittest.TestCase):
    def test_a_declared_interface(self):
        self.assertEqual(check({"checks": {"network": {
            "eth0": {"link": True, "max_mbit": 800, "for_minutes": 5},
            "br0": {"max_mbit": 0.5},
            "wg0": {"link": True},
        }}}), [])

    def test_network_errors(self):
        found = check({"checks": {"network": {
            "a very long interface": {"link": True},
            "eth0": {"link": "up", "max_mbit": -1, "for_minutes": 99,
                     "saturation": 90},
            "eth1": {},
            "eth2": "watch",
        }}})
        self.assertEqual(found, [
            "monitor.checks.network.a very long interface: not an interface"
            " name",
            "monitor.checks.network.eth0.saturation: unknown key",
            "monitor.checks.network.eth0.link: must be true or false",
            "monitor.checks.network.eth0.max_mbit: must be a number above 0",
            "monitor.checks.network.eth0.for_minutes: at most 64: monit"
            " holds a condition for at most 64 cycles, and keel sets a cycle"
            " of 60 s",
            "monitor.checks.network.eth1: nothing to watch; declare link:"
            " true, max_mbit, or both",
            "monitor.checks.network.eth2: must be a mapping",
        ])

    def test_two_interfaces_monit_would_name_alike(self):
        self.assertEqual(check({"checks": {"network": {
            "br0.10": {"link": True}, "br0_10": {"link": True}}}}), [
            "monitor.checks.network.br0_10: monit's service for it would"
            " have the name of br0.10's; watch one of them"])

    def test_infinity_and_nan_are_not_numbers(self):
        for value in (float("inf"), float("nan")):
            self.assertEqual(
                check({"checks": {"network": {"eth0": {"max_mbit": value}},
                                  "load_per_core": {"warn": value}}}),
                ["monitor.checks.load_per_core.warn: must be a number"
                 " above 0",
                 "monitor.checks.network.eth0.max_mbit: must be a number"
                 " above 0"])

    def test_an_address_label_is_not_an_interface(self):
        self.assertEqual(check({"checks": {"network": {
            "eth0:1": {"link": True}}}}),
            ["monitor.checks.network.eth0:1: not an interface name"])

    def test_network_must_be_a_mapping(self):
        self.assertEqual(check({"checks": {"network": ["eth0"]}}),
                         ["monitor.checks.network: must be a mapping"])


class TestEveryErrorAtOnce(unittest.TestCase):
    def test_the_whole_file_is_reported_in_one_pass(self):
        found = spec.validate({
            "version": 1,
            "security": {"alerts": "skip"},
            "monitor": {"enabled": True,
                        "checks": {"cpu": {"for_minutes": 100}},
                        "notify": {"email": True,
                                   "ntfy": {"url": "http://x"}}},
        })
        self.assertEqual(len(found), 3)


if __name__ == "__main__":
    unittest.main()
