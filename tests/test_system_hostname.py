# Copyright (c) 2026 KeelLinux maintainers
"""apply --system: instance.hostname on a running machine (keel#35)

The planner is pure; the loop through the CLI (rename, then diff is same,
then a second run changes nothing) is in tests/test_apply_system_cli.py.
"""

import subprocess
import tempfile
import unittest
from os.path import join
from unittest import mock

from helpers import spec  # noqa: F401

from keel.inspect.tree import NOT_PRESENT, PERMISSION_DENIED, File
from keel.system import Effects, execute
from keel.system import plan as plan_all
from keel.system import effects
from keel.system.actions import Note, Refuse, Run, WriteFile
from keel.system.hostname import plan_hostname, renamed, renamed_postfix
from keel.system.state import SystemState

ABSENT = File("/x/absent", problem=NOT_PRESENT)
HOSTS = (
    "127.0.0.1 localhost\n"
    "127.0.1.1 blog.example.org blog\n"
    "# blog lives here\n"
    "::1 ip6-localhost ip6-loopback\n"
    "2001:db8:1::10 blog.example.org blog\n"
    "192.0.2.7 weblog backup-blog\n"
)
MAIN_CF = (
    "smtpd_banner = $myhostname ESMTP\n"
    "myhostname = blog.example.org\n"
    "mydestination = blog.example.org, blog, localhost\n"
    "relayhost =\n"
)


def state(**overrides) -> SystemState:
    values = dict(
        root="/x", live=False, passwd=ABSENT, group=ABSENT,
        hosts=File("/x/etc/hosts", HOSTS), key_files={}, timezone=ABSENT,
        localtime_target=None, default_locale=ABSENT, locale_gen=ABSENT,
        generated=None, available=frozenset(),
        hostname=File("/x/etc/hostname", "blog\n"),
        mailname=File("/x/etc/mailname", "blog.example.org\n"),
        postfix_main=File("/x/etc/postfix/main.cf", MAIN_CF),
    )
    values.update(overrides)
    return SystemState(**values)


def by_path(steps, path):
    return [a for step in steps for a in step.actions
            if isinstance(a, WriteFile) and a.path == path]


def runs(steps):
    return [a.argv for step in steps for a in step.actions
            if isinstance(a, Run)]


class TestRenamed(unittest.TestCase):
    """The token rule: the name, or the name as the first label, only"""

    def test_a_token_and_a_first_label_are_renamed_and_nothing_else(self):
        self.assertEqual(
            renamed("127.0.1.1 blog.example.org blog", "blog", "news"),
            "127.0.1.1 news.example.org news")
        self.assertEqual(renamed("192.0.2.7 weblog backup-blog blogs",
                                 "blog", "news"),
                         "192.0.2.7 weblog backup-blog blogs")
        self.assertEqual(renamed("mydestination = blog.example.org, blog,"
                                 " localhost", "blog", "news"),
                         "mydestination = news.example.org, news, localhost")

    def test_case_is_ignored_in_the_old_name(self):
        self.assertEqual(renamed("127.0.1.1 BLOG", "blog", "news"),
                         "127.0.1.1 news")

    def test_spacing_is_kept(self):
        self.assertEqual(renamed("127.0.1.1\tblog   # blog", "blog", "news"),
                         "127.0.1.1\tnews   # news")


DEBIAN_MAIN_CF = (
    "smtpd_banner = $myhostname ESMTP $mail_name (Debian/GNU)\n"
    "smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache\n"
    "smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache\n"
    "smtpd_relay_restrictions = permit_mynetworks reject_unauth_destination\n"
    "# the mail host\n"
    "myhostname = mail.example.org\n"
    "mydestination = $myhostname, mail, localhost\n"
    "relayhost = relay.example.org\n"
)


class TestPostfixIsRenamedInItsTwoNameSettingsOnly(unittest.TestCase):
    """The review of #37: a host named like a postfix word"""

    def rename(self, old):
        found = state(hostname=File("/x/etc/hostname", f"{old}\n"),
                      postfix_main=File("/x/etc/postfix/main.cf",
                                        DEBIAN_MAIN_CF))
        steps, _ = plan_hostname({"hostname": "news"}, found)
        [main] = by_path(steps, "etc/postfix/main.cf")
        return main.content

    def test_mail_renames_its_settings_and_not_mail_name(self):
        self.assertEqual(self.rename("mail"), DEBIAN_MAIN_CF.replace(
            "myhostname = mail.example.org", "myhostname = news.example.org"
        ).replace("mydestination = $myhostname, mail,",
                  "mydestination = $myhostname, news,"))

    def test_smtp_and_relay_leave_every_parameter_name_alone(self):
        for old in ("smtp", "relay", "smtpd", "tls"):
            found = state(hostname=File("/x/etc/hostname", f"{old}\n"),
                          postfix_main=File("/x/etc/postfix/main.cf",
                                            DEBIAN_MAIN_CF))
            steps, _ = plan_hostname({"hostname": "news"}, found)
            self.assertEqual(by_path(steps, "etc/postfix/main.cf"), [], old)

    def test_a_continued_value_is_renamed_only_under_a_name_setting(self):
        text = ("mydestination = localhost,\n    mail, mail.example.org\n"
                "smtpd_recipient_restrictions = permit,\n    mail_check\n"
                "relay_domains =\n    mail\n")
        self.assertEqual(renamed_postfix(text, "mail", "news"), (
            "mydestination = localhost,\n    news, news.example.org\n"
            "smtpd_recipient_restrictions = permit,\n    mail_check\n"
            "relay_domains =\n    mail\n"))

    def test_an_underscore_is_part_of_a_name(self):
        self.assertEqual(renamed("$mail_name mail", "mail", "news"),
                         "$mail_name news")


class TestPlanHostname(unittest.TestCase):
    def test_nothing_declared_plans_nothing(self):
        self.assertEqual(plan_hostname({}, state())[0], [])

    def test_a_trailing_dot_is_the_same_name_as_diff_says(self):
        steps, after = plan_hostname({"hostname": "blog."}, state())
        self.assertEqual(steps[0].actions, (Note("unchanged (blog)"),))
        self.assertEqual(after, state())

    def test_a_rename_to_a_dotted_spelling_writes_no_dot(self):
        steps, _ = plan_hostname({"hostname": "news."}, state())
        [hostname] = by_path(steps, "etc/hostname")
        self.assertEqual(hostname.content, "news\n")
        [hosts] = by_path(steps, "etc/hosts")
        self.assertNotIn("news.\n", hosts.content)
        self.assertNotIn("news. ", hosts.content)

    def test_a_live_kernel_name_left_behind_is_set_again(self):
        """hostnamectl failed after the file was written; the rerun retries"""
        found = state(root="/", live=True, kernel_hostname="blog",
                      hostname=File("/x/etc/hostname", "news\n"),
                      available=frozenset(("hostnamectl",)))
        steps, _ = plan_hostname({"hostname": "news"}, found)
        self.assertEqual(runs(steps), [("hostnamectl", "set-hostname", "news")])
        self.assertEqual(by_path(steps, "etc/hostname"), [])

    def test_a_live_kernel_name_that_matches_is_unchanged(self):
        found = state(root="/", live=True, kernel_hostname="news",
                      hostname=File("/x/etc/hostname", "news\n"),
                      available=frozenset(("hostnamectl",)))
        steps, _ = plan_hostname({"hostname": "news"}, found)
        self.assertEqual(steps[0].actions, (Note("unchanged (news)"),))

    def test_the_declared_name_is_unchanged(self):
        steps, after = plan_hostname({"hostname": "blog"}, state())
        self.assertEqual(steps[0].actions, (Note("unchanged (blog)"),))
        self.assertEqual(after, state())
        steps, _ = plan_hostname({"hostname": "BLOG"}, state())
        self.assertEqual(steps[0].actions, (Note("unchanged (BLOG)"),))

    def test_a_rename_writes_every_file_that_carries_the_name(self):
        steps, _ = plan_hostname({"hostname": "news"}, state())
        self.assertEqual(steps[0].field, "instance.hostname")
        [hostname] = by_path(steps, "etc/hostname")
        self.assertEqual((hostname.content, hostname.mode), ("news\n", 0o644))
        [hosts] = by_path(steps, "etc/hosts")
        self.assertEqual(hosts.content, (
            "127.0.0.1 localhost\n"
            "127.0.1.1 news.example.org news\n"
            "# news lives here\n"
            "::1 ip6-localhost ip6-loopback\n"
            "2001:db8:1::10 news.example.org news\n"
            "192.0.2.7 weblog backup-blog\n"
        ))
        [mailname] = by_path(steps, "etc/mailname")
        self.assertEqual(mailname.content, "news.example.org\n")
        [main] = by_path(steps, "etc/postfix/main.cf")
        self.assertEqual(main.content, (
            "smtpd_banner = $myhostname ESMTP\n"
            "myhostname = news.example.org\n"
            "mydestination = news.example.org, news, localhost\n"
            "relayhost =\n"
        ))

    def test_the_fqdn_step_plans_on_the_renamed_hosts(self):
        _, after = plan_hostname({"hostname": "news"}, state())
        self.assertIn("news.example.org news", after.hosts.text)
        self.assertNotRegex(after.hosts.text, r"(?m)\sblog$")
        self.assertEqual(after.hosts.path, "/x/etc/hosts")

    def test_rename_and_fqdn_compose_into_one_final_hosts(self):
        doc = {"instance": {"hostname": "news", "fqdn": "news.example.org"},
               "network": {"interfaces": {"eth0": {"ipv6": {
                   "method": "static", "address": "2001:db8:1::10/64"}}}}}
        writes = [a for step in plan_all(doc, state()).steps
                  for a in step.actions
                  if isinstance(a, WriteFile) and a.path == "etc/hosts"]
        self.assertNotIn("blog.example.org", writes[-1].content)
        self.assertNotRegex(writes[-1].content, r"(?m)\sblog$")
        self.assertIn("192.0.2.7 weblog backup-blog", writes[-1].content)
        self.assertIn("2001:db8:1::10 news.example.org news", writes[-1].content)

    def test_files_that_do_not_carry_the_name_are_left_alone(self):
        found = state(mailname=File("/x/etc/mailname", "mail.example.org\n"),
                      postfix_main=ABSENT)
        steps, _ = plan_hostname({"hostname": "news"}, found)
        self.assertEqual(by_path(steps, "etc/mailname"), [])
        self.assertEqual(by_path(steps, "etc/postfix/main.cf"), [])

    def test_the_live_system_sets_the_kernel_name_and_reloads_postfix(self):
        found = state(root="/", live=True, available=frozenset(
            ("hostnamectl", "hostname", "systemctl")))
        steps, _ = plan_hostname({"hostname": "news"}, found)
        self.assertEqual(runs(steps), [
            ("hostnamectl", "set-hostname", "news"),
            ("systemctl", "try-reload-or-restart", "postfix.service"),
        ])

    def test_without_hostnamectl_the_hostname_command_is_used(self):
        found = state(root="/", live=True,
                      available=frozenset(("hostname",)))
        steps, _ = plan_hostname({"hostname": "news"}, found)
        self.assertEqual(runs(steps), [("hostname", "news")])
        notes = [a.summary for s in steps for a in s.actions
                 if isinstance(a, Note)]
        self.assertTrue(any("postfix" in note for note in notes), notes)

    def test_a_live_system_without_either_command_says_so(self):
        found = state(root="/", live=True, available=frozenset())
        steps, _ = plan_hostname({"hostname": "news"}, found)
        self.assertEqual(runs(steps), [])
        notes = [a.summary for s in steps for a in s.actions
                 if isinstance(a, Note)]
        self.assertIn("kernel hostname not set: neither hostnamectl nor"
                      " hostname found", notes)

    def test_a_scratch_tree_changes_files_and_runs_nothing(self):
        steps, _ = plan_hostname({"hostname": "news"}, state())
        self.assertEqual(runs(steps), [])
        notes = [a.summary for s in steps for a in s.actions
                 if isinstance(a, Note)]
        self.assertTrue(any("not the live system" in n for n in notes), notes)

    def test_the_certificate_is_named_and_not_regenerated(self):
        steps, _ = plan_hostname({"hostname": "news"}, state())
        notes = [a.summary for s in steps for a in s.actions
                 if isinstance(a, Note)]
        self.assertTrue(any("turnkey-make-ssl-cert" in n for n in notes),
                        notes)

    def test_an_unreadable_file_that_would_be_rewritten_is_refused(self):
        found = state(hosts=File("/x/etc/hosts", problem=PERMISSION_DENIED))
        steps, after = plan_hostname({"hostname": "news"}, found)
        self.assertIsInstance(steps[0].actions[0], Refuse)
        self.assertIn("/x/etc/hosts", steps[0].actions[0].summary)
        self.assertEqual(by_path(steps, "etc/hostname"), [])
        self.assertEqual(after, found)

    def test_a_machine_without_a_hostname_file_gets_one(self):
        steps, _ = plan_hostname({"hostname": "news"},
                                 state(hostname=ABSENT))
        [hostname] = by_path(steps, "etc/hostname")
        self.assertEqual(hostname.content, "news\n")


if __name__ == "__main__":
    unittest.main()


class TestHostnameAndFqdnAgree(unittest.TestCase):
    def test_a_fqdn_whose_first_label_is_another_name_is_said(self):
        doc = {"instance": {"hostname": "blog", "fqdn": "shop.example.org"}}
        notes = [a.summary for step in plan_all(doc, state()).steps
                 for a in step.actions if isinstance(a, Note)]
        self.assertTrue(any("shop.example.org" in n and "blog" in n
                            and "first label" in n for n in notes), notes)


class TestLiveRenameThatFails(unittest.TestCase):
    """hostnamectl fails at the subprocess boundary, as in a container
    without systemd-hostnamed: the field fails, the file stays written, and
    the plan for the rerun asks the kernel again"""

    def test_the_failure_is_reported_and_the_rerun_retries(self):
        root = tempfile.mkdtemp()
        found = state(root=root, live=True, kernel_hostname="blog",
                      available=frozenset(("hostnamectl",)),
                      mailname=ABSENT, postfix_main=ABSENT,
                      hosts=File(join(root, "etc/hosts"), "127.0.1.1 blog\n"))

        def failing(argv, **kwargs):
            return subprocess.CompletedProcess(
                argv, 1, "", "Failed to connect to bus\n")

        doc = {"instance": {"hostname": "news"}}
        with mock.patch.object(effects.subprocess, "run", side_effect=failing):
            outcome = execute(plan_all(doc, found), Effects(root), False,
                              "apply --system")
        self.assertTrue(outcome.failed)
        self.assertTrue(any("Failed to connect to bus" in line
                            for line in outcome.lines), outcome.lines)
        with open(join(root, "etc", "hostname")) as fob:
            self.assertEqual(fob.read(), "news\n")

        rerun = state(root=root, live=True, kernel_hostname="blog",
                      available=frozenset(("hostnamectl",)),
                      hostname=File(join(root, "etc/hostname"), "news\n"))
        steps, _ = plan_hostname({"hostname": "news"}, rerun)
        self.assertEqual(runs(steps), [("hostnamectl", "set-hostname", "news")])
