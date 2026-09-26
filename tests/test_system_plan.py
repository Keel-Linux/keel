# Copyright (c) 2026 KeelLinux maintainers
"""apply --system as pure functions: the state read from a tree, the plan

Every planner is exercised with a hand built SystemState and against
the fixture trees under tests/fixtures/inspect, one test per branch, so
that no test needs root, a shell or a live system.
"""

import subprocess
import unittest
from os.path import abspath, dirname, join
from unittest import mock

from helpers import spec  # noqa: F401

from keel.inspect.accounts import (
    Account,
    group_members,
    groups_of,
    home_of,
    passwd_entries,
)
from keel.inspect.tree import NOT_PRESENT, PERMISSION_DENIED, File
from keel.system import needs_root, observe, plan
from keel.system.actions import MakeDir, Note, Run, Symlink, WriteFile
from keel.system.locale import (
    charset_of,
    is_generated,
    modifier_of,
    plan_locale,
    with_lang,
)
from keel.system.state import SystemState, generated_locales, keys_path
from keel.system.users import plan_users

FIXTURES = join(dirname(abspath(__file__)), "fixtures", "inspect")
TURNKEY = join(FIXTURES, "turnkey")
MISSING = join(FIXTURES, "missing")
KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyMaterialOnly admin@blog"
ABSENT = File("/x/absent", problem=NOT_PRESENT)
PASSWD = File(
    "/x/etc/passwd",
    "root:x:0:0:root:/root:/bin/bash\n"
    "admin:x:1000:1000::/home/admin:/bin/sh\n",
)
GROUP = File("/x/etc/group", "root:x:0:\nadm:x:4:admin\nsudo:x:27:\n")


def state(**overrides) -> SystemState:
    """A scratch tree state with nothing in it, unless overridden"""
    values = dict(
        root="/x", live=False, passwd=ABSENT, group=ABSENT, key_files={},
        timezone=ABSENT, localtime_target=None, default_locale=ABSENT,
        locale_gen=ABSENT, generated=None, available=frozenset(),
    )
    values.update(overrides)
    return SystemState(**values)


def live(**overrides) -> SystemState:
    values = dict(root="/", live=True, passwd=PASSWD, group=GROUP,
                  available=frozenset(("useradd", "usermod", "timedatectl",
                                       "locale-gen", "localedef")))
    values.update(overrides)
    return state(**values)


def only(step):
    """The single action of a step"""
    assert len(step.actions) == 1, step
    return step.actions[0]


class TestAccounts(unittest.TestCase):
    def test_passwd_entries_skip_malformed_lines(self):
        text = "root:x:0:0:root:/root:/bin/bash\nshort:x:1\nbad:x:a:0::/h:/s\n"
        entries = passwd_entries(File("/x/etc/passwd", text))
        self.assertEqual(entries, {
            "root": Account("root", 0, 0, "/root", "/bin/bash"),
        })

    def test_group_members_and_groups_of(self):
        members = group_members(File("/x/etc/group",
                                     "adm:x:4:admin,bob\nshort:x:5\nx:x:6:\n"))
        self.assertEqual(members, {"adm": ("admin", "bob"), "x": ()})
        self.assertEqual(groups_of("bob", members), ["adm"])
        self.assertEqual(groups_of("root", members), [])

    def test_home_of_prefers_passwd_then_the_useradd_default(self):
        entries = passwd_entries(PASSWD)
        self.assertEqual(home_of("admin", entries), "/home/admin")
        self.assertEqual(home_of("root", {}), "/root")
        self.assertEqual(home_of("bob", {}), "/home/bob")
        self.assertEqual(keys_path("bob", {}), "home/bob/.ssh/authorized_keys")


class TestObserve(unittest.TestCase):
    def test_a_fixture_tree_is_read_offline_without_running_anything(self):
        doc = {"users": {"root": None, "admin": {"authorized_keys": [KEY]}}}
        with mock.patch.object(subprocess, "run") as run:
            found = observe(TURNKEY, doc)
        run.assert_not_called()
        self.assertFalse(found.live)
        self.assertEqual(found.root, TURNKEY)
        self.assertEqual(found.available, frozenset())
        self.assertIsNone(found.generated)
        self.assertEqual(sorted(found.key_files), ["admin", "root"])
        self.assertTrue(found.key_files["root"].readable)
        self.assertEqual(found.timezone.text, "Europe/Lisbon\n")
        self.assertIn("root", passwd_entries(found.passwd))

    def test_the_live_root_asks_for_commands_and_generated_locales(self):
        completed = subprocess.CompletedProcess(["locale", "-a"], 0,
                                                "C\nen_US.utf8\n", "")
        with mock.patch.object(subprocess, "run", return_value=completed), \
                mock.patch("shutil.which",
                           side_effect=lambda name: name == "useradd"):
            found = observe("/", {})
        self.assertTrue(found.live)
        self.assertEqual(found.generated, ("C", "en_US.utf8"))
        self.assertEqual(found.available, frozenset(("useradd",)))

    def test_generated_locales_is_none_when_locale_cannot_answer(self):
        failed = subprocess.CompletedProcess(["locale", "-a"], 1, "", "no")
        with mock.patch.object(subprocess, "run", return_value=failed):
            self.assertIsNone(generated_locales())
        with mock.patch.object(subprocess, "run",
                               side_effect=OSError(2, "not found")):
            self.assertIsNone(generated_locales())


class TestNeedsRoot(unittest.TestCase):
    def test_the_live_system_needs_root_and_a_scratch_tree_does_not(self):
        with mock.patch("os.geteuid", return_value=1000):
            refusal = needs_root("/")
            self.assertIn("must run as root", refusal)
            self.assertIn("uid 1000", refusal)
            self.assertIsNone(needs_root("/tmp/scratch"))
        with mock.patch("os.geteuid", return_value=0):
            self.assertIsNone(needs_root("/"))


class TestPlanUsers(unittest.TestCase):
    def test_an_absent_user_is_created_with_shell_and_groups(self):
        users = {"admin": {"shell": "/bin/bash", "groups": ["sudo", "adm"],
                           "authorized_keys": [KEY]}}
        steps = plan_users(users, state(root="/x"))
        self.assertEqual([step.field for step in steps],
                         ["users.admin", "users.admin.authorized_keys"])
        self.assertEqual(only(steps[0]), Run(
            ("useradd", "--root", "/x", "--create-home", "--shell",
             "/bin/bash", "--groups", "sudo,adm", "admin"),
            "create user admin",
        ))
        self.assertEqual(steps[1].actions, (
            MakeDir("home/admin/.ssh", 0o700, "admin",
                    "ensure /home/admin/.ssh"),
            WriteFile("home/admin/.ssh/authorized_keys", f"{KEY}\n", 0o600,
                      "admin", "write /home/admin/.ssh/authorized_keys with"
                      " 1 key(s)"),
        ))

    def test_a_bare_user_on_the_live_system_is_created_with_defaults(self):
        steps = plan_users({"bob": None}, live())
        self.assertEqual(only(steps[0]).argv,
                         ("useradd", "--create-home", "bob"))
        self.assertEqual(len(steps), 1)

    def test_an_existing_user_gets_its_shell_and_missing_groups(self):
        users = {"admin": {"shell": "/bin/bash", "groups": ["adm", "sudo"]}}
        step = plan_users(users, live())[0]
        self.assertEqual([action.argv for action in step.actions], [
            ("usermod", "--shell", "/bin/bash", "admin"),
            ("usermod", "--append", "--groups", "sudo", "admin"),
        ])

    def test_an_existing_user_that_matches_is_unchanged(self):
        users = {"admin": {"shell": "/bin/sh", "groups": ["adm"]},
                 "root": {}}
        steps = plan_users(users, live())
        self.assertEqual(only(steps[0]), Note("unchanged (exists, uid 1000)"))
        self.assertEqual(only(steps[1]), Note("unchanged (exists, uid 0)"))

    def test_an_unreadable_passwd_cannot_be_planned(self):
        denied = File("/x/etc/passwd", problem=PERMISSION_DENIED)
        step = plan_users({"root": None}, state(passwd=denied))[0]
        self.assertEqual(only(step), Note(
            "cannot plan: /x/etc/passwd permission denied (root only)"
        ))

    def test_matching_keys_are_unchanged_and_differing_keys_rewritten(self):
        current = File("/x/root/.ssh/authorized_keys", f"{KEY}\n")
        same = state(passwd=PASSWD, key_files={"root": current})
        step = plan_users({"root": {"authorized_keys": [KEY]}}, same)[1]
        self.assertEqual(only(step), Note(
            "unchanged (1 key(s) in /root/.ssh/authorized_keys)"
        ))
        step = plan_users({"root": {"authorized_keys": []}}, same)[1]
        self.assertEqual(step.actions[1].content, "")
        self.assertEqual(step.actions[1].summary,
                         "write /root/.ssh/authorized_keys with 0 key(s)")

    def test_a_keys_file_the_state_did_not_read_counts_as_absent(self):
        step = plan_users({"root": {"authorized_keys": [KEY]}},
                          state(passwd=PASSWD))[1]
        self.assertEqual(step.changes, 2)


class TestPlanLocale(unittest.TestCase):
    def test_a_matching_timezone_and_lang_are_unchanged(self):
        found = state(
            timezone=File("/x/etc/timezone", "Europe/Lisbon\n"),
            localtime_target="/usr/share/zoneinfo/Europe/Lisbon",
            default_locale=File("/x/etc/default/locale", "LANG=C.UTF-8\n"),
        )
        steps = plan_locale({"timezone": "Europe/Lisbon", "lang": "C.UTF-8"},
                            found)
        self.assertEqual([only(step) for step in steps], [
            Note("unchanged (Europe/Lisbon)"), Note("unchanged (C.UTF-8)"),
        ])

    def test_offline_timezone_writes_the_file_and_the_link(self):
        found = state(timezone=File("/x/etc/timezone", "Europe/Lisbon\n"),
                      localtime_target="/usr/share/zoneinfo/Etc/UTC")
        step = plan_locale({"timezone": "Europe/Lisbon"}, found)[0]
        self.assertEqual(step.actions, (
            WriteFile("etc/timezone", "Europe/Lisbon\n", 0o644, None,
                      "write /etc/timezone"),
            Symlink("etc/localtime", "/usr/share/zoneinfo/Europe/Lisbon",
                    "link /etc/localtime"),
        ))

    def test_live_timezone_goes_through_timedatectl_when_present(self):
        step = plan_locale({"timezone": "Etc/UTC"}, live())[0]
        self.assertEqual(only(step).argv,
                         ("timedatectl", "set-timezone", "Etc/UTC"))
        step = plan_locale({"timezone": "Etc/UTC"},
                           live(available=frozenset()))[0]
        self.assertIsInstance(step.actions[0], WriteFile)

    def test_lang_rewrites_the_default_locale_keeping_other_lines(self):
        current = File("/x/etc/default/locale",
                       "# generated\nLANG=C\nLANGUAGE=en_US\n")
        step = plan_locale({"lang": "C.UTF-8"},
                           state(default_locale=current))[0]
        self.assertEqual(only(step).content,
                         "# generated\nLANGUAGE=en_US\nLANG=C.UTF-8\n")
        self.assertEqual(with_lang(ABSENT, "C"), "LANG=C\n")

    def test_offline_lang_is_written_but_not_generated(self):
        step = plan_locale({"lang": "en_US.UTF-8"}, state())[0]
        self.assertEqual(step.actions[1],
                         Note("not generated: not the live system"))
        self.assertEqual(step.changes, 1)
        written = File("/x/etc/default/locale", "LANG=en_US.UTF-8\n")
        step = plan_locale({"lang": "en_US.UTF-8"},
                           state(default_locale=written))[0]
        self.assertEqual(only(step), Note(
            "unchanged (en_US.UTF-8); not generated: not the live system"
        ))

    def test_live_lang_already_generated_needs_only_the_file(self):
        found = live(generated=("C", "en_US.utf8"))
        step = plan_locale({"lang": "en_US.UTF-8"}, found)[0]
        self.assertEqual(len(step.actions), 1)
        self.assertIsInstance(step.actions[0], WriteFile)

    def test_live_lang_with_locale_gen_adds_the_entry_and_runs_it(self):
        commented = File("/x/etc/locale.gen", "# pt_PT.UTF-8 UTF-8\n")
        found = live(generated=("C",), locale_gen=commented)
        step = plan_locale({"lang": "pt_PT.UTF-8"}, found)[0]
        self.assertEqual([type(action) for action in step.actions],
                         [WriteFile, WriteFile, Run])
        self.assertEqual(step.actions[1].content,
                         "# pt_PT.UTF-8 UTF-8\npt_PT.UTF-8 UTF-8\n")
        self.assertEqual(step.actions[2].argv, ("locale-gen",))
        active = File("/x/etc/locale.gen", "pt_PT.UTF-8 UTF-8\n")
        listed = live(generated=("C",), locale_gen=active)
        step = plan_locale({"lang": "pt_PT.UTF-8"}, listed)[0]
        self.assertEqual([type(action) for action in step.actions],
                         [WriteFile, Run])

    def test_live_lang_without_locale_gen_uses_localedef(self):
        found = live(generated=(), available=frozenset(("localedef",)))
        step = plan_locale({"lang": "de_DE.UTF-8@euro"}, found)[0]
        self.assertEqual(step.actions[1].argv, (
            "localedef", "-i", "de_DE@euro", "-c", "-f", "UTF-8",
            "de_DE.UTF-8@euro",
        ))

    def test_live_lang_with_no_tool_or_no_charset_says_why(self):
        found = live(generated=(), available=frozenset())
        step = plan_locale({"lang": "en_US.UTF-8"}, found)[0]
        self.assertEqual(step.actions[1], Note(
            "not generated: neither locale-gen nor localedef found"
        ))
        step = plan_locale({"lang": "en_US"}, live(generated=()))[0]
        self.assertEqual(step.actions[1], Note(
            "not generated: the name has no charset"
        ))

    def test_lang_helpers(self):
        self.assertTrue(is_generated("en_US.UTF-8", ("en_US.utf8",)))
        self.assertFalse(is_generated("pt_PT.UTF-8", ("en_US.utf8",)))
        self.assertEqual(charset_of("en_US.UTF-8@euro"), "UTF-8")
        self.assertIsNone(charset_of("en_US."))
        self.assertEqual(modifier_of("de_DE.UTF-8@euro"), "@euro")
        self.assertEqual(modifier_of("de_DE.UTF-8"), "")


class TestPlan(unittest.TestCase):
    def test_the_plan_follows_spec_order_and_counts_changes(self):
        doc = {"users": {"root": {"authorized_keys": [KEY]}},
               "locale": {"timezone": "Etc/UTC"}}
        found = plan(doc, observe(MISSING, doc))
        self.assertEqual([step.field for step in found.steps], [
            "users.root", "users.root.authorized_keys", "locale.timezone",
        ])
        self.assertEqual(found.changes, 5)
        self.assertEqual(plan({"version": 1}, observe(MISSING, {})).steps, ())

    def test_describe_reads_as_one_line_each(self):
        self.assertEqual(
            Run(("useradd", "a b"), "create").describe(),
            "create (useradd 'a b')",
        )
        self.assertEqual(
            WriteFile("etc/x", "", 0o644, None, "write").describe(),
            "write (mode 0644)",
        )
        self.assertEqual(
            MakeDir("d", 0o700, "bob", "ensure").describe(),
            "ensure (mode 0700, owner bob)",
        )
        self.assertEqual(Symlink("l", "t", "link").describe(), "link (-> t)")


if __name__ == "__main__":
    unittest.main()
