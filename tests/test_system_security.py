# Copyright (c) 2026 KeelLinux maintainers
"""apply --system: security.alerts on a running machine (keel#35)

The planner is pure, so it is tested against SystemState values; the
round trip through the CLI, apply then inspect then diff on a scratch
tree, is in tests/test_apply_system_cli.py.
"""

import unittest

from helpers import spec  # noqa: F401

from keel.inspect.tree import NOT_PRESENT, PERMISSION_DENIED, File
from keel.system.actions import Note, Refuse, Run, WriteFile
from keel.system.security import plan_security
from keel.system.state import SystemState

ABSENT = File("/x/absent", problem=NOT_PRESENT)
EMAIL = "admin@example.org"
ALIASES = "etc/aliases"
CRON_APT = "etc/cron-apt/config"
CRON_APT_DEFAULT = (
    '# Configuration for cron-apt.\nMAILON="error"\nSYSLOGON="upgrade"\n'
)


def state(**overrides) -> SystemState:
    values = dict(
        root="/x", live=False, passwd=ABSENT, group=ABSENT, hosts=ABSENT,
        key_files={}, timezone=ABSENT, localtime_target=None,
        default_locale=ABSENT, locale_gen=ABSENT, generated=None,
        available=frozenset(),
        aliases=File("/x/etc/aliases", "postmaster:    root\n"),
        cron_apt_config=File("/x/etc/cron-apt/config", CRON_APT_DEFAULT),
    )
    values.update(overrides)
    return SystemState(**values)


def plan(alerts, found):
    return plan_security({"alerts": alerts}, found)


def written(step, path):
    return [a for a in step.actions
            if isinstance(a, WriteFile) and a.path == path]


class TestPlanSecurityAlerts(unittest.TestCase):
    def test_nothing_declared_plans_nothing(self):
        self.assertEqual(plan_security({}, state()), [])
        self.assertEqual(
            plan_security({"updates_at_first_boot": "force"}, state()), [])

    def test_an_address_adds_the_root_alias_and_mails_cron_apt_output(self):
        [step] = plan(EMAIL, state())
        self.assertEqual(step.field, "security.alerts")
        [aliases] = written(step, ALIASES)
        self.assertEqual(aliases.content,
                         f"postmaster:    root\nroot:    {EMAIL}\n")
        self.assertEqual(aliases.mode, 0o644)
        [cron] = written(step, CRON_APT)
        self.assertEqual(cron.content, (
            '# Configuration for cron-apt.\nMAILON="output"\n'
            'SYSLOGON="upgrade"\nMAILTO="root"\n'
        ))

    def test_a_converged_machine_is_unchanged(self):
        found = state(
            aliases=File("/x/etc/aliases", f"root:    {EMAIL}\n"),
            cron_apt_config=File("/x/etc/cron-apt/config",
                                 'MAILON="output"\nMAILTO="root"\n'),
        )
        [step] = plan(EMAIL, found)
        self.assertEqual(step.actions, (Note(f"unchanged ({EMAIL})"),))

    def test_another_address_replaces_the_root_alias_and_keeps_the_rest(self):
        found = state(aliases=File(
            "/x/etc/aliases",
            "# local\npostmaster:    root\nroot:    old@example.org\n"
            "www-data:    root\n",
        ))
        [aliases] = written(plan(EMAIL, found)[0], ALIASES)
        self.assertEqual(aliases.content, (
            "# local\npostmaster:    root\nroot:    admin@example.org\n"
            "www-data:    root\n"
        ))

    def test_two_root_lines_become_the_one_declared(self):
        found = state(aliases=File(
            "/x/etc/aliases",
            "root:    old@example.org\npostmaster:    root\nroot:    admin\n",
        ))
        [aliases] = written(plan(EMAIL, found)[0], ALIASES)
        self.assertEqual(aliases.content,
                         f"root:    {EMAIL}\npostmaster:    root\n")

    def test_cron_apt_duplicates_collapse_and_comments_are_kept(self):
        found = state(cron_apt_config=File(
            "/x/etc/cron-apt/config",
            '# MAILON="never"\nMAILON="error"\nMAILTO="root"\n'
            'MAILON="upgrade"\n',
        ))
        [cron] = written(plan(EMAIL, found)[0], CRON_APT)
        self.assertEqual(cron.content,
                         '# MAILON="never"\nMAILON="output"\nMAILTO="root"\n')

    def test_a_missing_aliases_file_is_created(self):
        [aliases] = written(plan(EMAIL, state(aliases=ABSENT))[0], ALIASES)
        self.assertEqual(aliases.content, f"root:    {EMAIL}\n")

    def test_an_unreadable_aliases_file_is_refused(self):
        found = state(aliases=File("/x/etc/aliases",
                                   problem=PERMISSION_DENIED))
        [step] = plan(EMAIL, found)
        self.assertIsInstance(step.actions[0], Refuse)
        self.assertIn("/x/etc/aliases", step.actions[0].summary)
        self.assertEqual(written(step, ALIASES), [])

    def test_the_live_system_rebuilds_the_aliases_database(self):
        found = state(root="/", live=True,
                      available=frozenset(("newaliases",)))
        runs = [a for a in plan(EMAIL, found)[0].actions
                if isinstance(a, Run)]
        self.assertEqual([r.argv for r in runs], [("newaliases",)])

    def test_a_live_system_without_newaliases_says_so(self):
        found = state(root="/", live=True)
        notes = [a.summary for a in plan(EMAIL, found)[0].actions
                 if isinstance(a, Note)]
        self.assertTrue(any("newaliases" in note for note in notes), notes)

    def test_a_scratch_tree_is_not_asked_to_rebuild_the_database(self):
        actions = plan(EMAIL, state())[0].actions
        self.assertFalse(any(isinstance(a, Run) for a in actions))
        self.assertTrue(any(isinstance(a, Note) and "not the live system"
                            in a.summary for a in actions))

    def test_without_cron_apt_only_the_alias_is_written(self):
        step = plan(EMAIL, state(cron_apt_config=ABSENT))[0]
        self.assertEqual(len(written(step, ALIASES)), 1)
        self.assertEqual(written(step, CRON_APT), [])
        self.assertTrue(any(isinstance(a, Note) and "cron-apt" in a.summary
                            for a in step.actions))

    def test_skip_removes_an_external_root_alias(self):
        found = state(aliases=File(
            "/x/etc/aliases", f"postmaster:    root\nroot:    {EMAIL}\n"))
        [step] = plan("skip", found)
        [aliases] = written(step, ALIASES)
        self.assertEqual(aliases.content, "postmaster:    root\n")
        self.assertEqual(written(step, CRON_APT), [])

    def test_skip_keeps_a_local_root_alias(self):
        found = state(aliases=File("/x/etc/aliases", "root:    admin\n"))
        self.assertEqual(plan("SKIP", found)[0].actions,
                         (Note("unchanged (skip)"),))

    def test_nothing_is_sent_to_the_turnkey_hub(self):
        for step in plan(EMAIL, state(root="/", live=True, available=frozenset(
                ("newaliases",)))):
            for action in step.actions:
                self.assertNotIn("hub.turnkeylinux.org", action.describe())
                self.assertNotIn("curl", action.describe())


if __name__ == "__main__":
    unittest.main()
