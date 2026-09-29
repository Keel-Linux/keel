# Copyright (c) 2026 KeelLinux maintainers
"""keel.conf for monit: the mounts it watches, the file, and reading it back

The renderer is pure, so every rule of decision 0021 is checked on its
output: warn and critical as two services, a reminder and a recovery on
every test, Mbit/s as bytes per second, minutes as cycles of the cycle
monit already runs at. The walk warn, critical, warn, ok is played
against the rendered file the way monit plays it, one state per service.
When a monit binary is at hand (on PATH, or named by KEEL_MONIT), the
rendered file is also given to `monit -t`.
"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from os.path import join

from helpers import spec  # noqa: F401

from keel.diff.compare import normalize
from keel.inspect.monitor import (
    NOTIFY_REASON,
    Cycle,
    monit_cycle,
    probe_monitor,
    read_services,
)
from keel.inspect.report import INFERRED, NOT_INFERRED
from keel.inspect.tree import File, Tree
from keel.monitor import settings
from keel.monitor.mounts import Mount, parse, real_filesystems, unescape
from keel.monitor.render import filesystem_names, render, slug
from keel.monitor.settings import effective

NOTIFY = ("/usr/bin/python3", "-B", "-m", "keel", "notify")
MINUTE = Cycle(60, "set daemon 60 in /etc/monit/monitrc")
DEBIAN = Cycle(120, "set daemon 120 in /etc/monit/monitrc")
# a Proxmox container on LVM thin storage, as its mountinfo reads, with a
# mount point, lxcfs and the host's bind mounts
CONTAINER = """\
1060 1030 253:7 / / rw,relatime master:1 - ext4 /dev/mapper/pve-vm--101--disk--0 rw,stripe=16
1061 1060 0:59 / /dev rw,relatime - tmpfs none rw,size=492k,mode=755,uid=100000
1062 1060 0:63 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
1063 1062 0:64 /proc/cpuinfo /proc/cpuinfo rw,nosuid,nodev,relatime - fuse.lxcfs lxcfs rw,user_id=0
1064 1060 0:65 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs ro
1065 1064 0:30 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw
1066 1060 253:8 / /var/lib/mysql rw,relatime - ext4 /dev/mapper/pve-vm--101--disk--1 rw
1067 1060 253:3 /images/101/hostname /etc/hostname rw,relatime - ext4 /dev/mapper/pve-root rw
1068 1060 0:70 / /run rw,nosuid,nodev - tmpfs tmpfs rw
1069 1060 0:71 / /srv/backup rw,relatime - nfs4 [2001:db8::9]:/backup rw
1070 1060 253:7 / /mnt/again rw,relatime - ext4 /dev/mapper/pve-vm--101--disk--0 rw
1071 1060 0:72 / /media/My\\040Disk rw,relatime - ext4 /dev/sdb1 rw
1072 1068 8:33 / /run/media/usb rw,relatime - ext4 /dev/sdc1 rw
1073 1060 8:49 / /srv/web+data=1~x rw,relatime - xfs /dev/sdd1 rw
1074 1060 8:50 / /srv/user@host rw,relatime - xfs /dev/sdd2 rw
1075 1060 8:51 / /srv/a:b rw,relatime - xfs /dev/sdd3 rw
1076 1060 0:80 / /mnt/s3 rw - fuse.s3fs s3fs rw
1077 1060 0:81 / /mnt/dav rw - davfs https://dav.example.org rw
"""
BTRFS = """\
28 1 0:26 /@ / rw,relatime - btrfs /dev/vda2 rw,subvol=/@
29 28 0:26 /@home /home rw,relatime - btrfs /dev/vda2 rw,subvol=/@home
30 28 254:1 / /boot rw,relatime - ext4 /dev/vda1 rw
malformed line without the separator
31 28 0:30 / /x rw - ext4
"""


def rendered(checks: dict | None = None, mounts=None, cycle: int = 60) -> (
    str
):
    return render(effective({"checks": checks or {}}),
                  mounts or [Mount("/", "ext4", "/dev/sda1")], NOTIFY, cycle)


def blocks(text: str) -> dict[str, str]:
    """Service name to its block, from a rendered file"""
    found = {}
    for block in text.split("\ncheck ")[1:]:
        found[block.split()[1]] = "check " + block
    return found


class TestMounts(unittest.TestCase):
    def test_a_container_keeps_its_own_filesystems_only(self):
        mounts, unsafe = real_filesystems(CONTAINER)
        self.assertEqual([m.path for m in mounts],
                         ["/", "/var/lib/mysql", "/srv/web+data=1~x"])
        self.assertEqual(mounts[0], Mount(
            "/", "ext4", "/dev/mapper/pve-vm--101--disk--0"))
        self.assertEqual(unsafe, ["/media/My Disk", "/srv/user@host",
                                  "/srv/a:b"])

    def test_every_pseudo_remote_and_fuse_type_is_left_out(self):
        lines = "".join(
            f"{n} 1 0:{n} / /data{n} rw - {fstype} src rw\n"
            for n, fstype in enumerate(sorted(
                ("proc", "sysfs", "tmpfs", "devtmpfs", "cgroup", "cgroup2",
                 "overlay", "squashfs", "fuse.lxcfs", "nfs", "cifs",
                 "iso9660", "erofs", "fuse.sshfs", "fuse.rclone", "davfs",
                 "9p", "ceph", "glusterfs")))
        )
        self.assertEqual(real_filesystems(lines), ([], []))
        self.assertEqual(len(real_filesystems(
            "1 0 8:1 / /win rw - fuseblk /dev/sda1 rw\n")[0]), 1)

    def test_a_device_skipped_for_its_name_is_watched_at_another(self):
        mounts, unsafe = real_filesystems(
            "1 0 8:1 / /my\\040disk rw - ext4 /dev/sdb1 rw\n"
            "2 0 8:1 / /srv/disk rw - ext4 /dev/sdb1 rw\n")
        self.assertEqual([m.path for m in mounts], ["/srv/disk"])
        self.assertEqual(unsafe, [])

    def test_btrfs_subvolumes_count_once_and_the_root_is_kept(self):
        mounts, _ = real_filesystems(BTRFS)
        self.assertEqual([(m.path, m.fstype) for m in mounts],
                         [("/", "btrfs"), ("/boot", "ext4")])

    def test_parse_skips_what_it_cannot_read(self):
        self.assertEqual(len(parse(BTRFS)), 3)

    def test_unescape(self):
        self.assertEqual(unescape(r"/media/My\040Disk\011x"),
                         "/media/My Disk\tx")


class TestSettings(unittest.TestCase):
    def test_defaults_are_the_decided_ones(self):
        found = effective({})
        self.assertEqual(found["disk"], {"warn": 80, "critical": 90})
        self.assertEqual(found["inodes"], {"critical": 90})
        self.assertEqual(found["memory"], {"warn": 85, "for_minutes": 5})
        self.assertEqual(found["swap"], {"warn": 50, "for_minutes": 5})
        self.assertEqual(found["cpu"], {"warn": 90, "for_minutes": 10})
        self.assertEqual(found["load_per_core"],
                         {"warn": 2, "for_minutes": 10})
        self.assertEqual(found["network"], {})

    def test_a_declared_value_replaces_its_default_only(self):
        found = effective({"checks": {"disk": {"warn": 70},
                                      "network": {"eth0": {"link": True}}}})
        self.assertEqual(found["disk"], {"warn": 70, "critical": 90})
        self.assertEqual(found["network"],
                         {"eth0": {"link": True, "for_minutes": 5}})

    def test_mbit_is_bytes_per_second_and_back(self):
        self.assertEqual(settings.bytes_per_second(800), 100_000_000)
        self.assertEqual(settings.bytes_per_second(1), 125_000)
        self.assertEqual(settings.bytes_per_second(0.5), 62_500)
        self.assertEqual(settings.mbit(100_000_000), 800.0)

    def test_minutes_and_cycles_at_the_machine_s_cycle(self):
        self.assertEqual(settings.cycles(5, 60), 5)
        self.assertEqual(settings.cycles(5, 120), 3)
        self.assertEqual(settings.cycles(1, 120), 1)
        self.assertEqual(settings.cycles(64, 60), settings.MAX_CYCLES)
        self.assertEqual(settings.minutes(3, 120), 6)
        self.assertEqual(settings.reminder(120), 30)
        self.assertEqual(settings.reminder(7200), 1)

    def test_too_long_is_counted_at_the_machine_s_cycle(self):
        checks = effective({"checks": {
            "cpu": {"for_minutes": 65},
            "network": {"eth0": {"link": True, "for_minutes": 200}}}})
        self.assertEqual(settings.too_long(checks, 120), [
            "monitor.checks.network.eth0.for_minutes: 200 minutes is 100"
            " cycles of 120 s, and monit holds a condition for at most 64"])
        self.assertEqual(len(settings.too_long(checks, 60)), 2)
        self.assertEqual(settings.too_long(effective({}), 30), [])

    def test_number(self):
        self.assertEqual(settings.number(2.0), "2")
        self.assertEqual(settings.number(1.5), "1.5")
        self.assertEqual(settings.number(0.00001), "0.00001")


class TestRender(unittest.TestCase):
    def test_the_file_is_keel_s_and_never_sets_the_cycle(self):
        text = rendered()
        self.assertTrue(text.startswith("# written by keel"))
        self.assertNotIn("set daemon", text)

    def test_warn_and_critical_are_two_services(self):
        found = blocks(rendered())
        self.assertEqual(sorted(found), [
            "keel_cpu", "keel_disk_critical_root", "keel_disk_warn_root",
            "keel_inodes_critical_root", "keel_load", "keel_memory",
            "keel_swap",
        ])
        warn = found["keel_disk_warn_root"]
        self.assertIn("check filesystem keel_disk_warn_root with path /\n",
                      warn)
        self.assertIn("if space usage > 80% then exec", warn)
        self.assertNotIn("90", warn)
        self.assertIn("if space usage > 90% then exec",
                      found["keel_disk_critical_root"])
        self.assertIn("if inode usage > 90% then exec",
                      found["keel_inodes_critical_root"])

    def test_every_test_has_a_reminder_and_a_recovery(self):
        text = rendered({"network": {"eth0": {"link": True,
                                              "max_mbit": 800}}}, cycle=120)
        tests = re.findall(r"^    if ", text, re.M)
        self.assertEqual(len(tests), 10)
        self.assertEqual(text.count("repeat every 30 cycles"), 10)
        self.assertEqual(text.count("else if succeeded then exec"), 10)
        self.assertEqual(text.count("--level recovery"), 10)

    def test_the_exec_line_is_keel_notify_with_no_spec_and_no_secret(self):
        found = blocks(rendered())["keel_disk_critical_root"]
        self.assertIn(
            'then exec "/usr/bin/python3 -B -m keel notify --level critical'
            ' --check disk --path / --threshold 90"', found)
        self.assertIn(
            'else if succeeded then exec "/usr/bin/python3 -B -m keel notify'
            ' --level recovery --check disk --path / --threshold 90"', found)
        self.assertNotIn("--spec", rendered())

    def test_system_checks_hold_for_their_minutes_at_the_cycle(self):
        found = blocks(rendered({"load_per_core": {"warn": 1.5,
                                                   "for_minutes": 3}}))
        self.assertIn("    # for_minutes: 5\n    if memory usage > 85% for"
                      " 5 cycles then exec", found["keel_memory"])
        self.assertIn("if swap usage > 50% for 5 cycles", found["keel_swap"])
        self.assertIn("if cpu usage > 90% for 10 cycles", found["keel_cpu"])
        self.assertIn("if loadavg (1min) per core > 1.5 for 3 cycles",
                      found["keel_load"])
        self.assertIn("--check load --threshold 1.5", found["keel_load"])
        slow = blocks(rendered(cycle=120))
        self.assertIn("if memory usage > 85% for 3 cycles",
                      slow["keel_memory"])
        self.assertIn("if cpu usage > 90% for 5 cycles", slow["keel_cpu"])

    def test_one_cycle_needs_no_for(self):
        found = blocks(rendered({"memory": {"for_minutes": 1}}, cycle=120))
        self.assertIn("if memory usage > 85% then exec", found["keel_memory"])

    def test_network_only_when_declared_in_bytes_per_second(self):
        self.assertNotIn("check network", rendered())
        found = blocks(rendered({"network": {
            "eth0": {"link": True, "max_mbit": 800, "for_minutes": 3},
            "br0.10": {"max_mbit": 100},
        }}))
        eth0 = found["keel_network_eth0"]
        self.assertIn("check network keel_network_eth0 with interface eth0",
                      eth0)
        self.assertIn("if failed link for 3 cycles then exec", eth0)
        self.assertIn("--level critical --check link --iface eth0\"", eth0)
        self.assertIn("if upload > 100000000 B/s for 3 cycles", eth0)
        self.assertIn("if download > 100000000 B/s for 3 cycles", eth0)
        vlan = found["keel_network_br0_10"]
        self.assertNotIn("link", vlan.split("\n", 1)[1])
        self.assertIn("if upload > 12500000 B/s for 5 cycles", vlan)

    def test_each_direction_is_told_its_own_recovery(self):
        eth0 = blocks(rendered({"network": {"eth0": {"max_mbit": 800}}}))[
            "keel_network_eth0"]
        for direction in ("upload", "download"):
            self.assertIn(
                f'else if succeeded then exec "/usr/bin/python3 -B -m keel'
                f' notify --level recovery --check throughput --iface eth0'
                f' --direction {direction} --threshold 800"', eth0)

    def test_one_block_per_filesystem_with_distinct_names(self):
        mounts = [Mount("/", "ext4", "a"), Mount("/var-lib", "ext4", "b"),
                  Mount("/var/lib", "ext4", "c")]
        self.assertEqual(filesystem_names(mounts), {
            "/": "root", "/var-lib": "var_lib", "/var/lib": "var_lib_2"})
        found = blocks(rendered(mounts=mounts))
        self.assertIn("keel_disk_warn_var_lib_2", found)
        self.assertIn("with path /var/lib\n",
                      found["keel_disk_warn_var_lib_2"])
        self.assertEqual(slug("/"), "root")


def walk(text: str, path: str, usages: list[float]) -> list[str]:
    """Play `usages` of `path` against the file as monit plays it

    Each service keeps its own state, so a service runs its exec when its
    own test fails and its recovery when its own test succeeds again;
    nothing is shared between services. Reminders are left out.
    """
    services = []
    for block in blocks(text).values():
        if f" with path {path}\n" not in block or "space usage" not in block:
            continue
        limit = float(re.search(r"space usage > ([0-9.]+)%", block)[1])
        fail, recover = re.findall(r'exec "([^"]+)"', block)
        services.append([limit, fail, recover, False])
    sent = []
    for usage in usages:
        for service in sorted(services):
            limit, fail, recover, failed = service
            if usage > limit and not failed:
                sent.append(fail)
                service[3] = True
            elif usage <= limit and failed:
                sent.append(recover)
                service[3] = False
    return [re.sub(r".* --level (\S+) .* --threshold (\S+)$", r"\1 \2", one)
            for one in sent]


class TestWarnCriticalWarnOk(unittest.TestCase):
    def test_each_level_fails_and_recovers_on_its_own(self):
        self.assertEqual(walk(rendered(), "/", [85, 95, 85, 50]), [
            "warn 80",
            "critical 90",
            "recovery 90",
            "recovery 80",
        ])

    def test_straight_to_critical_and_back_to_ok(self):
        self.assertEqual(walk(rendered(), "/", [50, 95, 50]), [
            "warn 80", "critical 90", "recovery 80", "recovery 90",
        ])


class TestCycle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        os.makedirs(join(self.root, "etc", "monit", "conf.d"))
        os.makedirs(join(self.root, "etc", "monit", "conf-enabled"))

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, relative: str, text: str) -> None:
        with open(join(self.root, relative), "w") as fob:
            fob.write(text)

    def test_the_last_set_daemon_monit_reads_wins_includes_in_place(self):
        self.write("etc/monit/monitrc",
                   "set daemon 120 with start delay 240\n"
                   "include /etc/monit/conf.d/*\n"
                   "include /etc/monit/conf-enabled/*\n")
        self.write("etc/monit/conf.d/a", "set daemon 30\n")
        self.write("etc/monit/conf.d/b", "# set daemon 5\ncheck system x\n")
        found = monit_cycle(Tree(self.root))
        self.assertEqual(found.seconds, 30)
        self.assertTrue(found.source.startswith("set daemon 30 in "))
        self.write("etc/monit/conf-enabled/z", "set daemon 90\n")
        self.assertEqual(monit_cycle(Tree(self.root)).seconds, 90)

    def test_no_set_daemon_is_debian_s(self):
        found = monit_cycle(Tree(self.root))
        self.assertEqual(found.seconds, settings.DEBIAN_CYCLE)
        self.assertIn("Debian's 120 s assumed", found.source)

    def test_includes_stop_at_a_depth(self):
        self.write("etc/monit/monitrc", "include /etc/monit/conf.d/*\n")
        self.write("etc/monit/conf.d/loop",
                   "set daemon 45\ninclude /etc/monit/conf.d/*\n")
        self.assertEqual(monit_cycle(Tree(self.root)).seconds, 45)


class TestReadBack(unittest.TestCase):
    def conf(self, text: str) -> File:
        return File("/etc/monit/conf.d/keel.conf", text)

    def test_absent_is_off(self):
        section, findings = probe_monitor(File("/x/keel.conf",
                                               problem="not present"),
                                          MINUTE)
        self.assertEqual(section, {"enabled": False})
        self.assertEqual(findings[0].line(),
                         "monitor.enabled: false (from /x/keel.conf not"
                         " present)")

    def test_unreadable_is_not_inferred(self):
        section, findings = probe_monitor(File(
            "/x/keel.conf", problem="permission denied (root only)"), MINUTE)
        self.assertIsNone(section)
        self.assertEqual(findings[0].status, NOT_INFERRED)

    def test_a_file_keel_did_not_write_says_nothing(self):
        section, findings = probe_monitor(self.conf("check system x\n"),
                                          MINUTE)
        self.assertIsNone(section)
        self.assertIn("not written by keel", findings[0].source)

    def test_what_was_rendered_is_read_back(self):
        declared = {"disk": {"warn": 70, "critical": 85},
                    "inodes": {"critical": 95},
                    "memory": {"warn": 80, "for_minutes": 3},
                    "load_per_core": {"warn": 1.5},
                    "network": {"eth0": {"link": True, "max_mbit": 800,
                                         "for_minutes": 2},
                                "eth1": {"max_mbit": 100}}}
        mounts = [Mount("/", "ext4", "a"), Mount("/srv", "xfs", "b")]
        for cycle in (MINUTE, DEBIAN, Cycle(45, "x")):
            section, findings = probe_monitor(
                self.conf(rendered(declared, mounts, cycle.seconds)), cycle)
            self.assertEqual(section, {"enabled": True, "checks": {
                "disk": {"warn": 70, "critical": 85},
                "inodes": {"critical": 95},
                "memory": {"warn": 80, "for_minutes": 3},
                "swap": {"warn": 50, "for_minutes": 5},
                "cpu": {"warn": 90, "for_minutes": 10},
                "load_per_core": {"warn": 1.5, "for_minutes": 10},
                "network": {
                    "eth0": {"link": True, "max_mbit": 800,
                             "for_minutes": 2},
                    "eth1": {"link": False, "max_mbit": 100,
                             "for_minutes": 5},
                },
            }}, cycle)
        self.assertEqual(findings[-1].field, "monitor.notify")
        self.assertEqual(findings[-1].source, NOTIFY_REASON)
        self.assertTrue(all(f.status == INFERRED for f in findings[:-1]))

    def test_minutes_the_cycles_no_longer_give_are_the_cycles_duration(self):
        text = rendered({"memory": {"for_minutes": 5}})
        section, _ = probe_monitor(self.conf(text), DEBIAN)
        self.assertEqual(section["checks"]["memory"]["for_minutes"], 10)
        section, _ = probe_monitor(self.conf(text.replace(
            "    # for_minutes: 5\n    if memory", "    if memory")), MINUTE)
        self.assertEqual(section["checks"]["memory"]["for_minutes"], 5)

    def test_filesystems_with_different_thresholds_are_not_inferred(self):
        text = rendered() + (
            "\ncheck filesystem keel_disk_warn_srv with path /srv\n"
            "    if space usage > 75% then exec \"x\"\n")
        section, findings = probe_monitor(self.conf(text), MINUTE)
        self.assertNotIn("warn", section["checks"]["disk"])
        found = [f for f in findings
                 if f.field == "monitor.checks.disk.warn"][0]
        self.assertEqual(found.status, NOT_INFERRED)
        self.assertIn("different thresholds (75, 80)", found.source)

    def test_lines_outside_a_service_are_ignored(self):
        self.assertEqual(read_services("if space usage > 5%\n"), [])

    def test_a_file_without_filesystems_has_no_disk_thresholds(self):
        text = "\n".join(line for line in rendered().split("\n\n")
                         if "check filesystem" not in line)
        section, _ = probe_monitor(self.conf(text), MINUTE)
        self.assertNotIn("disk", section["checks"])
        self.assertIn("memory", section["checks"])

    def test_thresholds_compare_as_numbers(self):
        self.assertEqual(normalize("monitor.checks.disk.warn", 80),
                         normalize("monitor.checks.disk.warn", "80.0"))
        self.assertEqual(normalize("monitor.checks.x", "high"), "high")
        self.assertEqual(normalize("monitor.checks.network.eth0.link", True),
                         "true")


def monit_binary() -> str | None:
    return os.environ.get("KEEL_MONIT") or shutil.which("monit")


@unittest.skipUnless(monit_binary(), "no monit binary (set KEEL_MONIT)")
class TestRealMonit(unittest.TestCase):
    """The rendered file, given to monit itself: its parser is the judge"""

    def check(self, text: str, extra: str = "") -> (
        subprocess.CompletedProcess
    ):
        with tempfile.TemporaryDirectory() as tmp:
            conf = os.path.join(tmp, "keel.conf")
            control = os.path.join(tmp, "monitrc")
            with open(conf, "w") as fob:
                fob.write(text)
            with open(control, "w") as fob:
                fob.write(f"set daemon 120 with start delay 240\n"
                          f"set idfile {tmp}/id\n"
                          f"set statefile {tmp}/state\ninclude {conf}\n")
            os.chmod(conf, 0o600)
            os.chmod(control, 0o600)
            return subprocess.run(
                [monit_binary(), "-t", "-c", control, *extra.split()],
                capture_output=True, text=True)

    def test_the_rendered_file_is_valid_monit(self):
        mounts, _ = real_filesystems(CONTAINER)
        out = self.check(rendered({
            "load_per_core": {"warn": 1.5, "for_minutes": 64},
            "network": {"lo": {"link": True, "max_mbit": 800,
                               "for_minutes": 3},
                        "br0.10": {"link": True},
                        "wg-ovl_0": {"max_mbit": 0.5}}}, mounts, 60))
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("Control file syntax OK", out.stdout + out.stderr)

    def test_the_operator_s_cycle_and_start_delay_are_left_alone(self):
        out = self.check(rendered(cycle=120), "-v")
        self.assertIn("Poll time          = 120 seconds with start delay"
                      " 240 seconds", out.stdout + out.stderr)

    def test_monit_refuses_65_cycles_as_the_plan_does(self):
        out = self.check(rendered().replace("for 10 cycles",
                                            "for 65 cycles"))
        self.assertNotEqual(out.returncode, 0)


if __name__ == "__main__":
    unittest.main()
