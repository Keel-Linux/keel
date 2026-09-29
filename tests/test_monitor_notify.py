# Copyright (c) 2026 KeelLinux maintainers
"""keel notify: the advice, the channels and the command (decision 0021)

The HTTPS channels are sent to a real server on the IPv6 loopback, with
a certificate made for ::1 in setUpClass and trusted through an explicit
context (or SSL_CERT_FILE, for the command), so TLS verification is the
one the code uses and nothing is mocked between keel and the socket. No
certificate is committed: it is made in a temporary directory each run.
"""

import contextlib
import http.server
import io
import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from os.path import join
from unittest import mock

from helpers import spec  # noqa: F401

from keel import exits
from keel.cli import main
from keel.monitor import advice, channels, notify
from keel.monitor.advice import Filesystem
from keel.spec.errors import SpecError

TOKEN = "123456789:SECRET-token-that-must-never-show"
PROXIES = ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY",
           "all_proxy", "ALL_PROXY")
MONIT_ENV = {
    "MONIT_SERVICE": "keel_disk_critical_root",
    "MONIT_EVENT": "Resource limit matched",
    "MONIT_DESCRIPTION":
        "space usage 92.3% matches resource limit [space usage > 90.0%]",
}


def no_proxy():
    """The test server is on ::1; a proxy from the environment is not"""
    clean = {key: value for key, value in os.environ.items()
             if key not in PROXIES}
    return mock.patch.dict(os.environ, clean, clear=True)


def probe_from(outputs: dict[str, str | None]):
    """A Probe answering by the command's name, and recording what ran"""
    ran = []

    def probe(argv):
        ran.append(argv)
        return outputs.get(argv[0])
    probe.ran = ran
    return probe


class Recorder(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.server.requests.append((self.path, dict(self.headers), body))
        if "moved" in self.path:
            self.send_response(301)
            self.send_header("Location", "http://[::1]:9/stolen")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        status = 500 if "fail" in self.path else 200
        self.send_response(status)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


class HttpsServer(http.server.ThreadingHTTPServer):
    """HTTPS on [::1] from a thread, recording every POST"""

    address_family = socket.AF_INET6

    def __init__(self, cert: str, key: str):
        super().__init__(("::1", 0), Recorder)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self.socket = context.wrap_socket(self.socket, server_side=True)
        self.requests: list = []
        self.thread = threading.Thread(target=self.serve_forever,
                                       daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"https://[::1]:{self.server_address[1]}"

    def close(self) -> None:
        self.shutdown()
        self.server_close()
        self.thread.join()


class TestAdvice(unittest.TestCase):
    def test_virtualisation(self):
        self.assertEqual(advice.virtualisation(probe_from(
            {"systemd-detect-virt": "lxc\n"})), "container")
        self.assertEqual(advice.virtualisation(probe_from(
            {"systemd-detect-virt": "kvm\n"})), "vm")
        self.assertEqual(advice.virtualisation(probe_from(
            {"systemd-detect-virt": "none\n"})), "none")
        self.assertEqual(advice.virtualisation(probe_from({})), "unknown")

    def test_filesystem_from_findmnt(self):
        probe = probe_from({"findmnt": 'TARGET="/" SOURCE="/dev/vda1"'
                            ' FSTYPE="ext4"\n'})
        self.assertEqual(advice.filesystem("/var/log", probe),
                         Filesystem("/", "/dev/vda1", "ext4"))
        self.assertEqual(probe.ran[0][-2:], ("-T", "/var/log"))
        self.assertIsNone(advice.filesystem("/", probe_from({})))
        self.assertIsNone(advice.filesystem("/", probe_from(
            {"findmnt": "garbage\n"})))

    def test_physical_volume(self):
        probe = probe_from({"lvs": "  vg0\n", "pvs": "  /dev/vda3\n"})
        self.assertEqual(advice.physical_volume("/dev/mapper/vg0-root",
                                                probe), "/dev/vda3")
        self.assertIsNone(advice.physical_volume("/dev/vda1",
                                                 probe_from({"lvs": " \n"})))
        self.assertIsNone(advice.physical_volume("rpool/data", probe))
        self.assertEqual(advice.physical_volume(
            "/dev/mapper/vg0-root", probe_from({"lvs": "vg0\n"})), "")

    def test_partition(self):
        self.assertEqual(advice.partition("/dev/sda3"), ("/dev/sda", "3"))
        self.assertEqual(advice.partition("/dev/vda1"), ("/dev/vda", "1"))
        self.assertEqual(advice.partition("/dev/nvme0n1p2"),
                         ("/dev/nvme0n1", "2"))
        self.assertIsNone(advice.partition("/dev/vdb"))
        self.assertIsNone(advice.partition("/dev/mapper/vg0-root"))

    def test_in_guest_steps_are_chosen_from_the_layout(self):
        ext4 = Filesystem("/", "/dev/vda1", "ext4")
        xfs = Filesystem("/srv", "/dev/sdb2", "xfs")
        lvm = Filesystem("/", "/dev/mapper/vg0-root", "ext4")
        whole = Filesystem("/data", "/dev/vdb", "ext4")
        btrfs = Filesystem("/", "/dev/vda2", "btrfs")
        zfs = Filesystem("/", "rpool/ROOT", "zfs")
        self.assertEqual(advice.grow_here(ext4, None),
                         ["growpart /dev/vda 1", "resize2fs /dev/vda1"])
        self.assertEqual(advice.grow_here(xfs, None),
                         ["growpart /dev/sdb 2", "xfs_growfs /srv"])
        self.assertEqual(advice.grow_here(lvm, "/dev/vda3"), [
            "growpart /dev/vda 3", "pvresize /dev/vda3",
            "lvextend -r -l +100%FREE /dev/mapper/vg0-root"])
        self.assertEqual(advice.grow_here(lvm, ""), [
            "pvresize <physical volume>",
            "lvextend -r -l +100%FREE /dev/mapper/vg0-root"])
        self.assertEqual(advice.grow_here(whole, None),
                         ["resize2fs /dev/vdb"])
        self.assertEqual(advice.grow_here(btrfs, None), [
            "growpart /dev/vda 2", "btrfs filesystem resize max /"])
        self.assertEqual(advice.grow_here(zfs, None), [
            "grow the zfs filesystem on rpool/ROOT with its own tool"])

    def test_a_container_grows_on_the_host_only(self):
        found = advice.disk_steps("/", "container", None, None)
        self.assertEqual(found[1], "  host (for example Proxmox, container):"
                         " pct resize <vmid> rootfs +10G")
        self.assertEqual(found[2], "  here: nothing more")
        found = advice.disk_steps("/var/lib/mysql", "container", Filesystem(
            "/var/lib/mysql", "/dev/mapper/x", "ext4"), None)
        self.assertIn("pct resize <vmid> <mpN of /var/lib/mysql> +10G",
                      found[1])

    def test_a_vm_bare_metal_and_the_unknown(self):
        ext4 = Filesystem("/", "/dev/vda1", "ext4")
        vm = advice.disk_steps("/", "vm", ext4, None)
        self.assertIn("qm resize <vmid> <disk> +10G", vm[1])
        self.assertEqual(vm[2], "  here: growpart /dev/vda 1; resize2fs"
                         " /dev/vda1")
        self.assertIn("not virtualised",
                      advice.disk_steps("/", "none", ext4, None)[1])
        unknown = advice.disk_steps("/", "unknown", None, None)
        self.assertIn("for a VM, pct resize <vmid> rootfs +10G for a"
                      " container", unknown[1])
        self.assertIn("findmnt -T / names the device", unknown[2])

    def test_steps_for_every_check(self):
        probe = probe_from({
            "systemd-detect-virt": "kvm\n",
            "findmnt": 'TARGET="/" SOURCE="/dev/vda1" FSTYPE="xfs"\n',
            "lvs": "",
        })
        disk = advice.steps("disk", "/", "90", probe)
        self.assertIn("  here: growpart /dev/vda 1; xfs_growfs /", disk)
        inodes = advice.steps("inodes", "/", "90", probe)
        self.assertIn("du --inodes -x --max-depth=2 /", inodes[1])
        self.assertEqual(inodes[3:], disk)
        self.assertIn("qm set <vmid> --memory <MiB>",
                      advice.steps("memory", "", "85", probe)[1])
        self.assertIn("qm set <vmid> --memory <MiB>",
                      advice.steps("swap", "", "50", probe)[1])
        self.assertIn("qm set <vmid> --cores <N>",
                      advice.steps("load", "", "2", probe)[1])
        lxc = probe_from({"systemd-detect-virt": "lxc\n"})
        self.assertIn("pct set <vmid> --swap <MiB>",
                      advice.steps("swap", "", "50", lxc)[1])
        self.assertIn("pct set <vmid> --cores <N>",
                      advice.steps("cpu", "", "90", lxc)[1])
        self.assertIn("The link of eth0 is down",
                      advice.steps("link", "eth0", "", probe)[0])
        self.assertIn("more than 800 Mbit/s",
                      advice.steps("throughput", "eth0", "800", probe)[0])

    def test_largest_directories_are_bounded_leaves(self):
        du = ("18874368\t/var/lib/mysql\n19000000\t/var/lib\n"
              "4300000\t/var/log\n23500000\t/var\n100\t/etc\n"
              "50\t/opt/x\n60\t/opt\n24000000\t/\n")
        found = advice.largest_directories("/", probe_from({"du": du}))
        self.assertEqual(found, "/var/lib/mysql 18G, /var/log 4.1G,"
                         " /etc 100K")
        self.assertIsNone(advice.largest_directories("/", probe_from({})))
        self.assertIsNone(advice.largest_directories(
            "/", probe_from({"du": "24000000\t/\n"})))

    def test_largest_processes(self):
        ps = "1258291 mariadbd\n 307200 php-fpm8.4\n  1024 cron\n 9 x\n"
        self.assertEqual(
            advice.largest_processes("memory", probe_from({"ps": ps})),
            "mariadbd 1.2G, php-fpm8.4 300M, cron 1.0M")
        cpu = probe_from({"ps": " 97.5 ffmpeg\n  1.0 sshd\nbroken\n"})
        self.assertEqual(advice.largest_processes("cpu", cpu),
                         "ffmpeg 97.5%, sshd 1.0%")
        self.assertEqual(cpu.ran[0], ("ps", "-eo", "pcpu=,comm=",
                                      "--sort=-pcpu"))
        self.assertIsNone(advice.largest_processes("load", probe_from({})))
        self.assertIsNone(advice.largest_processes(
            "cpu", probe_from({"ps": "broken\n"})))

    def test_human(self):
        self.assertEqual(advice.human(512), "512K")
        self.assertEqual(advice.human(4300000), "4.1G")
        self.assertEqual(advice.human(5 * 1024 ** 3), "5.0T")
        self.assertEqual(advice.human(20 * 1024 ** 4), "20480T")


class TestMessage(unittest.TestCase):
    PROBE = {
        "systemd-detect-virt": "lxc\n",
        "findmnt": 'TARGET="/" SOURCE="/dev/mapper/pve-vm--1" FSTYPE="ext4"\n',
        "du": "18874368\t/var/lib/mysql\n4300000\t/var/log\n",
        "ps": "1258291 mariadbd\n",
    }

    def event(self, level="critical", check="disk", target="/",
              threshold="90", environ=None):
        return notify.event_from(level, check, target, threshold,
                                 MONIT_ENV if environ is None else environ)

    def test_the_decision_example(self):
        message = notify.compose(self.event(), "blog", "2001:db8:1::10",
                                 True, probe_from(self.PROBE))
        self.assertEqual(message.text.splitlines()[:5], [
            "blog (2001:db8:1::10): / is 92.3% full (critical at 90%).",
            "Grow the disk on the host; the container sees the new size:",
            "  host (for example Proxmox, container): pct resize <vmid>"
            " rootfs +10G",
            "  here: nothing more",
            "Largest directories: /var/lib/mysql 18G, /var/log 4.1G.",
        ])
        self.assertEqual(message.title, "[critical] blog: disk /")
        self.assertEqual(message.fields, {
            "host": "blog", "address": "2001:db8:1::10", "check": "disk",
            "target": "/", "value": "92.3", "threshold": "90",
            "level": "critical", "service": "keel_disk_critical_root",
            "event": "Resource limit matched",
        })

    def test_details_false_leaves_the_directories_out(self):
        probe = probe_from(self.PROBE)
        message = notify.compose(self.event(), "blog", "", False, probe)
        self.assertNotIn("Largest", message.text)
        self.assertNotIn("du", [argv[0] for argv in probe.ran])
        self.assertTrue(message.text.startswith("blog: / is"))

    def test_a_recovery_says_so_and_gives_no_advice(self):
        message = notify.compose(
            self.event("recovery", environ={}), "blog", "", True,
            probe_from(self.PROBE))
        self.assertEqual(message.text, "blog: / is back under 90% full.")

    def test_headlines(self):
        cases = [
            (("warn", "inodes", "/srv", "90"),
             {"MONIT_DESCRIPTION": "inode usage 91% matches"},
             "/srv is 91% of its inodes used (warn at 90%)."),
            (("warn", "disk", "/", "80"), {},
             "/ is over the threshold full (warn at 80%)."),
            (("critical", "link", "eth0", ""), {},
             "the link of eth0 is down."),
            (("recovery", "link", "eth0", ""), {},
             "the link of eth0 is up again."),
            (("warn", "throughput", "eth0", "800"), {},
             "eth0 carries more than 800 Mbit/s."),
            (("recovery", "throughput", "eth0", "800"), {},
             "eth0 is back under 800 Mbit/s."),
            (("warn", "memory", "", "85"),
             {"MONIT_DESCRIPTION": "mem usage of 88.1% matches"},
             "memory is at 88.1% (warn at 85%)."),
            (("warn", "load", "", "2"),
             {"MONIT_DESCRIPTION": "loadavg (1min) per core of 2.7 matches"},
             "the load per core is at 2.7 (warn at 2)."),
            (("warn", "cpu", "", "90"), {},
             "CPU is at over the threshold (warn at 90%)."),
            (("recovery", "swap", "", "50"), {},
             "swap is back under 50%."),
        ]
        for args, environ, expected in cases:
            event = notify.event_from(*args, environ)
            self.assertEqual(notify.headline(event), expected, args)

    def test_process_details_for_memory_and_none_for_the_network(self):
        memory = notify.compose(self.event("warn", "memory", "", "85"),
                                "blog", "", True, probe_from(self.PROBE))
        self.assertIn("Largest processes: mariadbd 1.2G.", memory.text)
        link = notify.compose(self.event("critical", "link", "eth0", ""),
                              "blog", "", True, probe_from({}))
        self.assertNotIn("Largest", link.text)
        empty = notify.compose(self.event("warn", "memory", "", "85"),
                               "blog", "", True, probe_from({}))
        self.assertNotIn("Largest", empty.text)
        disk = notify.compose(self.event(), "blog", "", True,
                              probe_from({}))
        self.assertNotIn("Largest", disk.text)

    def test_the_address_is_the_first_static_one_ipv6_first(self):
        doc = {"network": {"interfaces": {
            "eth0": {"ipv4": {"method": "static",
                              "address": "192.0.2.10/24"},
                     "ipv6": {"method": "auto"}},
            "eth1": {"ipv6": {"method": "static",
                              "address": "2001:db8:1::10/64"}},
        }}}
        self.assertEqual(notify.address_of(doc), "2001:db8:1::10")
        del doc["network"]["interfaces"]["eth1"]
        self.assertEqual(notify.address_of(doc), "192.0.2.10")
        self.assertEqual(notify.address_of({}), "")

    def test_run_probe(self):
        self.assertEqual(notify.run_probe(("printf", "x")), "x")
        self.assertIsNone(notify.run_probe(("false",)))
        self.assertIsNone(notify.run_probe(("/nonexistent/command",)))
        with mock.patch.object(notify.subprocess, "run",
                               side_effect=subprocess.TimeoutExpired("du", 1)):
            self.assertIsNone(notify.run_probe(("du", "/")))
        with mock.patch.object(notify.subprocess, "run", return_value=(
                subprocess.CompletedProcess(["du"], 1, "5\t/x\n", ""))) as run:
            self.assertEqual(notify.run_probe(("du", "/")), "5\t/x\n")
        self.assertEqual(run.call_args.kwargs["timeout"], advice.DU_TIMEOUT)


@unittest.skipUnless(shutil.which("openssl"), "openssl is needed for a CA")
class ChannelTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.cert = join(cls.tmp, "cert.pem")
        key = join(cls.tmp, "key.pem")
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
            "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", key,
            "-out", cls.cert, "-days", "1", "-subj", "/CN=keel-test",
            "-addext", "subjectAltName=IP:::1",
        ], check=True, capture_output=True)
        cls.server = HttpsServer(cls.cert, key)
        cls.context = ssl.create_default_context(cafile=cls.cert)

    @classmethod
    def tearDownClass(cls):
        cls.server.close()
        shutil.rmtree(cls.tmp)

    def setUp(self):
        self.server.requests.clear()
        patcher = no_proxy()
        patcher.start()
        self.addCleanup(patcher.stop)
        self.token_file = join(self.tmp, "token")
        with open(self.token_file, "w") as fob:
            fob.write(f"{TOKEN}\n")
        os.chmod(self.token_file, 0o600)

    def doc(self, **notify_section) -> dict:
        return {"version": 1, "security": {"alerts": "admin@example.org"},
                "monitor": {"enabled": True, "notify": notify_section}}

    def message(self) -> notify.Message:
        return notify.Message("[critical] blog: disk /", "blog: / is full",
                              {"host": "blog", "check": "disk",
                               "value": "92", "threshold": "90",
                               "level": "critical"})


class TestChannels(ChannelTestCase):
    def test_telegram_sends_the_text_to_its_chat(self):
        channels.telegram("-100123", TOKEN, "x" * 5000, self.context,
                          self.server.url)
        path, headers, body = self.server.requests[0]
        self.assertEqual(path, f"/bot{TOKEN}/sendMessage")
        sent = json.loads(body)
        self.assertEqual(sent["chat_id"], "-100123")
        self.assertEqual(len(sent["text"]), channels.TELEGRAM_LIMIT)
        self.assertEqual(headers["Content-Type"], "application/json")

    def test_ntfy_with_and_without_a_token(self):
        channels.ntfy(f"{self.server.url}/keel", TOKEN, "[warn] blög", "warn",
                      "text", self.context)
        channels.ntfy(f"{self.server.url}/keel", None, "t", "critical",
                      "text", self.context)
        (path, first, body), (_, second, _) = self.server.requests
        self.assertEqual(path, "/keel")
        self.assertEqual(body, b"text")
        self.assertEqual(first["Authorization"], f"Bearer {TOKEN}")
        self.assertEqual(first["Title"], "[warn] bl?g")
        self.assertEqual(first["Priority"], "default")
        self.assertNotIn("Authorization", second)
        self.assertEqual(second["Priority"], "high")

    def test_webhook_is_slack_compatible_with_fields(self):
        channels.webhook(f"{self.server.url}/hook", {"text": "hi",
                                                     "level": "warn"},
                         self.context)
        self.assertEqual(json.loads(self.server.requests[0][2]),
                         {"text": "hi", "level": "warn"})

    def test_an_http_error_says_its_status_and_not_the_url(self):
        with self.assertRaises(channels.ChannelError) as caught:
            channels.telegram("1", f"fail{TOKEN}", "x", self.context,
                              self.server.url)
        self.assertEqual(str(caught.exception), "answered HTTP 500")
        self.assertIsNone(caught.exception.__cause__)
        self.assertTrue(caught.exception.__suppress_context__)

    def test_a_redirect_is_never_followed_with_the_token(self):
        with self.assertRaises(channels.ChannelError) as caught:
            channels.ntfy(f"{self.server.url}/moved", TOKEN, "t", "warn",
                          "text", self.context)
        self.assertEqual(str(caught.exception), "answered HTTP 301")
        self.assertEqual([path for path, _, _ in self.server.requests],
                         ["/moved"])

    def test_an_untrusted_certificate_is_refused(self):
        with self.assertRaises(channels.ChannelError) as caught:
            channels.webhook(f"{self.server.url}/hook", {},
                             ssl.create_default_context())
        self.assertIn("TLS: CERTIFICATE_VERIFY_FAILED", str(caught.exception))
        self.assertEqual(self.server.requests, [])

    def test_a_closed_port_says_why_and_not_where(self):
        with socket.socket(socket.AF_INET6) as probe:
            probe.bind(("::1", 0))
            port = probe.getsockname()[1]
        with self.assertRaises(channels.ChannelError) as caught:
            channels.telegram("1", TOKEN, "x", self.context,
                              f"https://[::1]:{port}")
        self.assertEqual(str(caught.exception),
                         "not reached: Connection refused")

    def test_other_failures_are_named_by_their_kind(self):
        self.assertEqual(channels.reason(ValueError("https://x/bot1")),
                         "ValueError")
        self.assertEqual(channels.reason("timed out"), "timed out")
        opener = mock.Mock()
        opener.open.side_effect = ValueError("unknown url type")
        with mock.patch.object(channels.urllib.request, "build_opener",
                               return_value=opener):
            with self.assertRaises(channels.ChannelError) as caught:
                channels.webhook("https://example.org/x", {})
        self.assertEqual(str(caught.exception), "not reached: ValueError")


class TestSend(ChannelTestCase):
    def test_every_channel_is_tried_and_one_failure_stops_none(self):
        sendmail = join(self.tmp, "sendmail")
        with open(sendmail, "w") as fob:
            fob.write('#!/bin/sh\ncat > "$0.out"\n')
        os.chmod(sendmail, 0o700)
        doc = self.doc(
            email=True,
            telegram={"chat_id": "-1", "token": {"file": self.token_file}},
            ntfy={"url": f"{self.server.url}/fail",
                  "token": {"file": self.token_file}},
            webhook={"url": f"{self.server.url}/hook"},
        )
        found = notify.send(doc, self.message(), "critical", self.context,
                            self.server.url, sendmail)
        self.assertEqual([d.line() for d in found], [
            "email: sent", "telegram: sent",
            "ntfy: failed: answered HTTP 500", "webhook: sent",
        ])
        with open(f"{sendmail}.out") as fob:
            mail = fob.read()
        self.assertIn("To: admin@example.org", mail)
        self.assertIn("Subject: [critical] blog: disk /", mail)
        hook = json.loads(self.server.requests[-1][2])
        self.assertEqual(hook["text"],
                         "[critical] blog: disk /\nblog: / is full")
        self.assertEqual(hook["threshold"], "90")

    def test_a_token_that_cannot_be_read_fails_its_channel_only(self):
        doc = self.doc(
            telegram={"chat_id": "-1", "token": {"file": "/nonexistent/t"}},
            webhook={"url": f"{self.server.url}/hook"},
        )
        found = notify.send(doc, self.message(), "warn", self.context,
                            self.server.url)
        self.assertEqual([d.line() for d in found], [
            "telegram: failed: /nonexistent/t: secret file not found",
            "webhook: sent",
        ])

    def test_a_token_file_that_is_not_text_fails_its_channel_only(self):
        binary = join(self.tmp, "binary-token")
        with open(binary, "wb") as fob:
            fob.write(b"\xff\xfe" + TOKEN.encode())
        os.chmod(binary, 0o600)
        doc = self.doc(
            telegram={"chat_id": "-1", "token": {"file": binary}},
            webhook={"url": f"{self.server.url}/hook"},
        )
        found = notify.send(doc, self.message(), "warn", self.context,
                            self.server.url)
        self.assertEqual([d.line() for d in found], [
            "telegram: failed: UnicodeDecodeError", "webhook: sent"])

    def test_no_channel_is_no_delivery(self):
        self.assertEqual(notify.send({"version": 1}, self.message(), "warn"),
                         [])

    def test_the_token_never_shows_in_what_is_said(self):
        doc = self.doc(telegram={"chat_id": "-1",
                                 "token": {"file": self.token_file}})
        for api in (f"{self.server.url}/fail", "https://[::1]:1"):
            found = notify.send(doc, self.message(), "warn", self.context,
                                api)
            self.assertTrue(found[0].problem)
            self.assertNotIn(TOKEN, found[0].line())
            self.assertNotIn("SECRET", found[0].line())

    def test_whatever_the_words_a_read_token_is_masked(self):
        doc = self.doc(ntfy={"url": "https://ntfy.example.org/k",
                             "token": {"file": self.token_file}})
        leak = channels.ChannelError(f"the server said {TOKEN}")
        with mock.patch.object(channels, "post", side_effect=leak):
            found = notify.send(doc, self.message(), "warn")
        self.assertEqual(found[0].line(),
                         "ntfy: failed: the server said [masked]")
        self.assertEqual(notify.masked("a", ["", "b"]), "a")


class TestEmail(unittest.TestCase):
    def test_a_failing_or_missing_sendmail_is_a_channel_error(self):
        with self.assertRaises(channels.ChannelError) as caught:
            channels.email("a@example.org", "s", "t", "/bin/false")
        self.assertEqual(str(caught.exception), "/bin/false exited 1: ")
        with self.assertRaises(channels.ChannelError) as caught:
            channels.email("a@example.org", "s", "t", "/nonexistent/sendmail")
        self.assertIn("cannot run /nonexistent/sendmail", str(caught.exception))
        with mock.patch.object(channels.subprocess, "run",
                               side_effect=subprocess.TimeoutExpired("x", 1)):
            with self.assertRaises(channels.ChannelError) as caught:
                channels.email("a@example.org", "s", "t")
        self.assertIn("took longer than 30 s", str(caught.exception))

    def test_a_secret_error_is_a_failed_channel(self):
        doc = {"monitor": {"notify": {"telegram": {
            "chat_id": 1, "token": {"file": "/x"}}}}}
        found = notify.send(doc, notify.Message("t", "x", {}), "warn",
                            secret=mock.Mock(side_effect=SpecError("gone")))
        self.assertEqual(found[0].line(), "telegram: failed: gone")


def run_cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class TestCommand(ChannelTestCase):
    def write_spec(self, notify_section: str) -> str:
        path = join(self.tmp, "instance.yaml")
        with open(path, "w") as fob:
            fob.write(
                "version: 1\n"
                "security:\n  alerts: admin@example.org\n"
                "monitor:\n  enabled: true\n  notify:\n" + notify_section)
        return path

    def notify(self, spec_path: str, *extra: str) -> tuple[int, str, str]:
        """keel notify as monit runs it; Telegram is the local server too"""
        environ = dict(os.environ, SSL_CERT_FILE=self.cert, **MONIT_ENV)
        with mock.patch.dict(os.environ, environ, clear=True), \
                mock.patch.object(channels, "TELEGRAM_API",
                                  f"{self.server.url}/fail"):
            return run_cli("notify", "--spec", spec_path, "--level",
                           "critical", "--check", "disk", "--path",
                           self.tmp, "--threshold", "90", *extra)

    def test_monit_s_event_reaches_every_channel(self):
        path = self.write_spec(
            f"    ntfy:\n      url: {self.server.url}/keel\n"
            f"      token: {{file: {self.token_file}}}\n"
            f"    webhook:\n      url: {self.server.url}/hook\n"
            "    details: true\n")
        os.makedirs(join(self.tmp, "data"), exist_ok=True)
        with open(join(self.tmp, "data", "blob"), "w") as fob:
            fob.write("x" * 8192)
        code, out, err = self.notify(path)
        self.assertEqual((code, err), (exits.OK, ""))
        self.assertEqual(out, "ntfy: sent\nwebhook: sent\n")
        ntfy_request, hook_request = self.server.requests
        text = ntfy_request[2].decode()
        self.assertIn(f"{self.tmp} is 92.3% full (critical at 90%).", text)
        self.assertIn("monit: space usage 92.3% matches", text)
        self.assertIn("Largest directories", text)
        self.assertEqual(ntfy_request[1]["Authorization"], f"Bearer {TOKEN}")
        hook = json.loads(hook_request[2])
        self.assertEqual((hook["check"], hook["level"], hook["value"]),
                         ("disk", "critical", "92.3"))

    def test_every_channel_failing_exits_22_and_hides_the_token(self):
        path = self.write_spec(
            "    telegram:\n      chat_id: '-1'\n"
            f"      token: {{file: {self.token_file}}}\n"
            f"    webhook:\n      url: {self.server.url}/fail\n")
        code, out, err = self.notify(path)
        self.assertEqual(code, exits.NOTIFY_FAILED)
        self.assertEqual(out, "")
        self.assertIn("Error: webhook: failed: answered HTTP 500", err)
        self.assertIn("Error: telegram: failed:", err)
        self.assertNotIn(TOKEN, out + err)

    def test_no_spec_no_channel_and_a_bad_spec(self):
        code, _, err = self.notify(join(self.tmp, "absent.yaml"))
        self.assertEqual(code, exits.NOTIFY_FAILED)
        self.assertIn("no channel to send to", err)
        path = join(self.tmp, "plain.yaml")
        with open(path, "w") as fob:
            fob.write("version: 1\n")
        code, _, err = self.notify(path)
        self.assertEqual(code, exits.NOTIFY_FAILED)
        self.assertIn("declares no channel", err)
        with open(path, "w") as fob:
            fob.write("version: 2\n")
        code, _, _ = self.notify(path)
        self.assertEqual(code, exits.SPEC_INVALID)

    def test_level_and_check_are_required_and_bounded(self):
        for argv in (("--level", "panic", "--check", "disk"),
                     ("--level", "warn")):
            with self.assertRaises(SystemExit) as caught:
                run_cli("notify", *argv)
            self.assertEqual(caught.exception.code, exits.USAGE)


if __name__ == "__main__":
    unittest.main()
