# Copyright (c) 2026 KeelLinux maintainers
"""keel.mesh.etcdclient: etcd over gRPC with etcdctl, its process
replaced at the subprocess boundary by one that records what keel runs
and answers as etcdctl 3.5 does (`-w json`; the shapes are etcdctl's
own, read off trixie's etcd-client); the real etcd is
tests/test_etcd_auth_netns.py's"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest

from keel.mesh import etcdclient, etcdstate
from keel.mesh.etcdclient import EtcdError, Tls

MESH = "ab" * 16
TLS = Tls("/ca", "/cert", "/key")
LIST = {"header": {"cluster_id": 2789167394324936806,
                   "member_id": 3585629427196971089},
        "members": [
            {"ID": 3585629427196971089, "name": "keel-fd00--1",
             "peerURLs": ["https://[fd00::1]:2380"],
             "clientURLs": ["https://[fd00::1]:2379"]},
            {"ID": 16334501404808820146,
             "peerURLs": ["https://[fd00::4]:2380"], "isLearner": True}]}


class FakeCtl:
    """etcdctl: each call's argument list, input and the keyword
    arguments it was run with; `answers` maps the first words of a call
    to (exit code, standard output, standard error)"""

    def __init__(self):
        self.calls: list[tuple[list[str], str | None, dict]] = []
        self.answers: dict[tuple[str, ...], tuple[int, str, str]] = {}

    def __call__(self, argv, input=None, **kwargs):
        self.calls.append((argv, input, kwargs))
        words = [one for one in argv[1:] if not one.startswith("-")
                 and one != "json"]
        for size in (3, 2, 1):
            found = self.answers.get(tuple(words[:size]))
            if found is not None:
                if isinstance(found, BaseException):
                    raise found
                code, out, err = found
                return subprocess.CompletedProcess(argv, code, out, err)
        return subprocess.CompletedProcess(argv, 1, "",
                                           "Error: not answered")

    def answer(self, words, data=None, code=0, err=""):
        out = data if isinstance(data, str) else json.dumps(data)
        self.answers[tuple(words.split())] = (code, out, err)

    def args(self, index=-1) -> list[str]:
        """The words after etcdctl's own flags"""
        argv = self.calls[index][0]
        return argv[argv.index("json") + 1:]


class Case(unittest.TestCase):
    def setUp(self):
        self.ctl = FakeCtl()
        self.client = etcdclient.Client(("https://[::1]:2379",), TLS, 5,
                                        run=self.ctl)


class TestTheProcess(Case):
    def test_an_argument_list_paths_timeouts_and_json(self):
        self.ctl.answer("member list", LIST)
        self.client.members()
        argv, stdin, kwargs = self.ctl.calls[0]
        self.assertEqual(argv[:8], [
            "etcdctl", "--endpoints=https://[::1]:2379", "--cacert=/ca",
            "--cert=/cert", "--key=/key", "--dial-timeout=5000ms",
            "--command-timeout=5000ms", "-w"])
        self.assertEqual(self.ctl.args(), ["member", "list"])
        self.assertIsNone(stdin)
        self.assertEqual(kwargs["timeout"], 5 + etcdclient.SPAWN)
        self.assertEqual(set(kwargs["env"]), {"PATH", "GOMAXPROCS"})
        self.assertFalse(kwargs["check"])
        self.assertEqual(kwargs["pass_fds"], ())

    def test_the_caller_s_etcdctl_variables_are_not_passed(self):
        self.ctl.answer("member list", LIST)
        os.environ["ETCDCTL_USER"] = "root:pw"
        self.addCleanup(os.environ.pop, "ETCDCTL_USER")
        self.client.members()
        self.assertNotIn("ETCDCTL_USER", self.ctl.calls[0][2]["env"])

    def test_several_endpoints_one_call(self):
        """The VIP's controller and etcd's gate ask this member first, then
        the others (keel#87): etcdctl takes them all and its balancer
        skips one that does not answer"""
        client = etcdclient.Client(("https://[::1]:2379",
                                    "https://[fd00::2]:2379"), TLS,
                                   run=self.ctl)
        self.ctl.answer("member list", LIST)
        client.members()
        self.assertIn("--endpoints=https://[::1]:2379,https://[fd00::2]:2379",
                      self.ctl.calls[0][0])

    def test_descriptors_the_paths_name_are_kept_by_the_child(self):
        client = etcdclient.Client(("https://[::1]:2379",), Tls(
            "/proc/self/fd/7", "/proc/self/fd/8", "/proc/self/fd/9",
            (7, 8, 9)), run=self.ctl)
        self.ctl.answer("member list", LIST)
        client.members()
        self.assertEqual(self.ctl.calls[0][2]["pass_fds"], (7, 8, 9))

    def test_failures_are_errors_never_answers(self):
        self.ctl.answer("member list", "", 1,
                        '{"level":"warn","msg":"retrying"}\n'
                        "Error: etcdserver: permission denied\n")
        with self.assertRaisesRegex(EtcdError, "member: etcdserver:"
                                    " permission denied$"):
            self.client.members()
        self.ctl.answer("member list", "", 1, "")
        with self.assertRaisesRegex(EtcdError, "no reason given"):
            self.client.members()
        self.ctl.answer("member list", "not json")
        with self.assertRaisesRegex(EtcdError, "not JSON"):
            self.client.members()
        self.ctl.answer("member list", "[1]")
        with self.assertRaisesRegex(EtcdError, "not etcd's"):
            self.client.members()
        self.ctl.answer("member list", {"members": [1]})
        with self.assertRaisesRegex(EtcdError, "not etcd's"):
            self.client.members()
        self.ctl.answer("member list", "x" * (etcdclient.MAX_ANSWER + 1))
        with self.assertRaisesRegex(EtcdError, "too long"):
            self.client.members()

    def test_a_process_that_hangs_or_cannot_start(self):
        self.ctl.answers[("member", "list")] = subprocess.TimeoutExpired(
            "etcdctl", 5)
        with self.assertRaisesRegex(EtcdError, "no answer within 5.5 s"):
            self.client.members()
        self.ctl.answers[("member", "list")] = FileNotFoundError("etcdctl")
        with self.assertRaisesRegex(EtcdError, "could not be run"):
            self.client.members()

    def test_ids_go_to_etcdctl_in_hex(self):
        self.assertEqual(etcdclient.hex_id("16334501404808820146"),
                         "e2afce7bd8bfb5b2")
        for bad in ("x", "-1", str(2 ** 64), None):
            with self.subTest(bad=bad), self.assertRaises(EtcdError):
                etcdclient.hex_id(bad)


class TestMembers(Case):
    def test_the_list_learners_and_unstarted(self):
        self.ctl.answer("member list", LIST)
        found = self.client.members()
        self.assertEqual([one.id for one in found],
                         ["3585629427196971089", "16334501404808820146"])
        self.assertEqual(found[0].address, "fd00::1")
        self.assertFalse(found[0].learner)
        self.assertTrue(found[1].learner)
        self.assertFalse(found[1].started)
        self.assertTrue(found[0].started)
        self.assertEqual(self.client.cluster_id(), "2789167394324936806")
        named = etcdclient.Member("1", "", ("https://host:2380",), (), True)
        self.assertIsNone(named.address)

    def test_add_a_learner_promote_remove(self):
        self.ctl.answer("member add", {"member": {
            "ID": 16334501404808820146,
            "peerURLs": ["https://[fd00::4]:2380"], "isLearner": True},
            "members": []})
        self.ctl.answer("member promote", {"header": {}})
        self.ctl.answer("member remove", {"header": {}})
        added = self.client.add_learner("https://[fd00::4]:2380")
        self.assertEqual(added.id, "16334501404808820146")
        self.assertEqual(self.ctl.args(), [
            "member", "add", "keel-learner",
            "--peer-urls=https://[fd00::4]:2380", "--learner"])
        self.client.promote(added.id)
        self.assertEqual(self.ctl.args(), ["member", "promote",
                                           "e2afce7bd8bfb5b2"])
        self.client.remove(added.id)
        self.assertEqual(self.ctl.args(), ["member", "remove",
                                           "e2afce7bd8bfb5b2"])
        self.ctl.answer("member add", {"members": []})
        with self.assertRaisesRegex(EtcdError, "not etcd's"):
            self.client.add_learner("https://[fd00::4]:2380")

    def test_status_health_and_leadership(self):
        self.ctl.answer("endpoint status", [{
            "Endpoint": "https://[fd00::1]:2379", "Status": {
                "header": {"member_id": 11}, "leader": 11, "raftTerm": 3,
                "version": "3.5.16"}}])
        found = self.client.status("https://[fd00::1]:2379")
        self.assertEqual((found.member_id, found.leader, found.raft_term,
                          found.learner), ("11", "11", 3, False))
        self.assertIn("--endpoints=https://[fd00::1]:2379",
                      self.ctl.calls[-1][0])
        self.ctl.answer("endpoint status", [{}])
        with self.assertRaisesRegex(EtcdError, "not etcd's"):
            self.client.status("https://[fd00::1]:2379")
        self.ctl.answer("endpoint health", [{
            "endpoint": "https://[fd00::1]:2379", "health": True}])
        self.assertEqual(self.client.health("https://[fd00::1]:2379"),
                         (True, ""))
        self.ctl.answer("endpoint health", [{
            "endpoint": "https://[fd00::1]:2379", "health": False,
            "error": "context deadline exceeded"}], 1,
            "Error: unhealthy cluster")
        self.assertEqual(self.client.health("https://[fd00::1]:2379"),
                         (False, "context deadline exceeded"))
        self.ctl.answer("endpoint health", "[]", 1)
        self.assertFalse(self.client.health("x")[0])
        self.ctl.answer("endpoint health", "[1]")
        self.assertFalse(self.client.health("x")[0])
        self.ctl.answer("move-leader", {"header": {}})
        self.client.move_leader("12")
        self.assertEqual(self.ctl.args(), ["move-leader", "c"])


class TestKeys(Case):
    def test_a_put_a_delete_and_a_prefix(self):
        self.ctl.answer("put", {"header": {"revision": 5}})
        self.assertEqual(self.client.put("-k", "-v"), 5)
        self.assertEqual(self.ctl.args(), ["put", "--", "-k", "-v"])
        self.ctl.answer("put", {"header": {}})
        with self.assertRaisesRegex(EtcdError, "not etcd's"):
            self.client.put("k", "v")
        self.ctl.answer("del", {"header": {}, "deleted": 1})
        self.assertEqual(self.client.delete("/k/a"), 1)
        self.assertEqual(self.ctl.args(), ["del", "--", "/k/a"])
        self.ctl.answer("get", {"kvs": [
            {"key": "L2svYQ==", "value": "b25l", "mod_revision": 4,
             "lease": 5211123377559930638},
            {"key": "L2svYg==", "mod_revision": 5}]})
        self.assertEqual(self.client.prefix("/k/"), [
            etcdclient.Value("/k/a", b"one", 4, "5211123377559930638"),
            etcdclient.Value("/k/b", b"", 5, None)])
        self.assertEqual(self.ctl.args(), ["get", "--prefix", "--", "/k/"])
        self.ctl.answer("get", {"kvs": [{"value": "x"}]})
        with self.assertRaisesRegex(EtcdError, "not etcd's"):
            self.client.prefix("/k/")

    def test_a_swap_as_etcdctl_s_transaction(self):
        self.ctl.answer("txn", {"succeeded": True})
        self.assertTrue(self.client.swap(
            [etcdclient.modified("/k/a", 4), etcdclient.absent('/k/"b')],
            [("/k/a", b'{"x": "\\n\xff"}', None),
             ("/k/b", b"two", "5211123377559930638")]))
        self.assertEqual(self.ctl.args(), ["txn", "--interactive=false"])
        self.assertEqual(self.ctl.calls[-1][1].split("\n"), [
            'mod("/k/a") = "4"', 'ver("/k/\\"b") = "0"', "",
            'put -- "/k/a" "{\\"x\\": \\"\\\\n\\xff\\"}"',
            'put --lease=4851a11a2831870e -- "/k/b" "two"', "", "", ""])
        # a failed comparison: etcdctl leaves `succeeded` out
        self.ctl.answer("txn", {"header": {}})
        self.assertFalse(self.client.swap([], []))
        with self.assertRaisesRegex(EtcdError, "not a comparison"):
            self.client.swap([{"key": "eA==", "target": "VALUE"}], [])

    def test_a_swap_that_deletes(self):
        """keel vip unpair: a reservation deleted only at the revision
        it was read at"""
        self.ctl.answer("txn", {"succeeded": True})
        self.assertTrue(self.client.swap(
            [etcdclient.modified("/k/a", 9)], [], ("/k/a",)))
        self.assertEqual(self.ctl.calls[-1][1].split("\n"), [
            'mod("/k/a") = "9"', "", 'del -- "/k/a"', "", "", ""])


class TestLeases(Case):
    """What the VIP's controller asks (keel.mesh.vipetcd)"""

    def test_granted_renewed_and_revoked(self):
        self.ctl.answer("lease grant", {"ID": 5211123377559930638,
                                        "TTL": 20, "Error": ""})
        self.assertEqual(self.client.grant(20), "5211123377559930638")
        self.assertEqual(self.ctl.args(), ["lease", "grant", "20"])
        self.ctl.answer("lease keep-alive", {"ID": 5211123377559930638,
                                             "TTL": 20})
        self.assertEqual(self.client.keepalive("5211123377559930638"), 20)
        self.assertEqual(self.ctl.args(), ["lease", "keep-alive", "--once",
                                           "4851a11a2831870e"])
        self.ctl.answer("lease timetolive", {"ttl": 19, "granted-ttl": 20})
        self.assertEqual(self.client.time_to_live("5211123377559930638"),
                         19)
        self.ctl.answer("lease revoke", {"header": {}})
        self.client.revoke("5211123377559930638")
        self.assertEqual(self.ctl.args(), ["lease", "revoke",
                                           "4851a11a2831870e"])

    def test_a_lease_gone_is_0_and_its_ttl_minus_1(self):
        self.ctl.answer("lease keep-alive", "", 2,
                        "Error: etcdserver: requested lease not found")
        self.assertEqual(self.client.keepalive("77"), 0)
        self.ctl.answer("lease timetolive", {"ttl": -1, "granted-ttl": 0})
        self.assertEqual(self.client.time_to_live("77"), -1)

    def test_anything_else_is_no_renewal(self):
        """keel#83: a failed or unparseable call never counts as renewed"""
        for code, out, err in (
                (1, "", "Error: context deadline exceeded"),
                (0, "not json", ""), (0, '{"TTL": "x"}', ""),
                (0, "{}", ""), (0, "[]", "")):
            self.ctl.answers[("lease", "keep-alive")] = (code, out, err)
            with self.subTest(out=out, err=err), \
                    self.assertRaises(EtcdError):
                self.client.keepalive("77")
        self.ctl.answers[("lease", "keep-alive")] = \
            subprocess.TimeoutExpired("etcdctl", 2)
        with self.assertRaises(EtcdError):
            self.client.keepalive("77")
        self.ctl.answer("lease keep-alive", {"TTL": -3})
        self.assertEqual(self.client.keepalive("77"), 0)

    def test_answers_that_are_not_etcd_s(self):
        self.ctl.answer("lease grant", {"TTL": 20})
        with self.assertRaisesRegex(EtcdError, "not etcd's"):
            self.client.grant(20)
        self.ctl.answer("lease grant", {"ID": 1, "Error": "no leader"})
        with self.assertRaisesRegex(EtcdError, "no leader"):
            self.client.grant(20)
        self.ctl.answer("lease timetolive", {"ttl": "x"})
        with self.assertRaisesRegex(EtcdError, "not etcd's"):
            self.client.time_to_live("77")


class TestAuth(Case):
    """What the root's holder asks as etcd's root user"""

    def test_users_roles_and_permissions(self):
        self.ctl.answer("auth status", {"enabled": True})
        self.assertTrue(self.client.auth_enabled())
        self.ctl.answer("auth status", {"authRevision": 1})
        self.assertFalse(self.client.auth_enabled())
        # etcdctl answers these two in words, whatever -w says
        self.ctl.answer("auth enable", "Authentication Enabled\n")
        self.ctl.answer("auth disable", "Authentication Disabled\n")
        self.client.auth_enable()
        self.client.auth_disable()
        self.ctl.answer("auth enable", "", 1,
                        "Error: etcdserver: root user does not exist")
        with self.assertRaisesRegex(EtcdError, "root user does not exist"):
            self.client.auth_enable()
        for words in ("user add",
                      "user delete", "user grant-role", "user revoke-role",
                      "role add", "role delete", "role grant-permission",
                      "role revoke-permission"):
            self.ctl.answer(words, {"header": {}})
        self.client.user_add("keel-fd00--1")
        self.assertEqual(self.ctl.args(), ["user", "add", "--no-password",
                                           "--", "keel-fd00--1"])
        self.client.user_delete("u")
        self.client.grant_role("u", "r")
        self.assertEqual(self.ctl.args(), ["user", "grant-role", "--", "u",
                                           "r"])
        self.client.revoke_role("u", "r")
        self.client.role_add("r")
        self.client.role_delete("r")
        self.client.permit("r", "readwrite", "/keel/x/")
        self.assertEqual(self.ctl.args(), [
            "role", "grant-permission", "--prefix", "--", "r", "readwrite",
            "/keel/x/"])
        with self.assertRaisesRegex(EtcdError, "not a permission"):
            self.client.permit("r", "all", "/keel/x/")
        self.client.unpermit("r", "/keel/x/")
        self.assertEqual(self.ctl.args(), [
            "role", "revoke-permission", "--prefix", "--", "r", "/keel/x/"])
        self.ctl.answer("user list", {"users": ["root", "u"]})
        self.assertEqual(self.client.users(), ["root", "u"])
        self.ctl.answer("user get", {"roles": ["r"]})
        self.assertEqual(self.client.user_roles("u"), ["r"])
        self.ctl.answer("role list", {"roles": ["r"]})
        self.assertEqual(self.client.roles(), ["r"])
        self.ctl.answer("role get", {"perm": [
            {"permType": 2, "key": "L2svdi8=", "range_end": "L2svdjA="},
            {"key": "L2s="}]})
        self.assertEqual(self.client.permissions("r"), {
            ("readwrite", "/k/v/", "/k/v0"), ("read", "/k", "")})
        self.ctl.answer("role get", {"perm": [{"permType": 9}]})
        with self.assertRaisesRegex(EtcdError, "not etcd's"):
            self.client.permissions("r")


class TestFiles(unittest.TestCase):
    def test_this_member_s_files_and_the_holder_s_admin(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        with self.assertRaisesRegex(EtcdError, "no certificate"):
            etcdclient.local(root)
        etcdstate.make_root(root, MESH, "fd00::1")
        found = etcdclient.local(root)
        self.assertEqual(found.endpoints, ("https://[::1]:2379",))
        self.assertTrue(found.tls.certificate.endswith(
            etcdstate.MEMBER_CERT))
        admin = etcdclient.admin(root, ("https://[fd00::1]:2379",))
        self.assertTrue(admin.tls.certificate.endswith(etcdstate.ADMIN_CERT))
        self.assertEqual(admin.endpoints, ("https://[fd00::1]:2379",))
        self.assertEqual(etcdclient.admin(root).endpoints,
                         ("https://[::1]:2379",))


if __name__ == "__main__":
    unittest.main()
