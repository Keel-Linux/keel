# Copyright (c) 2026 KeelLinux maintainers
"""keel#238: a Proxmox CT made from a released template has no TurnKey LXC
marker, but systemd writes /run/systemd/container with "lxc" at boot. Both
say that the host owns the interfaces (decision 0018)."""

import os
import shutil
import tempfile
import unittest
from os.path import abspath, dirname, join
from unittest import mock

from keel.inspect import constants, inspect_root
from keel.inspect.container import in_container
from keel.inspect.tree import Tree
from keel.spec import runtime

DHCP = join(dirname(abspath(__file__)), "fixtures", "inspect", "dhcp")


class WithRoot(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)

    def put(self, relative: str, text: str) -> None:
        path = join(self.root, relative)
        os.makedirs(dirname(path), exist_ok=True)
        with open(path, "w") as fob:
            fob.write(text)


class TestInContainer(WithRoot):
    def test_the_turnkey_marker_is_a_container(self):
        self.put(constants.LXC_MARKER, "")
        self.assertTrue(in_container(Tree(self.root)))

    def test_systemd_saying_lxc_is_a_container(self):
        self.put(constants.SYSTEMD_CONTAINER, "lxc\n")
        self.assertTrue(in_container(Tree(self.root)))

    def test_another_container_manager_is_not_lxc(self):
        self.put(constants.SYSTEMD_CONTAINER, "systemd-nspawn\n")
        self.assertFalse(in_container(Tree(self.root)))

    def test_neither_is_no_container(self):
        self.assertFalse(in_container(Tree(self.root)))


class TestInspectReadsSystemd(WithRoot):
    def test_a_ct_with_no_marker_is_host_managed(self):
        shutil.rmtree(self.root)
        shutil.copytree(DHCP, self.root, symlinks=True)
        os.remove(join(self.root, constants.LXC_MARKER))
        self.put(constants.SYSTEMD_CONTAINER, "lxc\n")
        result = inspect_root(self.root)
        self.assertEqual(result.spec["network"]["managed_by"], "host")


class TestDefaultManagedByReadsSystemd(unittest.TestCase):
    def test_systemd_saying_lxc_means_host(self):
        def exists(path):
            return path == runtime.SYSTEMD_CONTAINER

        def opened(path, *args, **kwargs):
            if path == runtime.SYSTEMD_CONTAINER:
                return mock.mock_open(read_data="lxc\n")()
            raise FileNotFoundError(path)

        with mock.patch.object(runtime.os.path, "exists", side_effect=exists), \
                mock.patch("builtins.open", side_effect=opened), \
                mock.patch.object(runtime.subprocess, "run") as run:
            self.assertEqual(runtime.default_managed_by(), "host")
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
