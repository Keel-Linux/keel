# Copyright (c) 2026 KeelLinux maintainers
"""What a systemd path unit with PathChanged= sees in a directory

systemd watches the directory with inotify and this mask (src/core/
path.c, PATH_CHANGED): a file that is created, deleted, moved, has its
attributes changed, or is closed after it was opened for writing,
whether or not anything was written. keel-database-follow.path is
PathChanged=/var/lib/keel/vip, so each such event starts keel database
follow (keel#164). Linux only, by ctypes, with no other dependency.
"""

import ctypes
import ctypes.util
import os
import select
import struct

IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_NONBLOCK = 0o4000
IN_CLOEXEC = 0o2000000
PATH_CHANGED = (IN_CREATE | IN_DELETE | IN_DELETE_SELF | IN_MOVE_SELF
                | IN_ATTRIB | IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO)
EVENT = struct.Struct("iIII")


class PathChanged:
    """An inotify watch of `directory` with systemd's PathChanged mask"""

    def __init__(self, directory: str):
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        self.fd = libc.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), "inotify_init1")
        if libc.inotify_add_watch(self.fd, os.fsencode(directory),
                                  PATH_CHANGED) < 0:
            os.close(self.fd)
            raise OSError(ctypes.get_errno(), f"inotify_add_watch {directory}")

    def events(self, timeout: float = 0.0) -> list[tuple[int, str]]:
        """The events since the last call: (mask, name)"""
        found: list[tuple[int, str]] = []
        ready, _, _ = select.select([self.fd], [], [], timeout)
        if not ready:
            return found
        try:
            data = os.read(self.fd, 65536)
        except BlockingIOError:
            return found
        at = 0
        while at + EVENT.size <= len(data):
            _, mask, _, size = EVENT.unpack_from(data, at)
            name = data[at + EVENT.size:at + EVENT.size + size]
            found.append((mask, name.rstrip(b"\0").decode()))
            at += EVENT.size + size
        return found

    def close(self) -> None:
        os.close(self.fd)
