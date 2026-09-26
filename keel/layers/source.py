# Copyright (c) 2026 KeelLinux maintainers
"""Where layers come from: a directory on disk or an http(s) URL

The two look the same to the caller: `open(name)` gives a binary file
object for the file called `name` under the source, and raises OSError
when it is not there. urllib's URLError and HTTPError are OSError
subclasses, so one except clause covers both kinds of source.
"""

import os
import urllib.request
from typing import BinaryIO
from urllib.parse import quote, urlsplit

from keel.layers.constants import FETCH_TIMEOUT, URL_SCHEMES


class Source:
    def __init__(self, location: str):
        self.location = location
        self.is_url = urlsplit(location).scheme in URL_SCHEMES

    def path(self, name: str) -> str:
        """Where `name` lives under the source, for fetching and messages"""
        if self.is_url:
            return self.location.rstrip("/") + "/" + quote(name)
        return os.path.join(self.location, name)

    def open(self, name: str) -> BinaryIO:
        """Open `name` for reading; raises OSError when it cannot be read"""
        if self.is_url:
            return urllib.request.urlopen(
                self.path(name), timeout=FETCH_TIMEOUT
            )
        return open(self.path(name), "rb")

    def read_text(self, name: str) -> str:
        """The whole of a small text file such as a manifest"""
        with self.open(name) as fob:
            return fob.read().decode("utf-8", errors="replace")
