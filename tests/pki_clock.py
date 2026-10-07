# Copyright (c) 2026 KeelLinux maintainers
"""The clock of the tests that make certificates and CRLs with the real
openssl

openssl stamps what it signs with the wall clock: notBefore and
notAfter of a certificate, lastUpdate and nextUpdate of a CRL, and the
CRL file's mtime that keel.mesh.etcdca.refresh reads. keel compares
those with the `now` its caller hands it, so a test's `now` has to
start where openssl's does. A fixed date drifts away from them as the
calendar moves: certificates minted days after it look days younger
than the test says, and renewal thresholds are missed.

NOW is the moment this module is imported, to the second, before any
fixture is made; tests move their clock relative to it, never to a
date.
"""

from datetime import datetime, timezone

NOW = datetime.now(timezone.utc).replace(microsecond=0)
