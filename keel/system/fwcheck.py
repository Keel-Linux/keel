# Copyright (c) 2026 KeelLinux maintainers
"""keel firewall check: is the table the kernel holds the file's?

Decision 0097, section 4: Monit runs this every cycle where keel writes
the firewall (keel.manifest.monit). The digest in the comment of the
`inet keel` table is compared with the one in keel's ruleset file, as
keel diff does. Exit 0 when they agree or when there is no file of
keel's; DRIFT_FOUND when the table is absent or another, which makes
Monit restart keel-firewall.service, and that loads the file again.
Nothing is written or loaded here.
"""

import os

from keel import exits
from keel.manifest.firewall import PATH, file_state, loaded_digest
from keel.system.fwstate import table_digest

UNIT = "keel-firewall.service"


def check(root: str) -> tuple[int, str]:
    path = os.path.join(root, PATH)
    try:
        with open(path) as fob:
            text = fob.read()
    except FileNotFoundError:
        text = None
    except OSError as e:
        return exits.DRIFT_FOUND, f"{path} cannot be read: {e.strerror}"
    if file_state(text) is None:
        return exits.OK, f"{path}: no ruleset of keel's, nothing to compare"
    wanted = loaded_digest(text or "")
    held = table_digest()
    if held == wanted:
        return exits.OK, f"table inet keel is the one {path} says ({wanted})"
    found = ("is not loaded" if held is None
             else f"holds {held}")
    return exits.DRIFT_FOUND, (f"table inet keel {found}; {path} says"
                               f" {wanted}: systemctl restart {UNIT} loads"
                               " it")
