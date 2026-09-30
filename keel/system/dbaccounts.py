# Copyright (c) 2026 KeelLinux maintainers
"""The primary's accounts, and what a new replica needs to match them

The accounts live in the `mysql` schema, which the dump of a seed leaves
out, and the binary log carries only what changes after the seed. So a
replica that lacks an account the primary made earlier, or holds it with
other grants, stops at the primary's first ALTER USER, REVOKE or DROP
USER of it. keel.system.dbseed asks both servers; this module reads the
answers and writes the statements that make the replica's accounts the
primary's, before replication starts.

Roles are not copied, and a primary that has any is refused, as is one
that grants privileges to PUBLIC: a role's grants, the roles granted to
each user and their default roles are a second graph to copy and align,
and a user copied without the role it depends on would silently hold
none of the privileges it has on the primary. Refusing says so;
docs/apply.md says what to do instead.

Pure: nothing here runs a command.
"""

import re
from dataclasses import dataclass

from keel.system import dbmariadb as mariadb

LIST_SQL = "SELECT User, Host, is_role FROM mysql.user"
# A line each answer is separated by: SELECT 'keel:account' prints it.
MARKER = "keel:account"
# The server's own accounts and keel's: Debian's socket accounts, the
# definer of the sys views, the old maintenance account, and the
# replication account each node already holds with its own grant.
EXCLUDED_USERS = frozenset(
    ("root", "mysql", "mariadb.sys", "debian-sys-maint",
     mariadb.REPLICATION_USER)
)
# The credential part of a grant line, up to WITH or the end: the same
# grants under another password are the same grants.
CREDENTIAL = re.compile(r" IDENTIFIED (?:BY|VIA) .*?(?= WITH |$)")
NO_LOG = "SET SESSION sql_log_bin = 0;\n"

ROLES = (
    "the primary has roles ({roles}), and keel does not copy roles: a"
    " user copied without the role it depends on would silently hold none"
    " of its privileges, and the primary's next change to a role would"
    " stop the replica. See docs/apply.md"
)
PUBLIC = (
    "the primary grants privileges to PUBLIC ({line}), which keel does"
    " not copy; see docs/apply.md"
)
MISMATCH = "the {where} answered for {got} account(s) and {asked} were asked"
UNEXPECTED = (
    "the {where} answered a question about an account with a statement"
    " that is not one ({line})"
)


@dataclass(frozen=True)
class Account:
    user: str
    host: str

    def key(self) -> tuple[str, str]:
        """How MariaDB tells accounts apart: the host without case"""
        return (self.user, self.host.lower())

    def sql(self) -> str:
        return f"{mariadb.literal(self.user)}@{mariadb.literal(self.host)}"


@dataclass(frozen=True)
class Definition:
    """An account as the primary would create it: CREATE USER and GRANTs"""

    create: str
    grants: tuple[str, ...]


def listing(text: str) -> tuple[list[Account], list[str]]:
    """The accounts worth copying, and the names of the roles

    From `SELECT User, Host, is_role FROM mysql.user`. Left out: the
    EXCLUDED_USERS and the anonymous account.
    """
    accounts, roles = [], []
    for line in (text or "").splitlines():
        fields = line.split("\t")
        if len(fields) != 3:
            continue
        user, host, is_role = fields
        if is_role.upper() == "Y":
            roles.append(user)
        elif user and user not in EXCLUDED_USERS:
            accounts.append(Account(user, host))
    return accounts, roles


def primary_questions(accounts: list[Account]) -> str:
    """What the primary is asked: each account, then PUBLIC's grants"""
    return "".join(
        f"SELECT '{MARKER}';\nSHOW CREATE USER {one.sql()};\n"
        f"SHOW GRANTS FOR {one.sql()};\n"
        for one in accounts
    ) + f"SELECT '{MARKER}';\nSHOW GRANTS FOR PUBLIC;\n"


def local_questions(accounts: list[Account]) -> str:
    """What this server is asked about the accounts it holds already"""
    return "".join(
        f"SELECT '{MARKER}';\nSHOW GRANTS FOR {one.sql()};\n"
        for one in accounts
    )


def primary_definitions(
    text: str, accounts: list[Account],
) -> tuple[dict[Account, Definition], str]:
    """Each account's definition from the primary's answer, or why not"""
    blocks = _blocks(text)
    if len(blocks) != len(accounts) + 1:
        return {}, MISMATCH.format(where="primary", got=len(blocks) - 1,
                                   asked=len(accounts))
    found = {}
    for account, lines in zip(accounts, blocks):
        if not lines or not lines[0].startswith("CREATE USER "):
            return {}, UNEXPECTED.format(
                where="primary", line=lines[0] if lines else "nothing"
            )
        for line in lines[1:]:
            if not _is_grant(line):
                return {}, UNEXPECTED.format(where="primary", line=line)
        found[account] = Definition(lines[0], tuple(lines[1:]))
    for line in blocks[-1]:
        if not _is_grant(line):
            return {}, UNEXPECTED.format(where="primary", line=line)
        return {}, PUBLIC.format(line=line)
    return found, ""


def local_grants(
    text: str, accounts: list[Account],
) -> tuple[dict[Account, tuple[str, ...]], str]:
    """Each held account's grants from this server's answer, or why not"""
    blocks = _blocks(text)
    if len(blocks) != len(accounts):
        return {}, MISMATCH.format(where="replica", got=len(blocks),
                                   asked=len(accounts))
    for line in (one for lines in blocks for one in lines):
        if not _is_grant(line):
            return {}, UNEXPECTED.format(where="replica", line=line)
    return dict(zip(accounts, (tuple(one) for one in blocks))), ""


def alignment(
    primary: dict[Account, Definition], held: set,
    local: dict[Account, tuple[str, ...]],
) -> str:
    """The statements that make this server's accounts the primary's

    An account it lacks is created as the primary has it. One it holds
    keeps its own authentication, always: every node makes its own
    application password at first boot, and the primary's would lock the
    replica's application out (1045). Only its grants are aligned, when
    they differ: all of them revoked, then the primary's granted without
    the credential the first one carries, since a REVOKE on the primary
    of a grant the replica lacks stops the replica ("There is no such
    grant"). The primary's next ALTER USER of such an account still
    replaces the replica's password; keel.system.database says so. All
    of it with sql_log_bin off, so none of it enters a binary log or the
    GTID history of this server. Empty when there is nothing to do.
    """
    theirs = {account.key(): grants for account, grants in local.items()}
    text = ""
    for account, definition in primary.items():
        if account.key() not in held:
            text += "".join(line + ";\n" for line in
                            (definition.create,) + definition.grants)
            continue
        if _same(definition.grants, theirs.get(account.key(), ())):
            continue
        text += f"REVOKE ALL PRIVILEGES, GRANT OPTION FROM {account.sql()};\n"
        text += "".join(
            normalized(line) + ";\n" for line in definition.grants
        )
    return NO_LOG + text if text else ""


def normalized(line: str) -> str:
    """A grant line without its credential"""
    return CREDENTIAL.sub("", line)


def _same(one: tuple[str, ...], other: tuple[str, ...]) -> bool:
    return (sorted(normalized(line) for line in one)
            == sorted(normalized(line) for line in other))


def _is_grant(line: str) -> bool:
    """A grant of privileges ON something; a role grant has no ON"""
    return line.startswith("GRANT ") and " ON " in line


def _blocks(text: str) -> list[list[str]]:
    """The answer split at each marker; what precedes the first is lost"""
    blocks: list[list[str]] = []
    for line in (one.strip() for one in (text or "").splitlines()):
        if line == MARKER:
            blocks.append([])
        elif line and blocks:
            blocks[-1].append(line)
    return blocks
