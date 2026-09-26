# Copyright (c) 2026 KeelLinux maintainers
"""Every inspect probe, as a pure function over file contents

The probes never touch the disk, so these tests hand them File values
and check the section they build and the findings they report, one test
per branch: the value found, the file missing, the file malformed.
"""

import unittest

from helpers import spec  # noqa: F401

from keel.inspect import app, hostname, interfaces, locale, network
from keel.inspect import secrets, security, tls, users
from keel.inspect.report import (
    INFERRED,
    NOT_EXTRACTED,
    NOT_INFERRED,
    Finding,
    Inspection,
    inferred,
    missing,
)
from keel.inspect.tree import NOT_PRESENT, File

ABSENT = File("/x/absent", problem=NOT_PRESENT)
HOSTNAME_F = File("hostname -f", "blog.example.org\n")
OFFLINE = File("hostname -f", problem="not run")
KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyMaterialOnly admin@blog"
PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "admin:x:1000:1000::/home/admin:/bin/bash\n"
)
GROUP = "root:x:0:\nadm:x:4:admin\nsudo:x:27:admin\nadmin:x:1000:\n"


def statuses(findings: list[Finding], field: str) -> list[str]:
    return [f.status for f in findings if f.field == field]


def reason(findings: list[Finding], field: str) -> str:
    return next(f.source for f in findings if f.field == field)


class TestReport(unittest.TestCase):
    def test_each_status_has_its_own_line_shape(self):
        self.assertEqual(inferred("a.b", 1, "/etc/x").line(),
                         "a.b: 1 (from /etc/x)")
        self.assertEqual(missing("a.b", "gone").line(),
                         "a.b: not inferred: gone")
        self.assertEqual(
            Finding("s", NOT_EXTRACTED, "file: /p", "never read").line(),
            "s: file: /p (not extracted: never read)",
        )

    def test_summary_counts_and_names_the_required_gaps(self):
        result = Inspection("/", "core", {}, (
            inferred("instance.hostname", "a", "f"),
            missing("instance.fqdn", "why"),
            missing("app.email", "why"),
            Finding("secrets.root_password", NOT_EXTRACTED, "v", "s"),
        ))
        self.assertFalse(result.complete)
        self.assertEqual(result.missing_required, ("instance.fqdn",))
        self.assertEqual(
            result.summary(),
            "inspect: 1 inferred, 2 not inferred (1 required), 1 secrets to"
            " provide; spec incomplete",
        )

    def test_optional_gaps_leave_the_spec_complete(self):
        result = Inspection("/", "core", {}, (missing("app.email", "x"),))
        self.assertTrue(result.complete)
        self.assertIn("spec complete", result.summary())


class TestFile(unittest.TestCase):
    def test_lines_drop_blanks_and_comments(self):
        self.assertEqual(File("p", "# c\n\n a \nb\n").lines(), ["a", "b"])
        self.assertEqual(ABSENT.lines(), [])

    def test_assignments_strip_export_and_quotes(self):
        text = 'export A="one"\nB=\'two\'\nC=3\nnot an assignment\n=x\n'
        self.assertEqual(File("p", text).assignments(),
                         {"A": "one", "B": "two", "C": "3"})


class TestHostname(unittest.TestCase):
    def probe(self, name, hosts, hostname_f=OFFLINE):
        return hostname.probe_hostname(
            File("/x/etc/hostname", name), File("/x/etc/hosts", hosts),
            hostname_f,
        )

    def test_fqdn_comes_from_the_hosts_line_naming_the_host(self):
        section, findings = self.probe(
            "blog\n", "127.0.0.1 localhost\n127.0.1.1 blog blog.example.org\n"
        )
        self.assertEqual(section,
                         {"hostname": "blog", "fqdn": "blog.example.org"})
        self.assertEqual(reason(findings, "instance.fqdn"), "/x/etc/hosts")

    def test_fqdn_falls_back_to_hostname_f_when_it_ran(self):
        section, findings = self.probe("blog\n", "127.0.1.1 blog\n",
                                       HOSTNAME_F)
        self.assertEqual(section["fqdn"], "blog.example.org")
        self.assertEqual(reason(findings, "instance.fqdn"), "hostname -f")

    def test_dotted_hostname_file_is_its_own_fqdn(self):
        section, findings = self.probe("blog.example.org\n", "")
        self.assertEqual(section["hostname"], "blog.example.org")
        self.assertEqual(section["fqdn"], "blog.example.org")
        self.assertIn("dotted name", reason(findings, "instance.fqdn"))

    def test_no_fqdn_anywhere_is_reported_with_every_source_checked(self):
        section, findings = self.probe("blog\n", "127.0.1.1 blog\n")
        self.assertEqual(section, {"hostname": "blog"})
        self.assertEqual(statuses(findings, "instance.fqdn"), [NOT_INFERRED])
        self.assertIn("hostname -f not run",
                      reason(findings, "instance.fqdn"))

    def test_hostname_f_without_a_domain_is_quoted_in_the_reason(self):
        _, findings = self.probe("blog\n", "", File("hostname -f", "blog\n"))
        self.assertIn("answered 'blog'", reason(findings, "instance.fqdn"))

    def test_empty_or_absent_hostname_file_leaves_both_fields_missing(self):
        for file in (File("/x/etc/hostname", "\n"), ABSENT):
            section, findings = hostname.probe_hostname(file, ABSENT, OFFLINE)
            self.assertIsNone(section)
            self.assertEqual(statuses(findings, "instance.hostname"),
                             [NOT_INFERRED])
            self.assertEqual(statuses(findings, "instance.fqdn"),
                             [NOT_INFERRED])


class TestInterfacesParser(unittest.TestCase):
    def test_stanzas_options_and_malformed_headers(self):
        text = (
            "    stray indented line\n"
            "# comment\n"
            "auto eth0\n"
            "iface eth0 inet6 static\n"
            "\taddress 2001:db8:1::10/64\n"
            "    gateway fe80::1\n"
            "    dns-nameservers 2001:db8:1::53 2001:db8:1::54\n"
            "iface eth0 inet\n"
            "allow-hotplug eth1\n"
            "iface eth1 inet dhcp\n"
        )
        stanzas, problems = interfaces.parse_interfaces(text)
        self.assertEqual(problems, ["iface eth0 inet"])
        self.assertEqual(
            [(s.iface, s.family, s.method) for s in stanzas],
            [("eth0", "inet6", "static"), ("eth1", "inet", "dhcp")],
        )
        self.assertEqual(stanzas[0].option("address"), "2001:db8:1::10/64")
        self.assertEqual(stanzas[0].values("dns-nameservers"),
                         ["2001:db8:1::53", "2001:db8:1::54"])
        self.assertEqual(stanzas[1].options, ())

    def test_option_without_a_value_is_none(self):
        stanzas, _ = interfaces.parse_interfaces(
            "iface eth0 inet6 static\n    gateway\n"
        )
        self.assertIsNone(stanzas[0].option("gateway"))
        self.assertIsNone(stanzas[0].option("address"))


class TestNetwork(unittest.TestCase):
    def probe(self, text, resolv="", container=False, extra=()):
        files = [File("/x/etc/network/interfaces", text), *extra]
        return network.probe_network(
            files, File("/x/etc/resolv.conf", resolv), container
        )

    def test_static_ipv6_is_read_and_stays_with_the_file(self):
        section, findings = self.probe(
            "iface eth0 inet dhcp\n"
            "iface eth0 inet6 static\n"
            "    address 2001:db8:1::10\n"
            "    netmask 64\n"
            "    gateway fe80::1\n"
        )
        self.assertEqual(section["interfaces"]["eth0"]["ipv6"], {
            "method": "static", "address": "2001:db8:1::10/64",
            "gateway": "fe80::1",
        })
        self.assertEqual(section["interfaces"]["eth0"]["ipv4"],
                         {"method": "dhcp"})
        self.assertEqual(section["managed_by"], "file")
        self.assertIn("interfaces file owns",
                      reason(findings, "network.managed_by"))

    def test_ipv4_netmask_is_turned_into_a_prefix_length(self):
        section, _ = self.probe(
            "iface eth0 inet static\n    address 192.0.2.10\n"
            "    netmask 255.255.255.0\n"
        )
        self.assertEqual(section["interfaces"]["eth0"]["ipv4"]["address"],
                         "192.0.2.10/24")
        self.assertEqual(section["managed_by"], "file")

    def test_container_marker_means_host_managed(self):
        section, findings = self.probe("iface eth0 inet6 dhcp\n",
                                       container=True)
        self.assertEqual(section["managed_by"], "host")
        self.assertIn("LXC marker", reason(findings, "network.managed_by"))

    def test_unknown_method_and_bad_addresses_are_reported_per_family(self):
        text = (
            "iface eth0 inet6 v4tunnel\n"
            "iface eth1 inet6 static\n"
            "iface eth2 inet6 static\n    address 2001:db8::1\n"
            "iface eth3 inet6 static\n    address nonsense/64\n"
            "iface eth4 inet6 static\n    address 192.0.2.1/24\n"
            "iface eth5 ipx static\n"
            "iface lo inet loopback\n"
        )
        section, findings = self.probe(text)
        self.assertIsNone(section)
        reasons = [f.source for f in findings if f.status == NOT_INFERRED]
        self.assertEqual(len(reasons), 6)
        self.assertIn("method v4tunnel", reasons[0])
        self.assertIn("without an address", reasons[1])
        self.assertIn("no prefix length or netmask", reasons[2])
        self.assertIn("is not valid", reasons[3])
        self.assertIn("is not an ipv6 address", reasons[4])
        self.assertIn("no interface stanza besides lo", reasons[5])

    def test_malformed_header_is_reported_and_the_rest_is_kept(self):
        section, findings = self.probe("iface eth0\niface eth1 inet dhcp\n")
        self.assertEqual(list(section["interfaces"]), ["eth1"])
        self.assertIn("malformed line 'iface eth0'",
                      reason(findings, "network.interfaces"))

    def test_absent_interfaces_file_is_a_required_gap(self):
        section, findings = network.probe_network(
            [ABSENT], File("/x/etc/resolv.conf", ""), False
        )
        self.assertIsNone(section)
        self.assertEqual(reason(findings, "network.interfaces"),
                         "/x/absent not present")

    def test_sourced_files_are_read_after_the_main_one(self):
        extra = File("/x/etc/network/interfaces.d/eth1",
                     "iface eth1 inet dhcp\n")
        section, _ = self.probe("iface eth0 inet6 auto\n", extra=(extra,))
        self.assertEqual(list(section["interfaces"]), ["eth0", "eth1"])

    def test_nameservers_are_deduplicated_ipv6_first(self):
        section, findings = self.probe(
            "iface eth0 inet6 dhcp\n    dns-nameservers 192.0.2.53\n",
            "nameserver 192.0.2.53\nnameserver 2001:db8::53\n"
            "nameserver\nnameserver nonsense\nsearch example.org\n",
        )
        self.assertEqual(section["nameservers"],
                         ["2001:db8::53", "192.0.2.53"])
        self.assertEqual(reason(findings, "network.nameservers"),
                         "/x/etc/resolv.conf")

    def test_local_resolver_is_reported_not_recorded(self):
        section, findings = self.probe("iface eth0 inet6 dhcp\n",
                                       "nameserver 127.0.0.53\n")
        self.assertNotIn("nameservers", section)
        self.assertIn("local resolver (127.0.0.53)",
                      reason(findings, "network.nameservers"))

    def test_absent_resolv_conf_is_reported(self):
        _, findings = network.probe_network(
            [File("/x/i", "iface eth0 inet6 dhcp\n")], ABSENT, False
        )
        self.assertEqual(reason(findings, "network.nameservers"),
                         "/x/absent not present")


class TestTLS(unittest.TestCase):
    CONFIG = File("/x/etc/dehydrated/confconsole.config",
                  'CHALLENGETYPE="dns-01"\n')
    DOMAINS = File("/x/etc/dehydrated/confconsole.domains.txt",
                   "# c\nblog.example.org www.blog.example.org\n"
                   "blog.example.org\n")
    PLAIN = File("/x/etc/dehydrated/domains.txt", "core.example.org\n")

    def test_no_dehydrated_directory_means_acme_disabled(self):
        section, findings = tls.probe_tls(ABSENT, [ABSENT], False)
        self.assertEqual(section, {"acme": {"enabled": False}})
        self.assertIn("not present", reason(findings, "tls.acme.enabled"))

    def test_no_domains_in_either_file_means_acme_disabled(self):
        empty = File("/x/etc/dehydrated/confconsole.domains.txt", "# none\n")
        section, findings = tls.probe_tls(self.CONFIG, [empty, ABSENT], True)
        self.assertEqual(section, {"acme": {"enabled": False}})
        self.assertIn("no domains in /x/etc/dehydrated/confconsole.domains.txt"
                      " or /x/absent", reason(findings, "tls.acme.enabled"))

    def test_confconsole_domains_and_challenge_are_read(self):
        section, findings = tls.probe_tls(
            self.CONFIG, [self.DOMAINS, self.PLAIN], True
        )
        self.assertEqual(section, {"acme": {
            "enabled": True, "challenge": "dns-01",
            "domains": ["blog.example.org", "www.blog.example.org"],
        }})
        self.assertEqual(reason(findings, "tls.acme.challenge"),
                         self.CONFIG.path)

    def test_plain_domains_file_and_default_challenge(self):
        section, findings = tls.probe_tls(ABSENT, [ABSENT, self.PLAIN], True)
        self.assertEqual(section["acme"]["domains"], ["core.example.org"])
        self.assertEqual(section["acme"]["challenge"], "http-01")
        self.assertIn("not present, dehydrated defaults to http-01",
                      reason(findings, "tls.acme.challenge"))

    def test_config_without_challenge_type_says_so(self):
        _, findings = tls.probe_tls(File("/x/c", "PROVIDER=x\n"),
                                    [self.PLAIN], True)
        self.assertIn("sets no CHALLENGETYPE",
                      reason(findings, "tls.acme.challenge"))

    def test_unknown_challenge_type_is_left_out_and_reported(self):
        config = File("/x/c", "CHALLENGETYPE=tls-alpn-01\n")
        section, findings = tls.probe_tls(config, [self.PLAIN], True)
        self.assertNotIn("challenge", section["acme"])
        self.assertEqual(statuses(findings, "tls.acme.challenge"),
                         [NOT_INFERRED])


class TestAppliance(unittest.TestCase):
    def test_hyphenated_appliance_names_parse(self):
        found, finding = app.probe_appliance(
            File("/x/v", "turnkey-nginx-php-fastcgi-19.0-trixie-amd64\n")
        )
        self.assertEqual(found, app.Appliance("nginx-php-fastcgi", "19.0",
                                              "trixie", "amd64"))
        self.assertEqual(str(found), "nginx-php-fastcgi 19.0 (trixie, amd64)")
        self.assertEqual(finding.status, INFERRED)

    def test_missing_or_foreign_version_file(self):
        for file in (ABSENT, File("/x/v", "\n"), File("/x/v", "debian-13\n"),
                     File("/x/v", "turnkey-core\n")):
            found, finding = app.probe_appliance(file)
            self.assertIsNone(found)
            self.assertEqual(finding.status, NOT_INFERRED)


class TestApp(unittest.TestCase):
    CONF = File("/x/etc/inithooks.conf",
                "export APP_EMAIL=admin@example.org\n"
                "export APP_DOMAIN=core.example.org\n"
                "export APP_PASS=secret\n"
                "export APP_IP_BIND='[2001:db8::10]'\n"
                "export ROOT_PASS=secret\n")

    def test_conf_variables_map_to_email_domain_and_options(self):
        section, findings = app.probe_app(self.CONF, "other.example.org")
        self.assertEqual(section, {
            "email": "admin@example.org", "domain": "core.example.org",
            "options": {"ip_bind": "[2001:db8::10]"},
        })
        self.assertEqual(statuses(findings, "app.options.ip_bind"),
                         [INFERRED])
        self.assertNotIn("secret", str(findings))

    def test_domain_falls_back_to_the_fqdn(self):
        section, findings = app.probe_app(ABSENT, "blog.example.org")
        self.assertEqual(section, {"domain": "blog.example.org"})
        self.assertIn("instance.fqdn", reason(findings, "app.domain"))
        self.assertEqual(reason(findings, "app.email"),
                         "/x/absent not present")

    def test_nothing_known_gives_no_section(self):
        section, findings = app.probe_app(ABSENT, None)
        self.assertIsNone(section)
        self.assertEqual(statuses(findings, "app.domain"), [NOT_INFERRED])

    def test_readable_conf_without_app_variables_says_so(self):
        _, findings = app.probe_app(File("/x/c", "export X=1\n"), None)
        self.assertEqual(reason(findings, "app.email"),
                         "/x/c does not set it")


class TestSecurity(unittest.TestCase):
    ALIASES = File("/x/etc/aliases",
                   "postmaster: root\nroot: admin@example.org\n")
    NEVER = File("/x/etc/cron-apt/config", 'MAILON="never"\n')
    OUTPUT = File("/x/etc/cron-apt/config", 'MAILON="output"\n')
    INSTALL = File("/x/etc/cron-apt/action.d/5-install", "dist-upgrade -y\n")
    AUTO = File("/x/etc/apt/apt.conf.d/20auto-upgrades",
                'APT::Periodic::Unattended-Upgrade "1";\n')

    def probe(self, conf=ABSENT, aliases=ABSENT, config=ABSENT,
              install=ABSENT, auto=ABSENT):
        return security.probe_security(conf, aliases, config, install, auto)

    def test_inithooks_conf_wins_when_readable(self):
        conf = File("/x/c", "SEC_ALERTS=SKIP\nSEC_UPDATES=FORCE\n")
        section, _ = self.probe(conf=conf, aliases=self.ALIASES)
        self.assertEqual(section, {"alerts": "skip", "updates": "force"})
        conf = File("/x/c", "SEC_ALERTS=ops@example.org\nSEC_UPDATES=maybe\n")
        section, _ = self.probe(conf=conf, install=self.INSTALL)
        self.assertEqual(section, {"alerts": "ops@example.org",
                                   "updates": "force"})

    def test_root_alias_and_cron_apt_install_action(self):
        section, findings = self.probe(aliases=self.ALIASES,
                                       install=self.INSTALL)
        self.assertEqual(section, {"alerts": "admin@example.org",
                                   "updates": "force"})
        self.assertIn("root alias", reason(findings, "security.alerts"))

    def test_local_root_alias_with_mail_never_means_skip(self):
        aliases = File("/x/etc/aliases", "no colon here\nroot: admin\n")
        section, findings = self.probe(aliases=aliases, config=self.NEVER)
        self.assertEqual(section["alerts"], "skip")
        self.assertIn("MAILON=never", reason(findings, "security.alerts"))

    def test_aliases_without_root_alias_means_skip(self):
        aliases = File("/x/etc/aliases", "postmaster: root\n")
        section, findings = self.probe(aliases=aliases, config=self.OUTPUT)
        self.assertEqual(section["alerts"], "skip")
        self.assertIn("no external root alias",
                      reason(findings, "security.alerts"))

    def test_no_evidence_leaves_alerts_missing(self):
        section, findings = self.probe()
        self.assertNotIn("alerts", section)
        self.assertIn("/x/absent not present",
                      reason(findings, "security.alerts"))
        _, findings = self.probe(config=self.OUTPUT)
        self.assertIn("does not set MAILON=never",
                      reason(findings, "security.alerts"))

    def test_unattended_upgrades_means_force(self):
        section, findings = self.probe(auto=self.AUTO)
        self.assertEqual(section["updates"], "force")
        self.assertIn("unattended", reason(findings, "security.updates"))

    def test_cron_apt_without_install_action_means_skip(self):
        section, findings = self.probe(config=self.OUTPUT)
        self.assertEqual(section["updates"], "skip")
        self.assertIn("no install action",
                      reason(findings, "security.updates"))

    def test_nothing_configured_means_skip(self):
        section, findings = self.probe()
        self.assertEqual(section["updates"], "skip")
        self.assertIn("neither", reason(findings, "security.updates"))


class TestSecrets(unittest.TestCase):
    def test_root_password_is_always_a_placeholder(self):
        section, findings = secrets.probe_secrets(
            ABSENT, "/etc/keel/secrets", False
        )
        self.assertEqual(section, {"root_password": {
            "file": "/etc/keel/secrets/root_password"}})
        self.assertEqual(statuses(findings, "secrets.root_password"),
                         [NOT_EXTRACTED])

    def test_conf_variables_and_database_add_placeholders_once(self):
        conf = File("/x/c", "DB_PASS=hunter2\nAPP_PASS=hunter3\n")
        section, findings = secrets.probe_secrets(conf, "/run/s", True)
        self.assertEqual(list(section),
                         ["root_password", "db_password", "app_password"])
        self.assertEqual(section["db_password"],
                         {"file": "/run/s/db_password"})
        self.assertNotIn("hunter", str(findings) + str(section))

    def test_database_directory_alone_adds_db_password(self):
        section, _ = secrets.probe_secrets(ABSENT, "/run/s", True)
        self.assertEqual(list(section), ["root_password", "db_password"])

    def test_hub_key_is_skip(self):
        section, findings = secrets.probe_hub()
        self.assertEqual(section, {"api_key": "skip"})
        self.assertEqual(findings[0].status, INFERRED)


class TestUsers(unittest.TestCase):
    def test_public_keys_are_kept_without_their_options(self):
        text = f"# c\n{KEY}\nno-pty,from=\"2001:db8::1\" {KEY}\nssh-rsa\n"
        section, findings = users.probe_users(
            [("root", File("/x/root/.ssh/authorized_keys", text))],
            ABSENT, ABSENT,
        )
        self.assertEqual(section, {"root": {"authorized_keys": [KEY, KEY]}})
        self.assertEqual(reason(findings, "users.root.authorized_keys"),
                         "/x/root/.ssh/authorized_keys")

    def test_shell_and_groups_come_from_passwd_and_group(self):
        passwd = File("/x/etc/passwd", PASSWD)
        group = File("/x/etc/group", GROUP)
        section, findings = users.probe_users(
            [("admin", File("/x/home/admin/.ssh/authorized_keys", KEY)),
             ("root", File("/x/root/.ssh/authorized_keys", KEY))],
            passwd, group,
        )
        self.assertEqual(section["admin"], {
            "authorized_keys": [KEY], "shell": "/bin/bash",
            "groups": ["adm", "sudo"],
        })
        self.assertEqual(section["root"],
                         {"authorized_keys": [KEY], "shell": "/bin/bash"})
        self.assertEqual(reason(findings, "users.admin.shell"), "/x/etc/passwd")
        self.assertEqual(reason(findings, "users.admin.groups"), "/x/etc/group")
        self.assertEqual(statuses(findings, "users.root.groups"), [])

    def test_unreadable_passwd_and_group_are_reported_per_user(self):
        denied = File("/x/etc/passwd", problem="permission denied")
        section, findings = users.probe_users(
            [("root", File("/x/root/.ssh/authorized_keys", KEY))],
            denied, File("/x/etc/group", problem="permission denied"),
        )
        self.assertEqual(section, {"root": {"authorized_keys": [KEY]}})
        self.assertEqual(reason(findings, "users.root.shell"),
                         "/x/etc/passwd permission denied")
        self.assertEqual(reason(findings, "users.root.groups"),
                         "/x/etc/group permission denied")

    def test_a_user_without_a_passwd_entry_has_no_shell(self):
        section, findings = users.probe_users(
            [("ghost", File("/x/home/ghost/.ssh/authorized_keys", KEY))],
            File("/x/etc/passwd", PASSWD), File("/x/etc/group", GROUP),
        )
        self.assertEqual(section, {"ghost": {"authorized_keys": [KEY]}})
        self.assertEqual(reason(findings, "users.ghost.shell"),
                         "no entry in /x/etc/passwd")

    def test_unreadable_or_keyless_files_are_reported(self):
        section, findings = users.probe_users([
            ("root", ABSENT),
            ("admin", File("/x/home/admin/.ssh/authorized_keys", "# none\n")),
        ], ABSENT, ABSENT)
        self.assertIsNone(section)
        self.assertEqual(reason(findings, "users.root.authorized_keys"),
                         "/x/absent not present")
        self.assertIn("holds no public key",
                      reason(findings, "users.admin.authorized_keys"))
        self.assertEqual(statuses(findings, "users"), [NOT_INFERRED])


class TestLocale(unittest.TestCase):
    LANG = File("/x/etc/default/locale", "LANG=en_US.UTF-8\n")

    def test_timezone_file_and_lang(self):
        section, _ = locale.probe_locale(
            File("/x/etc/timezone", "Europe/Lisbon\n"), None, self.LANG
        )
        self.assertEqual(section,
                         {"timezone": "Europe/Lisbon", "lang": "en_US.UTF-8"})

    def test_localtime_symlink_is_the_fallback(self):
        section, findings = locale.probe_locale(
            ABSENT, "../usr/share/zoneinfo/Etc/UTC", ABSENT
        )
        self.assertEqual(section, {"timezone": "Etc/UTC"})
        self.assertIn("symlink", reason(findings, "locale.timezone"))
        self.assertEqual(reason(findings, "locale.lang"),
                         "/x/absent not present")

    def test_nothing_known_gives_no_section(self):
        for target in (None, "/etc/somewhere/else"):
            section, findings = locale.probe_locale(
                ABSENT, target, File("/x/etc/default/locale", "LANGUAGE=C\n")
            )
            self.assertIsNone(section)
            self.assertEqual(statuses(findings, "locale.timezone"),
                             [NOT_INFERRED])
            self.assertIn("does not set LANG",
                          reason(findings, "locale.lang"))


if __name__ == "__main__":
    unittest.main()
