# Copyright (c) 2026 KeelLinux maintainers
"""Every validation rule of docs/manifest-v1.md refuses its fixture

One test class per rule, numbered as the format numbers them (rules 1
to 24; 25 to 27 are the spec's against the manifests, run by keel spec
validate, which reads no manifest yet). Each fixture is a manifest of
the format with one thing broken, or a small manifest written for the
rule, installed under a root the way a machine has it, and each test
checks the exit code, 3, and the message that names what is wrong.
"""

import os
import unittest
from unittest import mock

from manifest_helpers import (
    ManifestCase,
    appliance,
    hook,
    install_app,
    overlay,
    unit,
)


class Rule01TopLevel(ManifestCase):
    def test_a_newer_version_is_named_with_the_one_read(self):
        self.edit("overlays", "nginx", "manifest_version: 1",
                  "manifest_version: 2")
        self.refused("nginx",
                     "manifest_version: 2 is newer than this keel reads (1)")

    def test_a_version_that_is_not_the_integer(self):
        for value in ('"1"', "0", "true", "1.0"):
            with self.subTest(value=value):
                self.edit("overlays", "nginx", "manifest_version: 1",
                          f"manifest_version: {value}")
                self.refused("nginx", "manifest_version: must be the"
                             " integer 1")

    def test_a_missing_version(self):
        self.edit("overlays", "nginx", "manifest_version: 1\n", "")
        self.refused("nginx", "manifest_version: required")

    def test_an_unknown_kind(self):
        self.edit("overlays", "nginx", "kind: overlay", "kind: layer")
        self.refused("nginx", 'kind: must be overlay or appliance, not'
                     ' "layer"')

    def test_the_name_is_the_file_name(self):
        self.edit("overlays", "nginx", "name: nginx", "name: nginx2")
        self.refused("nginx", 'name: "nginx2" must be the file name'
                     " without .yaml, nginx")

    def test_the_name_pattern_and_length(self):
        for name in ("Nginx", "9nginx", "ng_inx", "n" * 33):
            with self.subTest(name=name):
                self.put("overlays", name, overlay(name))
                self.refused(self.path("overlays", name),
                             f'name: "{name}" must match [a-z][a-z0-9-]*'
                             " and be at most 32 characters")

    def test_title_and_summary(self):
        self.edit("overlays", "nginx", "title: Nginx\n", "")
        self.refused("nginx", "title: required")
        self.edit("overlays", "nginx", "summary: Terminates",
                  "summary: |\n  two\n  lines\n#")
        self.refused("nginx", "summary: must be one line")
        self.edit("overlays", "nginx", "title: Nginx", "title: ''")
        self.refused("nginx", "title: must be a non-empty string")


class Rule02UnknownKeys(ManifestCase):
    def test_an_unknown_top_level_key(self):
        self.edit("overlays", "nginx", "processes:", "procesess: []\n"
                  "processes:")
        self.refused("nginx", "procesess: unknown key")

    def test_an_unknown_key_at_every_level(self):
        self.edit("overlays", "nginx", "unit: nginx.service",
                  "unit: nginx.service\n    lisen: []")
        self.refused("nginx", "processes[0].lisen: unknown key")
        self.edit("overlays", "nginx", "expose: public}",
                  "expose: public, interface: eth0}")
        self.refused("nginx", "processes[0].listen[0].interface: unknown"
                     " key")
        self.edit("appliances", "web", "cloud_advanced: enabled}",
                  "cloud_advanced: enabled, default: on}")
        self.refused("web", "overlays.nginx.default: unknown key")

    def test_a_boolean_key_says_how_it_came_about(self):
        self.edit("overlays", "nginx", "processes:", "on: 1\nprocesses:")
        self.refused("nginx", "true: unknown key (read as the boolean"
                     " true: YAML 1.1 turns an unquoted on, off, yes or no"
                     " into a boolean")

    def test_a_key_of_the_other_kind(self):
        self.edit("overlays", "nginx", "processes:", "base: core\n"
                  "processes:")
        self.refused("nginx", "base: a key of an appliance manifest, not"
                     " of an overlay")
        self.edit("appliances", "web", "base: core",
                  "base: core\nprovides: {engine: redis}")
        self.refused("web", "provides: a key of an overlay manifest, not"
                     " of an appliance")

    def test_hooks_and_sections_of_the_wrong_shape(self):
        self.edit("overlays", "installer", "hooks:\n",
                  "hooks:\n  migrate: {command: [/bin/true]}\n")
        self.refused("installer", "hooks.migrate: a key of an appliance"
                     " manifest, not of an overlay")
        self.edit("overlays", "wireguard", "screen:",
                  "processes: {wg: {}}\nscreen:")
        self.refused("wireguard", "processes: must be a list")
        self.edit("overlays", "wireguard", "screen:",
                  "processes: [wg]\nscreen:")
        self.refused("wireguard", "processes[0]: must be a mapping")


class Rule03Names(ManifestCase):
    def test_a_name_of_the_wrong_shape(self):
        self.edit("overlays", "nginx", "- name: nginx",
                  "- name: Web Server")
        self.refused("nginx", 'processes[0].name: "Web Server" must match'
                     " [a-z][a-z0-9_-]*")

    def test_a_name_twice_in_its_list(self):
        self.edit("appliances", "core", "- {name: postfix,",
                  "- {name: webmin,")
        self.refused("core", 'checks[2].name: "webmin" appears twice in'
                     " checks")

    def test_secret_and_option_names_take_no_dash(self):
        self.edit("overlays", "anubis", "name: anubis_signing_key",
                  "name: anubis-signing-key")
        self.refused("anubis", 'secrets[0].name: "anubis-signing-key"'
                     " must match [a-z][a-z0-9_]*")

    def test_a_missing_name(self):
        self.edit("overlays", "nginx", "- name: nginx\n    unit",
                  "- unit")
        self.refused("nginx", "processes[0].name: required")


class Rule04Paths(ManifestCase):
    def test_paths_are_absolute_and_normalised(self):
        normalised = ": no .., no //, no trailing /"
        cases = (
            ("/var/lib/etcd/", '"/var/lib/etcd/" is not normalised'),
            ("/var/lib//etcd", '"/var/lib//etcd" is not normalised'),
            ("/var/lib/../etcd", '"/var/lib/../etcd" is not normalised'),
            ("//var/lib/etcd", '"//var/lib/etcd" is not normalised'),
            ("/", '"/" is not normalised'),
            ("var/lib/etcd", "must be an absolute path"),
        )
        for path, message in cases:
            with self.subTest(path=path):
                self.edit("overlays", "etcd", "path: /var/lib/etcd,",
                          f"path: '{path}',")
                err = self.refused("etcd", f"data[0].path: {message}")
                if "normalised" in message:
                    self.assertIn(normalised, err)

    def test_the_screen_is_a_path_too(self):
        self.edit("overlays", "crowdsec", "screen: /usr/lib/",
                  "screen: usr/lib/")
        self.refused("crowdsec", "screen: must be an absolute path")


class Rule05Units(ManifestCase):
    def test_a_unit_ends_in_service(self):
        self.edit("overlays", "etcd", "unit: etcd.service", "unit: etcd")
        self.refused("etcd", 'processes[0].unit: "etcd" must end in'
                     " .service")

    def test_the_unit_file_exists_under_the_root(self):
        os.remove(os.path.join(self.root, "usr/lib/systemd/system",
                               "etcd.service"))
        self.refused("etcd", "processes[0].unit: etcd.service has no unit"
                     f" file under {self.root}")

    def test_a_unit_in_etc_or_from_an_init_script_counts(self):
        os.remove(os.path.join(self.root, "usr/lib/systemd/system",
                               "etcd.service"))
        path = os.path.join(self.root, "etc/systemd/system", "etcd.service")
        os.makedirs(os.path.dirname(path))
        open(path, "w").close()
        code, _, err = self.cli("manifest", "validate", "etcd")
        self.assertEqual(code, 0, err)
        os.remove(path)
        script = os.path.join(self.root, "etc/init.d/etcd")
        os.makedirs(os.path.dirname(script))
        open(script, "w").close()
        os.chmod(script, 0o755)
        code, _, err = self.cli("manifest", "validate", "etcd")
        self.assertEqual(code, 0, err)


class Rule06PortsAndAddresses(ManifestCase):
    def test_a_port_out_of_range(self):
        for port in ("0", "65536", "'80'", "true"):
            with self.subTest(port=port):
                self.edit("overlays", "nginx", "{port: 443,",
                          f"{{port: {port},")
                self.refused("nginx", "processes[0].listen[1].port: must be"
                             " a port number")

    def test_a_name_is_refused_with_the_reason(self):
        for name in ("localhost", "ip6-localhost"):
            with self.subTest(name=name):
                self.edit("overlays", "crowdsec", "address: 127.0.0.1, port:"
                          " 8080", f"address: {name}, port: 8080")
                self.refused("crowdsec", f'processes[0].listen[0].address:'
                             f' "{name}" is a name, not an address: Debian'
                             " maps ::1 to ip6-localhost")

    def test_a_literal_other_than_loopback(self):
        self.edit("overlays", "crowdsec", "address: 127.0.0.1, port: 8080",
                  "address: '2001:db8::1', port: 8080")
        self.refused("crowdsec", "processes[0].listen[0].address: must be"
                     " ::1 or 127.0.0.1")

    def test_a_literal_goes_with_loopback_only(self):
        self.edit("overlays", "nginx", "{port: 443,",
                  "{address: '::1', port: 443,")
        self.refused("nginx", "processes[0].listen[1].address: a literal"
                     " loopback address goes with expose: loopback only")

    def test_a_check_names_a_class_never_a_literal(self):
        self.edit("overlays", "crowdsec", "address: loopback,",
                  "address: 127.0.0.1,")
        self.refused("crowdsec", "checks[0].address: must be loopback or"
                     " mesh, never a literal address")

    def test_expose_and_protocol(self):
        self.edit("overlays", "nginx", "{port: 80, protocol: tcp,"
                  " expose: public}", "{port: 80, protocol: sctp,"
                  " expose: world}")
        self.refused("nginx",
                     'processes[0].listen[0].protocol: must be tcp or udp,'
                     ' not "sctp"',
                     'processes[0].listen[0].expose: must be loopback, mesh'
                     ' or public, not "world"')


class Rule07Checks(ManifestCase):
    def test_the_process_is_one_of_the_overlay(self):
        self.edit("overlays", "nginx", "process: nginx,",
                  "process: nginxx,")
        self.refused("nginx", "checks[0].process: nginxx is not a process"
                     " of this overlay")

    def test_the_process_is_one_of_the_chain(self):
        self.edit("appliances", "core", "process: postfix,",
                  "process: exim,")
        self.refused("core", "checks[2].process: exim is not a process of"
                     " the chain of core")

    def test_restart_needs_a_process(self):
        self.edit("overlays", "coraza", "on_failure: alert",
                  "on_failure: restart")
        self.refused("coraza", "checks[0].on_failure: restart needs"
                     " process")

    def test_the_fields_of_the_type_and_no_others(self):
        self.edit("overlays", "crowdsec", "port: 8080, on_failure",
                  "port: 8080, path: /, on_failure")
        self.refused("crowdsec", "checks[0].path: not a field of a tcp"
                     " check")
        self.edit("overlays", "nginx", "expect: 204, ", "")
        self.refused("nginx", "checks[0].expect: required for an http"
                     " check")
        self.edit("appliances", "core", "protocol: smtp", "protocol: imap")
        self.refused("core", "checks[2].protocol: must be mysql, pgsql,"
                     ' redis, ssh or smtp, not "imap"')
        self.edit("overlays", "nginx", "type: http", "type: icmp")
        self.refused("nginx", 'checks[0].type: must be http, tcp, protocol'
                     ' or command, not "icmp"')

    def test_the_values_of_an_http_check(self):
        self.edit("overlays", "nginx", "path: /keel-health, expect: 204,",
                  "path: keel-health, expect: 999, tls: 1,")
        self.refused("nginx", "checks[0].path: must start with /",
                     "checks[0].expect: must be one HTTP status code",
                     "checks[0].tls: must be true or false")

    def test_on_failure_and_every_cycles(self):
        self.edit("overlays", "coraza", "every_cycles: 10\n"
                  "    on_failure: alert", "every_cycles: 0\n"
                  "    on_failure: reboot")
        self.refused("coraza", "checks[0].every_cycles: must be a whole"
                     " number of at least 1",
                     'checks[0].on_failure: must be restart or alert, not'
                     ' "reboot"')


class Rule08Restart(ManifestCase):
    def test_attempts_at_most_within_cycles(self):
        self.edit("overlays", "nginx", "unit: nginx.service",
                  "unit: nginx.service\n"
                  "    restart: {attempts: 6, within_cycles: 5}")
        self.refused("nginx", "processes[0].restart: attempts (6) must be"
                     " at most within_cycles (5)")

    def test_the_shape_of_restart(self):
        for value, message in (
            ("sometimes", "must be never or {attempts: N, within_cycles:"
             " M}"),
            ("{attempts: 0, within_cycles: 5}", "processes[0].restart"
             ".attempts: must be a whole number of at least 1"),
            ("{attempts: 3}", "processes[0].restart.within_cycles:"
             " required"),
            ("{attempts: 3, within_cycles: 5, delay: 1}",
             "processes[0].restart.delay: unknown key"),
        ):
            with self.subTest(value=value):
                self.edit("overlays", "nginx", "unit: nginx.service",
                          f"unit: nginx.service\n    restart: {value}")
                self.refused("nginx", message)


class Rule09Commands(ManifestCase):
    def check(self, command: str) -> None:
        self.edit("overlays", "coraza", "type: http\n    address: loopback\n"
                  "    port: 80\n    path: \"/keel-health?keel-waf-probe="
                  "%3Cscript%3Ealert(1)%3C%2Fscript%3E\"\n    expect: 403",
                  f"type: command\n    command: {command}")

    def test_a_shell_string_or_an_empty_list(self):
        for command in ("'/bin/true && x'", "[]"):
            with self.subTest(command=command):
                self.check(command)
                self.refused("coraza", "checks[0].command: must be a"
                             " non-empty argv list, never a shell string")

    def test_the_first_element_is_an_absolute_path(self):
        self.check("[curl, -f]")
        self.refused("coraza", "checks[0].command[0]: must be an absolute"
                     " path")

    def test_every_element_is_a_string(self):
        self.check("[/usr/bin/curl, 3]")
        self.refused("coraza", "checks[0].command[1]: must be a string")

    def test_a_command_check_has_no_address(self):
        self.check("[/usr/bin/curl]\n    address: loopback")
        self.refused("coraza", "checks[0].address: not a field of a command"
                     " check")


class Rule10Requires(ManifestCase):
    def test_requires_names_an_installed_overlay(self):
        self.edit("overlays", "anubis", "requires: [nginx]",
                  "requires: [nginx, redis]")
        self.refused("anubis", "requires: redis is not an installed"
                     " overlay")

    def test_the_graph_has_no_cycle(self):
        self.edit("overlays", "nginx", "processes:",
                  "requires: [coraza]\nprocesses:")
        self.refused("coraza", "requires: cycle coraza, nginx, coraza")

    def test_an_overlay_requiring_itself(self):
        self.edit("overlays", "anubis", "requires: [nginx]",
                  "requires: [anubis]")
        self.refused("anubis", "requires: cycle anubis, anubis")

    def test_the_shape_of_requires(self):
        self.edit("overlays", "anubis", "requires: [nginx]",
                  "requires: nginx")
        self.refused("anubis", "requires: must be a list")
        self.edit("overlays", "anubis", "requires: [nginx]",
                  "requires: [Nginx]")
        self.refused("anubis", 'requires[0]: "Nginx" is not an overlay'
                     " name")


class Rule11Data(ManifestCase):
    def test_replication_is_never_files(self):
        self.edit("overlays", "etcd", "replication: native",
                  "replication: files")
        self.refused("etcd", "data[0].replication: must be native or none;"
                     " never files: data with its own replication is never"
                     " replicated by file (0032)")

    def test_backup_values(self):
        self.edit("overlays", "etcd", "backup: none", "backup: rsync")
        self.refused("etcd", 'data[0].backup: must be dump, files or none,'
                     ' not "rsync"')

    def test_dump_only_with_an_engine_that_has_one(self):
        self.edit("overlays", "etcd", "backup: none", "backup: dump")
        self.refused("etcd", "data[0].backup: dump needs a provides engine"
                     " that has a dump (mariadb or postgresql)")
        self.edit("overlays", "etcd", "backup: none}",
                  "backup: dump}\nprovides: {engine: redis}")
        self.refused("etcd", "data[0].backup: dump needs a provides engine"
                     " that has a dump")

    def test_provides_names_a_known_engine(self):
        self.edit("overlays", "etcd", "requires:",
                  "provides: {engine: etcd}\nrequires:")
        self.refused("etcd", "provides.engine: must be mariadb, postgresql,"
                     ' redis, opensearch, elasticsearch or s3, not "etcd"')
        self.edit("overlays", "etcd", "requires:",
                  "provides: {engine: redis, port: 1}\nrequires:")
        self.refused("etcd", "provides.port: unknown key")

    def test_path_replication_and_backup_are_required(self):
        self.edit("overlays", "etcd", "{path: /var/lib/etcd, replication:"
                  " native, backup: none}", "{}")
        self.refused("etcd", "data[0].path: required",
                     "data[0].replication: required",
                     "data[0].backup: required")


class Rule12FirstBootHooks(ManifestCase):
    HOOK = "/usr/lib/inithooks/firstboot.d/75keel-role"

    def test_a_hook_under_the_directory(self):
        self.edit("overlays", "installer", self.HOOK, "/usr/lib/keel/role")
        self.refused("installer", "hooks.first_boot[2]: must be under"
                     " /usr/lib/inithooks/firstboot.d/")

    def test_a_hook_that_is_missing(self):
        os.remove(os.path.join(self.root, self.HOOK.lstrip("/")))
        self.refused("installer", f"hooks.first_boot[2]: {self.HOOK} does"
                     f" not exist under {self.root}")

    def test_a_hook_that_is_not_executable(self):
        hook(self.root, "75keel-role", 0o644)
        self.refused("installer", f"hooks.first_boot[2]: {self.HOOK} is not"
                     " executable")

    def test_a_hook_writable_by_others(self):
        hook(self.root, "75keel-role", 0o757)
        self.refused("installer", f"hooks.first_boot[2]: {self.HOOK} is"
                     " writable by group or others")

    def test_a_hook_not_owned_by_root(self):
        with mock.patch("keel.manifest.machine.ROOT_UID", os.getuid() + 1):
            self.refused("installer", f"hooks.first_boot[0]: /usr/lib/"
                         "inithooks/firstboot.d/00declarative is not owned"
                         " by root")

    def test_the_shape_of_hooks(self):
        self.edit("overlays", "installer", "hooks:\n  first_boot:",
                  "hooks:\n  first_boot: []\n  last_boot:")
        self.refused("installer", "hooks.last_boot: unknown key")


class Rule13Base(ManifestCase):
    def test_base_names_an_installed_appliance(self):
        self.edit("appliances", "web", "base: core", "base: nope")
        self.refused("web", "base: nope is not an installed appliance")

    def test_none_only_for_core(self):
        self.edit("appliances", "web", "base: core", "base: none")
        self.refused("web", "base: none is for core only")

    def test_core_is_built_on_debian(self):
        self.edit("appliances", "core", "base: none", "base: web")
        self.refused("core", "base: core is built on Debian: its base is"
                     " none")

    def test_the_chain_has_no_cycle(self):
        self.put("appliances", "one", appliance("one", "two"))
        self.put("appliances", "two", appliance("two", "one"))
        self.refused("one", "base: the chain has a cycle: one, two, one")

    def test_base_is_required(self):
        self.edit("appliances", "web", "base: core\n", "")
        self.refused("web", "base: required")


class Rule14OverlayStates(ManifestCase):
    def test_every_overlay_is_installed(self):
        self.edit("appliances", "web", "overlays:\n",
                  "overlays:\n  redis: {simple: disabled, cloud_simple:"
                  " disabled, cloud_advanced: disabled}\n")
        self.refused("web", "overlays.redis: no installed overlay manifest")

    def test_all_three_modes_are_written(self):
        self.edit("appliances", "web", "nginx:  {simple: enabled,  "
                  "cloud_simple: enabled, cloud_advanced: enabled}",
                  "nginx:  {simple: enabled,  cloud_simple: enabled}")
        self.refused("web", "overlays.nginx.cloud_advanced: required: every"
                     " overlay has a state in all three modes")

    def test_on_and_off_are_booleans_and_refused(self):
        for word, read in (("on", "true"), ("off", "false"),
                           ("yes", "true"), ("no", "false")):
            with self.subTest(word=word):
                self.edit("appliances", "web", "nginx:  {simple: enabled,",
                          f"nginx:  {{simple: {word},")
                self.refused("web", f"overlays.nginx.simple: read as the"
                             f" boolean {read}: YAML 1.1 turns an unquoted"
                             " on, off, yes or no into a boolean; write"
                             " enabled, disabled or ask")

    def test_a_state_that_is_no_state(self):
        self.edit("appliances", "web", "nginx:  {simple: enabled,",
                  "nginx:  {simple: maybe,")
        self.refused("web", 'overlays.nginx.simple: must be enabled,'
                     ' disabled or ask, not "maybe"')

    def test_ask_needs_a_screen(self):
        self.edit("appliances", "web", "nginx:  {simple: enabled,",
                  "nginx:  {simple: ask,")
        self.refused("web", "overlays.nginx.simple: ask needs a screen, and"
                     " nginx declares none")

    def test_ask_with_a_screen_is_valid(self):
        self.edit("appliances", "core", "crowdsec:  {simple: disabled,",
                  "crowdsec:  {simple: ask,")
        code, _, err = self.cli("manifest", "validate", "web")
        self.assertEqual(code, 0, err)

    def test_a_version_constraint(self):
        for value, ok in (("'>= 1.26'", True), ("'<< 2:1.0~rc1'", True),
                          ("'1.26'", False), ("'>= '", False),
                          ("1.26", False)):
            with self.subTest(value=value):
                self.edit("appliances", "web", "cloud_advanced: enabled}",
                          f"cloud_advanced: enabled, version: {value}}}")
                code, _, err = self.cli("manifest", "validate", "web")
                if ok:
                    self.assertEqual(code, 0, err)
                else:
                    self.assertIn("overlays.nginx.version: must be a"
                                  " constraint such as '>= 1.26'", err)

    def test_the_shape_of_overlays(self):
        self.edit("appliances", "web", "overlays:\n", "overlays:\n"
                  "  Bad: {}\n")
        self.refused("web", 'overlays: "Bad" is not an overlay name')
        self.edit("appliances", "web", "nginx:  {simple: enabled,  "
                  "cloud_simple: enabled, cloud_advanced: enabled}",
                  "nginx: enabled")
        self.refused("web", "overlays.nginx: must be a mapping")


class Rule15Requires(ManifestCase):
    def test_an_enabled_overlay_needs_its_requires_enabled(self):
        self.edit("appliances", "web", "nginx:  {simple: enabled,",
                  "nginx:  {simple: disabled,",
                  "coraza: {simple: disabled,",
                  "coraza: {simple: enabled,")
        self.refused("web", "overlays.coraza.simple: enabled, but coraza"
                     " requires nginx, which is disabled in simple")

    def test_across_the_chain(self):
        self.edit("appliances", "core", "etcd:      {simple: disabled,",
                  "etcd:      {simple: enabled,")
        self.refused("core", "overlays.etcd.simple: enabled, but etcd"
                     " requires wireguard, which is disabled in simple")

    def test_ask_counts_as_enabled(self):
        self.edit("overlays", "etcd", "requires: [wireguard]",
                  "requires: [wireguard]\nscreen: /usr/lib/x.py")
        self.edit("appliances", "core", "etcd:      {simple: disabled,",
                  "etcd:      {simple: ask,")
        self.refused("core", "overlays.etcd.simple: ask, but etcd requires"
                     " wireguard, which is disabled in simple")

    def test_a_requirement_the_chain_does_not_carry(self):
        self.put("overlays", "lonely", overlay("lonely", "requires: [etcd]\n"))
        self.edit("appliances", "web", "overlays:\n", "overlays:\n"
                  "  lonely: {simple: disabled, cloud_simple: disabled,"
                  " cloud_advanced: disabled}\n")
        self.edit("appliances", "core", "  etcd:      {simple: disabled,"
                  " cloud_simple: disabled, cloud_advanced: enabled}\n", "")
        self.refused("web", "overlays.lonely: requires etcd, which no"
                     " appliance of the chain carries")


class Rule16OverlayOnce(ManifestCase):
    def test_an_overlay_appears_once_in_the_chain(self):
        self.edit("appliances", "web", "overlays:\n", "overlays:\n"
                  "  etcd: {simple: disabled, cloud_simple: disabled,"
                  " cloud_advanced: enabled}\n")
        self.refused("web", "overlays.etcd: already carried by core")


class Rule17Ports(ManifestCase):
    def test_a_port_is_taken_across_the_chain_whatever_the_states(self):
        unit(self.root, "php-fpm")
        self.put("overlays", "php-fpm", overlay("php-fpm", (
            "processes:\n  - name: php-fpm\n    unit: php-fpm.service\n"
            "    listen: [{port: 8080, protocol: tcp, expose: loopback}]\n")))
        self.put("appliances", "php", appliance("php", "web", (
            "overlays:\n  php-fpm: {simple: enabled, cloud_simple: enabled,"
            " cloud_advanced: enabled}\n")))
        self.refused("php", "port 8080/tcp: declared by crowdsec, core"
                     " (crowdsec), and again by php-fpm, php (php-fpm)")

    def test_the_same_number_on_another_protocol_is_free(self):
        self.edit("overlays", "anubis", "{port: 8923, protocol: tcp,",
                  "{port: 8080, protocol: udp,")
        code, _, err = self.cli("manifest", "validate", "web")
        self.assertEqual(code, 0, err)

    def test_twice_in_one_overlay(self):
        self.edit("overlays", "nginx", "{port: 443,", "{port: 80,")
        self.refused("nginx", "processes[0].listen[1]: 80/tcp is already"
                     " declared by processes[0].listen[0]")


class Rule18NamesAcrossTheChain(ManifestCase):
    def test_a_process_name_taken_by_the_base(self):
        self.edit("overlays", "anubis", "- name: anubis\n    unit",
                  "- name: sshd\n    unit",
                  "process: anubis,", "process: sshd,")
        self.refused("web", "process sshd: declared by core, and again by"
                     " web (anubis)")

    def test_check_and_secret_names(self):
        self.edit("overlays", "nginx", "{name: nginx, process",
                  "{name: postfix, process")
        self.edit("overlays", "anubis", "name: anubis_signing_key",
                  "name: root_password")
        self.refused("web", "check postfix: declared by core, and again by"
                     " web (nginx)",
                     "secret root_password: declared by core, and again by"
                     " web (anubis)")


class Rule19ApplicationOnce(ManifestCase):
    def setUp(self):
        super().setUp()
        install_app(self.root)

    def test_the_application_is_valid(self):
        code, out, err = self.cli("manifest", "validate", "blog")
        self.assertEqual(code, 0, err)
        self.assertIn("blog: resolved along core, web, blog", out)

    def test_two_manifests_of_a_chain_declare_application_sections(self):
        self.edit("appliances", "web", "overlays:",
                  "web: {root: /var/www/html}\noverlays:")
        self.refused("blog", "application sections: declared by web and by"
                     " blog; a chain has one application, at its top")

    def test_the_application_is_at_the_top(self):
        self.edit("appliances", "web", "overlays:",
                  "web: {root: /var/www/html}\noverlays:")
        self.put("appliances", "shop", appliance("shop", "web"))
        self.refused("shop", "application sections: declared by web, which"
                     " is not the top of the chain of shop")


class Rule20SharedSecrets(ManifestCase):
    def test_a_shared_secret_is_generated(self):
        self.edit("overlays", "anubis", "generate: required",
                  "generate: never")
        self.refused("anubis", "secrets[0].shared: a shared secret is"
                     " generated (generate: required or allowed): a person"
                     " cannot be relied on to type the same value twice")

    def test_the_fields_of_a_secret(self):
        self.edit("overlays", "anubis", "generate: required\n"
                  "    shared: true", "generate: sometimes\n    shared: yes"
                  "\n    file: /etc/x")
        self.refused("anubis",
                     'secrets[0].generate: must be allowed, required or'
                     ' never, not "sometimes"',
                     "secrets[0].file: unknown key")
        self.edit("overlays", "anubis", "    shared: true", "    shared: 1")
        self.refused("anubis", "secrets[0].shared: must be true or false")
        self.edit("overlays", "anubis", "    description: The key Anubis"
                  " signs its challenge cookies with\n", "")
        self.refused("anubis", "secrets[0].description: required")


if __name__ == "__main__":
    unittest.main()
