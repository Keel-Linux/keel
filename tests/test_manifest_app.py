# Copyright (c) 2026 KeelLinux maintainers
"""The application sections and options (docs/manifest-v1.md, appendix)

Rules 21 to 24 of the format, each refusing its fixture, and the
options every appliance may declare. The fixture is tests/fixtures/
manifest/app/: a blog on Keel Web with an embedded MariaDB, which uses
every application section, since the format's own appendix examples
stand on appliances (Keel PHP, Keel Python) that are not built yet.
"""

import unittest

from manifest_helpers import ManifestCase, app_fixture, install_app


class AppCase(ManifestCase):
    def setUp(self):
        super().setUp()
        install_app(self.root)

    def blog(self, *pairs: str) -> None:
        """Install the blog with each OLD, NEW pair of text replaced"""
        text = app_fixture("appliances", "blog")
        for old, new in zip(pairs[::2], pairs[1::2]):
            self.assertIn(old, text)
            text = text.replace(old, new)
        self.put("appliances", "blog", text)


class Rule21Services(AppCase):
    def test_an_engine_that_is_not_provided_by_anything(self):
        for engine in ("mysql", "[mariadb, mysql]", "[]"):
            with self.subTest(engine=engine):
                self.blog("engine: mariadb", f"engine: {engine}")
                self.refused("blog", "services.database.engine: must be one"
                             " of mariadb, postgresql, redis, opensearch,"
                             " elasticsearch, s3, or a list of them")

    def test_none_only_when_not_required(self):
        self.blog("placement: {simple: embedded,", "placement: {simple: none,")
        self.refused("blog", "services.database.placement.simple: none only"
                     " when required is false")

    def test_a_placement_that_is_no_placement(self):
        self.blog("placement: {simple: embedded,",
                  "placement: {simple: remote,")
        self.refused("blog", "services.database.placement.simple: must be"
                     ' embedded, discovered or none, not "remote"')
        self.blog("placement: {simple: embedded, cloud_simple: embedded,\n"
                  "                cloud_advanced: discovered}",
                  "placement: {simple: embedded}")
        self.refused("blog", "services.database.placement.cloud_simple:"
                     " required")

    def test_embedded_needs_an_enabled_overlay_providing_the_engine(self):
        self.blog("cloud_simple: enabled, cloud_advanced: disabled",
                  "cloud_simple: disabled, cloud_advanced: disabled")
        self.refused("blog", "services.database.placement.cloud_simple:"
                     " embedded, but no overlay of the chain that provides"
                     " mariadb is enabled in cloud_simple")

    def test_the_fields_of_a_service(self):
        self.blog("    durable: true\n    secret", "    durable: 1\n"
                  "    replicas: 2\n    secret")
        self.refused("blog", "services.database.durable: must be true or"
                     " false", "services.database.replicas: unknown key")
        self.blog("    required: true\n", "")
        self.refused("blog", "services.database.required: required")
        self.blog("defaults: {name: blog, user: blog}",
                  "defaults: {name: blog, owner: blog}")
        self.refused("blog", "services.database.defaults.owner: unknown key")
        self.blog("version: \">= 10.11\"", "version: 10.11")
        self.refused("blog", "services.database.version: must be a"
                     " constraint such as '>= 1.26'")
        self.blog("services:\n  database:", "services:\n  Database:")
        self.refused("blog", 'services: "Database" must match'
                     " [a-z][a-z0-9_-]*")

    def test_rebuild_is_for_derived_data(self):
        self.blog("    durable: false\n    rebuild",
                  "    durable: true\n    rebuild")
        self.refused("blog", "services.search.rebuild: only for durable:"
                     " false")
        self.blog("rebuild: [/usr/lib/blog/reindex]", "rebuild: reindex")
        self.refused("blog", "services.search.rebuild: must be a non-empty"
                     " argv list")


class Rule22Declared(AppCase):
    def test_a_service_secret_is_declared_here(self):
        self.blog("secret: db_password", "secret: database_password")
        self.refused("blog", "services.database.secret: database_password"
                     " is not a secret of this manifest")

    def test_migrate_needs_and_a_worker_queue_are_services_here(self):
        self.blog("needs: [database]", "needs: [cache]")
        self.refused("blog", "hooks.migrate.needs[0]: cache is not a"
                     " service of this manifest")
        self.blog("queue: database", "queue: redis")
        self.refused("blog", "workers[0].queue: redis is not a service of"
                     " this manifest")

    def test_the_shape_of_migrate(self):
        self.blog("migrate: {command: [/usr/lib/blog/migrate],",
                  "migrate: {command: migrate, when: always,")
        self.refused("blog", "hooks.migrate.command: must be a non-empty"
                     " argv list", "hooks.migrate.when: unknown key")
        self.blog("migrate: {command: [/usr/lib/blog/migrate], needs:"
                  " [database]}", "migrate: {needs: database}")
        self.refused("blog", "hooks.migrate.command: required",
                     "hooks.migrate.needs: must be a list")


class Rule23State(AppCase):
    def test_a_path_under_a_system_directory(self):
        for path in ("/etc/blog", "/var/log/blog", "/run/blog", "/usr"):
            with self.subTest(path=path):
                self.blog("- /var/www/blog/content\n",
                          f"- {path}\n")
                self.refused("blog", f"state.replicate[0]: {path} is under"
                             " a directory that is never replicated")

    def test_a_path_inside_another(self):
        self.blog("{path: /var/www/blog/media,",
                  "{path: /var/www/blog/content/media,")
        self.refused("blog", "state.replicate[1]: /var/www/blog/content/"
                     "media is inside /var/www/blog/content")

    def test_a_path_inside_the_data_of_an_overlay(self):
        self.blog("- /var/www/blog/content/cache",
                  "- /var/lib/mysql/blog/cache",
                  "- /var/www/blog/content\n", "- /var/lib/mysql/blog\n")
        self.refused("blog", "state.replicate[0]: /var/lib/mysql/blog is"
                     " inside /var/lib/mysql, the data of mariadb")

    def test_an_exclude_inside_no_replicated_path(self):
        self.blog("- /var/www/blog/content/cache", "- /srv/cache")
        self.refused("blog", "state.exclude[0]: /srv/cache is inside no"
                     " replicated path")

    def test_unless_names_an_optional_service(self):
        self.blog("unless: search}", "unless: database}")
        self.refused("blog", "state.replicate[1].unless: database is not a"
                     " service with required: false")
        self.blog("unless: search}", "unless: search, mode: rw}")
        self.refused("blog", "state.replicate[1].mode: unknown key")

    def test_the_shape_of_state(self):
        self.blog("  exclude:\n", "  keep: []\n  exclude:\n")
        self.refused("blog", "state.keep: unknown key")
        self.blog("- /var/www/blog/content\n", "- 3\n")
        self.refused("blog", "state.replicate[0]: must be a path or"
                     " {path: P, unless: S}")


class Rule24Workers(AppCase):
    def test_a_worker_has_a_unit(self):
        self.blog("{name: mailer, unit: blog-mailer.service}",
                  "{name: mailer}")
        self.refused("blog", "workers[1].unit: required")

    def test_a_worker_never_writes(self):
        self.blog("{name: mailer, unit: blog-mailer.service}",
                  "{name: mailer, unit: blog-mailer.service,"
                  " writes: [/srv]}")
        self.refused("blog", "workers[1].writes: unknown key: a worker"
                     " never writes to local disk (0034, 0041)")

    def test_scaling(self):
        self.blog("scaling: {default: 1, max: 1, singleton: true}",
                  "scaling: {default: 3, max: 2, singleton: false}")
        self.refused("blog", "workers[0].scaling: default (3) must be at"
                     " most max (2)")
        self.blog("scaling: {default: 1, max: 1, singleton: true}",
                  "scaling: {default: 1, max: 2, singleton: true}")
        self.refused("blog", "workers[0].scaling: singleton: true means"
                     " max: 1")
        self.blog("scaling: {default: 1, max: 1, singleton: true}",
                  "scaling: {default: 0, max: 1, singleton: 1}")
        self.refused("blog", "workers[0].scaling.default: must be a whole"
                     " number of at least 1",
                     "workers[0].scaling.singleton: must be true or false")

    def test_every_is_a_time_span(self):
        self.blog("every: 5min", "every: often")
        self.refused("blog", 'workers[0].every: "often" is not a time span'
                     " such as 5min")

    def test_the_worker_unit_file_exists(self):
        self.blog("unit: blog-mailer.service", "unit: blog-sender.service")
        self.refused("blog", "workers[1].unit: blog-sender.service has no"
                     " unit file")


class TestWeb(AppCase):
    def test_the_fields_of_web(self):
        self.blog("  max_body: 64M", "  max_body: lots\n  vhost: x")
        self.refused("blog", 'web.max_body: "lots" must be a size such as'
                     " 128M", "web.vhost: unknown key")
        self.blog("- {path: /, to: php}", "- {path: /, to: ruby}")
        self.refused("blog", "web.routes[0].to: must be php or {port: N}")
        self.blog("- {path: /, to: php}", "- {path: x, to: {port: 0}}")
        self.refused("blog", "web.routes[0].path: must start with /",
                     "web.routes[0].to.port: must be a port number")
        self.blog("health: {path: /health, expect: 200}",
                  "health: {path: /health}")
        self.refused("blog", "web.health.expect: required")
        self.blog("websocket: true}", "websocket: yes please}")
        self.refused("blog", "web.routes[1].websocket: must be true or"
                     " false")


class TestOptions(AppCase):
    def test_the_types_and_their_defaults(self):
        cases = (
            ("{name: posts, type: integer, default: 10}",
             "{name: posts, type: integer, default: ten}",
             "options[1].default: must be an integer"),
            ("{name: posts, type: integer, default: 10}",
             "{name: posts, type: integer, default: true}",
             "options[1].default: must be an integer"),
            ("{name: comments, type: boolean, default: true}",
             "{name: comments, type: boolean, default: 'yes'}",
             "options[2].default: must be true or false"),
            ("{name: theme, type: enum, values: [light, dark],"
             " default: light}",
             "{name: theme, type: enum, values: [light, dark],"
             " default: blue}",
             'options[3].default: "blue" is not one of light, dark'),
            ("{name: theme, type: enum, values: [light, dark],"
             " default: light}",
             "{name: theme, type: enum}",
             "options[3].values: required for an enum"),
            ("{name: posts, type: integer, default: 10}",
             "{name: posts, type: integer, values: [1]}",
             "options[1].values: only for an enum"),
            ("{name: posts, type: integer, default: 10}",
             "{name: posts, type: integer, pattern: '^1$'}",
             "options[1].pattern: only for a string"),
            ("{name: posts, type: integer, default: 10}",
             "{name: posts, type: float}",
             'options[1].type: must be string, integer, boolean or enum,'
             ' not "float"'),
            ("{name: site_title, type: string, default: Blog,"
             " pattern: '^.{1,80}$'}",
             "{name: site_title, type: string, default: Blog,"
             " pattern: '^[a-z]+$'}",
             'options[0].default: "Blog" does not match ^[a-z]+$'),
            ("{name: site_title, type: string, default: Blog,"
             " pattern: '^.{1,80}$'}",
             "{name: site_title, type: string, pattern: '(['}",
             "options[0].pattern: not a regular expression"),
            ("{name: site_title, type: string, default: Blog,"
             " pattern: '^.{1,80}$'}",
             "{name: site_title, type: string, default: 3}",
             "options[0].default: must be a string"),
            ("{name: theme, type: enum, values: [light, dark],"
             " default: light}",
             "{name: theme, type: enum, values: light}",
             "options[3].values: must be a non-empty list of strings"),
        )
        for old, new, message in cases:
            with self.subTest(new=new):
                self.blog(old, new)
                self.refused("blog", message)

    def test_an_overlay_has_no_options(self):
        self.edit("overlays", "nginx", "processes:",
                  "options: []\nprocesses:")
        self.refused("nginx", "options: a key of an appliance manifest,"
                     " not of an overlay")


class TestShowApplication(AppCase):
    def test_options_and_the_application_are_printed(self):
        code, out, err = self.cli("manifest", "show", "blog", "--resolved")
        self.assertEqual(code, 0, err)
        self.assertIn("| mariadb | blog | enabled | enabled | disabled |",
                      out)
        self.assertIn("| 3306/tcp | mariadb | blog (mariadb) | loopback,"
                      " IPv6 |", out)
        self.assertIn("| blog | blog.service | blog | never |", out)
        self.assertIn("| mariadb | mariadb.service | blog (mariadb) |"
                      " 2 restarts within 10 cycles |", out)
        self.assertIn("| mariadb-ping | mariadb | blog (mariadb) | command"
                      " /usr/bin/mariadb-admin ping | alert | 1 cycle |",
                      out)
        self.assertIn("| blog-nginx | nginx | blog | tcp loopback port 443"
                      " | alert | 1 cycle |", out)
        self.assertIn("Options\n| Option | From | Type | Default |\n"
                      "| --- | --- | --- | --- |\n"
                      "| site_title | blog | string | Blog |\n"
                      "| posts | blog | integer | 10 |\n"
                      "| comments | blog | boolean | true |\n"
                      "| theme | blog | enum: light, dark | light |\n"
                      "| domain | blog | string | none: required |\n", out)
        self.assertIn("| app_password | blog | never | no | The"
                      " administrator |", out)
        self.assertIn("| /usr/lib/inithooks/firstboot.d/40blog | blog |",
                      out)
        self.assertIn("Application, from blog\nservices:\n  database:\n",
                      out)
        self.assertTrue(out.endswith("  migrate:\n    command:\n"
                                     "    - /usr/lib/blog/migrate\n"
                                     "    needs:\n    - database\n"))


if __name__ == "__main__":
    unittest.main()
