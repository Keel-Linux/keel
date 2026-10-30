"""state.replicate and state.exclude add up along the chain (keel#246, 0068)"""

import unittest

from manifest_helpers import ManifestCase, appliance

from keel.manifest import Catalog, resolve

WEB_STATE = ("state:\n  replicate:\n    - /var/www/keel-default\n"
             "overlays:")


def state(*replicate: str, exclude: tuple = ()) -> str:
    text = "state:\n  replicate:\n" + "".join(
        f"    - {path}\n" for path in replicate)
    if exclude:
        text += "  exclude:\n" + "".join(f"    - {path}\n" for path in exclude)
    return text


class StateAddsUpAlongTheChain(ManifestCase):
    def setUp(self):
        super().setUp()
        self.edit("appliances", "web", "overlays:", WEB_STATE)

    def resolved(self, name: str):
        catalog = Catalog(self.root)
        return resolve(catalog, catalog.read("appliance", name))

    def valid(self, name: str) -> None:
        code, _, err = self.cli("manifest", "validate", name)
        self.assertEqual(code, 0, err)

    def test_the_top_adds_its_paths_to_the_base(self):
        self.put("appliances", "shop", appliance(
            "shop", "web", state("/var/lib/shop")))
        self.valid("shop")
        found, errors = self.resolved("shop")
        self.assertEqual(errors, [])
        self.assertEqual(found.application.item["state"]["replicate"],
                         ["/var/www/keel-default", "/var/lib/shop"])

    def test_a_path_declared_twice_is_kept_once(self):
        self.put("appliances", "stack", appliance("stack", "web"))
        self.put("appliances", "shop", appliance(
            "shop", "stack", state("/var/www/keel-default", "/var/lib/shop")))
        self.valid("shop")
        found, _ = self.resolved("shop")
        self.assertEqual(found.application.item["state"]["replicate"],
                         ["/var/www/keel-default", "/var/lib/shop"])

    def test_services_stay_with_one_owner(self):
        self.edit("appliances", "web", "overlays:",
                  "web: {root: /var/www/html}\n" + WEB_STATE)
        self.put("appliances", "shop", appliance(
            "shop", "web", "web: {root: /var/www/shop}\n"))
        self.refused("shop", "application sections: declared by web and by"
                     " shop; only the top of the chain (shop) may declare"
                     " them when more than one manifest has them")

    def test_an_exclude_inside_the_base_path_is_valid(self):
        self.put("appliances", "shop", appliance(
            "shop", "web", "state:\n  exclude:\n"
            "    - /var/www/keel-default/cache\n"))
        self.valid("shop")
        found, _ = self.resolved("shop")
        self.assertEqual(found.application.item["state"]["exclude"],
                         ["/var/www/keel-default/cache"])

    def test_an_exclude_outside_every_path_is_refused(self):
        self.put("appliances", "shop", appliance(
            "shop", "web", state("/var/lib/shop", exclude=("/srv/x",))))
        self.refused("shop", "state.exclude[0]: /srv/x is inside no"
                     " replicated path")

    def test_a_path_inside_a_base_path_is_refused(self):
        self.put("appliances", "shop", appliance(
            "shop", "web", state("/var/www/keel-default/shop")))
        self.refused("shop", "state.replicate: /var/www/keel-default/shop,"
                     " from shop, is inside /var/www/keel-default, from web")

    def test_a_top_path_that_holds_a_base_path_is_refused(self):
        self.put("appliances", "shop", appliance(
            "shop", "web", state("/var/www")))
        self.refused("shop", "state.replicate: /var/www/keel-default, from"
                     " web, is inside /var/www, from shop")

    def test_an_exclude_declared_twice_is_kept_once(self):
        cache = "/var/www/keel-default/cache"
        self.edit("appliances", "web", "overlays:", state(
            "/var/www/keel-default", exclude=(cache,)) + "overlays:")
        self.put("appliances", "shop", appliance(
            "shop", "web", f"state:\n  exclude:\n    - {cache}\n"))
        self.valid("shop")
        found, _ = self.resolved("shop")
        self.assertEqual(found.application.item["state"]["exclude"], [cache])

    def test_show_names_the_manifest_of_each_path(self):
        self.put("appliances", "shop", appliance(
            "shop", "web", state("/var/lib/shop")))
        code, out, err = self.cli("manifest", "show", "shop", "--resolved")
        self.assertEqual(code, 0, err)
        self.assertIn("Replicated paths\n| Path | From |\n| --- | --- |\n"
                      "| /var/www/keel-default | web |\n"
                      "| /var/lib/shop | shop |\n", out)


class TheStableOneChains(ManifestCase):
    """The state sections of the published web, lnpp, lnmp, odoo, wordpress"""

    def setUp(self):
        super().setUp()
        self.edit("appliances", "web", "overlays:", WEB_STATE)

    def test_odoo_on_lnpp_on_web(self):
        self.put("appliances", "lnpp", appliance("lnpp", "web"))
        self.put("appliances", "odoo", appliance("odoo", "lnpp", state(
            "/var/lib/odoo/filestore", "/opt/odoo/extra-addons")))
        code, out, err = self.cli("manifest", "validate", "odoo")
        self.assertEqual(code, 0, err)
        self.assertIn("odoo: resolved along core, web, lnpp, odoo", out)

    def test_wordpress_on_lnmp_on_web(self):
        self.put("appliances", "lnmp", appliance("lnmp", "web"))
        content = "/var/www/wordpress/wp-content"
        self.put("appliances", "wordpress", appliance(
            "wordpress", "lnmp", state(
                f"{content}/uploads", f"{content}/themes",
                f"{content}/plugins", f"{content}/languages")))
        code, out, err = self.cli("manifest", "validate", "wordpress")
        self.assertEqual(code, 0, err)
        self.assertIn("wordpress: resolved along core, web, lnmp, wordpress",
                      out)


if __name__ == "__main__":
    unittest.main()
