# Copyright (c) 2026 KeelLinux maintainers
"""The installation modes an appliance allows, and the witness (0076)

`modes:` lists the modes of decision 0028 that an appliance may be
installed in; it is optional, and all three is the default. `witness:`
says that the appliance may be the cloud advanced witness, which is Keel
Core alone (0057, 0076). confconsole reads both through
keel.manifest.facts.gather, so the facts are tested here too.
"""

from manifest_helpers import ManifestCase, appliance, fixture

from keel.manifest.constants import MODES
from keel.manifest.facts import gather


class TheModesAnApplianceAllows(ManifestCase):
    def facts(self, name: str):
        found = gather(self.root, name)
        self.assertEqual(found.problems, ())
        return found

    def test_without_the_keys_every_mode_is_allowed_and_no_witness(self):
        code, out, err = self.cli("manifest", "validate", "web")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.facts("web").modes, MODES)
        self.assertFalse(self.facts("web").witness)
        self.assertFalse(self.facts("core").witness)

    def test_a_list_of_modes_is_taken_in_the_order_of_0028(self):
        self.edit("appliances", "web", "base: core\n",
                  "base: core\nmodes: [cloud_simple, simple]\n")
        code, _, err = self.cli("manifest", "validate", "web")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.facts("web").modes, ("simple", "cloud_simple"))

    def test_core_may_be_the_witness(self):
        self.edit("appliances", "core", "base: none\n",
                  "base: none\nwitness: true\n")
        code, _, err = self.cli("manifest", "validate", "core")
        self.assertEqual(code, 0, err)
        self.assertTrue(self.facts("core").witness)
        # a witness is Core's own word: what is built on Core is not one
        self.assertFalse(self.facts("web").witness)

    def test_modes_must_be_a_list_of_known_modes_without_repeats(self):
        for value, message in (
                ("simple", "modes: must be a list"),
                ("[]", "modes: must name at least one mode"),
                ("[simple, cloudy]", "modes[1]: must be simple, cloud_simple"
                 " or cloud_advanced"),
                ("[simple, simple]", "modes[1]: simple is listed twice"),
                ("[true]", "modes[0]: read as the boolean true")):
            with self.subTest(value=value):
                self.edit("appliances", "web", "base: core\n",
                          f"base: core\nmodes: {value}\n")
                self.refused("web", message)

    def test_witness_is_true_or_false_and_for_core_in_cloud_advanced(self):
        self.edit("appliances", "core", "base: none\n",
                  "base: none\nwitness: yes please\n")
        self.refused("core", "witness: must be true or false")
        self.edit("appliances", "web", "base: core\n",
                  "base: core\nwitness: true\n")
        self.refused("web", "witness: only Keel Core (core) may be the cloud"
                     " advanced witness (decisions 0057, 0076)")
        self.edit("appliances", "core", "base: none\n",
                  "base: none\nmodes: [simple, cloud_simple]\nwitness: true\n")
        self.refused("core", "witness: true needs cloud_advanced in modes")
        self.edit("appliances", "core", "base: none\n",
                  "base: none\nwitness: false\n")
        code, _, err = self.cli("manifest", "validate", "core")
        self.assertEqual(code, 0, err)

    def test_an_overlay_has_no_modes_and_no_witness(self):
        text = fixture("overlays", "nginx")
        self.put("overlays", "nginx", text + "modes: [simple]\nwitness: false\n")
        self.refused("nginx", "modes: a key of an appliance manifest, not of"
                     " an overlay", "witness: a key of an appliance manifest,"
                     " not of an overlay")

    def test_the_chain_narrows_the_modes(self):
        """A child is never installed in a mode its base cannot run in, so
        a child that says nothing takes its base's modes"""
        self.put("appliances", "single",
                 appliance("single", "core", "modes: [simple]\n"))
        self.put("appliances", "child", appliance("child", "single"))
        code, _, err = self.cli("manifest", "validate", "child")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.facts("child").modes, ("simple",))
        self.put("appliances", "wider", appliance(
            "wider", "single", "modes: [simple, cloud_simple]\n"))
        self.refused("wider", "modes: cloud_simple is not a mode of the"
                     " base single (it allows simple)")

    def test_a_chain_that_does_not_resolve_has_no_modes(self):
        self.edit("appliances", "web", "base: core", "base: nope")
        found = gather(self.root, "web")
        self.assertTrue(found.problems)
        self.assertEqual(found.modes, MODES)
        self.assertFalse(found.witness)
