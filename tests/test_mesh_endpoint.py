# Copyright (c) 2026 KeelLinux maintainers
"""keel.mesh.endpoint: the address another node reaches this one at

Found on the uplink when the spec declares no static address (a DHCP or
SLAAC host): its global, stable IPv6 address, else a public IPv4 one;
never a unique local address or one of the overlay's.
"""

import unittest

from keel.mesh import endpoint

# `ip -o address show scope global` on a SLAAC and DHCP host
HELD = """\
2: eth0    inet 10.88.5.212/24 metric 100 brd 10.88.5.255 scope global dynamic eth0\\       valid_lft 81578sec preferred_lft 81578sec
2: eth0    inet6 2804:710:d0:5:be24:11ff:fece:a035/64 scope global dynamic mngtmpaddr noprefixroute \\       valid_lft 2591782sec preferred_lft 604582sec
3: lxcbr0    inet 10.0.3.1/24 brd 10.0.3.255 scope global lxcbr0\\       valid_lft forever preferred_lft forever
3: lxcbr0    inet6 fc42:5009:ba4b:5ab0::1/64 scope global \\       valid_lft forever preferred_lft forever
4: wg0    inet6 fd00:6b65:1::1/64 scope global \\       valid_lft forever preferred_lft forever
"""  # noqa: E501
ROUTES6 = ("default nhid 61 via fe80::be24:11ff:fe71:707d dev eth0 proto ra"
           " metric 100 expires 1581sec pref medium\n")
ROUTES4 = "default via 10.88.5.254 dev eth0 proto dhcp src 10.88.5.212\n"


def line(iface: str, address: str, flags: str = "") -> str:
    family = "inet6" if ":" in address else "inet"
    return (f"2: {iface}    {family} {address} scope global {flags}"
            " \\       valid_lft 100sec preferred_lft 100sec\n")


def reader(held: str, routes6: str = ROUTES6, routes4: str = ROUTES4):
    def output(argv):
        if argv[:3] == ("ip", "-o", "address"):
            return held
        if argv[:2] == ("ip", "-6"):
            return routes6
        if argv[:2] == ("ip", "-4"):
            return routes4
        raise AssertionError(argv)
    return output


class TestHeld(unittest.TestCase):
    def test_parsed_with_their_flags(self):
        found = endpoint.held(HELD)
        self.assertEqual(found[1].iface, "eth0")
        self.assertEqual(str(found[1].address),
                         "2804:710:d0:5:be24:11ff:fece:a035")
        self.assertIn("mngtmpaddr", found[1].flags)
        self.assertEqual([one.iface for one in found],
                         ["eth0", "eth0", "lxcbr0", "lxcbr0", "wg0"])

    def test_what_is_not_an_address_line_is_skipped(self):
        self.assertEqual(endpoint.held("garbage\n1: lo inet6 x/1\n"), [])

    def test_uplinks_from_the_default_routes(self):
        self.assertEqual(endpoint.uplinks(ROUTES6 + ROUTES4), ("eth0",))
        self.assertEqual(endpoint.uplinks("default via 192.0.2.1\n"), ())


class TestPick(unittest.TestCase):
    def pick(self, held, uplinks=("eth0",)):
        return endpoint.pick(endpoint.held(held), uplinks)

    def test_the_uplink_s_stable_ipv6_and_not_rfc1918(self):
        found = self.pick(HELD)
        self.assertEqual(found.addresses,
                         ("2804:710:d0:5:be24:11ff:fece:a035",))
        self.assertEqual(found.refused, ())
        self.assertIn("eth0", found.said[0])

    def test_a_static_address_before_a_slaac_one(self):
        found = self.pick(line("eth0", "2001:db8::a/64", "dynamic mngtmpaddr")
                          + line("eth0", "2001:db8::5/64"))
        self.assertEqual(found.addresses, ("2001:db8::5",))

    def test_a_public_ipv4_beside_the_ipv6(self):
        found = self.pick(line("eth0", "2001:db8::5/64")
                          + line("eth0", "198.51.100.7/24", "dynamic"))
        self.assertEqual(found.addresses, ("2001:db8::5", "198.51.100.7"))

    def test_no_ula_no_wg_and_nothing_off_the_uplink(self):
        found = self.pick(line("eth0", "fd12::5/64")
                          + line("wg0", "2001:db8:7::1/64")
                          + line("eth1", "2001:db8:8::1/64"))
        self.assertEqual(found.addresses, ())
        self.assertIn("no global address", found.refused[0])

    def test_without_a_default_route_any_interface_but_wg(self):
        found = self.pick(line("wg0", "2001:db8:7::1/64")
                          + line("eth1", "2001:db8:8::1/64"), uplinks=())
        self.assertEqual(found.addresses, ("2001:db8:8::1",))

    def test_deprecated_and_temporary_are_not_stable(self):
        found = self.pick(line("eth0", "2001:db8::d/64", "deprecated dynamic")
                          + line("eth0", "2001:db8::7/64",
                                 "temporary dynamic")
                          + line("eth0", "203.0.113.9/24"))
        self.assertEqual(found.addresses, ("203.0.113.9",))
        self.assertEqual(found.refused, ())
        self.assertIn("privacy", found.said[-1])

    def test_only_a_privacy_address_is_refused(self):
        found = self.pick(line("eth0", "2001:db8::7/64", "temporary dynamic"))
        self.assertEqual(found.addresses, ())
        self.assertIn("privacy address", found.refused[0])

    def test_only_rfc1918_or_carrier_nat_is_refused(self):
        for address in ("10.0.0.5/24", "100.64.1.5/10"):
            found = self.pick(line("eth0", address, "dynamic"))
            self.assertEqual(found.addresses, ())
            self.assertIn("RFC 1918", found.refused[0])

    def test_a_privacy_ipv6_and_rfc1918_are_both_refused(self):
        found = self.pick(line("eth0", "2001:db8::7/64", "temporary")
                          + line("eth0", "192.168.1.5/24"))
        self.assertEqual(found.addresses, ())
        self.assertEqual(len(found.refused), 2)


class TestDetect(unittest.TestCase):
    def test_through_ip(self):
        found = endpoint.detect(reader(HELD))
        self.assertEqual(found.addresses,
                         ("2804:710:d0:5:be24:11ff:fece:a035",))

    def test_ip_gives_no_answer(self):
        found = endpoint.detect(lambda argv: None)
        self.assertEqual(found.addresses, ())


if __name__ == "__main__":
    unittest.main()
