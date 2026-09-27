# Copyright (c) 2026 KeelLinux maintainers
"""The two spellings of one authorization, and what is not one

keel.spec.origins is what lets a description write the prefix docs/spec.md
tells an operator to prefer while a MariaDB primary holds the host pattern
that engine has for the same range.
"""

import pytest

from keel.spec.fields import origin_error
from keel.spec.origins import as_prefix, canonical, host_pattern


class TestCanonical:
    @pytest.mark.parametrize(
        "pattern,prefix",
        [
            ("2804:710:d0:5:%", "2804:710:d0:5::/64"),
            ("2001:db8:1:%", "2001:db8:1::/48"),
            ("2001:DB8:1:%", "2001:db8:1::/48"),
            ("2001:db8:%", "2001:db8::/32"),
            ("2001:%", "2001::/16"),
            ("192.0.2.%", "192.0.2.0/24"),
            ("192.0.%", "192.0.0.0/16"),
        ],
    )
    def test_a_host_pattern_is_the_prefix_it_authorizes(
        self, pattern, prefix
    ):
        assert canonical(pattern) == prefix

    def test_the_prefix_and_the_pattern_reduce_to_one_value(self):
        assert canonical("2804:710:d0:5::/64") == canonical(
            "2804:710:d0:5:%"
        )

    def test_a_prefix_written_off_its_boundary_is_its_network(self):
        assert canonical("2001:db8:1::5/64") == "2001:db8:1::/64"

    def test_an_address_is_compressed(self):
        assert canonical("2001:0db8:0000:0000:0000:0000:0000:0020") == (
            "2001:db8::20"
        )

    @pytest.mark.parametrize(
        "text",
        [
            "Replica.Example.ORG.",
            "2001:db8:1:5%",
            "%",
            "2001:db8::%",
            "not:an:address:%%",
        ],
    )
    def test_anything_that_names_no_whole_prefix_is_only_lower_cased(
        self, text
    ):
        assert canonical(text) == text.lower().rstrip(".")

    def test_an_empty_origin_comes_back_empty(self):
        assert canonical("  ") == ""

    def test_a_full_length_pattern_is_not_a_prefix(self):
        # Eight groups and a wildcard authorize one address, not a range,
        # and ip_network would refuse the /128 spelling of it anyway.
        assert canonical("2001:db8:0:0:0:0:0:1:%") == "2001:db8:0:0:0:0:0:1:%"

    def test_a_group_outside_its_range_is_not_a_prefix(self):
        assert canonical("2001:zz:%") == "2001:zz:%"
        assert canonical("300.0.2.%") == "300.0.2.%"

    def test_a_group_that_reads_as_a_number_but_not_as_an_address(self):
        # int() accepts the spaces an address does not, so the groups are
        # counted and the result is still refused when it is assembled.
        assert canonical("2001: db8:%") == "2001: db8:%"


class TestAsPrefix:
    def test_a_prefix_is_returned_in_network_form(self):
        assert as_prefix("2001:db8:1::5/64") == "2001:db8:1::/64"

    def test_something_that_is_not_a_prefix_at_all_is_none(self):
        assert as_prefix("2001:db8::1/999") is None
        assert as_prefix("replica.example.org") is None


class TestHostPattern:
    @pytest.mark.parametrize(
        "prefix,pattern",
        [
            ("2804:710:d0:5::/64", "2804:710:d0:5:%"),
            ("2001:db8::/32", "2001:db8:%"),
            ("2001:db8:1:2:3::/80", "2001:db8:1:2:3:%"),
            ("192.0.2.0/24", "192.0.2.%"),
            ("10.0.0.0/8", "10.%"),
        ],
    )
    def test_a_group_aligned_prefix_becomes_the_engines_spelling(
        self, prefix, pattern
    ):
        assert host_pattern(prefix) == pattern

    def test_a_single_address_prefix_is_that_address(self):
        assert host_pattern("2001:db8::20/128") == "2001:db8::20"
        assert host_pattern("192.0.2.10/32") == "192.0.2.10"

    @pytest.mark.parametrize("prefix", ["2001:db8::/56", "192.0.2.0/25"])
    def test_a_prefix_that_stops_inside_a_group_has_no_spelling(
        self, prefix
    ):
        # Authorizing a /56 as a /48 or a /64 would grant more or less than
        # the description asked for, so the caller is told there is none.
        assert host_pattern(prefix) is None

    def test_the_whole_address_space_has_no_spelling(self):
        assert host_pattern("::/0") is None

    @pytest.mark.parametrize(
        "origin", ["2001:db8::20", "replica.example.org", "2001:db8:1:%"]
    )
    def test_what_a_grant_already_holds_comes_back_unchanged(self, origin):
        assert host_pattern(origin) == origin

    def test_a_prefix_that_does_not_parse_has_no_spelling(self):
        assert host_pattern("2001:db8::/999") is None

    def test_an_empty_origin_has_no_spelling(self):
        assert host_pattern("") is None


class TestAgainstTheSchema:
    """Every spelling this module produces is one the schema accepts.

    The property test of issue 25 in the other direction: there, every
    origin the reading can produce validates; here, every origin the apply
    path can write does, so a description an operator copies from a
    console screen cannot fail to load.
    """

    @pytest.mark.parametrize(
        "prefix",
        [
            "2804:710:d0:5::/64",
            "2001:db8::/32",
            "192.0.2.0/24",
            "2001:db8::20/128",
        ],
    )
    def test_every_host_pattern_validates_as_an_origin(self, prefix):
        pattern = host_pattern(prefix)

        assert pattern is not None
        assert origin_error("allowed_from", pattern) is None
