"""Unit + property tests for the CIDR normalization core (stdlib only)."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import itertools
import random

import pytest

from app.policy import (
    _anonymize_address,
    _normalize_family,
    _parse_nameserver,
    _parse_reverse_cidr,
    allocate,
    anonymize,
    audit_rules,
    compare,
    evaluate,
    locate_free_addresses,
    minimize_policy,
    nat64_codec,
    normalize,
    parse_address,
    parse_key_hex,
    parse_nat64_prefix,
    parse_network,
    parse_strict_cidr,
    reverse_delegations,
    roa_coverage,
    TRANSITION_KEYS,
)


def ref_subtract(allow, deny):
    """Reference implementation using ipaddress.address_exclude."""
    nets = list(ipaddress.collapse_addresses(allow))
    for d in ipaddress.collapse_addresses(deny):
        nxt = []
        for n in nets:
            if d == n or n.subnet_of(d):
                continue
            if d.subnet_of(n):
                nxt.extend(n.address_exclude(d))
            else:
                nxt.append(n)
        nets = nxt
    return set(ipaddress.collapse_addresses(nets))


def _strings(networks):
    return {str(n) for n in networks}


def test_simple_cut_through_ipv4():
    # 10.0.0.128/26 cuts 10.0.0.0/24 into two prefixes.
    result = normalize(["10.0.0.0/24"], ["10.0.0.128/26"])
    assert result["ipv4"] == ["10.0.0.0/25", "10.0.0.192/26"]


def test_sibling_halves_merge_back():
    # Deny a hole whose leftovers are the two halves; they must merge.
    result = normalize(["10.0.0.0/24"], ["10.0.0.128/25"])
    assert result["ipv4"] == ["10.0.0.0/25"]


def test_nested_split_minimal():
    # Two adjacent /26 denies in the lower half leave one /25 survivor...
    result = normalize(
        ["10.0.0.0/24"],
        ["10.0.0.0/26", "10.0.0.64/26"],
    )
    assert result["ipv4"] == ["10.0.0.128/25"]


def test_non_sibling_adjacent_prefixes_do_not_merge():
    # 10.0.0.0/25 and 10.0.0.128/26 are adjacent but unequal siblings of no
    # common pair; minimal canonical remainder of /24 minus 10.0.0.192/26 is
    # exactly these two pieces (10.0.0.0/24 \\ 10.0.0.192/26).
    result = normalize(["10.0.0.0/24"], ["10.0.0.192/26"])
    assert result["ipv4"] == ["10.0.0.0/25", "10.0.0.128/26"]


def test_deny_swallows_allow_entirely():
    result = normalize(["10.0.0.0/24"], ["10.0.0.0/16"])
    assert result["ipv4"] == []


def test_deny_equals_allow():
    result = normalize(["10.0.0.0/24"], ["10.0.0.0/24"])
    assert result["ipv4"] == []


def test_overlapping_allow_inputs_are_collapsed():
    result = normalize(["10.0.0.0/25", "10.0.0.128/25"], [])
    assert result["ipv4"] == ["10.0.0.0/24"]


def test_duplicates_are_deduplicated():
    result = normalize(
        ["10.0.0.0/24", "10.0.0.0/24", "10.0.0.1/32"],
        ["10.0.0.0/8", "10.0.0.0/8"],
    )
    stats = result["stats"]
    assert stats["allow"] == {"input": 3, "unique": 2, "duplicates_removed": 1,
                              "ipv4": 2, "ipv6": 0}
    assert stats["deny"] == {"input": 2, "unique": 1, "duplicates_removed": 1,
                             "ipv4": 1, "ipv6": 0}
    assert stats["output"] == {"ipv4": 0, "ipv6": 0, "total": 0}


def test_mixed_families_are_independent():
    result = normalize(
        ["10.0.0.0/24", "2001:db8::/32"],
        ["10.0.0.128/25", "2001:db8:1::/48"],
    )
    assert result["ipv4"] == ["10.0.0.0/25"]
    assert result["ipv6"] == ["2001:db8::/48", "2001:db8:2::/47",
                              "2001:db8:4::/46", "2001:db8:8::/45",
                              "2001:db8:10::/44", "2001:db8:20::/43",
                              "2001:db8:40::/42", "2001:db8:80::/41",
                              "2001:db8:100::/40", "2001:db8:200::/39",
                              "2001:db8:400::/38", "2001:db8:800::/37",
                              "2001:db8:1000::/36", "2001:db8:2000::/35",
                              "2001:db8:4000::/34", "2001:db8:8000::/33"]


def test_sorting_is_stable_by_network_then_prefixlen():
    result = normalize(
        ["192.0.2.0/24", "10.0.0.0/8", "172.16.0.0/12"],
        [],
    )
    assert result["ipv4"] == ["10.0.0.0/8", "172.16.0.0/12", "192.0.2.0/24"]


def test_bare_address_means_host_prefix():
    result = normalize(["10.0.0.1", "::1"], [])
    assert result["ipv4"] == ["10.0.0.1/32"]
    assert result["ipv6"] == ["::1/128"]


def test_host_bits_rejected():
    with pytest.raises(ValueError):
        parse_network("10.0.0.1/24")
    with pytest.raises(ValueError):
        parse_network("2001:db8::1/32")


def test_garbage_rejected():
    for bad in ["not-a-cidr", "10.0.0.0/33", "999.0.0.0/8", "", "10.0.0.0/"]:
        with pytest.raises(ValueError):
            parse_network(bad)


def test_host_prefix_subtraction():
    result = normalize(["10.0.0.0/30"], ["10.0.0.1/32", "10.0.0.2/32"])
    assert result["ipv4"] == ["10.0.0.0/32", "10.0.0.3/32"]


def test_output_is_non_overlapping_and_minimal():
    result = normalize(
        ["10.0.0.0/23", "10.0.2.0/24", "192.168.0.0/16"],
        ["10.0.1.0/24", "192.168.255.0/24", "10.0.0.128/25"],
    )
    nets = [ipaddress.ip_network(s) for s in result["ipv4"]]
    for i, a in enumerate(nets):
        for b in nets[i + 1:]:
            assert not a.overlaps(b)
    # No pair of complete sibling prefixes may remain (they would be merged).
    for i, a in enumerate(nets):
        if a.prefixlen == 0:
            continue
        supernet = a.supernet()
        siblings = [n for n in nets if n != a and n.subnet_of(supernet)
                    and n.prefixlen == a.prefixlen]
        # If both halves of the supernet are present, collapse would have
        # merged them, so at most a alone sits directly under that supernet.
        assert not (siblings and set(supernet.subnets()) <= set(nets))


@pytest.mark.parametrize("seed", range(64))
def test_matches_ipaddress_reference_ipv4(seed):
    rng = random.Random(seed)
    base = ipaddress.IPv4Address(0x0A000000)  # 10.0.0.0
    allow, deny = [], []
    for _ in range(rng.randint(1, 12)):
        shift = rng.randint(0, 20)
        addr = int(base) + (rng.getrandbits(shift) << (24 - shift) if shift else 0)
        allow.append(ipaddress.IPv4Network((addr, rng.randint(8, 32)), strict=False))
    for _ in range(rng.randint(0, 12)):
        shift = rng.randint(0, 20)
        addr = int(base) + (rng.getrandbits(shift) << (24 - shift) if shift else 0)
        deny.append(ipaddress.IPv4Network((addr, rng.randint(8, 32)), strict=False))

    expected = ref_subtract(allow, deny)
    actual = set(_normalize_family(allow, deny, ipaddress.IPv4Network))
    assert actual == expected


@pytest.mark.parametrize("seed", range(32))
def test_matches_ipaddress_reference_ipv6(seed):
    rng = random.Random(1000 + seed)
    base = int(ipaddress.IPv6Address("2001:db8::"))

    def random_net():
        # Pick a host part within the 2001:db8::/32 block so the address can
        # never overflow 2**128, then mask it to the chosen prefix length.
        host = rng.randrange(2 ** 96)
        prefixlen = rng.randint(32, 120)
        addr = (base | host) & (~((1 << (128 - prefixlen)) - 1))
        return ipaddress.IPv6Network((addr, prefixlen), strict=False)

    allow = [random_net() for _ in range(rng.randint(1, 8))]
    deny = [random_net() for _ in range(rng.randint(0, 8))]

    expected = ref_subtract(allow, deny)
    actual = set(_normalize_family(allow, deny, ipaddress.IPv6Network))
    assert actual == expected


# --------------------------------------------------------------------------
# evaluate: longest-prefix matching
# --------------------------------------------------------------------------


def test_evaluate_longest_prefix_wins():
    # The more specific allow /25 must beat the broader allow /24.
    result = evaluate(
        ["10.0.0.0/24", "10.0.0.0/25"],
        [],
        ["10.0.0.1", "10.0.0.200"],
    )
    assert result == [
        {"decision": "allow", "matched_cidr": "10.0.0.0/25",
         "matched_side": "allow"},
        {"decision": "allow", "matched_cidr": "10.0.0.0/24",
         "matched_side": "allow"},
    ]


def test_evaluate_deny_beats_allow_at_equal_length():
    result = evaluate(
        ["10.0.0.0/24"],
        ["10.0.0.0/25"],
        ["10.0.0.1", "10.0.0.200"],
    )
    assert result[0] == {
        "decision": "deny", "matched_cidr": "10.0.0.0/25",
        "matched_side": "deny",
    }
    # Only the broader allow covers the upper half.
    assert result[1] == {
        "decision": "allow", "matched_cidr": "10.0.0.0/24",
        "matched_side": "allow",
    }


def test_evaluate_longer_prefix_always_wins_over_side():
    # Even though the /16 is deny, the longer allow /24 must win inside it.
    result = evaluate(
        ["10.0.0.0/24"],
        ["10.0.0.0/16"],
        ["10.0.0.1"],
    )
    assert result == [
        {"decision": "allow", "matched_cidr": "10.0.0.0/24",
         "matched_side": "allow"},
    ]


def test_evaluate_stable_tie_break_keeps_first_list_entry():
    # Two identical allow entries: the earlier index wins; its canonical
    # representation is reported, which is the same string either way, so
    # also verify with two distinct equal-length matches is impossible
    # (a host belongs to only one network of a given prefix length); instead
    # assert the earlier duplicate does not produce a surprising result.
    result = evaluate(
        ["10.0.0.0/24", "10.0.0.0/24"],
        ["10.0.0.0/24"],
        ["10.0.0.1"],
    )
    assert result[0]["decision"] == "deny"
    assert result[0]["matched_cidr"] == "10.0.0.0/24"

    # Equal-length allow/allow duplicates remain stable allow decisions.
    result = evaluate(
        ["10.0.0.0/24", "10.0.0.0/24"], [], ["10.0.0.1"],
    )
    assert result[0] == {
        "decision": "allow", "matched_cidr": "10.0.0.0/24",
        "matched_side": "allow",
    }


def test_evaluate_unmatched_is_null():
    result = evaluate(["10.0.0.0/8"], ["10.1.0.0/16"], ["192.0.2.1"])
    assert result == [
        {"decision": "unmatched", "matched_cidr": None, "matched_side": None},
    ]


def test_evaluate_order_is_preserved():
    addresses = ["10.0.0.2", "10.0.0.1", "10.1.0.1", "192.0.2.1"]
    result = evaluate(["10.0.0.0/24"], ["10.1.0.0/16"], addresses)
    assert [item["decision"] for item in result] == [
        "allow", "allow", "deny", "unmatched",
    ]
    assert [item["matched_cidr"] for item in result] == [
        "10.0.0.0/24", "10.0.0.0/24", "10.1.0.0/16", None,
    ]


def test_evaluate_mixed_families_are_independent():
    result = evaluate(
        ["10.0.0.0/8", "2001:db8::/32"],
        ["10.1.0.0/16", "2001:db8:1::/48"],
        ["10.1.0.1", "2001:db8:1::1", "2001:db8::1"],
    )
    assert result == [
        {"decision": "deny", "matched_cidr": "10.1.0.0/16",
         "matched_side": "deny"},
        {"decision": "deny", "matched_cidr": "2001:db8:1::/48",
         "matched_side": "deny"},
        {"decision": "allow", "matched_cidr": "2001:db8::/32",
         "matched_side": "allow"},
    ]


def test_evaluate_empty_inputs():
    assert evaluate([], [], ["10.0.0.1"]) == [
        {"decision": "unmatched", "matched_cidr": None, "matched_side": None},
    ]
    assert evaluate([], [], []) == []


def test_evaluate_bare_host_prefix_cidr_entries_match():
    # A bare CIDR-list entry is a host prefix and matches that one address.
    result = evaluate(["10.0.0.1"], [], ["10.0.0.1", "10.0.0.2"])
    assert result[0] == {
        "decision": "allow", "matched_cidr": "10.0.0.1/32",
        "matched_side": "allow",
    }
    assert result[1]["decision"] == "unmatched"


def test_parse_address_rejects_cidr_and_garbage():
    assert parse_address("10.0.0.1") == ipaddress.IPv4Address("10.0.0.1")
    assert parse_address(" 2001:db8::1 ") == ipaddress.IPv6Address("2001:db8::1")
    for bad in ["10.0.0.1/24", "10.0.0.1/32", "bogus", "999.0.0.1", ""]:
        with pytest.raises(ValueError):
            parse_address(bad)
    with pytest.raises(ValueError):
        parse_address(10)


# --------------------------------------------------------------------------
# compare: scope partitioning and baseline/candidate diff
# --------------------------------------------------------------------------


def test_compare_basic_two_transitions():
    result = compare(
        "10.0.0.0/24",
        ["10.0.0.0/24"], [],
        ["10.0.0.0/25"], ["10.0.0.128/26"],
    )
    assert result["differences"] == [
        {"cidr": "10.0.0.128/26", "baseline_decision": "allow",
         "candidate_decision": "deny"},
        {"cidr": "10.0.0.192/26", "baseline_decision": "allow",
         "candidate_decision": "unmatched"},
    ]
    assert result["transition_counts"] == {
        "allow->deny": "64",
        "allow->unmatched": "64",
        "deny->allow": "0",
        "deny->unmatched": "0",
        "unmatched->allow": "0",
        "unmatched->deny": "0",
    }


def test_compare_identical_policies_have_no_differences():
    result = compare(
        "10.0.0.0/24",
        ["10.0.0.0/25"], ["10.0.0.128/26"],
        ["10.0.0.0/25"], ["10.0.0.128/26"],
    )
    assert result["differences"] == []
    assert all(value == "0" for value in result["transition_counts"].values())


def test_compare_sibling_regions_merge_recursively():
    # Candidate denies the whole upper /25 via two /26 halves; the two
    # equal-transition sibling halves must merge into one /25.
    result = compare(
        "10.0.0.0/24",
        ["10.0.0.0/24"], [],
        [], ["10.0.0.128/26", "10.0.0.192/26"],
    )
    assert result["differences"] == [
        {"cidr": "10.0.0.0/25", "baseline_decision": "allow",
         "candidate_decision": "unmatched"},
        {"cidr": "10.0.0.128/25", "baseline_decision": "allow",
         "candidate_decision": "deny"},
    ]
    assert result["transition_counts"]["allow->deny"] == "128"
    assert result["transition_counts"]["allow->unmatched"] == "128"


def test_compare_deny_wins_equal_length_tie():
    # Equal /25 allow and deny in candidate: lower half denies; upper half,
    # covered by neither candidate entry, becomes unmatched.
    result = compare(
        "10.0.0.0/24",
        ["10.0.0.0/24"], [],
        ["10.0.0.0/25"], ["10.0.0.0/25"],
    )
    assert result["differences"] == [
        {"cidr": "10.0.0.0/25", "baseline_decision": "allow",
         "candidate_decision": "deny"},
        {"cidr": "10.0.0.128/25", "baseline_decision": "allow",
         "candidate_decision": "unmatched"},
    ]


def test_compare_longer_prefix_beats_broader_side():
    result = compare(
        "10.0.0.0/24",
        [], [],
        ["10.0.0.0/24"], ["10.0.0.0/16"],
    )
    assert result["differences"] == [
        {"cidr": "10.0.0.0/24", "baseline_decision": "unmatched",
         "candidate_decision": "allow"},
    ]


def test_compare_adjacent_unequal_lengths_do_not_merge():
    # 128/26 allow->unmatched and 192/26 allow->deny are sibling /26s but
    # carry different transitions, so they must stay separate.
    result = compare(
        "10.0.0.0/24",
        ["10.0.0.0/24"], [],
        ["10.0.0.0/25"], ["10.0.0.192/26"],
    )
    assert result["differences"] == [
        {"cidr": "10.0.0.128/26", "baseline_decision": "allow",
         "candidate_decision": "unmatched"},
        {"cidr": "10.0.0.192/26", "baseline_decision": "allow",
         "candidate_decision": "deny"},
    ]


def test_compare_supernet_entry_outside_scope_still_applies():
    # Both sides share a broader allow; inside the narrower scope nothing
    # changes, even though the scope itself is not listed.
    result = compare(
        "10.0.0.0/25",
        ["10.0.0.0/24"], [],
        ["10.0.0.0/24"], [],
    )
    assert result["differences"] == []


def test_compare_other_family_entries_are_ignored():
    result = compare(
        "10.0.0.0/24",
        [], ["2001:db8::/32"],
        ["2001:db8::/32"], [],
    )
    assert result["differences"] == []


def test_compare_ipv6_scope_and_decimal_string_counts():
    result = compare(
        "2001:db8::/32",
        [], [],
        ["2001:db8::/32"], [],
    )
    assert result["differences"] == [
        {"cidr": "2001:db8::/32", "baseline_decision": "unmatched",
         "candidate_decision": "allow"},
    ]
    # Count is a decimal string even at IPv6 magnitudes.
    assert result["transition_counts"]["unmatched->allow"] == str(2 ** 96)
    assert isinstance(result["transition_counts"]["unmatched->allow"], str)


def test_compare_host_prefix_scope():
    result = compare("10.0.0.5/32", [], [], ["10.0.0.5"], [])
    assert result["differences"] == [
        {"cidr": "10.0.0.5/32", "baseline_decision": "unmatched",
         "candidate_decision": "allow"},
    ]


def test_compare_invalid_scope_raises():
    for bad in ["10.0.0.1/24", "bogus", "10.0.0.0/33", ""]:
        with pytest.raises(ValueError):
            compare(bad, [], [], [], [])


def _point_decisions(allow_raw, deny_raw, addresses):
    """evaluate() decisions for a list of bare addresses."""
    return [
        item["decision"]
        for item in evaluate(allow_raw, deny_raw, addresses)
    ]


def _assert_compare_exhaustive(scope, base_a, base_d, cand_a, cand_d):
    """Check compare() against per-address /evaluate over a small scope."""
    scope_net = ipaddress.ip_network(scope)

    result = compare(scope, base_a, base_d, cand_a, cand_d)
    blocks = [ipaddress.ip_network(d["cidr"]) for d in result["differences"]]

    # Enumerate every address of the scope (including network/broadcast,
    # which .hosts() omits for IPv4).
    start = int(scope_net.network_address)
    all_hosts = [
        ipaddress.ip_address(start + offset)
        for offset in range(scope_net.num_addresses)
    ]
    addresses = [str(host) for host in all_hosts]
    base_point = _point_decisions(base_a, base_d, addresses)
    cand_point = _point_decisions(cand_a, cand_d, addresses)

    # Output blocks are strict subnets of scope, non-overlapping, and carry a
    # genuine change.
    for diff, network in zip(result["differences"], blocks, strict=True):
        assert network.subnet_of(scope_net)
        assert diff["baseline_decision"] != diff["candidate_decision"]
    for i, left in enumerate(blocks):
        for right in blocks[i + 1:]:
            assert not left.overlaps(right)

    # Every differing address is covered by exactly one block; every address
    # covered by a block really does change, with the reported decisions.
    covered = [False] * len(addresses)
    for diff, network in zip(result["differences"], blocks, strict=True):
        for index, host in enumerate(all_hosts):
            if host in network:
                assert not covered[index]
                covered[index] = True
                assert base_point[index] == diff["baseline_decision"]
                assert cand_point[index] == diff["candidate_decision"]
    for index, changed in enumerate(
        b != c for b, c in zip(base_point, cand_point)
    ):
        assert covered[index] == changed

    # Totals match the per-address enumeration.
    totals = {key: 0 for key in TRANSITION_KEYS}
    for base, cand in zip(base_point, cand_point):
        if base != cand:
            totals[f"{base}->{cand}"] += 1
    assert {key: int(value) for key, value in
            result["transition_counts"].items()} == totals

    # Minimality: no output pair forms two complete siblings of one parent
    # with the same transition (those would have been merged).
    for diff, network in zip(result["differences"], blocks, strict=True):
        if network.prefixlen == 0:
            continue
        parent = network.supernet()
        same_label_siblings = [
            other for other_diff, other in zip(result["differences"], blocks)
            if other != network and other.subnet_of(parent)
            and other.prefixlen == network.prefixlen
            and (other_diff["baseline_decision"],
                 other_diff["candidate_decision"])
            == (diff["baseline_decision"], diff["candidate_decision"])
        ]
        assert not (
            len(same_label_siblings) == 1
            and set(parent.subnets()) <= set(blocks)
        )


@pytest.mark.parametrize("seed", range(40))
def test_compare_matches_pointwise_evaluation_ipv4(seed):
    rng = random.Random(2000 + seed)
    prefixlen = rng.randint(26, 29)  # <= /29 keeps enumeration cheap

    def random_list():
        items = []
        for _ in range(rng.randint(0, 5)):
            length = rng.randint(prefixlen - 2, 32)
            base = rng.randrange(2 ** 32)
            addr = (base >> (32 - length)) << (32 - length)
            items.append(str(ipaddress.IPv4Network((addr, length))))
        return items

    scope_addr = (rng.randrange(2 ** 32) >> (32 - prefixlen)) << (32 - prefixlen)
    scope = str(ipaddress.IPv4Network((scope_addr, prefixlen)))
    _assert_compare_exhaustive(
        scope, random_list(), random_list(), random_list(), random_list()
    )


@pytest.mark.parametrize("seed", range(16))
def test_compare_matches_pointwise_evaluation_ipv6(seed):
    rng = random.Random(3000 + seed)
    # Tiny /124-ish scopes under 2001:db8:: keep host enumeration cheap.
    prefixlen = rng.randint(122, 126)
    base = int(ipaddress.IPv6Address("2001:db8::"))

    def random_list():
        items = []
        for _ in range(rng.randint(0, 4)):
            length = rng.randint(prefixlen - 2, 128)
            host = rng.randrange(2 ** (128 - prefixlen))
            root = base + (host & ~((1 << (128 - prefixlen)) - 1))
            addr = (root >> (128 - length)) << (128 - length)
            items.append(str(ipaddress.IPv6Network((addr, length))))
        return items

    host = rng.randrange(2 ** (128 - prefixlen))
    scope_addr = (base + host) & ~((1 << (128 - prefixlen)) - 1)
    scope = str(ipaddress.IPv6Network((scope_addr, prefixlen)))
    _assert_compare_exhaustive(
        scope, random_list(), random_list(), random_list(), random_list()
    )


# --------------------------------------------------------------------------
# audit-rules: per-rule impact classification inside one scope
# --------------------------------------------------------------------------


def _entry(side, index, cidr, status, witness=None, shadowed_by=None):
    result = {"side": side, "index": index, "cidr": cidr, "status": status}
    if status == "effective":
        result["witness"] = witness
    elif status == "shadowed":
        result["shadowed_by"] = shadowed_by
    return result


def test_audit_effective_rules_report_smallest_witness():
    result = audit_rules(
        "10.0.0.0/24",
        ["10.0.0.0/24"],
        ["10.0.0.128/25"],
    )
    # The allow wins the lower half: smallest address 10.0.0.0.
    assert result["allow"] == [
        _entry("allow", 0, "10.0.0.0/24", "effective", witness="10.0.0.0")
    ]
    assert result["deny"] == [
        _entry("deny", 0, "10.0.0.128/25", "effective", witness="10.0.0.128")
    ]


def test_audit_witness_is_smallest_winning_piece_not_cidr_start():
    # The denies eat the lower two quarters of the allow /24; the allow's
    # winning region starts at 10.0.0.128, which must be the witness rather
    # than the rule's own network address 10.0.0.0.
    result = audit_rules(
        "10.0.0.0/24",
        ["10.0.0.0/24"],
        ["10.0.0.0/26", "10.0.0.64/26"],
    )
    assert result["allow"] == [
        _entry("allow", 0, "10.0.0.0/24", "effective", witness="10.0.0.128")
    ]


def test_audit_equal_length_deny_shadows_allow():
    result = audit_rules(
        "10.0.0.0/24",
        ["10.0.0.0/25"],
        ["10.0.0.0/25"],
    )
    assert result["allow"] == [
        _entry("allow", 0, "10.0.0.0/25", "shadowed",
               shadowed_by=[{"side": "deny", "index": 0}])
    ]
    assert result["deny"] == [
        _entry("deny", 0, "10.0.0.0/25", "effective", witness="10.0.0.0")
    ]


def test_audit_duplicate_same_side_rules_keep_earliest_priority():
    result = audit_rules(
        "10.0.0.0/24",
        ["10.0.0.0/25", "10.0.0.0/25"],
        [],
    )
    # The earlier copy wins; the later duplicate is shadowed by index 0.
    assert result["allow"][0] == _entry(
        "allow", 0, "10.0.0.0/25", "effective", witness="10.0.0.0")
    assert result["allow"][1] == _entry(
        "allow", 1, "10.0.0.0/25", "shadowed",
        shadowed_by=[{"side": "allow", "index": 0}])


def test_audit_shadowed_by_collects_distinct_winning_rules():
    # The broad /24 allow wins nowhere: deny /25 takes the lower half, the
    # more specific allow /26 takes one quarter of the upper half, and deny
    # 192/26 takes the remaining quarter.
    result = audit_rules(
        "10.0.0.0/24",
        ["10.0.0.0/24", "10.0.0.128/26"],
        ["10.0.0.0/25", "10.0.0.192/26"],
    )
    assert result["allow"][0] == _entry(
        "allow", 0, "10.0.0.0/24", "shadowed",
        shadowed_by=[{"side": "allow", "index": 1},
                     {"side": "deny", "index": 0},
                     {"side": "deny", "index": 1}])
    assert result["allow"][1] == _entry(
        "allow", 1, "10.0.0.128/26", "effective", witness="10.0.0.128")
    assert result["deny"][0] == _entry(
        "deny", 0, "10.0.0.0/25", "effective", witness="10.0.0.0")
    assert result["deny"][1] == _entry(
        "deny", 1, "10.0.0.192/26", "effective", witness="10.0.0.192")


def test_audit_dead_rules_never_appear_as_shadowers():
    # deny/25 is itself shadowed everywhere by two /26 denies; it must still
    # classify as shadowed (it never wins), and only the actual winners may
    # appear in anyone's shadowed_by.
    result = audit_rules(
        "10.0.0.0/24",
        ["10.0.0.0/25"],
        ["10.0.0.0/25", "10.0.0.0/26", "10.0.0.64/26"],
    )
    assert result["deny"][0]["status"] == "shadowed"
    assert result["deny"][0]["shadowed_by"] == [
        {"side": "deny", "index": 1}, {"side": "deny", "index": 2}]
    allow_shadowers = {
        (ref["side"], ref["index"])
        for ref in result["allow"][0]["shadowed_by"]
    }
    assert ("deny", 0) not in allow_shadowers
    assert allow_shadowers == {("deny", 1), ("deny", 2)}


def test_audit_disjoint_rules_are_out_of_scope():
    result = audit_rules(
        "10.0.0.0/24",
        ["10.1.0.0/16"],
        ["192.0.2.0/24"],
    )
    assert result["allow"] == [
        _entry("allow", 0, "10.1.0.0/16", "out_of_scope")]
    assert result["deny"] == [
        _entry("deny", 0, "192.0.2.0/24", "out_of_scope")]


def test_audit_broader_than_scope_entry_is_effective():
    # A rule containing the whole scope is analyzed on the clipped region.
    result = audit_rules("10.0.0.0/25", ["10.0.0.0/16"], [])
    assert result["allow"] == [
        _entry("allow", 0, "10.0.0.0/16", "effective", witness="10.0.0.0")]


def test_audit_bare_address_entries():
    result = audit_rules(
        "10.0.0.0/30",
        ["10.0.0.0", "10.0.0.1"],
        ["10.0.0.1"],
    )
    assert result["allow"][0] == _entry(
        "allow", 0, "10.0.0.0/32", "effective", witness="10.0.0.0")
    assert result["allow"][1] == _entry(
        "allow", 1, "10.0.0.1/32", "shadowed",
        shadowed_by=[{"side": "deny", "index": 0}])
    assert result["deny"][0] == _entry(
        "deny", 0, "10.0.0.1/32", "effective", witness="10.0.0.1")


def test_audit_ipv6_compressed_witness():
    result = audit_rules(
        "2001:db8::/120",
        ["2001:db8::/120"],
        ["2001:db8::/121"],
    )
    # The /121 deny covers 0..127; the allow wins the upper half starting at
    # 0x80.  Witnesses use the standard compressed textual representation.
    assert result["allow"][0] == _entry(
        "allow", 0, "2001:db8::/120", "effective",
        witness="2001:db8::80")
    assert result["deny"][0] == _entry(
        "deny", 0, "2001:db8::/121", "effective", witness="2001:db8::")


def test_audit_empty_rules():
    result = audit_rules("10.0.0.0/24", [], [])
    assert result == {"allow": [], "deny": []}


def test_audit_input_order_and_indices_preserved():
    allow = ["10.0.0.128/25", "10.0.0.0/24", "10.0.0.0/25"]
    deny = ["10.1.0.0/16", "10.0.0.0/25"]
    result = audit_rules("10.0.0.0/24", allow, deny)
    assert [item["index"] for item in result["allow"]] == [0, 1, 2]
    assert [item["cidr"] for item in result["allow"]] == allow
    assert [item["index"] for item in result["deny"]] == [0, 1]
    assert [item["cidr"] for item in result["deny"]] == deny


# Pointwise reference model for property tests: brute-force the winning rule
# at every address (small scopes only), without any partition logic.
_AUDIT_SIDE_RANK = {"allow": 0, "deny": 1}


def _audit_brute_force(scope_raw, allow_raw, deny_raw):
    scope = ipaddress.ip_network(scope_raw)
    rules = [
        (i, ipaddress.ip_network(item), "allow") for i, item in enumerate(allow_raw)
    ]
    rules += [
        (i, ipaddress.ip_network(item), "deny") for i, item in enumerate(deny_raw)
    ]
    start = int(scope.network_address)
    won: dict[tuple[str, int], list[int]] = {}
    shadowers: dict[tuple[str, int], set[tuple[str, int]]] = {}
    covered: set[tuple[str, int]] = set()
    for index, _, side in rules:
        won[(side, index)] = []
        shadowers[(side, index)] = set()

    for offset in range(scope.num_addresses):
        address_int = start + offset
        winner: tuple[str, int] | None = None
        best_key = None
        active: list[tuple[str, int]] = []
        for index, network, side in rules:
            low = int(network.network_address)
            high = low + network.num_addresses - 1
            if network.version != scope.version or not low <= address_int <= high:
                continue
            active.append((side, index))
            key = (network.prefixlen, _AUDIT_SIDE_RANK[side], -index)
            if best_key is None or key > best_key:
                best_key, winner = key, (side, index)
        for reference in active:
            covered.add(reference)
            if winner == reference:
                won[reference].append(address_int)
            elif winner is not None:
                shadowers[reference].add(winner)

    output = {"allow": [], "deny": []}
    for side, raw_list in (("allow", allow_raw), ("deny", deny_raw)):
        for index, item in enumerate(raw_list):
            reference = (side, index)
            if reference not in covered:
                status = {"status": "out_of_scope"}
            elif won[reference]:
                witness = str(ipaddress.ip_address(min(won[reference])))
                status = {"status": "effective", "witness": witness}
            else:
                status = {
                    "status": "shadowed",
                    "shadowed_by": [
                        {"side": s, "index": i}
                        for s, i in sorted(shadowers[reference])
                    ],
                }
            output[side].append({
                "side": side, "index": index,
                "cidr": str(ipaddress.ip_network(item)), **status,
            })
    return output


def _assert_audit_matches_brute_force(scope, allow, deny):
    expected = _audit_brute_force(scope, allow, deny)
    actual = audit_rules(scope, allow, deny)
    assert actual == expected


@pytest.mark.parametrize("seed", range(120))
def test_audit_matches_pointwise_brute_force_ipv4(seed):
    rng = random.Random(6000 + seed)
    prefixlen = rng.randint(26, 29)

    def random_list():
        items = []
        for _ in range(rng.randint(0, 6)):
            length = rng.randint(prefixlen - 2, 32)
            addr = (rng.randrange(2 ** 32) >> (32 - length)) << (32 - length)
            items.append(str(ipaddress.IPv4Network((addr, length))))
        # Occasionally duplicate an entry to exercise stable priorities.
        if items and rng.random() < 0.4:
            items.append(items[rng.randrange(len(items))])
        return items

    scope_addr = (rng.randrange(2 ** 32) >> (32 - prefixlen)) << (32 - prefixlen)
    scope = str(ipaddress.IPv4Network((scope_addr, prefixlen)))
    _assert_audit_matches_brute_force(scope, random_list(), random_list())


@pytest.mark.parametrize("seed", range(48))
def test_audit_matches_pointwise_brute_force_ipv6(seed):
    rng = random.Random(7000 + seed)
    prefixlen = rng.randint(122, 126)
    base = int(ipaddress.IPv6Address("2001:db8::"))

    def random_list():
        items = []
        for _ in range(rng.randint(0, 5)):
            length = rng.randint(prefixlen - 2, 128)
            host = rng.randrange(2 ** (128 - prefixlen))
            root = base + (host & ~((1 << (128 - prefixlen)) - 1))
            addr = (root >> (128 - length)) << (128 - length)
            items.append(str(ipaddress.IPv6Network((addr, length))))
        if items and rng.random() < 0.4:
            items.append(items[rng.randrange(len(items))])
        return items

    host = rng.randrange(2 ** (128 - prefixlen))
    scope_addr = (base + host) & ~((1 << (128 - prefixlen)) - 1)
    scope = str(ipaddress.IPv6Network((scope_addr, prefixlen)))
    _assert_audit_matches_brute_force(scope, random_list(), random_list())


def test_audit_does_not_enumerate_large_scopes():
    # A /0 IPv6 scope must finish instantly: any address enumeration of
    # 2**128 addresses would never return.  Inside the allow /32 the deny
    # /48 wins its quarter, so the allow's smallest winning piece is the
    # following /48 at 2001:db8:1::.
    result = audit_rules("::/0", ["2001:db8::/32"], ["2001:db8::/48"])
    assert result["allow"][0]["status"] == "effective"
    assert result["allow"][0]["witness"] == "2001:db8:1::"
    assert result["deny"][0]["status"] == "effective"
    assert result["deny"][0]["witness"] == "2001:db8::"
    # Outside both entries the scope is unmatched, but both rules overlap it.
    assert all(item["status"] != "out_of_scope"
               for item in result["allow"] + result["deny"])


# --------------------------------------------------------------------------
# minimize-policy: minimum equivalent rule subset inside one scope
# --------------------------------------------------------------------------

_MINIMIZE_SIDE_RANK = {"allow": 0, "deny": 1}


def test_minimize_drops_shadowed_and_out_of_scope_rules():
    # deny /25 beats the equal-length allow /25 (index 1); the broad allow /24
    # still wins the upper half; an out-of-scope deny is removed outright.
    result = minimize_policy(
        "10.0.0.0/24",
        ["10.0.0.0/24", "10.0.0.0/25"],
        ["10.0.0.0/25", "10.1.0.0/16"],
    )
    assert result == {
        "retained": [
            {"side": "allow", "index": 0, "cidr": "10.0.0.0/24",
             "witness": "10.0.0.128"},
            {"side": "deny", "index": 0, "cidr": "10.0.0.0/25",
             "witness": "10.0.0.0"},
        ],
        "removed": [
            {"side": "allow", "index": 1, "cidr": "10.0.0.0/25"},
            {"side": "deny", "index": 1, "cidr": "10.1.0.0/16"},
        ],
    }


def test_minimize_lex_tie_prefers_smaller_allow_index():
    # Both the broad allow /24 and the narrow allow /25 combine with the deny
    # /25 into a size-2 solution; (allow, 0) wins the lexicographic tie.
    result = minimize_policy(
        "10.0.0.0/24",
        ["10.0.0.0/24", "10.0.0.0/25"],
        ["10.0.0.128/25"],
    )
    assert [(item["side"], item["index"]) for item in result["retained"]] == [
        ("allow", 0), ("deny", 0),
    ]
    assert result["removed"] == [
        {"side": "allow", "index": 1, "cidr": "10.0.0.0/25"},
    ]


def test_minimize_lex_tie_across_deny_indices():
    # The broad deny /24 and the narrower deny /26 both keep the single deny
    # quarter beside the two /26 allows; the earlier deny index wins.
    result = minimize_policy(
        "10.0.0.0/24",
        ["10.0.0.0/26", "10.0.0.128/25"],
        ["10.0.0.0/24", "10.0.0.64/26"],
    )
    assert [(item["side"], item["index"]) for item in result["retained"]] == [
        ("allow", 0), ("allow", 1), ("deny", 0),
    ]
    assert result["removed"] == [
        {"side": "deny", "index": 1, "cidr": "10.0.0.64/26"},
    ]
    # Witness of the broad deny is the first quarter it actually wins under
    # the reduced policy (0/26 allow wins the lowest quarter).
    deny0 = next(
        item for item in result["retained"]
        if item["side"] == "deny" and item["index"] == 0
    )
    assert deny0["witness"] == "10.0.0.64"


def test_minimize_duplicate_entries_keep_earliest_copy():
    # Two identical denies: later copy is shadowed by the earlier one.
    result = minimize_policy(
        "10.0.0.0/24",
        [],
        ["10.0.0.0/24", "10.0.0.0/24"],
    )
    assert result["retained"] == [
        {"side": "deny", "index": 0, "cidr": "10.0.0.0/24",
         "witness": "10.0.0.0"},
    ]
    assert result["removed"] == [
        {"side": "deny", "index": 1, "cidr": "10.0.0.0/24"},
    ]


def test_minimize_equal_length_deny_makes_allow_fully_removable():
    result = minimize_policy(
        "10.0.0.0/24",
        ["10.0.0.128/25"],
        ["10.0.0.128/25"],
    )
    assert result["retained"] == [
        {"side": "deny", "index": 0, "cidr": "10.0.0.128/25",
         "witness": "10.0.0.128"},
    ]
    assert result["removed"] == [
        {"side": "allow", "index": 0, "cidr": "10.0.0.128/25"},
    ]


def test_minimize_empty_policy_retains_nothing():
    assert minimize_policy("10.0.0.0/24", [], []) == {
        "retained": [], "removed": [],
    }


def test_minimize_references_follow_original_input_order():
    # Allows are emitted by index before denies, in both lists.
    result = minimize_policy(
        "10.0.0.0/30",
        ["10.0.0.0/32", "10.0.0.1/32", "10.0.0.2/32"],
        ["10.0.0.3/32"],
    )
    assert [(item["side"], item["index"]) for item in result["retained"]] == [
        ("allow", 0), ("allow", 1), ("allow", 2), ("deny", 0),
    ]
    assert [item["witness"] for item in result["retained"]] == [
        "10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3",
    ]
    assert result["removed"] == []


def test_minimize_ipv6_witnesses_and_huge_scope():
    result = minimize_policy(
        "2001:db8::/120",
        ["2001:db8::/120"],
        ["2001:db8::/121"],
    )
    assert [(item["side"], item["index"]) for item in result["retained"]] == [
        ("allow", 0), ("deny", 0),
    ]
    witnesses = {
        (item["side"], item["index"]): item["witness"]
        for item in result["retained"]
    }
    assert witnesses[("allow", 0)] == "2001:db8::80"
    assert witnesses[("deny", 0)] == "2001:db8::"

    # ::/0 must complete without enumerating addresses.
    result = minimize_policy("::/0", ["2001:db8::/32"], ["2001:db8::/48"])
    assert [(item["side"], item["index"]) for item in result["retained"]] == [
        ("allow", 0), ("deny", 0),
    ]


def _minimize_brute_force(scope_raw, allow_raw, deny_raw):
    """Reference: enumerate every subset and keep the minimum, lex-smallest."""
    rules = [
        (index, "allow", item) for index, item in enumerate(allow_raw)
    ] + [
        (index, "deny", item) for index, item in enumerate(deny_raw)
    ]

    def decisions(allow_subset, deny_subset):
        return [
            item["decision"]
            for item in evaluate(allow_subset, deny_subset, _scope_addresses)
        ]

    scope = ipaddress.ip_network(scope_raw)
    start = int(scope.network_address)
    _scope_addresses = [
        str(ipaddress.ip_address(start + offset))
        for offset in range(scope.num_addresses)
    ]
    target = decisions(list(allow_raw), list(deny_raw))

    best = None
    for mask in range(1 << len(rules)):
        allow_subset = [
            cidr for pos, (_i, side, cidr) in enumerate(rules)
            if side == "allow" and mask & (1 << pos)
        ]
        deny_subset = [
            cidr for pos, (_i, side, cidr) in enumerate(rules)
            if side == "deny" and mask & (1 << pos)
        ]
        if decisions(allow_subset, deny_subset) != target:
            continue
        key = sorted(
            (side, index)
            for pos, (index, side, _cidr) in enumerate(rules)
            if mask & (1 << pos)
        )
        if best is None or (len(key), key) < (len(best), best):
            best = key
    return best


def _assert_minimize_matches_brute_force(scope, allow, deny):
    result = minimize_policy(scope, allow, deny)
    retained = [
        (item["side"], item["index"]) for item in result["retained"]
    ]
    assert retained == _minimize_brute_force(scope, allow, deny)

    # retained + removed partition every input reference exactly once.
    removed = [(item["side"], item["index"]) for item in result["removed"]]
    expected = [
        ("allow", index) for index in range(len(allow))
    ] + [
        ("deny", index) for index in range(len(deny))
    ]
    assert sorted(retained + removed) == sorted(expected)
    # Both lists are in canonical original-input order (allow then deny).
    assert retained == sorted(retained)
    assert removed == sorted(removed)

    # Every witness is the numerically smallest winning address of its rule
    # under the reduced policy, checked pointwise with original indices.
    scope_net = ipaddress.ip_network(scope)
    reduced_entries = [
        (item["index"], ipaddress.ip_network(
            (allow if item["side"] == "allow" else deny)[item["index"]]
        ), item["side"])
        for item in result["retained"]
    ]
    smallest: dict[tuple[str, int], int] = {}
    for offset in range(scope_net.num_addresses):
        address = scope_net.network_address + offset
        winner = None
        for index, network, side in reduced_entries:
            if address in network:
                key = (network.prefixlen, _MINIMIZE_SIDE_RANK[side], -index)
                if winner is None or key > winner[0]:
                    winner = (key, side, index)
        if winner is not None:
            rule_key = (winner[1], winner[2])
            value = int(address)
            if rule_key not in smallest or value < smallest[rule_key]:
                smallest[rule_key] = value
    for item in result["retained"]:
        key = (item["side"], item["index"])
        assert item["witness"] == str(ipaddress.ip_address(smallest[key]))


@pytest.mark.parametrize("seed", range(80))
def test_minimize_matches_brute_force_ipv4(seed):
    rng = random.Random(8000 + seed)
    prefixlen = rng.randint(26, 29)

    def random_list():
        items = []
        for _ in range(rng.randint(0, 6)):
            length = rng.randint(prefixlen - 2, 32)
            addr = (rng.randrange(2 ** 32) >> (32 - length)) << (32 - length)
            items.append(str(ipaddress.IPv4Network((addr, length))))
        if items and rng.random() < 0.4:
            items.append(items[rng.randrange(len(items))])
        return items

    scope_addr = (rng.randrange(2 ** 32) >> (32 - prefixlen)) << (32 - prefixlen)
    scope = str(ipaddress.IPv4Network((scope_addr, prefixlen)))
    allow, deny = random_list(), random_list()
    if len(allow) + len(deny) <= 16:
        _assert_minimize_matches_brute_force(scope, allow, deny)


@pytest.mark.parametrize("seed", range(32))
def test_minimize_matches_brute_force_ipv6(seed):
    rng = random.Random(9000 + seed)
    prefixlen = rng.randint(122, 126)
    base = int(ipaddress.IPv6Address("2001:db8::"))

    def random_list():
        items = []
        for _ in range(rng.randint(0, 5)):
            length = rng.randint(prefixlen - 2, 128)
            host = rng.randrange(2 ** (128 - prefixlen))
            root = base + (host & ~((1 << (128 - prefixlen)) - 1))
            addr = (root >> (128 - length)) << (128 - length)
            items.append(str(ipaddress.IPv6Network((addr, length))))
        if items and rng.random() < 0.4:
            items.append(items[rng.randrange(len(items))])
        return items

    host = rng.randrange(2 ** (128 - prefixlen))
    scope_addr = (base + host) & ~((1 << (128 - prefixlen)) - 1)
    scope = str(ipaddress.IPv6Network((scope_addr, prefixlen)))
    allow, deny = random_list(), random_list()
    if len(allow) + len(deny) <= 16:
        _assert_minimize_matches_brute_force(scope, allow, deny)


def test_minimize_does_not_enumerate_large_scopes():
    # A /0 IPv6 scope completes instantly: any per-address enumeration over
    # 2**128 addresses could not return.
    result = minimize_policy("::/0", ["2001:db8::/32"], ["2001:db8::/48"])
    assert len(result["retained"]) == 2


# --------------------------------------------------------------------------
# allocate: lexicographically smallest non-overlapping subnet assignment
# --------------------------------------------------------------------------


def test_allocate_basic_lexicographic_order():
    result = allocate(
        "10.0.0.0/24", ["10.0.0.0/25"], [("b", 26), ("a", 26)]
    )
    assert result == {
        "allocations": [
            {"id": "b", "cidr": "10.0.0.128/26"},
            {"id": "a", "cidr": "10.0.0.192/26"},
        ],
        "remaining": [],
        "remaining_addresses": "0",
    }


def test_allocate_sequence_order_follows_requests_not_addresses():
    # The lexicographic key is the address sequence in request order: the
    # /26 goes to the lowest free block, the /25 takes what remains.
    result = allocate("10.0.0.0/24", [], [("x", 26), ("y", 25)])
    assert result["allocations"] == [
        {"id": "x", "cidr": "10.0.0.0/26"},
        {"id": "y", "cidr": "10.0.0.128/25"},
    ]
    assert result["remaining"] == ["10.0.0.64/26"]


def test_allocate_backtracks_to_lexicographic_minimum():
    # First-fit for "small" (10.0.0.0/25 or 10.0.0.128/25) strands the /24;
    # the only complete plans put "small" at 10.0.1.128/25.
    result = allocate(
        "10.0.0.0/23", ["10.0.1.0/25"], [("small", 25), ("big", 24)]
    )
    assert [item["cidr"] for item in result["allocations"]] == [
        "10.0.1.128/25", "10.0.0.0/24",
    ]
    assert result["remaining"] == []


def test_allocate_infeasible_returns_none():
    # Two /25s beside an occupied /25.
    assert allocate(
        "10.0.0.0/24", ["10.0.0.0/25"], [("x", 25), ("y", 25)]
    ) is None
    # A prefix shorter than the scope prefix can never fit inside it.
    assert allocate("10.0.0.0/24", [], [("wan", 16)]) is None
    # Scope fully occupied.
    assert allocate("10.0.0.0/24", ["10.0.0.0/24"], [("x", 32)]) is None
    # Fragmentation: two /26 holes cannot host a /25.
    assert allocate(
        "10.0.0.0/24",
        ["10.0.0.0/26", "10.0.0.128/26"],
        [("x", 25)],
    ) is None


def test_allocate_empty_requests_returns_free_space():
    result = allocate("10.0.0.0/24", ["10.0.0.0/25"], [])
    assert result == {
        "allocations": [],
        "remaining": ["10.0.0.128/25"],
        "remaining_addresses": "128",
    }


def test_allocate_host_prefix_scope_and_request():
    result = allocate("10.0.0.5/32", [], [("host", 32)])
    assert result["allocations"] == [{"id": "host", "cidr": "10.0.0.5/32"}]
    assert result["remaining"] == []
    assert result["remaining_addresses"] == "0"


def test_allocate_ipv6():
    result = allocate(
        "2001:db8::/126", ["2001:db8::1/128"], [("node", 128)]
    )
    assert result["allocations"] == [{"id": "node", "cidr": "2001:db8::/128"}]
    assert result["remaining"] == ["2001:db8::2/127"]
    assert result["remaining_addresses"] == "2"


def test_allocate_remaining_is_minimal_and_non_overlapping():
    result = allocate(
        "10.0.0.0/24",
        ["10.0.0.64/26", "10.0.0.128/26"],
        [("first", 26)],
    )
    assert result["allocations"] == [{"id": "first", "cidr": "10.0.0.0/26"}]
    assert result["remaining"] == ["10.0.0.192/26"]
    assert result["remaining_addresses"] == "64"


def _brute_force_allocate(scope_raw, occupied_raw, requests):
    """Reference: enumerate every feasible assignment and keep the one whose
    network-address sequence (in request order) is lexicographically minimal.
    """
    scope = ipaddress.ip_network(scope_raw)
    occupied = [ipaddress.ip_network(item) for item in occupied_raw]
    max_bits = 32 if scope.version == 4 else 128
    free = _normalize_family([scope], occupied, type(scope))

    def candidates(free_nets, prefixlen):
        size = 1 << (max_bits - prefixlen)
        for net in free_nets:
            if net.prefixlen <= prefixlen:
                base = int(net.network_address)
                for offset in range(0, net.num_addresses, size):
                    yield type(net)((base + offset, prefixlen))

    def subtract(free_nets, block):
        out = []
        for net in free_nets:
            if block.subnet_of(net):
                out.extend(net.address_exclude(block))
            else:
                out.append(net)
        return out

    best = None

    def rec(free_nets, depth, acc):
        nonlocal best
        if depth == len(requests):
            key = tuple(int(net.network_address) for net in acc)
            if best is None or key < best[0]:
                best = (key, list(acc))
            return
        for candidate in candidates(free_nets, requests[depth][1]):
            rec(subtract(free_nets, candidate), depth + 1, acc + [candidate])

    rec(free, 0, [])
    return None if best is None else best[1]


def _assert_allocate_matches_brute_force(scope, occupied, requests):
    occupied_raw = [str(net) for net in occupied]
    expected = _brute_force_allocate(str(scope), occupied_raw, requests)
    result = allocate(str(scope), occupied_raw, requests)

    if expected is None:
        assert result is None
        return

    assert result is not None
    chosen = [
        ipaddress.ip_network(item["cidr"]) for item in result["allocations"]
    ]
    # Exactly the lexicographically smallest feasible sequence, with the
    # request ids attached in request order.
    assert chosen == expected
    assert [item["id"] for item in result["allocations"]] == [
        request_id for request_id, _ in requests
    ]
    # Sanity: allocations lie in scope, avoid occupied, and are disjoint.
    for (_, prefix_length), network in zip(requests, chosen, strict=True):
        assert network.subnet_of(scope)
        assert network.prefixlen == prefix_length
        assert not any(network.overlaps(net) for net in occupied)
    for i, left in enumerate(chosen):
        for right in chosen[i + 1:]:
            assert not left.overlaps(right)
    # Remaining space equals scope - occupied - allocations, minimally.
    leftover = _normalize_family([scope], [*occupied, *chosen], type(scope))
    assert result["remaining"] == [str(net) for net in leftover]
    assert int(result["remaining_addresses"]) == sum(
        net.num_addresses for net in leftover
    )


def _random_occupied(rng, scope, max_bits):
    """Random, mutually non-overlapping strict subnets of ``scope``."""
    occupied = []
    for _ in range(rng.randint(0, 3)):
        prefixlen = rng.randint(scope.prefixlen, min(scope.prefixlen + 2, max_bits))
        slot = rng.randrange(1 << (prefixlen - scope.prefixlen))
        addr = int(scope.network_address) + slot * (1 << (max_bits - prefixlen))
        net = type(scope)((addr, prefixlen))
        if all(not net.overlaps(other) for other in occupied):
            occupied.append(net)
    return occupied


@pytest.mark.parametrize("seed", range(40))
def test_allocate_matches_brute_force_ipv4(seed):
    rng = random.Random(4000 + seed)
    prefixlen = rng.randint(28, 30)  # small scopes keep enumeration cheap
    base = rng.randrange(2 ** 32) & ~((1 << (32 - prefixlen)) - 1)
    scope = ipaddress.IPv4Network((base, prefixlen))
    occupied = _random_occupied(rng, scope, 32)
    requests = [
        (f"r{i}", rng.randint(prefixlen, 32))
        for i in range(rng.randint(0, 3))
    ]
    _assert_allocate_matches_brute_force(scope, occupied, requests)


@pytest.mark.parametrize("seed", range(16))
def test_allocate_matches_brute_force_ipv6(seed):
    rng = random.Random(5000 + seed)
    prefixlen = rng.randint(124, 126)
    base = int(ipaddress.IPv6Address("2001:db8::"))
    host = rng.randrange(2 ** (128 - prefixlen))
    scope = ipaddress.IPv6Network(
        (base + (host << (128 - prefixlen)), prefixlen)
    )
    occupied = _random_occupied(rng, scope, 128)
    requests = [
        (f"r{i}", rng.randint(prefixlen, 128))
        for i in range(rng.randint(0, 3))
    ]
    _assert_allocate_matches_brute_force(scope, occupied, requests)


# ---------------------------------------------------------------------------
# free-addresses: 0-based ordinal lookup in scope minus occupied union.
# ---------------------------------------------------------------------------


def test_free_addresses_plain_ordinal_walk_ipv4():
    result = locate_free_addresses("192.0.2.0/29", [], [0, 1, 7])
    assert result == {
        "free_total": "8",
        "addresses": ["192.0.2.0", "192.0.2.1", "192.0.2.7"],
    }


def test_free_addresses_all_address_bits_count_including_network_broadcast():
    # No /31-style exception: both network and broadcast addresses are free.
    result = locate_free_addresses("192.0.2.0/30", [], [0, 3])
    assert result["free_total"] == "4"
    assert result["addresses"] == ["192.0.2.0", "192.0.2.3"]


def test_free_addresses_union_before_clip_overlapping_and_out_of_scope():
    # 192.0.2.3/32 is a duplicate already inside the /31; the disjoint
    # 203.0.113.64/26 reaches beyond the scope and is clipped away. Free are
    # .0 .1 .4 .5 .6 .7.
    result = locate_free_addresses(
        "192.0.2.0/29",
        ["192.0.2.2/31", "192.0.2.3/32", "203.0.113.64/26"],
        [0, 1, 2, 5],
    )
    assert result == {
        "free_total": "6",
        "addresses": ["192.0.2.0", "192.0.2.1", "192.0.2.4", "192.0.2.7"],
    }


def test_free_addresses_occupied_supernet_covers_scope():
    # A broad occupied CIDR containing the whole scope frees nothing.
    assert locate_free_addresses(
        "10.0.0.0/24", ["0.0.0.0/0", "10.0.0.5/32"], []
    ) == {"free_total": "0", "addresses": []}


def test_free_addresses_empty_query_still_returns_total():
    assert locate_free_addresses(
        "10.0.0.0/24", ["10.0.0.0/30", "10.0.0.128/25"], []
    ) == {"free_total": "124", "addresses": []}


def test_free_addresses_keeps_input_order_duplicates_and_repeats():
    # Free: .0 .1 .2 .3 .5 .6 .7 (ordinal 4 lands on .5 because .4 is busy).
    result = locate_free_addresses(
        "10.0.0.0/29", ["10.0.0.4/32"], [3, 0, 4, 6, 6]
    )
    assert result["free_total"] == "7"
    assert result["addresses"] == [
        "10.0.0.3", "10.0.0.0", "10.0.0.5", "10.0.0.7", "10.0.0.7",
    ]


def test_free_addresses_host_prefix_scope():
    assert locate_free_addresses("10.0.0.1", [], [0]) == {
        "free_total": "1",
        "addresses": ["10.0.0.1"],
    }


def test_free_addresses_ipv6_small_scope():
    result = locate_free_addresses(
        "2001:db8::/126",
        ["2001:db8::1/128"],
        [0, 1, 2],
    )
    assert result == {
        "free_total": "3",
        "addresses": ["2001:db8::", "2001:db8::2", "2001:db8::3"],
    }


def test_free_addresses_ipv6_slash0_total_and_extremes():
    result = locate_free_addresses("::/0", [], [0, 2 ** 128 - 1])
    assert result["free_total"] == str(2 ** 128)
    assert result["addresses"] == [
        "::",
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    ]


def test_free_addresses_ipv6_slash0_with_occupied_half():
    total = 2 ** 127
    result = locate_free_addresses(
        "::/0", ["::/1"], [0, 1, total - 2, total - 1]
    )
    assert result["free_total"] == str(total)
    assert result["addresses"] == [
        "8000::",
        "8000::1",
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe",
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    ]


def test_free_addresses_decimal_string_indices_accepted():
    # Strings are the only portable way to carry ordinals past JSON's
    # safe-integer range; both spellings are equivalent.
    result_int = locate_free_addresses("10.0.0.0/30", [], [2])
    result_str = locate_free_addresses("10.0.0.0/30", [], ["2"])
    assert result_str == result_int == {
        "free_total": "4",
        "addresses": ["10.0.0.2"],
    }


def test_free_addresses_index_equal_to_total_rejected():
    with pytest.raises(ValueError, match="out of range"):
        locate_free_addresses("10.0.0.0/30", ["10.0.0.0/32"], [3])


def test_free_addresses_any_index_rejected_when_no_free_space():
    with pytest.raises(ValueError, match="0 free addresses"):
        locate_free_addresses("10.0.0.0/30", ["10.0.0.0/30"], [0])


@pytest.mark.parametrize("bad", [-1, "-1", " 1", "1 ", "", "abc", "0x1", "1.0", True, False, None, 1.5, object()])
def test_free_addresses_malformed_indices_rejected(bad):
    with pytest.raises(ValueError):
        locate_free_addresses("10.0.0.0/24", [], [bad])


def test_free_addresses_wrong_family_occupied_rejected():
    with pytest.raises(ValueError, match="address family"):
        locate_free_addresses("10.0.0.0/24", ["2001:db8::/32"], [])
    with pytest.raises(ValueError, match="address family"):
        locate_free_addresses("::/0", ["0.0.0.0/0"], [])


@pytest.mark.parametrize("bad_scope", ["10.0.0.1/24", "bogus", "10.0.0.0/33"])
def test_free_addresses_invalid_scope_rejected(bad_scope):
    with pytest.raises(ValueError):
        locate_free_addresses(bad_scope, [], [])


@pytest.mark.parametrize("seed", range(40))
def test_free_addresses_matches_brute_force_ipv4(seed):
    rng = random.Random(6100 + seed)
    prefixlen = rng.randint(26, 30)
    base = rng.randrange(2 ** 32) & ~((1 << (32 - prefixlen)) - 1)
    scope = ipaddress.IPv4Network((base, prefixlen))

    occupied = set()
    for _ in range(rng.randint(0, 5)):
        p = rng.randint(prefixlen, 32)
        host = rng.randrange(2 ** (32 - p))
        network = ipaddress.IPv4Network(
            (rng.randrange(2 ** 32) & ~((1 << (32 - p)) - 1), p)
        )
        # Strict networks only; keep both in-scope and disjoint entries.
        occupied.add(network)

    # Brute-force free set over the bounded scope.
    free_nums = sorted(
        set(range(int(scope.network_address),
                  int(scope.broadcast_address) + 1))
        - {
            n
            for net in occupied
            for n in range(
                max(int(net.network_address), int(scope.network_address)),
                min(int(net.broadcast_address),
                    int(scope.broadcast_address)) + 1,
            )
        }
    )

    queried = [rng.randrange(0, len(free_nums) + 8) for _ in range(rng.randint(0, 6))]
    if any(i >= len(free_nums) for i in queried):
        with pytest.raises(ValueError, match="out of range"):
            locate_free_addresses(str(scope), [str(n) for n in occupied], queried)
        return

    result = locate_free_addresses(
        str(scope), [str(n) for n in occupied], queried
    )
    assert result["free_total"] == str(len(free_nums))
    assert result["addresses"] == [
        str(ipaddress.IPv4Address(free_nums[i])) for i in queried
    ]


@pytest.mark.parametrize("seed", range(20))
def test_free_addresses_matches_brute_force_ipv6(seed):
    rng = random.Random(6200 + seed)
    prefixlen = rng.randint(122, 126)
    scope_base = int(ipaddress.IPv6Address("2001:db8::"))
    scope = ipaddress.IPv6Network((scope_base, prefixlen))

    occupied = set()
    for _ in range(rng.randint(0, 5)):
        p = rng.randint(prefixlen, 128)
        network = ipaddress.IPv6Network(
            (rng.getrandbits(128) & ~((1 << (128 - p)) - 1), p)
        )
        occupied.add(network)

    free_nums = sorted(
        set(range(int(scope.network_address),
                  int(scope.broadcast_address) + 1))
        - {
            n
            for net in occupied
            for n in range(
                max(int(net.network_address), int(scope.network_address)),
                min(int(net.broadcast_address),
                    int(scope.broadcast_address)) + 1,
            )
        }
    )

    queried = [rng.randrange(0, len(free_nums) + 8) for _ in range(rng.randint(0, 6))]
    if any(i >= len(free_nums) for i in queried):
        with pytest.raises(ValueError, match="out of range"):
            locate_free_addresses(str(scope), [str(n) for n in occupied], queried)
        return

    result = locate_free_addresses(
        str(scope), [str(n) for n in occupied], queried
    )
    assert result["free_total"] == str(len(free_nums))
    assert result["addresses"] == [
        str(ipaddress.IPv6Address(free_nums[i])) for i in queried
    ]


def test_free_addresses_does_not_enumerate_slash0_slash128():
    # Functional proxy for "no per-address enumeration": the exact-index
    # result equals the value computed arithmetically, and the call returns
    # immediately where enumeration could never finish.
    result = locate_free_addresses(
        "::/0",
        ["8000::/1"],
        [2 ** 127 - 1, 0],
    )
    assert result["addresses"] == ["7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "::"]


# ---------------------------------------------------------------------------
# anonymize: prefix-preserving keyed HMAC anonymization.
# ---------------------------------------------------------------------------


def _ref_anonymize_address(address, key):
    """Independent bit-by-bit reference using the documented HMAC message."""
    family = type(address)
    width = 32 if family is ipaddress.IPv4Address else 128
    tag = 4 if family is ipaddress.IPv4Address else 6
    bits = "".join(f"{byte:08b}" for byte in address.packed)
    out = []
    for position, bit in enumerate(bits):
        prefix_bits = bits[:position].ljust(width, "0")
        message = (
            bytes([tag, position])
            + int(prefix_bits, 2).to_bytes(width // 8, "big")
        )
        mask = hmac.new(key, message, hashlib.sha256).digest()[0] >> 7
        out.append(str(int(bit) ^ mask))
    return family(int("".join(out), 2))


def test_anonymize_matches_independent_reference():
    for key in (bytes(32), bytes(range(32))):
        for text in (
            "0.0.0.0", "10.0.0.1", "127.0.0.1", "255.255.255.255",
            "::", "::1", "2001:db8::1",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        ):
            address = ipaddress.ip_address(text)
            assert _anonymize_address(address, key) == _ref_anonymize_address(
                address, key
            )


def test_anonymize_is_stable_for_one_key():
    key = "11" * 32
    first = anonymize(key, ["10.0.0.1", "2001:db8::1"], ["10.0.0.0/24"])
    second = anonymize(key, ["10.0.0.1", "2001:db8::1"], ["10.0.0.0/24"])
    assert first == second


def test_anonymize_is_deterministic_bitwise():
    key = bytes.fromhex("ab" * 32)
    address = ipaddress.ip_address("198.51.100.7")
    assert _anonymize_address(address, key) == _anonymize_address(address, key)


def test_anonymize_mapping_is_one_to_one_over_ipv4_block():
    # Exhaustive over a /24: 256 distinct inputs map to 256 distinct outputs.
    key = bytes(range(32))
    base = int(ipaddress.IPv4Address("198.51.100.0"))
    outputs = {
        int(_anonymize_address(ipaddress.IPv4Address(base + i), key))
        for i in range(256)
    }
    assert len(outputs) == 256


def test_anonymize_mapping_is_one_to_one_over_ipv6_block():
    # Exhaustive over a /120 (keeps enumeration cheap while covering IPv6).
    key = bytes(range(32))
    base = int(ipaddress.IPv6Address("2001:db8::"))
    outputs = {
        int(_anonymize_address(ipaddress.IPv6Address(base + i), key))
        for i in range(256)
    }
    assert len(outputs) == 256


def _lcp_length(left, right, width):
    differing = int(left) ^ int(right)
    return width - differing.bit_length() if differing else width


@pytest.mark.parametrize("seed", range(40))
def test_anonymize_preserves_longest_common_prefix(seed):
    rng = random.Random(6000 + seed)
    for _ in range(50):
        width = rng.choice((32, 128))
        family = (
            ipaddress.IPv4Address if width == 32 else ipaddress.IPv6Address
        )
        left = family(rng.getrandbits(width))
        right = family(rng.getrandbits(width))
        key = rng.randbytes(32)
        anon_left = _anonymize_address(left, key)
        anon_right = _anonymize_address(right, key)
        assert _lcp_length(left, right, width) == _lcp_length(
            anon_left, anon_right, width
        )


def test_anonymize_address_families_use_domain_separation():
    # The IPv4-mapped IPv6 address of an IPv4 input must NOT share the IPv4
    # anonymization pattern, because family tags separate the HMAC messages.
    key = bytes(range(32))
    v4 = ipaddress.ip_address("192.0.2.123")
    mapped = ipaddress.ip_address("::ffff:192.0.2.123")
    assert int(_anonymize_address(v4, key)) != int(
        _anonymize_address(mapped, key)
    ) & ((1 << 32) - 1)


def test_anonymize_outputs_follow_input_order():
    key = "00" * 32
    result = anonymize(
        key,
        ["10.0.0.2", "10.0.0.1", "192.0.2.1", "2001:db8::1"],
        ["2001:db8::/32", "10.0.0.0/24"],
    )
    expected_addresses = [
        str(_anonymize_address(parse_address(item), bytes(32)))
        for item in ["10.0.0.2", "10.0.0.1", "192.0.2.1", "2001:db8::1"]
    ]
    assert result["addresses"] == expected_addresses
    assert len(result["cidrs"]) == 2


def test_anonymize_cidr_re_masks_anonymized_network_address():
    # Anonymization of the /24 network address may produce host bits; the
    # returned CIDR must be canonical and keep the original prefix length.
    key = "0123456789abcdef" * 4
    result = anonymize(key, [], ["10.0.0.0/24", "2001:db8::/32"])
    for text in result["cidrs"]:
        # parse_network is strict: this rejects any non-zero host bits.
        network = parse_network(text)
        assert str(network) == text
    assert result["cidrs"][0].endswith("/24")
    assert result["cidrs"][1].endswith("/32")


def test_anonymize_network_address_lies_in_anonymized_cidr():
    # Prefix preservation means the anonymized network address is inside the
    # anonymized network for every network in the block (checked exhaustively
    # for one /29).
    key = bytes(range(32))
    for host in range(8):
        text = f"192.0.2.{host}"
        result = anonymize(key.hex(), [], ["192.0.2.0/29"])
        anon_address = parse_address(
            anonymize(key.hex(), [text], [])["addresses"][0]
        )
        anon_network = parse_network(result["cidrs"][0])
        assert anon_address in anon_network


def test_anonymize_empty_lists():
    assert anonymize("00" * 32, [], []) == {"addresses": [], "cidrs": []}


def test_parse_key_hex_accepts_64_hex_characters():
    assert parse_key_hex("00" * 32) == bytes(32)
    assert parse_key_hex("  AbCdEf" + "00" * 29 + "  ") == bytes.fromhex(
        "abcdef" + "00" * 29
    )


@pytest.mark.parametrize(
    "bad",
    [
        "00" * 31,              # too short (62 chars)
        "00" * 33,              # too long
        "z" * 64,               # non-hex characters
        "00 " + "00" * 31,      # whitespace inside
        "",
        123,
        None,
    ],
)
def test_parse_key_hex_rejects_invalid_keys(bad):
    with pytest.raises(ValueError):
        parse_key_hex(bad)


def test_parse_strict_cidr_requires_explicit_prefix():
    with pytest.raises(ValueError):
        parse_strict_cidr("10.0.0.1")
    with pytest.raises(ValueError):
        parse_strict_cidr("2001:db8::1")
    with pytest.raises(ValueError):
        parse_strict_cidr(10)
    assert str(parse_strict_cidr("10.0.0.0/24")) == "10.0.0.0/24"


def test_parse_strict_cidr_rejects_host_bits():
    with pytest.raises(ValueError):
        parse_strict_cidr("10.0.0.1/24")


def test_anonymize_rejects_bare_address_in_cidrs():
    with pytest.raises(ValueError):
        anonymize("00" * 32, [], ["10.0.0.1"])

# ---------------------------------------------------------------------------
# reverse-delegations: in-addr.arpa / RFC 2317 delegation plans.
# ---------------------------------------------------------------------------


def test_reverse_direct_slash24_delegation():
    result = reverse_delegations([("192.0.2.0/24", ["ns1.example.net"])])
    assert result["zones"] == [{
        "zone": "2.0.192.in-addr.arpa.",
        "method": "direct",
        "parent_zone": None,
        "cidr": "192.0.2.0/24",
        "nameservers": ["ns1.example.net."],
    }]
    assert result["records"] == [{
        "zone": "2.0.192.in-addr.arpa.",
        "type": "NS",
        "name": "2.0.192.in-addr.arpa.",
        "target": "ns1.example.net.",
        "cidr": "192.0.2.0/24",
    }]


def test_reverse_slash25_rfc2317_ns_and_cnames():
    result = reverse_delegations([
        ("10.0.0.128/25", ["ns1.cust.example", "ns2.cust.example"]),
    ])
    assert result["zones"] == [{
        "zone": "128/25.0.0.10.in-addr.arpa.",
        "method": "rfc2317",
        "parent_zone": "0.0.10.in-addr.arpa.",
        "cidr": "10.0.0.128/25",
        "nameservers": ["ns1.cust.example.", "ns2.cust.example."],
    }]
    records = result["records"]
    # Two NS records first, then one CNAME per covered address (128..255).
    assert [r["type"] for r in records[:2]] == ["NS", "NS"]
    cnames = records[2:]
    assert len(cnames) == 128
    assert cnames[0] == {
        "zone": "0.0.10.in-addr.arpa.",
        "type": "CNAME",
        "name": "128.0.0.10.in-addr.arpa.",
        "target": "128.128/25.0.0.10.in-addr.arpa.",
        "cidr": "10.0.0.128/25",
    }
    assert cnames[-1]["name"] == "255.0.0.10.in-addr.arpa."
    assert cnames[-1]["target"] == "255.128/25.0.0.10.in-addr.arpa."
    # CNAME owner names are strictly ascending by last octet.
    owners = [int(r["name"].split(".", 1)[0]) for r in cnames]
    assert owners == list(range(128, 256))


def test_reverse_slash32_rfc2317_single_address():
    result = reverse_delegations([("10.0.0.5/32", ["host-5.example.org"])])
    assert result["zones"][0]["zone"] == "5/32.0.0.10.in-addr.arpa."
    assert result["records"] == [
        {
            "zone": "0.0.10.in-addr.arpa.",
            "type": "NS",
            "name": "5/32.0.0.10.in-addr.arpa.",
            "target": "host-5.example.org.",
            "cidr": "10.0.0.5/32",
        },
        {
            "zone": "0.0.10.in-addr.arpa.",
            "type": "CNAME",
            "name": "5.0.0.10.in-addr.arpa.",
            "target": "5.5/32.0.0.10.in-addr.arpa.",
            "cidr": "10.0.0.5/32",
        },
    ]


def test_reverse_non_octet_boundary_prefix_uses_network_last_octet():
    result = reverse_delegations([("172.16.5.192/26", ["ns.example"])])
    assert result["zones"][0]["zone"] == "192/26.5.16.172.in-addr.arpa."
    cnames = [r for r in result["records"] if r["type"] == "CNAME"]
    assert len(cnames) == 64
    assert cnames[0]["target"] == "192.192/26.5.16.172.in-addr.arpa."
    assert cnames[-1]["target"] == "255.192/26.5.16.172.in-addr.arpa."


def test_reverse_zones_and_records_sorted_by_network_address():
    # Three disjoint /25-/32 networks in one /24, input deliberately
    # shuffled; both zones and record groups must come back sorted by
    # network address (5/32 before 64/27 before 128/30).  A direct /24
    # delegation cannot share a batch with anything (it would overlap or
    # leave the parent /24), so it is covered by its own test above.
    result = reverse_delegations([
        ("10.0.0.128/30", ["ns-b.example"]),
        ("10.0.0.64/27", ["ns-a.example"]),
        ("10.0.0.5/32", ["ns-c.example"]),
    ])
    assert [z["cidr"] for z in result["zones"]] == [
        "10.0.0.5/32", "10.0.0.64/27", "10.0.0.128/30",
    ]
    # Group boundaries in the flat record list follow the same order.
    group_order = []
    for record in result["records"]:
        if not group_order or group_order[-1] != record["cidr"]:
            group_order.append(record["cidr"])
    assert group_order == ["10.0.0.5/32", "10.0.0.64/27", "10.0.0.128/30"]
    # Within each group every NS record precedes the CNAME records.
    for cidr in group_order:
        types = [r["type"] for r in result["records"] if r["cidr"] == cidr]
        assert types[0] == "NS"
        assert types[1:] == ["CNAME"] * (len(types) - 1)


def test_reverse_every_record_carries_its_source_cidr():
    result = reverse_delegations([
        ("10.0.0.0/26", ["ns1.example"]),
        ("10.0.0.64/27", ["ns2.example"]),
    ])
    counts = {}
    for record in result["records"]:
        counts[record["cidr"]] = counts.get(record["cidr"], 0) + 1
    # /26: 1 NS + 64 CNAMEs; /27: 1 NS + 32 CNAMEs.
    assert counts == {"10.0.0.0/26": 65, "10.0.0.64/27": 33}


def test_reverse_nameservers_normalized_and_deduplicated():
    # Missing trailing dot is appended; upper case is folded; a duplicate
    # target spelling collapses to one NS record, first order kept.
    result = reverse_delegations([
        ("192.0.2.0/24", ["NS1.Example.NET", "ns1.example.net.", "ns2.x.test"]),
    ])
    assert result["zones"][0]["nameservers"] == [
        "ns1.example.net.", "ns2.x.test.",
    ]
    assert [r["target"] for r in result["records"]] == [
        "ns1.example.net.", "ns2.x.test.",
    ]


def test_reverse_empty_batch():
    assert reverse_delegations([]) == {"zones": [], "records": []}


def test_parse_reverse_cidr_accepts_slash24_through_slash32():
    for prefixlen in range(24, 33):
        network = _parse_reverse_cidr(f"10.0.0.0/{prefixlen}")
        assert network.prefixlen == prefixlen
    # Non-zero starting addresses aligned to the prefix are fine.
    assert str(_parse_reverse_cidr("10.0.0.128/25")) == "10.0.0.128/25"
    assert str(_parse_reverse_cidr("10.0.0.1/32")) == "10.0.0.1/32"


@pytest.mark.parametrize(
    "bad",
    [
        "10.0.0.0/23",      # prefix too short
        "10.0.0.0/8",
        "10.0.0.1/24",      # host bits set
        "10.0.0.1",         # bare address: explicit prefix required
        "2001:db8::/120",   # IPv6
        "bogus",
        "10.0.0.0/33",
        "",
    ],
)
def test_parse_reverse_cidr_rejects_invalid(bad):
    with pytest.raises(ValueError):
        _parse_reverse_cidr(bad)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("ns1.example.net", "ns1.example.net."),
        ("NS1.Example.NET.", "ns1.example.net."),
        ("a.b.c.", "a.b.c."),
        ("x", "x."),
    ],
)
def test_parse_nameserver_canonicalizes(raw, expected):
    assert _parse_nameserver(raw) == expected


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "-bad.example",        # label starts with hyphen
        "bad-.example",        # label ends with hyphen
        "exa mple.net",        # whitespace inside
        "exa..mple.net",       # empty label
        ".example.net.",       # leading dot (empty first label)
        "10.0.0.1",            # bare IPv4
        "10.0.0.1.",           # trailing-dot IPv4
        "2001:db8::1",         # bare IPv6
        "x" * 64 + ".test",    # label too long
        "a." + "b." * 127 + "c",  # name over 253 chars
        None,
        10,
    ],
)
def test_parse_nameserver_rejects_invalid(bad):
    with pytest.raises(ValueError):
        _parse_nameserver(bad)


def test_reverse_rejects_overlapping_cidrs():
    with pytest.raises(ValueError, match="overlap"):
        reverse_delegations([
            ("10.0.0.0/25", ["a.example"]),
            ("10.0.0.64/26", ["b.example"]),
        ])
    # A /24 beside anything in that /24 is an overlap as well.
    with pytest.raises(ValueError, match="overlap"):
        reverse_delegations([
            ("10.0.0.0/24", ["a.example"]),
            ("10.0.0.0/32", ["b.example"]),
        ])


def test_reverse_rejects_different_parent_24():
    with pytest.raises(ValueError, match="parent /24"):
        reverse_delegations([
            ("10.0.0.0/25", ["a.example"]),
            ("10.0.1.0/25", ["b.example"]),
        ])


def test_reverse_rejects_empty_nameserver_list():
    with pytest.raises(ValueError, match="at least one nameserver"):
        reverse_delegations([("10.0.0.0/25", [])])


def test_reverse_rejects_bad_nameserver_text():
    with pytest.raises(ValueError, match="nameserver"):
        reverse_delegations([("10.0.0.0/25", ["not a name"])])


@pytest.mark.parametrize("prefixlen", range(25, 33))
def test_reverse_rfc2317_plan_covers_every_prefix_length(prefixlen):
    # One /p block at the lowest aligned address: NS + 2**(32-p) CNAMEs.
    count = 1 << (32 - prefixlen)
    cidr = f"198.51.100.0/{prefixlen}"
    result = reverse_delegations([(cidr, ["ns.example"])])
    zone = result["zones"][0]
    assert zone["zone"] == f"0/{prefixlen}.100.51.198.in-addr.arpa."
    assert zone["method"] == "rfc2317"
    records = result["records"]
    assert len(records) == 1 + count
    assert records[0]["type"] == "NS"
    owners = [
        int(r["name"].split(".", 1)[0])
        for r in records[1:]
    ]
    assert owners == list(range(count))
    # Every CNAME points into the same labelled subzone.
    assert all(
        r["target"].split(".", 1)[1] == f"0/{prefixlen}.100.51.198.in-addr.arpa."
        for r in records[1:]
    )


def test_reverse_sibling_delegations_partition_the_parent_without_gaps():
    # Two /25 halves of one /24 are disjoint and together own every CNAME.
    result = reverse_delegations([
        ("10.0.0.0/25", ["low.example"]),
        ("10.0.0.128/25", ["high.example"]),
    ])
    cnames = [r for r in result["records"] if r["type"] == "CNAME"]
    owners = sorted(int(r["name"].split(".", 1)[0]) for r in cnames)
    assert owners == list(range(256))
    assert all(r["cidr"] == "10.0.0.0/25" for r in cnames[:128])
    assert all(r["cidr"] == "10.0.0.128/25" for r in cnames[128:])


# ---------------------------------------------------------------------------
# roa-coverage: ROA valid/invalid/unknown partition, with a brute-force
# per-candidate reference implementation and random IPv4/IPv6 cross-checks.
# ---------------------------------------------------------------------------


def _ref_roa_status(candidate, asn, roas):
    """Brute-force RFC 6483 status for one aligned candidate route."""
    covered = False
    for network, roa_asn, max_length in roas:
        if candidate.subnet_of(network):
            covered = True
            if roa_asn == asn and candidate.prefixlen <= max_length:
                return "valid"
    return "invalid" if covered else "unknown"


def _assert_roa_partition_matches_reference(scope_s, asn, length, roas_raw):
    """Validate tiling, statuses, minimality and ordering against brute force."""
    scope = ipaddress.ip_network(scope_s, strict=True)
    roas = [
        (ipaddress.ip_network(c, strict=True), a, m) for c, a, m in roas_raw
    ]
    result = roa_coverage(scope_s, asn, length, roas_raw)["partitions"]
    parts = [
        (ipaddress.ip_network(p["cidr"], strict=True), p["status"])
        for p in result
    ]

    if length < scope.prefixlen:
        assert parts == []
        return

    candidates = list(scope.subnets(new_prefix=length))
    expected = {c: _ref_roa_status(c, asn, roas) for c in candidates}

    # Sorted by network address.
    assert [int(n.network_address) for n, _ in parts] == sorted(
        int(n.network_address) for n, _ in parts
    )
    # Pieces are inside scope, no longer than the requested length, pairwise
    # disjoint and jointly exhaust the whole scope candidate region.
    for network, _status in parts:
        assert network.subnet_of(scope)
        assert scope.prefixlen <= network.prefixlen <= length
        for other, _ in parts:
            assert not (network != other and network.overlaps(other))
    assert sum(1 << (length - n.prefixlen) for n, _ in parts) == len(candidates)
    # Every candidate inside a piece shares the piece's status.
    for network, status in parts:
        inside = [c for c in candidates if c.subnet_of(network)]
        assert inside  # a piece always covers at least one aligned candidate
        assert all(expected[c] == status for c in inside)
    # Minimum: no two equal-status siblings are left unmerged.
    table = {(int(n.network_address), n.prefixlen): s for n, s in parts}
    for network, status in parts:
        if network.prefixlen > scope.prefixlen:
            halves = list(network.supernet().subnets())
            sibling = halves[1] if halves[0] == network else halves[0]
            assert table.get((int(sibling.network_address), sibling.prefixlen)) != status


def test_roa_valid_invalid_unknown_basic_partition():
    result = roa_coverage(
        "203.0.113.0/24", 64500, 26,
        [
            ("203.0.113.0/25", 64500, 26),    # authorizes both lower /26s
            ("203.0.113.128/26", 64501, 26),  # covers with the wrong ASN
        ],
    )
    assert result == {"partitions": [
        {"cidr": "203.0.113.0/25", "status": "valid"},
        {"cidr": "203.0.113.128/26", "status": "invalid"},
        {"cidr": "203.0.113.192/26", "status": "unknown"},
    ]}


def test_roa_max_length_too_short_makes_invalid_and_merges_to_scope():
    # A covering ROA for the target ASN whose max_length is below the
    # proposed length leaves both /25 candidates invalid; the equal-status
    # siblings merge to one piece coarser than the requested length.
    result = roa_coverage(
        "203.0.113.0/24", 64500, 25,
        [("203.0.113.0/24", 64500, 24)],
    )
    assert result == {"partitions": [
        {"cidr": "203.0.113.0/24", "status": "invalid"},
    ]}


def test_roa_wrong_asn_beside_validating_roa():
    # Covered by a wrong-ASN ROA everywhere, but a narrower target-ASN ROA
    # promotes one candidate to valid.
    result = roa_coverage(
        "10.0.0.0/24", 100, 25,
        [
            ("10.0.0.0/24", 200, 32),
            ("10.0.0.0/25", 100, 25),
        ],
    )
    assert result == {"partitions": [
        {"cidr": "10.0.0.0/25", "status": "valid"},
        {"cidr": "10.0.0.128/25", "status": "invalid"},
    ]}


def test_roa_valid_never_degrades_under_stricter_wrong_asn_roa():
    # A broad authorizing ROA covers the whole scope; a narrow wrong-ASN ROA
    # must not make the covered region invalid.
    result = roa_coverage(
        "10.0.0.0/24", 100, 28,
        [
            ("10.0.0.0/24", 100, 32),
            ("10.0.0.0/26", 200, 32),
        ],
    )
    assert result == {"partitions": [
        {"cidr": "10.0.0.0/24", "status": "valid"},
    ]}


def test_roa_no_roas_means_entire_scope_unknown():
    result = roa_coverage("10.0.0.0/24", 65000, 28, [])
    assert result == {"partitions": [
        {"cidr": "10.0.0.0/24", "status": "unknown"},
    ]}


def test_roa_roa_stricter_than_candidate_does_not_cover():
    # The /32 ROA lives entirely inside the single /24 candidate route, so it
    # does not cover that route; it stays unknown.
    result = roa_coverage(
        "10.0.0.0/24", 100, 24, [("10.0.0.1/32", 100, 32)],
    )
    assert result == {"partitions": [
        {"cidr": "10.0.0.0/24", "status": "unknown"},
    ]}


def test_roa_disjoint_roas_are_ignored():
    result = roa_coverage(
        "10.0.0.0/24", 100, 26,
        [
            ("0.0.0.0/0", 100, 32),          # broader: valid everywhere
            ("9.255.255.255/32", 100, 32),   # disjoint: ignored
            ("11.0.0.0/16", 200, 32),        # disjoint: ignored
        ],
    )
    assert result == {"partitions": [
        {"cidr": "10.0.0.0/24", "status": "valid"},
    ]}
    result = roa_coverage(
        "10.0.0.0/24", 100, 26, [("11.0.0.0/16", 200, 32)],
    )
    assert result == {"partitions": [
        {"cidr": "10.0.0.0/24", "status": "unknown"},
    ]}


def test_roa_prefix_length_shorter_than_scope_returns_empty():
    # No aligned candidate of length < scope prefix fits inside the scope;
    # this is treated as an empty candidate region (the API rejects it as a
    # 422, but the core function returns no partitions).
    assert roa_coverage(
        "10.0.0.0/24", 100, 23, [("10.0.0.0/24", 100, 24)]
    ) == {"partitions": []}


def test_roa_host_route_granularity_ipv6():
    result = roa_coverage(
        "2001:db8::/120", 100, 128,
        [
            ("2001:db8::5/128", 100, 128),
            ("2001:db8::a/128", 200, 128),
        ],
    )
    partitions = result["partitions"]
    statuses = {p["cidr"]: p["status"] for p in partitions}
    assert statuses["2001:db8::5/128"] == "valid"
    assert statuses["2001:db8::a/128"] == "invalid"
    # All other addresses collapse to one unknown block covering 253 hosts.
    unknown = [p for p in partitions if p["status"] == "unknown"]
    assert sum(
        1 << (128 - ipaddress.ip_network(p["cidr"]).prefixlen)
        for p in unknown
    ) == 254


def test_roa_ipv6_zero_scope_at_128_does_not_enumerate_and_tiles_space():
    # A ::/0 scope with /128 candidates has 2**128 routes; the result must
    # come back instantly as a small CIDR tiling covering the whole space.
    result = roa_coverage(
        "::/0", 100, 128,
        [
            ("2001:db8::/32", 100, 128),
            ("2001:db9::/32", 200, 48),
        ],
    )
    partitions = result["partitions"]
    assert len(partitions) < 100
    total = sum(
        1 << (128 - ipaddress.ip_network(p["cidr"]).prefixlen)
        for p in partitions
    )
    assert total == 1 << 128
    by_cidr = {p["cidr"]: p["status"] for p in partitions}
    assert by_cidr["2001:db8::/32"] == "valid"
    assert by_cidr["2001:db9::/32"] == "invalid"


def test_roa_default_scope_route_length_zero():
    assert roa_coverage(
        "0.0.0.0/0", 1, 0, [("0.0.0.0/0", 1, 0)]
    ) == {"partitions": [{"cidr": "0.0.0.0/0", "status": "valid"}]}
    assert roa_coverage(
        "0.0.0.0/0", 1, 0, [("0.0.0.0/0", 2, 0)]
    ) == {"partitions": [{"cidr": "0.0.0.0/0", "status": "invalid"}]}
    assert roa_coverage("0.0.0.0/0", 1, 0, []) == {
        "partitions": [{"cidr": "0.0.0.0/0", "status": "unknown"}],
    }


def test_roa_max_length_authorization_boundary():
    # Exactly-equal max_length authorizes; one less does not.
    assert roa_coverage(
        "10.0.0.0/24", 100, 26, [("10.0.0.0/24", 100, 26)]
    )["partitions"] == [{"cidr": "10.0.0.0/24", "status": "valid"}]
    assert roa_coverage(
        "10.0.0.0/24", 100, 26, [("10.0.0.0/24", 100, 25)]
    )["partitions"] == [{"cidr": "10.0.0.0/24", "status": "invalid"}]


def test_roa_cross_family_roa_rejected():
    with pytest.raises(ValueError, match="address family"):
        roa_coverage("10.0.0.0/24", 100, 26, [("2001:db8::/32", 100, 48)])
    with pytest.raises(ValueError, match="address family"):
        roa_coverage("2001:db8::/32", 100, 48, [("10.0.0.0/8", 100, 24)])


def test_roa_invalid_max_length_rejected():
    # max_length below the ROA prefix length.
    with pytest.raises(ValueError, match="max_length"):
        roa_coverage("10.0.0.0/24", 100, 26, [("10.0.0.0/25", 100, 24)])
    # max_length beyond the family width.
    with pytest.raises(ValueError, match="max_length"):
        roa_coverage("10.0.0.0/24", 100, 26, [("10.0.0.0/24", 100, 33)])
    with pytest.raises(ValueError, match="max_length"):
        roa_coverage("2001:db8::/32", 100, 48, [("2001:db8::/32", 100, 129)])


def test_roa_strict_cidr_required():
    with pytest.raises(ValueError):
        roa_coverage("10.0.0.0/24", 100, 26, [("10.0.0.0", 100, 24)])
    with pytest.raises(ValueError):
        roa_coverage("10.0.0.0/24", 100, 26, [("10.0.0.1/24", 100, 24)])


def test_roa_random_ipv4_cases_match_brute_force():
    rng = random.Random(20240927)
    for _ in range(500):
        scope_len = rng.randint(0, 20)
        scope = ipaddress.IPv4Network((
            rng.getrandbits(32) & (((1 << (32 - scope_len)) - 1)
                                   << (32 - scope_len))
            if scope_len else 0,
            scope_len,
        ))
        length = rng.randint(scope.prefixlen, min(32, scope.prefixlen + 8))
        roas = []
        for _ in range(rng.randint(0, 8)):
            pl = rng.randint(scope.prefixlen,
                             min(length + rng.randint(0, 3), 32))
            base = rng.getrandbits(32) & (
                ((1 << (32 - pl)) - 1) << (32 - pl)
            )
            roas.append((
                str(ipaddress.IPv4Network((base, pl))),
                rng.choice([100, 200, 300]),
                rng.randint(pl, min(32, pl + 3)),
            ))
        _assert_roa_partition_matches_reference(
            str(scope), rng.choice([100, 400]), length, roas,
        )


def test_roa_random_ipv6_cases_match_brute_force():
    rng = random.Random(20240928)
    for _ in range(300):
        scope_len = rng.randint(0, 8)
        scope = ipaddress.IPv6Network((
            rng.getrandbits(128) & (((1 << (128 - scope_len)) - 1)
                                    << (128 - scope_len))
            if scope_len else 0,
            scope_len,
        ))
        length = rng.randint(scope.prefixlen, min(128, scope.prefixlen + 6))
        roas = []
        for _ in range(rng.randint(0, 8)):
            pl = rng.randint(scope.prefixlen, min(length + 2, 128))
            base = rng.getrandbits(128) & (
                ((1 << (128 - pl)) - 1) << (128 - pl)
            )
            roas.append((
                str(ipaddress.IPv6Network((base, pl))),
                rng.choice([100, 200]),
                rng.randint(pl, min(128, pl + 2)),
            ))
        _assert_roa_partition_matches_reference(
            str(scope), rng.choice([100, 300]), length, roas,
        )


def test_roa_random_shorter_length_cases_return_empty():
    rng = random.Random(7)
    for _ in range(50):
        scope_len = rng.randint(1, 24)
        scope = ipaddress.IPv4Network((
            rng.getrandbits(32) & (((1 << (32 - scope_len)) - 1)
                                   << (32 - scope_len)),
            scope_len,
        ))
        length = rng.randint(0, scope_len - 1)
        assert roa_coverage(str(scope), 1, length, []) == {"partitions": []}


# ---------------------------------------------------------------------------
# as-relationship-repair: minimum-cardinality valley-free repair
# ---------------------------------------------------------------------------

from app.policy import (  # noqa: E402
    AS_PATH_LIMIT,
    AS_RELATIONSHIP_LIMIT,
    REL_HI_CUSTOMER,
    REL_LO_CUSTOMER,
    REL_PEER,
    _hop_kind,
    as_relationship_repair,
    as_relationship_token,
)

#: Build the public response-style relationship dict for one canonical pair.
def _as_entry(pair, token):
    """Build the public response-style dict for one repaired pair/token."""
    lo, hi = pair
    if token == REL_PEER:
        return {"type": "peer", "peers": [lo, hi]}
    if token == REL_LO_CUSTOMER:
        return {"type": "customer_provider", "customer": lo, "provider": hi}
    return {"type": "customer_provider", "customer": hi, "provider": lo}


def _brute_force_repair(relationships, paths):
    """Independent reference: enumerate all 3^n relationship assignments."""
    original = dict(relationships)
    used = sorted({
        pair
        for path in paths
        for left, right in zip(path, path[1:])
        for pair in (tuple(sorted((left, right))),)
    })

    def vf(path, tokens):
        state = "U"
        for left, right in zip(path, path[1:]):
            pair = tuple(sorted((left, right)))
            kind = _hop_kind(left, right, tokens[pair])
            if kind == "U":
                if state != "U":
                    return False
            elif kind == "P":
                if state != "U":
                    return False
                state = "P"
            else:
                state = "D"
        return True

    best = None
    for combo in itertools.product((0, 1, 2), repeat=len(used)):
        tokens = dict(zip(used, combo))
        if not all(vf(path, tokens) for path in paths):
            continue
        changed = tuple(
            (pair, token)
            for pair, token in zip(used, combo)
            if token != original[pair]
        )
        full_seq = tuple(combo)
        key = (len(changed), full_seq)
        if best is None or key < best[0]:
            best = (key, changed)
    if best is None:
        return None
    return [_as_entry(pair, token) for pair, token in best[1]]


def test_as_token_orientation_helpers():
    assert as_relationship_token(1, 2) == REL_LO_CUSTOMER
    assert as_relationship_token(2, 1) == REL_HI_CUSTOMER
    # Endpoint order is irrelevant for the canonical code.
    assert as_relationship_token(2, 1) == as_relationship_token(2, 1)


def test_as_repair_shared_single_flip_repairs_two_paths():
    # Both paths go provider->customer (down) into AS 200 and then
    # customer->provider (up) out of it: the same valley on the shared
    # 200/300 edge; reversing that one relationship repairs both paths.
    relationships = [
        ((100, 200), REL_HI_CUSTOMER),  # customer 200, provider 100
        ((200, 300), REL_LO_CUSTOMER),  # customer 200, provider 300
        ((200, 400), REL_LO_CUSTOMER),  # customer 200, provider 400
    ]
    paths = [[100, 200, 300], [400, 200, 300]]
    result = as_relationship_repair(relationships, paths)
    assert result == {
        "violating_path_indices": [0, 1],
        "corrections": [
            {"type": "customer_provider", "customer": 300, "provider": 200},
        ],
        "changes": 1,
    }


def test_as_repair_all_valley_free_returns_zero_changes():
    # 1 -> 2 -> 3 is up then down: 1 customer of 2, 3 customer of 2.
    relationships = [
        ((1, 2), REL_LO_CUSTOMER),
        ((2, 3), REL_HI_CUSTOMER),
    ]
    assert as_relationship_repair(relationships, [[1, 2, 3]]) == {
        "violating_path_indices": [],
        "corrections": [],
        "changes": 0,
    }


def test_as_repair_peer_patterns_need_no_change():
    # up, peer, down is the canonical legal summit path.
    relationships = [
        ((1, 2), REL_LO_CUSTOMER),   # 1 customer of 2
        ((2, 3), REL_PEER),
        ((3, 4), REL_HI_CUSTOMER),   # 4 customer of 3
    ]
    assert as_relationship_repair(relationships, [[1, 2, 3, 4]]) == {
        "violating_path_indices": [],
        "corrections": [],
        "changes": 0,
    }
    # A peer-only path and an all-peer path are legal too, but two peer hops
    # in a three-AS path (which needs no c2p hop) is still one peer hop.
    assert as_relationship_repair(
        [((5, 6), REL_PEER)], [[5, 6]]
    )["changes"] == 0


def test_as_repair_two_peers_in_a_path_is_repaired():
    # up, peer, peer would climb through two summits; a one-change repair
    # exists on either peer edge.  The full new-relationship sequence over
    # (1,2),(2,3),(3,4) chooses (0,0,2) over (0,2,1): turn the earlier peer
    # (2,3) into a c2p link, giving up, up, peer.
    relationships = [
        ((1, 2), REL_LO_CUSTOMER),
        ((2, 3), REL_PEER),
        ((3, 4), REL_PEER),
    ]
    result = as_relationship_repair(relationships, [[1, 2, 3, 4]])
    assert result["violating_path_indices"] == [0]
    assert result["changes"] == 1
    assert result["corrections"] == [
        {"type": "customer_provider", "customer": 2, "provider": 3},
    ]


def test_as_repair_single_as_path_is_trivially_valid():
    assert as_relationship_repair([], [[7]]) == {
        "violating_path_indices": [],
        "corrections": [],
        "changes": 0,
    }
    assert as_relationship_repair([], []) == {
        "violating_path_indices": [],
        "corrections": [],
        "changes": 0,
    }


def test_as_repair_violating_indices_follow_input_order():
    # AS 2 has providers 1 and 3 and customer 4.
    #   [3,2,1] up then up     -> legal (customer reaches its providers)
    #   [4,2,3] down then down -> legal (provider reaches its customers)
    #   [1,2,4] down then up   -> valley (violating)
    relationships = [
        ((1, 2), REL_HI_CUSTOMER),   # customer 2, provider 1
        ((2, 3), REL_HI_CUSTOMER),   # customer 2, provider 3
        ((2, 4), REL_LO_CUSTOMER),   # customer 2, provider 4
    ]
    paths = [[3, 2, 1], [4, 2, 3], [1, 2, 4]]
    result = as_relationship_repair(relationships, paths)
    assert result["violating_path_indices"] == [2]


def test_as_repair_tie_break_prefers_smaller_pair_change():
    # Valley 100->200->300 with both edges orientable either way at cost 1;
    # the lexicographically smallest full new-relationship sequence changes
    # the smaller pair (100,200) first.
    relationships = [
        ((100, 200), REL_HI_CUSTOMER),
        ((200, 300), REL_LO_CUSTOMER),
    ]
    result = as_relationship_repair(relationships, [[100, 200, 300]])
    assert result["corrections"] == [
        {"type": "customer_provider", "customer": 100, "provider": 200},
    ]
    assert result["changes"] == 1


def test_as_repair_tie_break_full_sequence_vs_changed_only():
    # Path 6 -> 1 -> 5 is a peer hop followed by an up-hop (a summit after
    # the first hop is illegal).  Two one-change repairs exist:
    #   * flip the later (1,5) edge to customer 5/provider 1: path becomes
    #     peer, down (changed sequence starts at (1,5));
    #   * flip the earlier (1,6) edge to customer 6/provider 1: path becomes
    #     up, up (changed sequence starts at (1,6)).
    # A changed-only lexicographic comparison would pick the (1,5) flip
    # (smaller changed pair), but the full sorted new-relationship sequence
    # over (1,5),(1,6) is (1,0) for the (1,6) flip versus (0,1) for the
    # (1,5) flip, so the (1,6) flip is the unique answer here.
    relationships = [
        ((1, 5), REL_LO_CUSTOMER),  # token 0
        ((1, 6), REL_PEER),         # token 2
    ]
    paths = [[6, 1, 5]]
    result = as_relationship_repair(relationships, paths)
    assert result["changes"] == 1
    assert result["corrections"] == [
        {"type": "customer_provider", "customer": 6, "provider": 1},
    ]


def test_as_repair_unused_relationships_are_never_changed():
    relationships = [
        ((100, 200), REL_HI_CUSTOMER),
        ((200, 300), REL_LO_CUSTOMER),
        ((900, 901), REL_PEER),
    ]
    result = as_relationship_repair(relationships, [[100, 200, 300]])
    # The unused (900,901) relationship neither constrains the search nor
    # appears in the corrections.
    assert all(
        item["type"] == "customer_provider"
        and {item["customer"], item["provider"]} != {900, 901}
        for item in result["corrections"]
    )
    assert result["changes"] == len(result["corrections"]) == 1


def test_as_repair_shared_edge_across_paths_uses_one_correction():
    # Three paths share the (2,3) edge; whatever it becomes must satisfy all.
    relationships = [
        ((1, 2), REL_HI_CUSTOMER),
        ((2, 3), REL_LO_CUSTOMER),
        ((2, 4), REL_LO_CUSTOMER),
    ]
    paths = [[1, 2, 3], [4, 2, 3]]
    result = as_relationship_repair(relationships, paths)
    # One flip of the shared edge repairs both, never two corrections.
    assert result["changes"] == 1
    assert result["corrections"] == [
        {"type": "customer_provider", "customer": 3, "provider": 2},
    ]


def test_as_repair_infeasible_returns_none():
    # Four paths on five edges whose constraints contradict under every
    # relabeling (any three of the paths are jointly satisfiable).
    relationships = [
        ((1, 2), REL_LO_CUSTOMER),
        ((1, 3), REL_HI_CUSTOMER),
        ((1, 4), REL_PEER),
        ((2, 3), REL_LO_CUSTOMER),
        ((3, 4), REL_HI_CUSTOMER),
    ]
    paths = [
        [4, 3, 2, 1],
        [2, 1, 3, 4],
        [4, 1, 3, 2],
        [3, 4, 1, 2],
    ]
    assert as_relationship_repair(relationships, paths) is None
    # Every three-path subset is feasible, proving the witness is tight.
    for keep in itertools.combinations(range(4), 3):
        assert as_relationship_repair(
            relationships, [paths[i] for i in keep]
        ) is not None


def _random_instance(rng, max_edges=9):
    asns = list(range(1, rng.randint(3, 7)))
    edge_pool = list(itertools.combinations(asns, 2))
    rng.shuffle(edge_pool)
    edges = sorted(edge_pool[: rng.randint(1, min(max_edges, len(edge_pool)))])
    relationships = [(edge, rng.randint(0, 2)) for edge in edges]

    adjacency = {}
    for left, right in edges:
        adjacency.setdefault(left, []).append(right)
        adjacency.setdefault(right, []).append(left)

    paths = []
    for _ in range(rng.randint(1, AS_PATH_LIMIT)):
        start = rng.choice(list(adjacency))
        path = [start]
        current = start
        for _ in range(rng.randint(0, 4)):
            options = [asn for asn in adjacency[current] if asn not in path]
            if not options:
                break
            current = rng.choice(options)
            path.append(current)
        if len(path) >= 2:
            paths.append(path)
    if not paths:
        paths.append([edges[0][0], edges[0][1]])
    return relationships, paths


def test_as_repair_matches_brute_force_on_random_instances():
    rng = random.Random(20260927)
    for _ in range(400):
        relationships, paths = _random_instance(rng)
        result = as_relationship_repair(relationships, paths)
        expected = _brute_force_repair(relationships, paths)
        if expected is None:
            assert result is None
            continue
        assert result is not None
        assert result["corrections"] == expected
        assert result["changes"] == len(expected)


def _brute_force_path_valid(path, tokens):
    state = "U"
    for left, right in zip(path, path[1:]):
        kind = _hop_kind(
            left, right, tokens[tuple(sorted((left, right)))]
        )
        if kind == "U":
            if state != "U":
                return False
        elif kind == "P":
            if state != "U":
                return False
            state = "P"
        else:
            state = "D"
    return True


def test_as_repair_violating_indices_match_grammar_on_random_instances():
    rng = random.Random(987654321)
    for _ in range(400):
        relationships, paths = _random_instance(rng)
        result = as_relationship_repair(relationships, paths)
        original = dict(relationships)
        expected = [
            index
            for index, path in enumerate(paths)
            if not _brute_force_path_valid(path, original)
        ]
        # Violating indices are computed from the originals, independent of
        # whether a repair exists (an infeasible instance still reports them).
        if result is not None:
            assert result["violating_path_indices"] == expected


def test_as_repair_repaired_output_makes_every_path_valid_randomly():
    rng = random.Random(13579)
    for _ in range(400):
        relationships, paths = _random_instance(rng)
        result = as_relationship_repair(relationships, paths)
        if result is None:
            continue
        tokens = dict(relationships)
        for correction in result["corrections"]:
            if correction["type"] == "peer":
                pair = tuple(sorted(correction["peers"]))
                tokens[pair] = REL_PEER
            else:
                pair = tuple(sorted(
                    (correction["customer"], correction["provider"])
                ))
                tokens[pair] = as_relationship_token(
                    correction["customer"], correction["provider"]
                )
        assert all(_brute_force_path_valid(path, tokens) for path in paths)


def test_as_repair_respects_declared_limits():
    assert AS_RELATIONSHIP_LIMIT == 9
    assert AS_PATH_LIMIT == 20


# ---------------------------------------------------------------------------
# nat64-codec: RFC 6052 Network-Specific IPv4/IPv6 translation mapping
# ---------------------------------------------------------------------------

#: Worked examples from RFC 6052 section 2.4, mapping 192.0.2.33 under each
#: allowed Network-Specific Prefix length.
RFC6052_EXAMPLES = {
    32: ("2001:db8::/32", "2001:db8:c000:221::"),
    40: ("2001:db8:100::/40", "2001:db8:1c0:2:21::"),
    48: ("2001:db8:1::/48", "2001:db8:1:c000:2:2100::"),
    56: ("2001:db8:1:100::/56", "2001:db8:1:1c0:0:221::"),
    64: ("2001:db8:1:2::/64", "2001:db8:1:2:c0:2:2100:0"),
    96: ("2001:db8:1:2::/96", "2001:db8:1:2::c000:221"),
}


@pytest.mark.parametrize("length", [32, 40, 48, 56, 64, 96])
def test_nat64_encode_matches_rfc6052_worked_examples(length):
    prefix, mapped = RFC6052_EXAMPLES[length]
    result = nat64_codec(prefix, ["192.0.2.33"], [])
    assert result == {"encoded": [mapped], "decoded": []}


@pytest.mark.parametrize("length", [32, 40, 48, 56, 64, 96])
def test_nat64_decode_matches_rfc6052_worked_examples(length):
    prefix, mapped = RFC6052_EXAMPLES[length]
    result = nat64_codec(prefix, [], [mapped])
    assert result == {"encoded": [], "decoded": ["192.0.2.33"]}


def test_nat64_results_keep_input_order_and_length():
    v4 = ["0.0.0.0", "255.255.255.255", "192.0.2.33", "10.20.30.40"]
    prefix = "2001:db8::/48"
    encoded = nat64_codec(prefix, v4, [])["encoded"]
    assert len(encoded) == len(v4)
    decoded = nat64_codec(prefix, [], list(reversed(encoded)))["decoded"]
    assert decoded == list(reversed(v4))
    assert nat64_codec(prefix, [], []) == {"encoded": [], "decoded": []}


@pytest.mark.parametrize("length", [32, 40, 48, 56, 64, 96])
def test_nat64_encode_decode_roundtrip_random(length):
    rng = random.Random(60520000 + length)
    base = rng.getrandbits(length)
    prefix = str(ipaddress.IPv6Network((base << (128 - length), length),
                                       strict=False))
    addresses = [str(ipaddress.IPv4Address(rng.getrandbits(32)))
                 for _ in range(32)]
    encoded = nat64_codec(prefix, addresses, [])["encoded"]
    assert nat64_codec(prefix, [], encoded)["decoded"] == addresses


def test_nat64_embedded_address_uses_zero_u_octet_and_zero_suffix():
    # 192.0.2.33 under a /32: bytes 4-7 = c0 00 02 21, byte 8 (u) and the
    # whole remaining suffix are zero.
    packed = ipaddress.IPv6Address("2001:db8:c000:221::").packed
    assert packed[4:8] == bytes([0xC0, 0x00, 0x02, 0x21])
    assert packed[8:] == b"\x00" * 8
    # /96 keeps no u octet: IPv4 directly follows the 96-bit prefix.
    packed96 = ipaddress.IPv6Address("2001:db8:1:2::c000:221").packed
    assert packed96[:12] == bytes.fromhex("20010db80001000200000000")
    assert packed96[12:] == bytes([0xC0, 0x00, 0x02, 0x21])


@pytest.mark.parametrize("length", [32, 40, 48, 56, 64])
def test_nat64_nonzero_u_octet_rejected(length):
    rng = random.Random(64 + length)
    base = rng.getrandbits(length)
    prefix = ipaddress.IPv6Network((base << (128 - length), length),
                                   strict=False)
    mapped = bytearray(
        ipaddress.IPv6Address(nat64_codec(str(prefix), ["192.0.2.33"], [])[
            "encoded"][0]).packed
    )
    mapped[8] = 0xFF
    with pytest.raises(ValueError, match="u octet"):
        nat64_codec(str(prefix), [], [str(ipaddress.IPv6Address(bytes(mapped)))])


@pytest.mark.parametrize("length", [32, 40, 48, 56, 64])
def test_nat64_nonzero_suffix_rejected(length):
    rng = random.Random(128 + length)
    base = rng.getrandbits(length)
    prefix = ipaddress.IPv6Network((base << (128 - length), length),
                                   strict=False)
    mapped = bytearray(
        ipaddress.IPv6Address(nat64_codec(str(prefix), ["192.0.2.33"], [])[
            "encoded"][0]).packed
    )
    mapped[15] = 1
    with pytest.raises(ValueError, match="suffix"):
        nat64_codec(str(prefix), [], [str(ipaddress.IPv6Address(bytes(mapped)))])


def test_nat64_prefix_mismatch_rejected():
    with pytest.raises(ValueError, match="does not match"):
        nat64_codec("2001:db8::/96", [], ["2001:db9::1"])
    # An address outside a shorter prefix fails too.
    with pytest.raises(ValueError, match="does not match"):
        nat64_codec("2001:db8::/32", [], ["2001:db9:c000:221::"])


def test_nat64_prefix_validation():
    for length in (32, 40, 48, 56, 64, 96):
        network = parse_nat64_prefix(f"2001:db8::/{length}")
        assert network.prefixlen == length
    for bad in [
        "2001:db8::",        # bare address, no prefix length
        "2001:db8::/31",     # disallowed length
        "2001:db8::/65",
        "2001:db8::/128",
        "2001:db8::1/96",    # host bits set
        "10.0.0.0/32",       # IPv4
        "2001:db8::/0",      # host bits on a /0
    ]:
        with pytest.raises(ValueError):
            parse_nat64_prefix(bad)


def test_nat64_wrong_family_addresses_rejected():
    with pytest.raises(ValueError, match="must be IPv4"):
        nat64_codec("2001:db8::/96", ["2001:db8::1"], [])
    with pytest.raises(ValueError, match="must be IPv6"):
        nat64_codec("2001:db8::/96", [], ["10.0.0.1"])
    with pytest.raises(ValueError):
        nat64_codec("2001:db8::/96", ["10.0.0.1/32"], [])
    with pytest.raises(ValueError):
        nat64_codec("2001:db8::/96", [], ["2001:db8::1/128"])
