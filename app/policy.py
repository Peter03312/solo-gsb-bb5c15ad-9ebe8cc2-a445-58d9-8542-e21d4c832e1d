"""CIDR allow/deny normalization built on the standard-library ``ipaddress``.

The core operation is a set difference ``allow - deny`` computed independently
for IPv4 and IPv6.  When a deny prefix cuts through an allow prefix the allow
network is recursively split into its two halves until every deny boundary is
aligned with a prefix.  Pieces are merged back only when they form two
complete, adjacent sibling prefixes (via :func:`ipaddress.collapse_addresses`),
which yields the equivalent, non-overlapping and minimum-cardinality CIDR set.

The module also hosts three scope-based consumers of the same primitives:
``compare`` (decision diff of two policy sets inside one scope),
``audit_rules`` (per-entry impact classification inside one scope) and
``minimize_policy`` (minimum-cardinality equivalent rule subset inside one
scope), plus ``allocate`` (lexicographically smallest non-overlapping subnet
assignment inside one scope, avoiding occupied CIDRs), ``locate_free_addresses``
(0-based ordinal lookup of free addresses inside one scope minus the union of
occupied CIDRs, by cumulative block sizes rather than address enumeration),
``anonymize``
(prefix-preserving keyed HMAC anonymization of bare addresses and strict
CIDRs for safe sharing of address lists), ``reverse_delegations``
(reverse-DNS delegation plans for the IPv4 networks of one /24: direct
in-addr.arpa NS records for a /24, RFC 2317 range-label subzones plus
per-address parent-zone CNAMEs for /25 through /32) and ``roa_coverage``
(RFC 6483 RPKI ROA valid/invalid/unknown coverage map for every aligned
candidate route of one prefix length inside one scope, returned as a
minimal non-overlapping CIDR status partition), and ``as_relationship_repair``
(minimum-cardinality repair of undirected AS customer-provider/peer
relationships so every supplied AS path becomes valley-free), plus
``nat64_codec`` (RFC 6052 Network-Specific IPv4/IPv6 translation: embedding
bare IPv4 addresses after a strict translation prefix and extracting them
back from canonical mapped IPv6 addresses).
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import itertools
import re
from bisect import bisect_right
from collections.abc import Iterable, Sequence
from typing import NamedTuple, TypeAlias, Union

Network: TypeAlias = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
Address: TypeAlias = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

#: Maximum total number of allow/deny rules accepted by ``/minimize-policy``.
MINIMIZE_POLICY_RULE_LIMIT = 16

# Side rank used as the second component of the match-comparison key: at equal
# prefix length a deny entry must beat an allow entry.
_SIDE_RANK: dict[str, int] = {"allow": 0, "deny": 1}

_MAX_PREFIXLEN: dict[type, int] = {
    ipaddress.IPv4Network: 32,
    ipaddress.IPv6Network: 128,
}


def parse_network(value: object) -> Network:
    """Parse a strict CIDR string into an IPv4/IPv6 network object.

    ``strict=True`` rejects addresses with host bits set (e.g. ``10.0.0.1/24``).
    A bare address (``10.0.0.1``) is accepted as a host prefix (``/32`` or
    ``/128``).  Any invalid input raises :class:`ValueError`.
    """
    if not isinstance(value, str):
        raise ValueError(f"CIDR must be a string, got {type(value).__name__}")
    return ipaddress.ip_network(value.strip(), strict=True)


def parse_address(value: object) -> Address:
    """Parse a bare IPv4/IPv6 address (CIDR notation is rejected).

    Unlike :func:`parse_network`, neither ``10.0.0.1/24`` nor a host prefix
    such as ``10.0.0.1/32`` is accepted here — evaluation targets are plain
    addresses only.  Any invalid input raises :class:`ValueError`.
    """
    if not isinstance(value, str):
        raise ValueError(f"address must be a string, got {type(value).__name__}")
    text = value.strip()
    if "/" in text:
        raise ValueError(f"{value!r} is an address with a prefix length")
    return ipaddress.ip_address(text)


#: Exactly 64 hexadecimal characters (32 bytes / 256 bits), case-insensitive.
KEY_HEX_RE = re.compile(r"[0-9a-fA-F]{64}\Z")


def parse_key_hex(value: object) -> bytes:
    """Decode the 64-hex-character (256-bit) ``key_hex`` into raw key bytes.

    Any non-string, wrong-length or non-hexadecimal input raises
    :class:`ValueError`.
    """
    if not isinstance(value, str):
        raise ValueError(
            f"key_hex must be a string, got {type(value).__name__}"
        )
    text = value.strip()
    if KEY_HEX_RE.fullmatch(text) is None:
        raise ValueError(
            "key_hex must be exactly 64 hexadecimal characters (256 bits)"
        )
    return bytes.fromhex(text)


def parse_strict_cidr(value: object) -> Network:
    """Parse a CIDR string carrying an explicit prefix length, strictly.

    Unlike :func:`parse_network`, a bare address (``10.0.0.1``) is rejected:
    the ``cidrs`` input of ``/anonymize`` accepts explicit CIDR notation only.
    Any invalid input raises :class:`ValueError`.
    """
    if not isinstance(value, str):
        raise ValueError(f"CIDR must be a string, got {type(value).__name__}")
    if "/" not in value.strip():
        raise ValueError(f"{value!r} is missing a prefix length (expected a.b.c.d/p)")
    return parse_network(value)


def _sort_key(network: Network) -> tuple[bytes, int]:
    # ``packed`` orders network addresses as unsigned byte strings (works for
    # both families); prefix length is the secondary, stable key.
    return network.network_address.packed, network.prefixlen


def _diff(network: Network, deny: Sequence[Network]) -> list[Network]:
    """Subtract every deny network from one allow network by recursive splits.

    Caller guarantees that ``deny`` contains only strict subnets of
    ``network`` (equal/net-supernet cases are handled before calling this).
    Each recursion splits ``network`` into its two immediate sibling halves;
    a half that contains no deny prefix survives whole, while a half that does
    is split again — this is exactly the "cut through, split recursively"
    rule, and it produces maximal (minimum-count) aligned prefixes.
    """
    if not deny:
        return [network]

    # Defensive guard: a /32 or /128 has no strict subnets, so with a
    # correctly filtered ``deny`` this branch is unreachable.
    if network.prefixlen == _MAX_PREFIXLEN[type(network)]:
        return [network]

    left, right = network.subnets()

    result: list[Network] = []
    for half in (left, right):
        half_deny = [d for d in deny if d.subnet_of(half)]
        if any(d == half for d in half_deny):
            # The whole half is denied: it contributes nothing.
            continue
        if not half_deny:
            # No deny boundary touches the half: keep it whole.
            result.append(half)
        else:
            # Deny prefixes cut through the half: split again.
            result.extend(_diff(half, half_deny))
    return result


def _normalize_family(
    allow: Iterable[Network],
    deny: Iterable[Network],
    family: type,
) -> list[Network]:
    """Compute allow - deny for one address family, minimum and non-overlapping."""
    # Collapsing first removes duplicates/overlap and contained prefixes in
    # each input list, which also bounds the recursion work below.
    allow_nets = list(ipaddress.collapse_addresses(
        n for n in allow if isinstance(n, family)
    ))
    deny_nets = list(ipaddress.collapse_addresses(
        n for n in deny if isinstance(n, family)
    ))

    survivors: list[Network] = []
    for network in allow_nets:
        strict_deny: list[Network] = []
        swallowed = False
        for blocked in deny_nets:
            if network == blocked or network.subnet_of(blocked):
                # A deny prefix equal to or larger than the allow network
                # removes it completely.
                swallowed = True
                break
            if blocked.subnet_of(network):
                # A deny prefix cutting through the network: recurse.
                strict_deny.append(blocked)
        if swallowed:
            continue
        if not strict_deny:
            survivors.append(network)
        else:
            survivors.extend(_diff(network, strict_deny))

    # Sibling-only merge.  collapse_addresses merges a pair only when both are
    # complete adjacent halves of one common parent; merely adjacent prefixes
    # of unequal length are left untouched.
    merged = list(ipaddress.collapse_addresses(survivors))
    merged.sort(key=_sort_key)
    return merged


def _list_stats(raw: Sequence[str], networks: Sequence[Network]) -> dict:
    unique = set(networks)
    return {
        "input": len(raw),
        "unique": len(unique),
        "duplicates_removed": len(raw) - len(unique),
        "ipv4": sum(isinstance(n, ipaddress.IPv4Network) for n in unique),
        "ipv6": sum(isinstance(n, ipaddress.IPv6Network) for n in unique),
    }


def normalize(allow_raw: Sequence[str], deny_raw: Sequence[str]) -> dict:
    """Parse, validate and normalize allow/deny CIDR lists.

    Input strings are assumed to have been validated already (e.g. by the
    Pydantic schema); a malformed value raises :class:`ValueError`.
    """
    allow_nets = [parse_network(item) for item in allow_raw]
    deny_nets = [parse_network(item) for item in deny_raw]

    ipv4_result = _normalize_family(
        allow_nets, deny_nets, ipaddress.IPv4Network
    )
    ipv6_result = _normalize_family(
        allow_nets, deny_nets, ipaddress.IPv6Network
    )

    return {
        "ipv4": [str(network) for network in ipv4_result],
        "ipv6": [str(network) for network in ipv6_result],
        "stats": {
            "allow": _list_stats(allow_raw, allow_nets),
            "deny": _list_stats(deny_raw, deny_nets),
            "output": {
                "ipv4": len(ipv4_result),
                "ipv6": len(ipv6_result),
                "total": len(ipv4_result) + len(ipv6_result),
            },
        },
    }


def _best_match(
    address: Address,
    entries: Sequence[tuple[int, Network, str]],
) -> dict | None:
    """Return the winning list entry for one address, or ``None`` if none match.

    ``entries`` holds ``(original_index, network, side)`` triples restricted to
    the address family.  The comparison key orders by:

    1. prefix length — longest-prefix wins;
    2. side rank — at equal length ``deny`` beats ``allow``;
    3. original list index (negated) — the earlier entry in its side list
       wins, which makes the final decision stable.
    """
    best: tuple[int, int, int] | None = None
    best_network: Network | None = None
    best_side: str | None = None
    for index, network, side in entries:
        if address in network:
            key = (network.prefixlen, _SIDE_RANK[side], -index)
            if best is None or key > best:
                best = key
                best_network = network
                best_side = side
    if best is None:
        return None
    return {
        "decision": best_side,
        "matched_cidr": str(best_network),
        "matched_side": best_side,
    }


def evaluate(
    allow_raw: Sequence[str],
    deny_raw: Sequence[str],
    address_raw: Sequence[str],
) -> list[dict]:
    """Evaluate each address against allow/deny lists by longest-prefix match.

    Inputs are assumed validated already (e.g. by the Pydantic schema); a
    malformed value raises :class:`ValueError`.  Results are returned in the
    same order as ``address_raw``.
    """
    allow_entries: list[tuple[int, Network, str]] = [
        (i, parse_network(item), "allow") for i, item in enumerate(allow_raw)
    ]
    deny_entries: list[tuple[int, Network, str]] = [
        (i, parse_network(item), "deny") for i, item in enumerate(deny_raw)
    ]
    entries = allow_entries + deny_entries

    results: list[dict] = []
    for item in address_raw:
        address = parse_address(item)
        family_entries = [
            (index, network, side)
            for index, network, side in entries
            if network.version == address.version
        ]
        match = _best_match(address, family_entries)
        if match is None:
            results.append(
                {"decision": "unmatched", "matched_cidr": None,
                 "matched_side": None}
            )
        else:
            results.append(match)
    return results


# ---------------------------------------------------------------------------
# compare: decision-constant CIDR partitioning of one scope for two policy
# sets (baseline vs candidate), reusing the evaluate precedence rules.
# ---------------------------------------------------------------------------

#: Possible per-address decisions, including "nothing matches".
DECISIONS: tuple[str, ...] = ("allow", "deny", "unmatched")

#: Every baseline -> candidate transition, in a fixed display order.
TRANSITION_KEYS: tuple[str, ...] = tuple(
    f"{left}->{right}"
    for left in DECISIONS
    for right in DECISIONS
    if left != right
)


def _parse_entries(
    allow_raw: Sequence[str],
    deny_raw: Sequence[str],
    family: type,
) -> list[tuple[int, Network, str]]:
    """Build ``(index, network, side)`` entries for one address family."""
    entries: list[tuple[int, Network, str]] = []
    for index, item in enumerate(allow_raw):
        network = parse_network(item)
        if isinstance(network, family):
            entries.append((index, network, "allow"))
    for index, item in enumerate(deny_raw):
        network = parse_network(item)
        if isinstance(network, family):
            entries.append((index, network, "deny"))
    return entries


def _entry_key(entry: tuple[int, Network, str]) -> tuple[int, int, int]:
    """Match-comparison key shared with :func:`_best_match`."""
    index, network, side = entry
    return network.prefixlen, _SIDE_RANK[side], -index


def _pick_winner(
    entries: Sequence[tuple[int, Network, str]],
) -> tuple[int, Network, str] | None:
    """Best entry by longest-prefix/deny/index priority, or ``None``."""
    return max(entries, key=_entry_key, default=None)


def _winner_side(winner: tuple[int, Network, str] | None) -> str:
    return winner[2] if winner is not None else "unmatched"


def _partition_node(
    network: Network,
    inherited: tuple[int, Network, str] | None,
    entries: Sequence[tuple[int, Network, str]],
    out: list[tuple[Network, tuple[int, Network, str] | None]],
) -> None:
    """Recursively append winner-constant pieces covering ``network``.

    Each emitted piece is paired with the exact entry that wins everywhere in
    it (``None`` when the piece is unmatched).  ``inherited`` is the winning
    entry of a strictly broader prefix (already decided at an ancestor);
    ``entries`` are all entries that are subnets of ``network`` (equal or
    stricter).  A node only needs splitting while it contains an entry
    strictly deeper than itself, mirroring :func:`_diff`: untouched halves
    survive whole, which keeps every piece maximal.
    """
    own = [entry for entry in entries if entry[1] == network]
    strict = [entry for entry in entries if entry[1] != network]
    # An equal-length entry always beats the inherited strictly-broader
    # winner (longest-prefix rule); deny still wins equal-length own ties.
    winner = _pick_winner(own)
    if winner is None:
        winner = inherited

    if not strict or network.prefixlen == _MAX_PREFIXLEN[type(network)]:
        out.append((network, winner))
        return

    left, right = network.subnets()
    for half in (left, right):
        half_entries = [entry for entry in strict if entry[1].subnet_of(half)]
        _partition_node(half, winner, half_entries, out)


def _winner_partition(
    scope: Network,
    entries: Sequence[tuple[int, Network, str]],
) -> list[tuple[Network, tuple[int, Network, str] | None]]:
    """Partition ``scope`` into maximal CIDRs, each paired with its winner.

    Entries equal to or broader than ``scope`` decide the root (longest
    prefix, deny winning equal-length ties); strict subnets force recursive
    splits.  The returned pieces are non-overlapping and jointly exhaust
    ``scope``; a paired winner of ``None`` means the piece is unmatched.
    """
    covering = [
        entry for entry in entries
        if entry[1] == scope or scope.subnet_of(entry[1])
    ]
    root_winner = _pick_winner(covering)
    strict = [
        entry for entry in entries
        if entry[1] != scope and entry[1].subnet_of(scope)
    ]

    pieces: list[tuple[Network, tuple[int, Network, str] | None]] = []
    if not strict:
        pieces.append((scope, root_winner))
        return pieces

    left, right = scope.subnets()
    for half in (left, right):
        half_entries = [entry for entry in strict if entry[1].subnet_of(half)]
        _partition_node(half, root_winner, half_entries, pieces)
    return pieces


def _decision_partition(
    scope: Network,
    entries: Sequence[tuple[int, Network, str]],
) -> list[tuple[Network, str]]:
    """Partition ``scope`` into maximal CIDRs each having one constant decision.

    Thin decision-side projection of :func:`_winner_partition` (the
    ``/compare`` path only needs the winning side, not the entry itself).
    """
    return [
        (network, _winner_side(winner))
        for network, winner in _winner_partition(scope, entries)
    ]


def _overlay_partitions(
    baseline: Sequence[tuple[Network, str]],
    candidate: Sequence[tuple[Network, str]],
) -> list[tuple[Network, str, str]]:
    """Intersect two tilings of the same scope into (cidr, base, candidate).

    Every baseline piece and candidate piece is prefix-aligned, so when two
    pieces overlap one equals or contains the other; the finer network of the
    pair is the intersection.  The result again tiles the whole scope.
    """
    refined: list[tuple[Network, str, str]] = []
    for base_network, base_decision in baseline:
        for cand_network, cand_decision in candidate:
            if not base_network.overlaps(cand_network):
                continue
            if cand_network == base_network or cand_network.subnet_of(base_network):
                refined.append((cand_network, base_decision, cand_decision))
            else:
                # The baseline piece is the finer (strict subnet) one.
                refined.append((base_network, base_decision, cand_decision))
    return refined


def _merge_labelled(
    blocks: Sequence[tuple[Network, str, str]],
) -> list[tuple[Network, str, str]]:
    """Recursively merge complete sibling pairs with identical transition.

    A pair merges only when both halves of one common parent are present and
    both carry the same ``(baseline, candidate)`` label.  The fixpoint loop
    repeats so parents formed by a merge can merge again, just like
    :func:`ipaddress.collapse_addresses` — but adjacent unequal-length
    prefixes, and siblings whose transitions differ, are never joined.
    """
    pieces = list(blocks)
    while True:
        groups: dict[tuple[bytes, int], list[tuple[Network, str, str]]] = {}
        for block in pieces:
            network = block[0]
            if network.prefixlen == 0:
                continue
            parent = network.supernet()
            groups.setdefault(_sort_key(parent), []).append(block)

        merged: list[tuple[Network, str, str]] = []
        consumed: set[int] = set()
        for group in groups.values():
            labels = {block[1:] for block in group}
            if len(group) == 2 and len(labels) == 1:
                parent = group[0][0].supernet()
                merged.append((parent, group[0][1], group[0][2]))
                consumed.update(id(block) for block in group)

        if not merged:
            return pieces
        pieces = merged + [
            block for block in pieces if id(block) not in consumed
        ]


def compare(
    scope_raw: str,
    baseline_allow: Sequence[str],
    baseline_deny: Sequence[str],
    candidate_allow: Sequence[str],
    candidate_deny: Sequence[str],
) -> dict:
    """Compare baseline vs candidate decisions everywhere inside ``scope``.

    Both policy sets are independently partitioned into decision-constant
    CIDRs; the two tilings are overlaid (intersected) and only regions whose
    decision differs survive, after sibling merging by transition type.
    Inputs are assumed validated already (e.g. by the Pydantic schema); a
    malformed value raises :class:`ValueError`.
    """
    scope = parse_network(scope_raw)
    family = type(scope)

    baseline_entries = _parse_entries(baseline_allow, baseline_deny, family)
    candidate_entries = _parse_entries(candidate_allow, candidate_deny, family)

    baseline_parts = _decision_partition(scope, baseline_entries)
    candidate_parts = _decision_partition(scope, candidate_entries)
    refined = _overlay_partitions(baseline_parts, candidate_parts)

    differences = [
        (network, base_decision, cand_decision)
        for network, base_decision, cand_decision in refined
        if base_decision != cand_decision
    ]
    differences = _merge_labelled(differences)
    differences.sort(key=lambda block: _sort_key(block[0]))

    counts = {key: 0 for key in TRANSITION_KEYS}
    for network, base_decision, cand_decision in differences:
        counts[f"{base_decision}->{cand_decision}"] += network.num_addresses

    return {
        "differences": [
            {
                "cidr": str(network),
                "baseline_decision": base_decision,
                "candidate_decision": cand_decision,
            }
            for network, base_decision, cand_decision in differences
        ],
        "transition_counts": {
            key: str(counts[key]) for key in TRANSITION_KEYS
        },
    }


# ---------------------------------------------------------------------------
# audit-rules: per-entry impact classification inside one scope.  Every allow/
# deny entry is effective (wins somewhere in scope, with the numerically
# smallest witness IP), shadowed (covered inside scope by entries that always
# beat it; shadowed_by lists their side+index) or out_of_scope (no overlap).
# Analysis reuses the CIDR winner partition above and never enumerates
# addresses.
# ---------------------------------------------------------------------------


def audit_rules(
    scope_raw: str,
    allow_raw: Sequence[str],
    deny_raw: Sequence[str],
) -> dict:
    """Classify every input rule by its real impact on decisions in ``scope``.

    The scope is partitioned into winner-constant maximal CIDRs by
    :func:`_winner_partition`.  A rule's region is its CIDR clipped to the
    scope; it is ``effective`` when it wins one or more partition pieces
    (the witness is the smallest network address among those pieces),
    ``shadowed`` when the region is non-empty but another entry wins every
    piece of it, or ``out_of_scope`` when its CIDR does not intersect the
    scope at all.  ``shadowed_by`` holds the distinct ``(side, index)``
    references of the entries actually winning those pieces — only entries
    that can win themselves can shadow.

    Inputs are assumed validated already (e.g. by the Pydantic schema): the
    scope and every rule CIDR parse strictly and all share one address
    family.  A malformed value raises :class:`ValueError`.
    """
    scope = parse_network(scope_raw)
    family = type(scope)

    allow_nets = [parse_network(item) for item in allow_raw]
    deny_nets = [parse_network(item) for item in deny_raw]
    entries: list[tuple[int, Network, str]] = [
        (index, network, "allow")
        for index, network in enumerate(allow_nets)
        if isinstance(network, family)
    ]
    entries.extend(
        (index, network, "deny")
        for index, network in enumerate(deny_nets)
        if isinstance(network, family)
    )

    partition = _winner_partition(scope, entries)

    def classify(
        side: str, index: int, network: Network
    ) -> dict:
        if not network.overlaps(scope):
            # CIDRs are laminar: a same-family network is either disjoint or
            # nested, so a disjoint entry never affects scope at all.
            return {"status": "out_of_scope"}

        # Pieces tile the whole scope; because CIDRs never partially overlap,
        # a piece intersects the entry exactly when one equals or contains
        # the other (the entry may be broader than the whole scope).
        own_pieces = [
            (piece, winner)
            for piece, winner in partition
            if piece == network or piece.subnet_of(network)
            or network.subnet_of(piece)
        ]

        won = [
            piece
            for piece, winner in own_pieces
            if winner is not None
            and winner[1] == network and winner[2] == side
            and winner[0] == index
        ]
        if won:
            # Smallest network address of the pieces the rule wins is the
            # numerically smallest address in its winning region and is
            # always inside that region.
            witness = min(won, key=_sort_key).network_address
            return {"status": "effective", "witness": str(witness)}

        # The rule never wins inside scope: collect the distinct entries that
        # win pieces of its region (unmatched pieces contribute no shadower).
        shadowed_by = sorted(
            {
                (winner[2], winner[0])
                for _, winner in own_pieces
                if winner is not None
            },
        )
        return {
            "status": "shadowed",
            "shadowed_by": [
                {"side": rule_side, "index": rule_index}
                for rule_side, rule_index in shadowed_by
            ],
        }

    allow_results: list[dict] = []
    for index, network in enumerate(allow_nets):
        allow_results.append({
            "side": "allow",
            "index": index,
            "cidr": str(network),
            **classify("allow", index, network),
        })

    deny_results: list[dict] = []
    for index, network in enumerate(deny_nets):
        deny_results.append({
            "side": "deny",
            "index": index,
            "cidr": str(network),
            **classify("deny", index, network),
        })

    return {"allow": allow_results, "deny": deny_results}


# ---------------------------------------------------------------------------
# minimize-policy: smallest subset of the input rules whose decisions are
# identical to the original policy everywhere inside one scope.  The scope is
# partitioned into winner-constant CIDRs (no address enumeration); the subset
# search is an exact branch-and-bound over rules (forced inclusions/exclusions,
# most-constrained piece first), not one-by-one greedy deletion.  Ties between
# minimum solutions are broken by the (side, index) sequence, lexicographically.
# ---------------------------------------------------------------------------

# Canonical rule ordering shared with the lex tie-break and the response:
# allow before deny, lower original index first.
_CANONICAL_SIDE_RANK: dict[str, int] = {"allow": 0, "deny": 1}


def _piece_intersects_rule(piece: Network, network: Network) -> bool:
    """Whether a partition piece intersects a rule (aligned CIDRs are laminar)."""
    return piece == network or piece.subnet_of(network) or network.subnet_of(piece)


def _minimize_family(
    scope: Network,
    rules: Sequence[tuple[int, Network, str]],
) -> list[tuple[int, Network, str]]:
    """Return the minimum subset of ``rules`` preserving decisions in scope.

    ``rules`` are ``(original_index, network, side)`` triples sharing
    ``scope``'s family; triples come back in the same shape.  The original
    policy partitions the scope into winner-constant pieces.  A piece whose
    original winner is ``None`` needs nothing (any covering rule would win
    it, so no retained rule can cover one in the first place); every other
    piece carries its winner side as a requirement.  A retained candidate
    secures such a piece once every covering opposite-side rule that outranks
    it on the piece — its blockers — is excluded: same-side rules only
    replace the winner by another rule of the same decision and never block.

    The exact DFS branches on the most constrained non-secured piece,
    retaining one viable candidate (forcing that candidate's blockers out) or
    committing no new rule via the exclusion-only branch of a candidate that
    is already retained.  The distinct set of original winners is the
    initial feasible bound; the lexicographically smallest ``(side, index)``
    sequence among equal-cardinality solutions wins.
    """
    # Canonical positions double as bit positions; order matches the lex key.
    ordered = sorted(
        rules,
        key=lambda rule: (_CANONICAL_SIDE_RANK[rule[2]], rule[0]),
    )
    total = len(ordered)
    full_mask = (1 << total) - 1

    partition = _winner_partition(scope, ordered)

    # Per labelled piece: (candidate bit, blocker mask) pairs.  Candidates are
    # covering rules of the winner side; blockers are covering opposite-side
    # rules with a strictly higher match key on that piece.
    piece_options: list[list[tuple[int, int]]] = []
    ever_candidate = 0
    for piece, winner in partition:
        if winner is None:
            continue
        options: list[tuple[int, int]] = []
        for bit, (index, network, side) in enumerate(ordered):
            if side != winner[2] or not _piece_intersects_rule(piece, network):
                continue
            blockers = 0
            candidate_key = (network.prefixlen, _SIDE_RANK[side], -index)
            for other_bit, (other_index, other_network, other_side) in enumerate(ordered):
                if other_side == side or not _piece_intersects_rule(
                    piece, other_network
                ):
                    continue
                other_key = (
                    other_network.prefixlen,
                    _SIDE_RANK[other_side],
                    -other_index,
                )
                if other_key > candidate_key:
                    blockers |= 1 << other_bit
            options.append((1 << bit, blockers))
            ever_candidate |= 1 << bit
        piece_options.append(options)

    # A rule that is nowhere a candidate (disjoint, or out-gunned on every
    # labelled piece it covers) can never belong to an equivalent subset.
    initial_excluded = full_mask & ~ever_candidate

    # Feasible upper bound: the distinct original winners.  Each original
    # winner outranks every covering opposite-side rule of its own piece, so
    # its blocker mask there is empty and the set secures all labelled pieces.
    winner_keys = {
        (winner[2], winner[0])
        for _piece, winner in partition
        if winner is not None
    }
    initial_best = 0
    for bit, (index, _network, side) in enumerate(ordered):
        if (side, index) in winner_keys:
            initial_best |= 1 << bit
    best_mask = initial_best & ~initial_excluded

    def lex_key(mask: int) -> tuple[tuple[str, int], ...]:
        return tuple(
            (ordered[bit][2], ordered[bit][0])
            for bit in range(total)
            if mask & (1 << bit)
        )

    def solve() -> int:
        best = best_mask
        visited: set[tuple[int, int]] = set()
        stack: list[tuple[int, int]] = [(0, initial_excluded)]
        while stack:
            retained, excluded = stack.pop()
            retained &= ~excluded
            state = (retained, excluded)
            if state in visited:
                continue
            visited.add(state)

            # Descendants only add retained rules; a state already larger than
            # the incumbent cannot improve cardinality.  Same-size states stay
            # eligible: an exclusion-only completion may beat its (side,index)
            # sequence.
            if retained.bit_count() > best.bit_count():
                continue

            selected: tuple | None = None
            dead = False
            for options in piece_options:
                viable: list[tuple[int, int]] = []
                for candidate, blockers in options:
                    if candidate & excluded:
                        continue
                    # A retained blocker can never be excluded later.
                    if blockers & retained:
                        continue
                    viable.append((candidate, blockers))
                if not viable:
                    dead = True
                    break
                if any(
                    candidate & retained and not (blockers & ~excluded)
                    for candidate, blockers in viable
                ):
                    continue  # this piece is already secured
                new_options = [
                    (candidate, blockers)
                    for candidate, blockers in viable
                    if not (candidate & retained)
                ]
                retained_options = [
                    (candidate, blockers)
                    for candidate, blockers in viable
                    if candidate & retained
                ]
                # Most-constrained piece first: fewest fresh candidates, then
                # prefer one already half-committed (exclusion-only branch).
                rank = (len(new_options), 0 if retained_options else 1)
                if selected is None or rank < selected[0]:
                    selected = (rank, new_options, retained_options)

            if dead:
                continue
            if selected is None:
                # All labelled pieces secured; drop every undecided rule.
                if (
                    retained.bit_count() < best.bit_count()
                    or (
                        retained.bit_count() == best.bit_count()
                        and lex_key(retained) < lex_key(best)
                    )
                ):
                    best = retained
                continue

            _rank, new_options, retained_options = selected
            # Push largest canonical bit first so the smallest is popped first:
            # a small lex incumbent prunes the rest of the search harder.
            for candidate, blockers in sorted(
                new_options, key=lambda item: item[0], reverse=True
            ):
                new_retained = retained | candidate
                new_excluded = excluded | blockers
                if new_retained & new_excluded:
                    continue
                stack.append((new_retained, new_excluded))
            for candidate, blockers in sorted(
                retained_options, key=lambda item: item[0], reverse=True
            ):
                new_excluded = excluded | blockers
                if retained & new_excluded:
                    continue
                stack.append((retained, new_excluded))
        return best

    best_mask = solve()
    return [ordered[bit] for bit in range(total) if best_mask & (1 << bit)]


def minimize_policy(
    scope_raw: str,
    allow_raw: Sequence[str],
    deny_raw: Sequence[str],
) -> dict:
    """Find the smallest rule subset equivalent to the policy inside scope.

    The scope is partitioned into winner-constant maximal CIDRs by
    :func:`_winner_partition`; :func:`_minimize_family` runs the exact
    minimum-subset search over those pieces — no address enumeration, no
    one-by-one greedy deletion.  Ties resolve by the lexicographically
    smallest retained ``(side, index)`` sequence (allow before deny, then
    original list index).

    The response lists retained and removed references in original input
    order (all allow references first, then deny, each by index); every
    retained rule carries the numerically smallest witness IP of a piece it
    wins under the reduced policy.

    Caller validation (e.g. the Pydantic schema) guarantees the scope and
    every rule parse strictly, share one address family, and that the total
    rule count is within :data:`MINIMIZE_POLICY_RULE_LIMIT`.
    """
    scope = parse_network(scope_raw)
    family = type(scope)

    allow_nets = [parse_network(item) for item in allow_raw]
    deny_nets = [parse_network(item) for item in deny_raw]
    rules: list[tuple[int, Network, str]] = [
        (index, network, "allow")
        for index, network in enumerate(allow_nets)
        if isinstance(network, family)
    ]
    rules.extend(
        (index, network, "deny")
        for index, network in enumerate(deny_nets)
        if isinstance(network, family)
    )

    retained = _minimize_family(scope, rules)
    retained_keys = {(side, index) for index, _network, side in retained}

    # Witness per retained rule from the reduced policy's own partition: in a
    # minimum subset every retained rule wins at least one piece.
    witness: dict[tuple[str, int], Address] = {}
    for piece, winner in _winner_partition(scope, retained):
        if winner is None:
            continue
        key = (winner[2], winner[0])
        address = piece.network_address
        if key not in witness or int(address) < int(witness[key]):
            witness[key] = address

    retained_refs = [
        {
            "side": "allow", "index": index, "cidr": str(network),
            "witness": str(witness[("allow", index)]),
        }
        for index, network in enumerate(allow_nets)
        if ("allow", index) in retained_keys
    ]
    retained_refs.extend(
        {
            "side": "deny", "index": index, "cidr": str(network),
            "witness": str(witness[("deny", index)]),
        }
        for index, network in enumerate(deny_nets)
        if ("deny", index) in retained_keys
    )
    removed_refs = [
        {"side": "allow", "index": index, "cidr": str(network)}
        for index, network in enumerate(allow_nets)
        if ("allow", index) not in retained_keys
    ]
    removed_refs.extend(
        {"side": "deny", "index": index, "cidr": str(network)}
        for index, network in enumerate(deny_nets)
        if ("deny", index) not in retained_keys
    )

    return {"retained": retained_refs, "removed": removed_refs}


def _subtract_free(free: Sequence[Network], block: Network) -> list[Network]:
    """Remove ``block`` from the sorted, non-overlapping free list.

    ``block`` is an aligned subnet of exactly one free piece; that piece is
    replaced by its :meth:`ipaddress.IPv4Network.address_exclude`
    decomposition, which keeps the list sorted, non-overlapping and minimal
    (pieces of one exclusion are never mergeable siblings, and pieces of
    different original blocks stay separated by non-free gaps).
    """
    out: list[Network] = []
    for net in free:
        if block.subnet_of(net):
            out.extend(net.address_exclude(block))
        else:
            out.append(net)
    out.sort(key=_sort_key)
    return out


def _aligned_candidates(
    free: Sequence[Network],
    prefixlen: int,
    max_bits: int,
) -> Iterable[Network]:
    """Yield every aligned ``/prefixlen`` subnet of the free space, in order.

    Iteration is lazy and follows the sorted free list, so candidates come
    out in strictly increasing network-address order — exactly the order the
    lexicographic search must try them in.
    """
    size = 1 << (max_bits - prefixlen)
    for net in free:
        if net.prefixlen > prefixlen:
            # This free piece is itself smaller than the requested block.
            continue
        base = int(net.network_address)
        for offset in range(0, net.num_addresses, size):
            yield type(net)((base + offset, prefixlen))


def _fits(free: Sequence[Network], prefixlens: Sequence[int]) -> bool:
    """Necessary capacity condition for placing ``prefixlens`` in ``free``.

    At every requested granularity ``p``, the still-unplaced requests with
    prefix length ``<= p`` need ``sum(2 ** (p - q))`` aligned ``/p`` slots,
    while the free space offers one such slot per ``/p`` block inside each
    free piece at least as large.  Checking only the requested prefix
    lengths suffices: between two consecutive requested lengths both sides
    of the inequality at least double, so no new violation can appear.
    """
    for prefix in set(prefixlens):
        required = sum(1 << (prefix - q) for q in prefixlens if q <= prefix)
        available = sum(
            1 << (prefix - net.prefixlen)
            for net in free
            if net.prefixlen <= prefix
        )
        if required > available:
            return False
    return True


def _search(
    free: Sequence[Network],
    prefixlens: Sequence[int],
    max_bits: int,
    memo: set,
) -> list[Network] | None:
    """DFS over candidates in address order; first complete plan is lex-min.

    ``prefixlens[d]`` is placed at depth ``d``; every aligned candidate
    subnet is tried in increasing network-address order, so the first
    complete assignment found is the lexicographically smallest feasible
    sequence.  ``memo`` caches failed ``(depth, free-state)`` keys —
    feasibility of a state depends only on the remaining free space and
    the remaining requests, never on how the state was reached.  The
    traversal is iterative so the request count is not bounded by the
    interpreter's recursion limit.
    """
    if not prefixlens:
        return []

    def state_key(depth: int, free_nets: Sequence[Network]) -> tuple:
        return (
            depth,
            tuple(
                (int(net.network_address), net.prefixlen) for net in free_nets
            ),
        )

    def enter(depth: int) -> Iterable[Network] | None:
        """Prune the state at ``depth`` or return its candidate iterator."""
        key = state_key(depth, frees[depth])
        if key in memo:
            return None
        if not _fits(frees[depth], prefixlens[depth:]):
            memo.add(key)
            return None
        return _aligned_candidates(frees[depth], prefixlens[depth], max_bits)

    # Invariant while ``candidates`` is non-empty: depth d = len(candidates)-1
    # is the deepest entered state, frees[d] its free list, and ``chosen``
    # holds the d blocks (depths 0..d-1) that led to it.
    frees: list[Sequence[Network]] = [list(free)]
    first = enter(0)
    if first is None:
        return None
    candidates: list[Iterable[Network]] = [first]
    chosen: list[Network] = []

    while candidates:
        depth = len(candidates) - 1
        block = next(candidates[-1], None)
        if block is None:
            # Every candidate at this depth failed: memoize and backtrack.
            memo.add(state_key(depth, frees[depth]))
            candidates.pop()
            frees.pop()
            if chosen:
                chosen.pop()
            continue
        if depth == len(prefixlens) - 1:
            # Last request placed: the complete, lexicographically smallest
            # plan, in request order.
            return [*chosen, block]
        # Descend: tentatively place the block, then prune or enter the
        # child state; undo the descend if the child is already infeasible.
        chosen.append(block)
        frees.append(_subtract_free(frees[depth], block))
        child = enter(depth + 1)
        if child is None:
            chosen.pop()
            frees.pop()
            continue
        candidates.append(child)
    return None


def allocate(
    scope_raw: str,
    occupied_raw: Sequence[str],
    requests: Sequence[tuple[str, int]],
) -> dict | None:
    """Assign one subnet per ``(id, prefix_length)`` request inside ``scope``.

    Allocations are non-overlapping, avoid every occupied CIDR and follow
    request order; among all complete feasible assignments the one with the
    lexicographically smallest sequence of network addresses wins.  Returns
    ``None`` when no complete assignment exists (the caller maps this to
    HTTP 409 and must not emit partial allocations).

    Inputs are assumed validated already (e.g. by the Pydantic schema):
    occupied CIDRs share the scope family, lie inside it and do not overlap;
    request ids are unique; prefix lengths fit the address family.  A
    malformed value raises :class:`ValueError`.
    """
    scope = parse_network(scope_raw)
    family = type(scope)
    max_bits = _MAX_PREFIXLEN[family]

    occupied = [parse_network(item) for item in occupied_raw]
    # Free space before any allocation: scope minus the occupied CIDRs, as a
    # minimal, sorted, non-overlapping CIDR list.
    free = _normalize_family([scope], occupied, family)

    prefixlens = [prefix_length for _, prefix_length in requests]
    chosen = _search(free, prefixlens, max_bits, memo=set())
    if chosen is None:
        return None

    remaining = free
    for block in chosen:
        remaining = _subtract_free(remaining, block)

    return {
        "allocations": [
            {"id": request_id, "cidr": str(network)}
            for (request_id, _), network in zip(requests, chosen, strict=True)
        ],
        "remaining": [str(net) for net in remaining],
        # Decimal string: IPv6 remainders exceed JSON's safe integer range.
        "remaining_addresses": str(
            sum(net.num_addresses for net in remaining)
        ),
    }


# ---------------------------------------------------------------------------
# free-addresses: locate free addresses inside one scope by 0-based ordinal.
# The free space is scope minus the union of the occupied CIDRs (occupied
# entries may overlap each other and reach beyond the scope; union first,
# then clip, is exactly what the set difference provides).  Ordinal lookup
# walks the sorted minimal free-block list with cumulative sizes, so no free
# address is ever enumerated — even IPv6 ::/0 costs O(occupied * width).
# ---------------------------------------------------------------------------


def _parse_free_index(value: object) -> int:
    """Coerce one ordinal input into a non-negative Python ``int``.

    JSON numbers arrive as ``int`` (Pydantic rejects fractional values) and
    decimal strings such as ``"340282366920938463463374607431768211455"``
    are accepted too, so indices beyond JSON's 2^53 safe-integer range stay
    usable for IPv6.  Booleans, signs and surrounding whitespace are
    rejected; the caller separately rejects ordinals >= the free total.
    """
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(
            f"index must be a non-negative decimal integer, got {value!r}"
        )
    if isinstance(value, str):
        text = value
        if not text or not text.isascii() or not text.isdigit():
            raise ValueError(
                f"index {value!r} is not a non-negative decimal integer"
            )
        return int(text)
    if value < 0:
        raise ValueError(f"index {value} must be non-negative")
    return value


def locate_free_addresses(
    scope_raw: str,
    occupied_raw: Sequence[str],
    index_raw: Sequence[object],
) -> dict:
    """Return the free-address total and the address at each ordinal.

    The free region is ``scope - union(occupied)``: occupied CIDRs may
    overlap each other and may (partly) reach beyond the scope — the union
    is computed first and the difference naturally clips it to the scope.
    Every address bit counts (network and broadcast addresses included for
    IPv4).  Ordinals are 0-based over the free addresses in ascending
    numeric order; the result list keeps the input order (duplicates and
    repeats are allowed).

    The lookup uses cumulative block sizes plus :func:`bisect.bisect_right`
    rather than enumerating addresses, so an IPv6 ``::/0`` scope is as
    cheap as any other.  Inputs are assumed validated already (e.g. by the
    Pydantic schema): the scope and every occupied CIDR parse strictly and
    share one family.  Any ordinal at or past the free total raises
    :class:`ValueError`, which rejects the whole batch.
    """
    scope = parse_network(scope_raw)
    family = type(scope)

    occupied: list[Network] = []
    for item in occupied_raw:
        network = parse_network(item)
        if not isinstance(network, family):
            raise ValueError(
                f"occupied CIDR {network} does not match the scope address "
                f"family ({scope})"
            )
        occupied.append(network)

    # Minimal, sorted, non-overlapping free list; out-of-scope occupied
    # entries are dropped by the family filter + set difference, overlaps
    # collapse into the union before subtraction.
    free = _normalize_family([scope], occupied, family)
    sizes = [net.num_addresses for net in free]
    cumulative: list[int] = []
    running = 0
    for size in sizes:
        running += size
        cumulative.append(running)
    total = running

    indices = [_parse_free_index(item) for item in index_raw]
    for index in indices:
        if index >= total:
            raise ValueError(
                f"index {index} is out of range: scope {scope} has only "
                f"{total} free address"
                f"{'es' if total != 1 else ''} (valid indices 0..{total - 1})"
            )

    addresses: list[str] = []
    address_class = (
        ipaddress.IPv4Address if family is ipaddress.IPv4Network
        else ipaddress.IPv6Address
    )
    for index in indices:
        # First free block whose cumulative end is strictly greater than the
        # ordinal; blocks are sorted ascending and disjoint.
        block_pos = bisect_right(cumulative, index)
        block = free[block_pos]
        before = cumulative[block_pos] - sizes[block_pos]
        addresses.append(
            str(address_class(int(block.network_address) + index - before))
        )

    return {"free_total": str(total), "addresses": addresses}


# ---------------------------------------------------------------------------
# anonymize: prefix-preserving, keyed HMAC anonymization of bare addresses and
# strict CIDRs (Crypto-PAn-style bitwise prefix cipher).
# ---------------------------------------------------------------------------

#: HMAC domain-separation tag per address family (IPv4 -> 0x04, IPv6 -> 0x06).
_ANON_FAMILY_TAG: dict[type, int] = {
    ipaddress.IPv4Address: 4,
    ipaddress.IPv6Address: 6,
}

#: Address width in bits per address family.
_ANON_WIDTH: dict[type, int] = {
    ipaddress.IPv4Address: 32,
    ipaddress.IPv6Address: 128,
}


def _anonymize_address(address: Address, key: bytes) -> Address:
    """Anonymize one address bit by bit in network (MSB-first) bit order.

    For bit position ``i`` (0-based from the most significant bit), the HMAC
    message is the address-family tag byte, the single current-position byte
    ``i``, followed by the *original* bits that precede position ``i`` right
    zero-padded to the full address width (4 bytes for IPv4, 16 for IPv6).
    The most significant bit of the HMAC-SHA256 digest is XORed onto the
    current original bit.

    Because the pad at every position contains only original prefix bits, two
    addresses sharing a prefix take identical HMAC decisions all through that
    prefix (prefix preservation); at each prefix node the two outgoing bits
    stay distinct under the fixed XOR mask, so the whole-family mapping is a
    bijection; and with a fixed key the same address always maps identically.
    """
    family = type(address)
    width = _ANON_WIDTH[family]
    packed = address.packed
    output = bytearray(len(packed))
    # Prefix of *original* bits processed so far, right zero-padded to width:
    # at position i its top i bits equal the source's top i bits.
    prefix = bytearray(len(packed))
    family_tag = _ANON_FAMILY_TAG[family]
    for i in range(width):
        source_byte = packed[i >> 3]
        bit_index = 7 - (i & 7)
        original_bit = (source_byte >> bit_index) & 1
        message = bytes([family_tag, i]) + bytes(prefix)
        digest = hmac.new(key, message, hashlib.sha256).digest()
        mask_bit = digest[0] >> 7
        output[i >> 3] |= (original_bit ^ mask_bit) << bit_index
        prefix[i >> 3] |= original_bit << bit_index
    return family(bytes(output))


def anonymize(
    key_hex_raw: str,
    address_raw: Sequence[str],
    cidr_raw: Sequence[str],
) -> dict:
    """Anonymize bare addresses and strict CIDRs under one 256-bit key.

    Addresses are transformed by :func:`_anonymize_address`.  Each CIDR is
    parsed strictly (host bits must already be zero), its network address is
    anonymized, and host bits are cleared again at the original prefix length
    so the result is a canonical network.  Each output list keeps its input
    order; IPv4 and IPv6 entries may be mixed.

    Inputs are assumed validated already (e.g. by the Pydantic schema):
    ``key_hex_raw`` is 64 hex characters, addresses are bare and CIDRs carry
    explicit prefix lengths with zero host bits.  A malformed value raises
    :class:`ValueError`.
    """
    key = parse_key_hex(key_hex_raw)

    anonymized_addresses: list[str] = []
    for item in address_raw:
        address = parse_address(item)
        anonymized_addresses.append(str(_anonymize_address(address, key)))

    anonymized_cidrs: list[str] = []
    for item in cidr_raw:
        network = parse_strict_cidr(item)
        anon_network_address = _anonymize_address(network.network_address, key)
        # Anonymization can flip host bits even when the source network
        # address had none, so re-mask to the original prefix length for a
        # canonical network (strict=False performs that masking).
        anon_network = type(network)(
            (anon_network_address, network.prefixlen), strict=False
        )
        anonymized_cidrs.append(str(anon_network))

    return {
        "addresses": anonymized_addresses,
        "cidrs": anonymized_cidrs,
    }


# ---------------------------------------------------------------------------
# reverse-delegations: reverse-DNS delegation plans for the IPv4 networks of
# one /24.  A /24 delegates the in-addr.arpa zone directly; anything tighter
# (/25-/32) is unrepresentable as a classful in-addr.arpa zone, so RFC 2317 is
# used instead: a range-labelled forwardable subzone (e.g. "0/25" or "64/26",
# here written "<last-octet-of-network-address>/<prefixlen>") receives NS
# records while the parent /24 zone hands out per-address CNAMEs into it.
# ---------------------------------------------------------------------------

#: Prefix lengths the reverse-delegation endpoint accepts for its CIDR entries.
REVERSE_MIN_PREFIXLEN = 24

#: One RFC 1035 label: letters/digits/hyphens, not starting/ending with a
#: hyphen, 1-63 characters.  Used to validate every dot-separated NS label.
_DNS_LABEL_RE = re.compile(r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)\Z")


def _parse_nameserver(value: object) -> str:
    """Validate an NS owner domain name and return its canonical FQDN text.

    Names are case-insensitive, so the result is lower-cased and guaranteed to
    carry exactly one trailing root dot.  Each dot-separated label must match
    :data:`_DNS_LABEL_RE`, the encoded name may be at most 253 characters, and
    a bare IPv4/IPv6 address (valid dots/digits but not a domain name) is
    rejected.  Any invalid input raises :class:`ValueError`.
    """
    if not isinstance(value, str):
        raise ValueError(
            f"nameserver must be a string, got {type(value).__name__}"
        )
    text = value.strip()
    if not text:
        raise ValueError("nameserver must not be empty")
    if not text.endswith("."):
        text += "."
    # Drop the trailing root dot before splitting labels: the empty label it
    # implies is implicit, not a real label.
    labels = text[:-1].split(".")
    for label in labels:
        if _DNS_LABEL_RE.fullmatch(label) is None:
            raise ValueError(f"invalid nameserver domain name {value!r}")
    # RFC 1035 wire encoding limit expressed textually: at most 253
    # characters excluding the trailing root dot.
    if len(text) - 1 > 253:
        raise ValueError(
            f"nameserver domain name {value!r} exceeds 253 characters"
        )
    try:
        ipaddress.ip_address(text[:-1])
    except ValueError:
        pass
    else:
        raise ValueError(
            f"nameserver {value!r} must be a domain name, not an IP address"
        )
    return text.lower()


def _parse_reverse_cidr(value: object) -> ipaddress.IPv4Network:
    """Parse one strict IPv4 CIDR restricted to the /24-/32 range.

    Unlike :func:`parse_network`, IPv6, non-strict host bits and any prefix
    length shorter than /24 are all rejected; a bare address is rejected too
    (the endpoint requires explicit CIDR notation).  Any invalid input raises
    :class:`ValueError`.
    """
    network = parse_strict_cidr(value)
    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError(
            f"reverse-delegation CIDR {value!r} must be IPv4, not IPv6"
        )
    if network.prefixlen < REVERSE_MIN_PREFIXLEN:
        raise ValueError(
            f"reverse-delegation CIDR {value!r} has prefix /"
            f"{network.prefixlen}; only /24 through /32 are accepted"
        )
    return network


def _validate_reverse_batch(
    networks: Sequence[ipaddress.IPv4Network],
) -> None:
    """Reject a batch whose CIDRs span more than one /24 or intersect.

    Every accepted entry lies inside exactly one parent /24; a pair from a
    different /24 is rejected, and within one /24 any overlap (a /24 beside
    anything, a /25 beside an intersecting /27, ...) is rejected outright so
    the plan never needs to resolve two delegations for one address.
    """
    if not networks:
        return
    parent_24 = type(networks[0])(
        (int(networks[0].network_address) & 0xFFFFFF00, 24)
    )
    for network in networks:
        if not network.subnet_of(parent_24):
            raise ValueError(
                f"reverse-delegation CIDR {network} is not inside the common "
                f"parent /24 {parent_24}; all CIDRs must share one /24"
            )
    ordered = sorted(
        networks, key=lambda n: (int(n.network_address), n.prefixlen)
    )
    # For intervals sorted by start, any overlap implies an overlap of some
    # consecutive pair (same check as the occupied list of /allocate).
    for left, right in zip(ordered, ordered[1:]):
        if left.overlaps(right):
            raise ValueError(
                f"reverse-delegation CIDRs {left} and {right} overlap; the "
                f"whole batch is rejected"
            )


def reverse_delegations(
    entries: Sequence[tuple[str, Sequence[str]]],
) -> dict:
    """Build the reverse-DNS delegation plan for one batch of CIDR/NS pairs.

    Each entry is ``(cidr, nameservers)`` with a strict IPv4 CIDR in the
    /24-/32 range and one or more NS domain names.  Every CIDR must share the
    same parent /24 and no two CIDRs may intersect, otherwise the whole batch
    is rejected with :class:`ValueError`; malformed CIDRs/NS names raise too.

    A /24 entry delegates its ``d.c.b.a.in-addr.arpa`` zone directly: one NS
    record at the zone apex per distinct nameserver (input order kept).  A
    /25-/32 entry is delegated per RFC 2317 as the range-labelled subzone
    ``<last-octet>/<prefixlen>`` beneath the parent /24: the subzone gets its
    NS records, and every covered address gets a CNAME in the parent zone from
    ``<n>.d.c.b.a.in-addr.arpa.`` to ``<n>.<label>.d.c.b.a.in-addr.arpa.``,
    the PTR name the delegated subzone will own.

    The response zones and records are sorted by source network address (then
    prefix length); records of one CIDR stay grouped together, its NS records
    first and the per-address CNAMEs ascending by last octet.  Every record
    carries the canonical input ``cidr`` it was generated from.
    """
    parsed: list[tuple[ipaddress.IPv4Network, list[str]]] = []
    for cidr, nameservers in entries:
        network = _parse_reverse_cidr(cidr)
        if not nameservers:
            raise ValueError(
                f"reverse-delegation CIDR {network} must list at least one "
                f"nameserver"
            )
        # De-duplicate repeated NS targets case-insensitively, keeping the
        # first spelling/order so the plan does not emit duplicate RRs.
        seen: set[str] = set()
        targets: list[str] = []
        for raw in nameservers:
            target = _parse_nameserver(raw)
            if target not in seen:
                seen.add(target)
                targets.append(target)
        parsed.append((network, targets))

    networks = [network for network, _targets in parsed]
    _validate_reverse_batch(networks)

    zones: list[dict] = []
    records: list[dict] = []
    for network, targets in sorted(parsed, key=lambda item: _sort_key(item[0])):
        octets = network.network_address.packed
        parent = f"{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa."
        cidr_text = str(network)

        if network.prefixlen == 24:
            zone_name = parent
            parent_zone = None
            method = "direct"
        else:
            # RFC 2317 range label: last octet of the network address and the
            # actual prefix length, e.g. 10.0.0.128/25 -> "128/25",
            # 10.0.0.64/26 -> "64/26", 10.0.0.5/32 -> "5/32".
            label = f"{octets[3]}/{network.prefixlen}"
            zone_name = f"{label}.{parent}"
            parent_zone = parent
            method = "rfc2317"

        zones.append({
            "zone": zone_name,
            "method": method,
            "parent_zone": parent_zone,
            "cidr": cidr_text,
            "nameservers": targets,
        })

        for target in targets:
            records.append({
                "zone": parent_zone if method == "rfc2317" else zone_name,
                "type": "NS",
                "name": zone_name,
                "target": target,
                "cidr": cidr_text,
            })

        if method == "rfc2317":
            start = int(network.network_address)
            for offset in range(network.num_addresses):
                address = ipaddress.IPv4Address(start + offset)
                last = int(address) & 0xFF
                records.append({
                    "zone": parent,
                    "type": "CNAME",
                    "name": f"{last}.{parent}",
                    "target": f"{last}.{label}.{parent}",
                    "cidr": cidr_text,
                })

    return {"zones": zones, "records": records}


# ---------------------------------------------------------------------------
# roa-coverage: RFC 6483 RPKI ROA coverage map for every candidate route of a
# fixed prefix length inside one scope.  Each candidate is:
#   valid   - some covering ROA with the origin ASN and max_length >= length;
#   invalid - covered by at least one ROA, but none authorizes (target ASN
#             with a big-enough max_length) — wrong-ASN and length-exceeded
#             ROAs both make the route invalid (RFC 6483);
#   unknown - no ROA prefix covers the route at all.
# The scope is partitioned into maximal status-constant CIDRs by a prefix-tree
# walk driven only by ROA boundaries (never enumerating the aligned /L
# candidates, so a /128-granular IPv6 scope stays cheap), then equal-status
# sibling halves are merged bottom-up into the minimum CIDR set.
# ---------------------------------------------------------------------------

#: ROA validation states (a valid ROA wins over any invalid one on the same
#: route; unknown means no ROA covers the route).
ROA_STATES: tuple[str, ...] = ("valid", "invalid", "unknown")


class Roa(NamedTuple):
    """One Route Origin Authorization: prefix, origin ASN, max_length."""

    network: Network
    asn: int
    max_length: int


def _roa_partition_node(
    network: Network,
    active: Sequence[Roa],
    pending: Sequence[Roa],
    target_asn: int,
    length: int,
    out: list[tuple[Network, str]],
) -> None:
    """Append status-constant pieces covering every aligned ``/length`` route.

    ``active`` ROAs have a prefix equal to or broader than ``network`` (they
    cover every candidate in it); ``pending`` ROAs are strict subnets whose
    prefix reaches no deeper than ``/length`` (an ROA stricter than the
    candidate granularity lives inside one candidate and never covers it, so
    such ROAs are dropped before the walk).

    A node terminates as soon as the pending ROAs cannot change its status:

    * an authorizing active ROA already covers it — ``valid`` never degrades;
    * at the ``/length`` boundary every aligned candidate shares the active
      set and no pending ROA covers the whole candidate;
    * ``invalid`` (covered, not authorized) with no validating pending ROA —
      wrong-ASN/length-too-short ROAs only keep it invalid;
    * ``unknown`` with no pending ROA at all — nothing can cover it.

    Otherwise the node splits into its two sibling halves, forwarding each
    ROA to the half it reaches, exactly like :func:`_partition_node`.  The
    walk therefore touches only ROA boundaries instead of every candidate
    (an uncut ``::/0`` region costs O(1), not :math:`2^{128}` nodes).
    """
    authorizing = any(
        roa.asn == target_asn and roa.max_length >= length for roa in active
    )
    if authorizing:
        out.append((network, "valid"))
        return

    if network.prefixlen == length:
        out.append((network, "invalid" if active else "unknown"))
        return

    if active:
        # Covered but not authorized: only a ROA carrying the target ASN with
        # sufficient max_length can promote any region to valid.
        if not any(
            roa.asn == target_asn and roa.max_length >= length
            for roa in pending
        ):
            out.append((network, "invalid"))
            return
    elif not pending:
        out.append((network, "unknown"))
        return

    left, right = network.subnets()
    for half in (left, right):
        half_active = list(active)
        half_pending: list[Roa] = []
        for roa in pending:
            # Pending prefixes are strict subnets of network: each one equals
            # exactly one half (and starts covering there) or is a strict
            # subnet of exactly one half.
            if roa.network == half:
                half_active.append(roa)
            elif roa.network.subnet_of(half):
                half_pending.append(roa)
        _roa_partition_node(
            half, half_active, half_pending, target_asn, length, out
        )


def _merge_status_pieces(
    blocks: Sequence[tuple[Network, str]],
    scope: Network,
) -> list[tuple[Network, str]]:
    """Recursively merge complete sibling pairs carrying the same ROA status.

    Same bottom-up fixpoint as :func:`ipaddress.collapse_addresses` (used by
    :func:`_merge_labelled`): two pieces merge only when both halves of one
    common parent are present, carry the identical status and the parent
    stays inside ``scope`` (or equals it).  A pair whose parent would be
    broader than the scope is never joined — the pieces tile exactly the
    scope, which is therefore the coarsest legal output; that boundary test
    on the parent (not the pieces) also covers a ``/0`` scope.
    """
    pieces = list(blocks)
    while True:
        # One pass pairs disjoint sibling sets: pieces that can still merge
        # are grouped by the parent they would merge into; a two-piece,
        # same-status group whose parent stays inside the scope becomes that
        # parent, while every other piece (and every piece already at/above
        # the scope boundary) carries over unchanged.  Repeat so parents born
        # in this pass can merge again (fixpoint), just like
        # ipaddress.collapse_addresses.
        groups: dict[tuple[bytes, int], list[tuple[Network, str]]] = {}
        carried: list[tuple[Network, str]] = []
        for network, status in pieces:
            if network.prefixlen <= scope.prefixlen:
                # The scope itself is the coarsest legal output; skipping its
                # piece by length (rather than by parent containment) also
                # stops a /0 scope's halves-merged-to-root from looping.
                carried.append((network, status))
                continue
            parent = network.supernet()
            groups.setdefault(_sort_key(parent), []).append((network, status))

        merged: list[tuple[Network, str]] = []
        any_merge = False
        for group in groups.values():
            if len(group) == 2 and group[0][1] == group[1][1]:
                merged.append((group[0][0].supernet(), group[0][1]))
                any_merge = True
            else:
                merged.extend(group)

        if not any_merge:
            pieces.sort(key=lambda block: _sort_key(block[0]))
            return pieces
        pieces = carried + merged


def roa_coverage(
    scope_raw: str,
    target_asn: int,
    prefix_length: int,
    roas: Sequence[tuple[str, int, int]],
) -> dict:
    """Partition ``scope`` into the ROA status of every aligned candidate route.

    A candidate route is each aligned network of prefix ``prefix_length``
    fully contained in the strict scope.  Per RFC 6483 a route is ``valid``
    when some covering ROA lists ``target_asn`` with ``max_length`` at least
    ``prefix_length``; otherwise ``invalid`` when at least one ROA covers it
    (wrong origin ASN, or every covering ROA's ``max_length`` is too small);
    and ``unknown`` when no ROA covers it.

    The output is the minimum tiling of the candidate region: sorted,
    non-overlapping, jointly-exhaustive CIDRs whose prefix length is at most
    ``prefix_length`` (pieces may be shorter where every candidate in a larger
    aligned block shares one status), each paired with its constant status.
    Nothing is enumerated candidate-by-candidate — the prefix-tree walk is
    driven only by ROA prefix boundaries, so even a ``::/0`` scope at
    ``/128`` costs at most :math:`O(|ROAs| \\cdot \\text{width})` nodes.

    Caller validation (e.g. the Pydantic schema) guarantees the scope parses
    strictly, ``prefix_length`` fits the scope family and is not shorter than
    the scope prefix, every ROA CIDR parses strictly in the same family, and
    each ``max_length`` lies between its ROA prefix length and the family
    width; ``target_asn`` is a 32-bit AS number.  A malformed value raises
    :class:`ValueError`.
    """
    scope = parse_network(scope_raw)
    family = type(scope)
    length = prefix_length
    max_bits = _MAX_PREFIXLEN[family]

    parsed: list[Roa] = []
    for cidr, asn, max_length in roas:
        network = parse_strict_cidr(cidr)
        if not isinstance(network, family):
            raise ValueError(
                f"ROA CIDR {network} does not match the scope address "
                f"family ({scope})"
            )
        if max_length < network.prefixlen or max_length > max_bits:
            raise ValueError(
                f"ROA for {network} has max_length /{max_length}; it must "
                f"lie between /{network.prefixlen} and /{max_bits}"
            )
        if network.overlaps(scope):
            parsed.append(Roa(network, asn, max_length))

    pieces: list[tuple[Network, str]] = []
    if length >= scope.prefixlen:
        # ROAs equal to or broader than the scope cover its root; ROAs
        # strictly inside the scope can change the status below it.  An ROA
        # stricter than the candidate granularity lives entirely inside one
        # candidate route and covers none of them, so it never participates.
        root_active = [
            roa for roa in parsed if roa.network.prefixlen <= scope.prefixlen
        ]
        root_pending = [
            roa for roa in parsed
            if scope.prefixlen < roa.network.prefixlen <= length
        ]
        _roa_partition_node(
            scope, root_active, root_pending, target_asn, length, pieces
        )
        pieces = _merge_status_pieces(pieces, scope)
        pieces.sort(key=lambda block: _sort_key(block[0]))

    return {
        "partitions": [
            {"cidr": str(network), "status": status}
            for network, status in pieces
        ],
    }


# ---------------------------------------------------------------------------
# as-relationship-repair: minimum-cardinality repair of undirected AS
# customer-provider/peer relationships so every given origin-to-receiver AS
# path satisfies the valley-free rule (zero or more up-hops, at most one peer
# hop, then zero or more down-hops).
# ---------------------------------------------------------------------------

#: Maximum number of undirected AS relationships accepted.
AS_RELATIONSHIP_LIMIT = 9

#: Maximum number of AS paths accepted.
AS_PATH_LIMIT = 20

#: Inclusive 32-bit AS number range (same bounds as the ROA endpoints).
ASN_MIN = 0
ASN_MAX = 4294967295

#: New-relationship code on a canonical pair ``(lo, hi)`` used as the
#: deterministic component of the equal-cost lexicographic tie-break:
#: ``lo`` is the customer (``lo`` -> ``hi`` up-hill), then ``hi`` is the
#: customer (``hi`` -> ``lo`` up-hill), then a peer relationship.
REL_LO_CUSTOMER = 0
REL_HI_CUSTOMER = 1
REL_PEER = 2
RELATIONSHIP_CODES: tuple[int, int, int] = (
    REL_LO_CUSTOMER,
    REL_HI_CUSTOMER,
    REL_PEER,
)


def as_relationship_token(customer: int, provider: int) -> int:
    """Return the canonical new-relationship code for one c2p orientation.

    The code of an undirected pair ``(lo, hi)`` (``lo < hi``) is
    :data:`REL_LO_CUSTOMER` when ``lo`` is the customer and
    :data:`REL_HI_CUSTOMER` when ``hi`` is the customer.  Peer relationships
    always carry :data:`REL_PEER`.
    """
    lo, hi = sorted((customer, provider))
    return REL_LO_CUSTOMER if customer == lo else REL_HI_CUSTOMER


def _hop_kind(left: int, right: int, token: int) -> str:
    """Classify one traversed hop ``left -> right`` as ``U``, ``D`` or ``P``.

    ``U`` (up-hill) and ``D`` (down-hill) are the two orientations of a
    customer-provider relationship: a customer walking to its provider goes up,
    a provider walking to its customer goes down; a peer hop is ``P`` in
    either direction.  ``token`` follows :data:`RELATIONSHIP_CODES` on the
    canonical pair of ``left``/``right``.
    """
    if token == REL_PEER:
        return "P"
    lo, hi = sorted((left, right))
    customer = lo if token == REL_LO_CUSTOMER else hi
    return "U" if left == customer else "D"


def _path_is_valley_free(
    path: Sequence[int], tokens: dict[tuple[int, int], int]
) -> bool:
    """Whether one origin-to-receiver path matches ``up* peer? down*``.

    The state is the most permissive hop class still legal: ``U`` while only
    up-hops (and none after) have been seen, ``P`` after the single peer hop,
    ``D`` after the first down-hop.  An up-hop after a peer/down-hop, or a
    second peer hop, forms a valley (or a second summit) and fails the path.
    """
    state = "U"
    for left, right in zip(path, path[1:]):
        pair = (left, right) if left < right else (right, left)
        kind = _hop_kind(left, right, tokens[pair])
        if kind == "U":
            if state != "U":
                return False
        elif kind == "P":
            if state != "U":
                return False
            state = "P"
        else:  # down-hop: legal from every non-final state, then stay in "D"
            state = "D"
    return True


def _relationship_record(pair: tuple[int, int], token: int) -> dict:
    """Serialize one repaired relationship in the request/response shape."""
    lo, hi = pair
    if token == REL_PEER:
        return {"type": "peer", "peers": [lo, hi]}
    if token == REL_LO_CUSTOMER:
        return {"type": "customer_provider", "customer": lo, "provider": hi}
    return {"type": "customer_provider", "customer": hi, "provider": lo}


def as_relationship_repair(
    relationships: Sequence[tuple[tuple[int, int], int]],
    paths: Sequence[Sequence[int]],
) -> dict | None:
    """Repair AS relationships so every path is simultaneously valley-free.

    ``relationships`` maps every undirected pair that may be used (as
    ``((lo, hi), token)`` with ``lo < hi`` and a token from
    :data:`RELATIONSHIP_CODES`) to its original relationship.  ``paths`` are
    origin-to-receiver AS sequences; the caller (Pydantic schema) guarantees
    the bounds, unique ASNs inside each path and that every hop pair exists in
    ``relationships``.

    Every used pair may keep its token or take one of the other two
    relationships (the reverse customer-provider orientation or a peer).  The
    repair minimizes the number of changed pairs; pairs unused by any path are
    never changed.  Among equal-cost repairs the lexicographically smallest
    token sequence over the used pairs in canonical ``(lo, hi)`` order — the
    sorted new-relationship sequence — uniquely wins.  Returns ``None`` when
    no relationship assignment makes every path valley-free (HTTP 409).

    The result lists the indices of paths that were already violating under
    the original relationships, every changed pair (sorted by canonical pair)
    with its new relationship, and the change count.  With at most
    :data:`AS_RELATIONSHIP_LIMIT` used pairs the exhaustive search visits at
    most :math:`3^9 = 19683` assignments.
    """
    original = {pair: token for pair, token in relationships}
    used_pairs = sorted({
        pair
        for path in paths
        for left, right in zip(path, path[1:])
        for pair in ((left, right) if left < right else (right, left),)
    })

    original_tokens = {pair: original[pair] for pair in used_pairs}
    violating_indices = [
        index
        for index, path in enumerate(paths)
        if not _path_is_valley_free(path, original_tokens)
    ]

    # Iterate tokens pair-by-pair in canonical order; itertools.product emits
    # tuples lexicographically, so ties are resolved by the full sorted
    # new-relationship sequence without a second comparison pass.
    best_combo: tuple[int, ...] | None = None
    best_cost = len(used_pairs) + 1
    for combo in itertools.product(
        RELATIONSHIP_CODES, repeat=len(used_pairs)
    ):
        tokens = dict(zip(used_pairs, combo))
        if not all(_path_is_valley_free(path, tokens) for path in paths):
            continue
        cost = sum(
            token != original_tokens[pair]
            for pair, token in zip(used_pairs, combo)
        )
        # Minimum cardinality first; at equal cost the first visited combo is
        # already the lexicographically smallest new-relationship sequence.
        if cost < best_cost:
            best_cost = cost
            best_combo = combo

    if best_combo is None:
        return None

    corrections = [
        _relationship_record(pair, token)
        for pair, token in zip(used_pairs, best_combo)
        if token != original_tokens[pair]
    ]
    return {
        "violating_path_indices": violating_indices,
        "corrections": corrections,
        "changes": best_cost,
    }


# ---------------------------------------------------------------------------
# nat64-codec: RFC 6052 Network-Specific IPv4/IPv6 translation mapping.  The
# IPv4 bits straddle the bit-64 boundary: a variable number of leading IPv4
# octets sit inside the first 64 bits, then the all-zero "u" octet at bit
# position 64, then the remaining IPv4 octets, then an all-zero suffix.  A
# /96 prefix has no u octet and no suffix (IPv4 directly follows the prefix).
# ---------------------------------------------------------------------------

#: Prefix lengths allowed by RFC 6052 section 2.2 for a Network-Specific Prefix.
NAT64_PREFIX_LENGTHS: tuple[int, ...] = (32, 40, 48, 56, 64, 96)


def parse_nat64_prefix(value: object) -> ipaddress.IPv6Network:
    """Parse one strict IPv6 translation prefix restricted to RFC 6052 lengths.

    Only explicit IPv6 CIDRs whose prefix length is one of
    :data:`NAT64_PREFIX_LENGTHS` (32/40/48/56/64/96) are accepted; host bits
    must be zero (``strict=True``) and a bare address is rejected.  Any invalid
    input raises :class:`ValueError`.
    """
    network = parse_strict_cidr(value)
    if not isinstance(network, ipaddress.IPv6Network):
        raise ValueError(
            f"NAT64 translation prefix {value!r} must be IPv6, not IPv4"
        )
    if network.prefixlen not in NAT64_PREFIX_LENGTHS:
        allowed = ", ".join(f"/{length}" for length in NAT64_PREFIX_LENGTHS)
        raise ValueError(
            f"NAT64 translation prefix {value!r} has prefix "
            f"/{network.prefixlen}; only {allowed} are accepted (RFC 6052)"
        )
    return network


def _nat64_layout(prefixlen: int) -> tuple[int, int]:
    """Return ``(leading_v4_octets, trailing_v4_octets)`` for a prefix length.

    The first count IPv4 octets are placed immediately after the prefix (still
    inside bit positions 0-63); the rest follow the u octet at byte 9.  A /96
    prefix uses neither the u octet nor this split.
    """
    leading = (64 - prefixlen) // 8
    return leading, 4 - leading


def _nat64_encode(
    prefix: ipaddress.IPv6Network, address: ipaddress.IPv4Address
) -> ipaddress.IPv6Address:
    """Embed one bare IPv4 address after an RFC 6052 translation prefix."""
    mapped = bytearray(prefix.network_address.packed)
    v4 = address.packed
    if prefix.prefixlen == 96:
        # /96: the 32 IPv4 bits follow the 96-bit prefix directly; there is no
        # u octet and no suffix (RFC 6052 section 2.2, last row).
        mapped[12:16] = v4
        return ipaddress.IPv6Address(bytes(mapped))
    leading, trailing = _nat64_layout(prefix.prefixlen)
    start = prefix.prefixlen // 8
    mapped[start:start + leading] = v4[:leading]
    mapped[8] = 0  # u octet
    mapped[9:9 + trailing] = v4[leading:]
    # Every remaining suffix byte is zero; the prefix network address already
    # had its host part cleared by the strict parse, but set them explicitly.
    mapped[9 + trailing:] = b"\x00" * (16 - 9 - trailing)
    return ipaddress.IPv6Address(bytes(mapped))


def _nat64_decode(
    prefix: ipaddress.IPv6Network, address: ipaddress.IPv6Address
) -> ipaddress.IPv4Address:
    """Extract the embedded IPv4 address from one canonical mapped IPv6 address.

    The address must match the translation prefix; for every prefix length
    shorter than /96 the u octet (byte 8) and the whole suffix after the IPv4
    bits must be all zero.  A non-canonical mapping raises :class:`ValueError`.
    """
    packed = address.packed
    prefix_bytes = prefix.prefixlen // 8
    if packed[:prefix_bytes] != prefix.network_address.packed[:prefix_bytes]:
        raise ValueError(
            f"IPv6 address {address} does not match the NAT64 translation "
            f"prefix {prefix}"
        )
    if prefix.prefixlen == 96:
        return ipaddress.IPv4Address(packed[12:16])
    leading, trailing = _nat64_layout(prefix.prefixlen)
    start = prefix.prefixlen // 8
    if packed[8] != 0:
        raise ValueError(
            f"IPv6 address {address} under NAT64 prefix {prefix} has a "
            f"non-zero u octet (0x{packed[8]:02x}); the u octet must be zero"
        )
    if any(packed[9 + trailing:]):
        raise ValueError(
            f"IPv6 address {address} under NAT64 prefix {prefix} has "
            f"non-zero suffix bits; the {8 * (16 - 9 - trailing)}-bit "
            f"suffix must be zero"
        )
    return ipaddress.IPv4Address(
        bytes(packed[start:start + leading]) + bytes(packed[9:9 + trailing])
    )


def nat64_codec(
    prefix_raw: str,
    encode_raw: Sequence[str],
    decode_raw: Sequence[str],
) -> dict:
    """Encode IPv4 addresses and decode IPv6 mappings under one NAT64 prefix.

    ``encode_raw`` holds bare IPv4 addresses and ``decode_raw`` bare IPv6
    addresses; each result list keeps the corresponding input order and length.
    Every IPv6 decoding input must be a canonical RFC 6052 mapping of the
    prefix (matching prefix, zero u octet and zero suffix) or the whole batch
    is rejected with :class:`ValueError`; malformed addresses or an invalid
    prefix raise too.
    """
    prefix = parse_nat64_prefix(prefix_raw)

    encoded: list[str] = []
    for item in encode_raw:
        address = parse_address(item)
        if not isinstance(address, ipaddress.IPv4Address):
            raise ValueError(
                f"encode address {item!r} must be IPv4, not IPv6"
            )
        encoded.append(str(_nat64_encode(prefix, address)))

    decoded: list[str] = []
    for item in decode_raw:
        address = parse_address(item)
        if not isinstance(address, ipaddress.IPv6Address):
            raise ValueError(
                f"decode address {item!r} must be IPv6, not IPv4"
            )
        decoded.append(str(_nat64_decode(prefix, address)))

    return {"encoded": encoded, "decoded": decoded}
