"""Pydantic request/response models for the normalization API."""

from __future__ import annotations

import ipaddress
from typing import Annotated, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from app.policy import (
    ASN_MAX,
    ASN_MIN,
    AS_PATH_LIMIT,
    AS_RELATIONSHIP_LIMIT,
    MINIMIZE_POLICY_RULE_LIMIT,
    REL_PEER,
    _MAX_PREFIXLEN,
    _nat64_decode,
    _parse_nameserver,
    _parse_reverse_cidr,
    _validate_reverse_batch,
    as_relationship_token,
    parse_address,
    parse_key_hex,
    parse_nat64_prefix,
    parse_network,
    parse_strict_cidr,
)


class PolicyRequest(BaseModel):
    allow: list[str] = Field(
        default_factory=list,
        description="Allowed CIDR list (IPv4/IPv6 may be mixed).",
    )
    deny: list[str] = Field(
        default_factory=list,
        description="Denied CIDR list (IPv4/IPv6 may be mixed).",
    )

    @field_validator("allow", "deny")
    @classmethod
    def _validate_cidr_list(cls, values: list[str]) -> list[str]:
        # A ValueError raised here is turned by FastAPI into an HTTP 422
        # response carrying the offending field and value.
        for value in values:
            parse_network(value)
        return values


class EvaluateRequest(PolicyRequest):
    addresses: list[str] = Field(
        default_factory=list,
        description="Bare IPv4/IPv6 addresses to evaluate, in response order.",
    )

    @field_validator("addresses")
    @classmethod
    def _validate_address_list(cls, values: list[str]) -> list[str]:
        for value in values:
            parse_address(value)
        return values


class ListStats(BaseModel):
    input: int = Field(description="Raw number of entries in the request list.")
    unique: int = Field(description="Distinct networks after de-duplication.")
    duplicates_removed: int = Field(description="input - unique.")
    ipv4: int = Field(description="Distinct IPv4 networks after de-duplication.")
    ipv6: int = Field(description="Distinct IPv6 networks after de-duplication.")


class OutputStats(BaseModel):
    ipv4: int
    ipv6: int
    total: int


class Stats(BaseModel):
    allow: ListStats
    deny: ListStats
    output: OutputStats


class NormalizeResponse(BaseModel):
    ipv4: list[str] = Field(
        description="allow - deny for IPv4, minimal, non-overlapping, sorted.",
    )
    ipv6: list[str] = Field(
        description="allow - deny for IPv6, minimal, non-overlapping, sorted.",
    )
    stats: Stats


class AddressDecision(BaseModel):
    decision: Literal["allow", "deny", "unmatched"] = Field(
        description=(
            "Winner side after longest-prefix matching; 'unmatched' when no "
            "list entry contains the address."
        ),
    )
    matched_cidr: str | None = Field(
        description="Canonical CIDR of the winning entry; null when unmatched.",
    )
    matched_side: Literal["allow", "deny"] | None = Field(
        description="List the winning entry came from; null when unmatched.",
    )


class CompareRequest(BaseModel):
    scope: str = Field(
        description=(
            "Single CIDR (IPv4 or IPv6) limiting the comparison region. "
            "Strict: host bits must be zero."
        ),
    )
    baseline: PolicyRequest = Field(
        default_factory=PolicyRequest,
        description="Baseline allow/deny policy set.",
    )
    candidate: PolicyRequest = Field(
        default_factory=PolicyRequest,
        description="Candidate allow/deny policy set to compare against.",
    )

    @field_validator("scope")
    @classmethod
    def _validate_scope(cls, value: str) -> str:
        # A missing/blank scope is invalid; a bare address (host prefix) is
        # accepted, just like allow/deny entries.
        parse_network(value)
        return value


class CompareDifference(BaseModel):
    cidr: str = Field(
        description="Non-overlapping region inside scope where decisions differ.",
    )
    baseline_decision: Literal["allow", "deny", "unmatched"] = Field(
        description="Baseline decision throughout cidr.",
    )
    candidate_decision: Literal["allow", "deny", "unmatched"] = Field(
        description="Candidate decision throughout cidr.",
    )


class CompareResponse(BaseModel):
    differences: list[CompareDifference] = Field(
        description=(
            "Regions whose decision changes, sorted IPv4 then IPv6, by "
            "network address then prefix length."
        ),
    )
    transition_counts: dict[str, str] = Field(
        description=(
            "Addresses covered per 'baseline->candidate' transition type, "
            "as decimal strings; all six transitions are present (0 when "
            "unused)."
        ),
    )


class AuditRulesRequest(BaseModel):
    scope: str = Field(
        description=(
            "Single CIDR (IPv4 or IPv6) limiting the audit region. "
            "Strict: host bits must be zero."
        ),
    )
    allow: list[str] = Field(
        default_factory=list,
        description="Allowed CIDR list; every entry must match the scope family.",
    )
    deny: list[str] = Field(
        default_factory=list,
        description="Denied CIDR list; every entry must match the scope family.",
    )

    @field_validator("scope")
    @classmethod
    def _validate_scope(cls, value: str) -> str:
        parse_network(value)
        return value

    @field_validator("allow", "deny")
    @classmethod
    def _validate_cidr_list(cls, values: list[str]) -> list[str]:
        for value in values:
            parse_network(value)
        return values

    @model_validator(mode="after")
    def _validate_family_against_scope(self) -> "AuditRulesRequest":
        # A wrong-family rule is a 422 here (unlike /compare, which ignores
        # it): the audit is explicitly scoped to one address family.
        scope = parse_network(self.scope)
        for side, entries in (("allow", self.allow), ("deny", self.deny)):
            for value in entries:
                network = parse_network(value)
                if not isinstance(network, type(scope)):
                    raise ValueError(
                        f"{side} CIDR {network} does not match the scope "
                        f"address family ({scope})"
                    )
        return self


class RuleReference(BaseModel):
    side: Literal["allow", "deny"] = Field(
        description="Input list the shadowing rule came from.",
    )
    index: int = Field(
        description="Position of the shadowing rule in that list (0-based).",
    )


class RuleAuditResult(BaseModel):
    side: Literal["allow", "deny"] = Field(
        description="Input list this rule came from.",
    )
    index: int = Field(
        description="Position of this rule in its input list (0-based).",
    )
    cidr: str = Field(description="Canonical CIDR of the input rule.")
    status: Literal["effective", "shadowed", "out_of_scope"] = Field(
        description=(
            "'effective' when the rule decides somewhere inside scope; "
            "'shadowed' when other rules beat it everywhere inside scope; "
            "'out_of_scope' when the rule CIDR does not intersect scope."
        ),
    )
    witness: str | None = Field(
        default=None,
        description=(
            "Numerically smallest network address in the region where the "
            "rule wins; present only when status is 'effective'."
        ),
    )
    shadowed_by: list[RuleReference] | None = Field(
        default=None,
        description=(
            "Distinct input rules that win every part of this rule's region "
            "inside scope; present only when status is 'shadowed'."
        ),
    )


class AuditRulesResponse(BaseModel):
    allow: list[RuleAuditResult] = Field(
        description="One result per allow entry, in input order.",
    )
    deny: list[RuleAuditResult] = Field(
        description="One result per deny entry, in input order.",
    )


class MinimizePolicyRequest(BaseModel):
    scope: str = Field(
        description=(
            "Single CIDR (IPv4 or IPv6) limiting the minimization region. "
            "Strict: host bits must be zero."
        ),
    )
    allow: list[str] = Field(
        default_factory=list,
        description=(
            "Allowed CIDR list; every entry must match the scope family."
        ),
    )
    deny: list[str] = Field(
        default_factory=list,
        description=(
            "Denied CIDR list; every entry must match the scope family."
        ),
    )

    @field_validator("scope")
    @classmethod
    def _validate_scope(cls, value: str) -> str:
        parse_network(value)
        return value

    @field_validator("allow", "deny")
    @classmethod
    def _validate_cidr_list(cls, values: list[str]) -> list[str]:
        for value in values:
            parse_network(value)
        return values

    @model_validator(mode="after")
    def _validate_rules_against_scope(self) -> "MinimizePolicyRequest":
        # Same hard rules as /audit-rules: one family, bounded rule count.
        scope = parse_network(self.scope)
        total = len(self.allow) + len(self.deny)
        if total > MINIMIZE_POLICY_RULE_LIMIT:
            raise ValueError(
                f"total number of allow/deny rules ({total}) exceeds the "
                f"limit of {MINIMIZE_POLICY_RULE_LIMIT}"
            )
        for side, entries in (("allow", self.allow), ("deny", self.deny)):
            for value in entries:
                network = parse_network(value)
                if not isinstance(network, type(scope)):
                    raise ValueError(
                        f"{side} CIDR {network} does not match the scope "
                        f"address family ({scope})"
                    )
        return self


class RetainedRule(RuleReference):
    cidr: str = Field(description="Canonical CIDR of the retained rule.")
    witness: str = Field(
        description=(
            "Numerically smallest IP address at which this rule wins under "
            "the minimized policy inside the scope."
        ),
    )


class RemovedRule(RuleReference):
    cidr: str = Field(description="Canonical CIDR of the removed rule.")


class MinimizePolicyResponse(BaseModel):
    retained: list[RetainedRule] = Field(
        description=(
            "Rules kept in the unique minimum subset. References follow the "
            "original input order: all allow entries (by index) first, then "
            "all deny entries (by index)."
        ),
    )
    removed: list[RemovedRule] = Field(
        description=(
            "Rules dropped by the minimization, in the same original input "
            "order as retained: allow references by index, then deny by index."
        ),
    )


class AllocationRequest(BaseModel):
    id: str = Field(
        min_length=1,
        description="Caller-chosen request identifier; must be unique.",
    )
    prefix_length: int = Field(
        ge=0,
        description=(
            "Requested subnet prefix length; must fit the scope address "
            "family (0-32 for IPv4, 0-128 for IPv6)."
        ),
    )


class AllocateRequest(BaseModel):
    scope: str = Field(
        description=(
            "Single CIDR (IPv4 or IPv6) the allocations are carved from. "
            "Strict: host bits must be zero."
        ),
    )
    occupied: list[str] = Field(
        default_factory=list,
        description=(
            "Already-allocated CIDRs. Each must share the scope address "
            "family, lie inside the scope, and not overlap any other entry."
        ),
    )
    requests: list[AllocationRequest] = Field(
        default_factory=list,
        description="Subnet requests, allocated in this order.",
    )

    @field_validator("scope")
    @classmethod
    def _validate_scope(cls, value: str) -> str:
        parse_network(value)
        return value

    @field_validator("occupied")
    @classmethod
    def _validate_occupied_list(cls, values: list[str]) -> list[str]:
        for value in values:
            parse_network(value)
        return values

    @model_validator(mode="after")
    def _validate_against_scope(self) -> "AllocateRequest":
        # A ValueError raised here is turned by FastAPI into an HTTP 422
        # response, exactly like the per-field validators above.
        scope = parse_network(self.scope)
        max_prefixlen = _MAX_PREFIXLEN[type(scope)]

        networks = [parse_network(value) for value in self.occupied]
        for network in networks:
            if not isinstance(network, type(scope)):
                raise ValueError(
                    f"occupied CIDR {network} does not match the scope "
                    f"address family ({scope})"
                )
            if not network.subnet_of(scope):
                raise ValueError(
                    f"occupied CIDR {network} is not contained in scope "
                    f"{scope}"
                )
        ordered = sorted(
            networks, key=lambda n: (int(n.network_address), n.prefixlen)
        )
        # For intervals sorted by start, any overlap implies an overlap of
        # some consecutive pair.
        for left, right in zip(ordered, ordered[1:]):
            if left.overlaps(right):
                raise ValueError(
                    f"occupied CIDRs {left} and {right} overlap"
                )

        seen: set[str] = set()
        for item in self.requests:
            if item.id in seen:
                raise ValueError(f"duplicate request id {item.id!r}")
            seen.add(item.id)
            if item.prefix_length > max_prefixlen:
                raise ValueError(
                    f"prefix_length {item.prefix_length} exceeds "
                    f"/{max_prefixlen} for the scope address family"
                )
        return self


class Allocation(BaseModel):
    id: str = Field(description="Identifier of the fulfilled request.")
    cidr: str = Field(
        description="Allocated subnet, canonical CIDR, inside the scope.",
    )


class AllocateResponse(BaseModel):
    allocations: list[Allocation] = Field(
        description=(
            "One entry per request, in request order; the sequence of "
            "network addresses is the lexicographically smallest complete "
            "feasible assignment."
        ),
    )
    remaining: list[str] = Field(
        description=(
            "Free space left in the scope after allocation: minimal, "
            "non-overlapping CIDR set, sorted by network address."
        ),
    )
    remaining_addresses: str = Field(
        description=(
            "Total free addresses left in the scope, as a decimal string "
            "(IPv6 remainders exceed JSON's safe integer range)."
        ),
    )


class AnonymizeRequest(BaseModel):
    key_hex: str = Field(
        description=(
            "256-bit anonymization key as exactly 64 hexadecimal characters. "
            "The mapping is stable for a fixed key."
        ),
    )
    addresses: list[str] = Field(
        default_factory=list,
        description="Bare IPv4/IPv6 addresses to anonymize, in response order.",
    )
    cidrs: list[str] = Field(
        default_factory=list,
        description=(
            "Strict CIDRs (explicit prefix length, zero host bits) to "
            "anonymize, in response order."
        ),
    )

    @field_validator("key_hex")
    @classmethod
    def _validate_key_hex(cls, value: str) -> str:
        # A ValueError raised here is turned by FastAPI into an HTTP 422
        # response carrying the offending field and value.
        parse_key_hex(value)
        return value

    @field_validator("addresses")
    @classmethod
    def _validate_address_list(cls, values: list[str]) -> list[str]:
        for value in values:
            parse_address(value)
        return values

    @field_validator("cidrs")
    @classmethod
    def _validate_cidr_list(cls, values: list[str]) -> list[str]:
        for value in values:
            parse_strict_cidr(value)
        return values


class AnonymizeResponse(BaseModel):
    addresses: list[str] = Field(
        description=(
            "Anonymized bare addresses, one per input address, in input order."
        ),
    )
    cidrs: list[str] = Field(
        description=(
            "Anonymized canonical network segments, one per input CIDR, in "
            "input order, each keeping the original prefix length."
        ),
    )


class ReverseDelegationEntry(BaseModel):
    cidr: str = Field(
        description=(
            "Strict IPv4 CIDR to delegate; only prefix lengths /24 through "
            "/32 are accepted, host bits must be zero, and an explicit "
            "prefix length is required (bare addresses are rejected)."
        ),
    )
    nameservers: list[str] = Field(
        min_length=1,
        description=(
            "NS domain names for this delegation, in record order; "
            "duplicate targets collapse to one NS record."
        ),
    )

    @field_validator("cidr")
    @classmethod
    def _validate_cidr(cls, value: str) -> str:
        # Re-parsed for the 422 response; the endpoint also parses to build
        # the plan, so the message must stay identical here and there.
        _parse_reverse_cidr(value)
        return value

    @field_validator("nameservers")
    @classmethod
    def _validate_nameservers(cls, values: list[str]) -> list[str]:
        for value in values:
            _parse_nameserver(value)
        return values


class ReverseDelegationsRequest(BaseModel):
    delegations: list[ReverseDelegationEntry] = Field(
        default_factory=list,
        description=(
            "CIDR/NS pairs sharing one parent /24. Every CIDR must be a "
            "strict IPv4 /24-/32 network; the whole batch is rejected when "
            "two CIDRs intersect or their parent /24s differ."
        ),
    )

    @model_validator(mode="after")
    def _validate_batch(self) -> "ReverseDelegationsRequest":
        # Same-/24 and overlap checks span entries, so they belong to the
        # whole-model validator; the ValueError becomes an HTTP 422.
        networks = [
            _parse_reverse_cidr(entry.cidr) for entry in self.delegations
        ]
        _validate_reverse_batch(networks)
        return self


class ReverseZone(BaseModel):
    zone: str = Field(
        description=(
            "FQDN of the delegated zone: the in-addr.arpa zone for a direct "
            "/24 delegation, or the RFC 2317 range-labelled subzone "
            "(e.g. '0/25.0.0.10.in-addr.arpa.') for a /25-/32 delegation."
        ),
    )
    method: Literal["direct", "rfc2317"] = Field(
        description=(
            "'direct' for a /24 (in-addr.arpa NS); 'rfc2317' for /25-/32 "
            "(range-label subzone NS plus parent-zone CNAMEs)."
        ),
    )
    parent_zone: str | None = Field(
        description=(
            "Parent /24 in-addr.arpa zone that publishes the CNAMEs for an "
            "RFC 2317 delegation; null for a direct /24 delegation."
        ),
    )
    cidr: str = Field(description="Canonical input CIDR that produced this zone.")
    nameservers: list[str] = Field(
        description=(
            "Canonical FQDN NS targets (lower-case, single trailing dot), "
            "one per distinct input nameserver, in first-seen order."
        ),
    )


class ReverseRecord(BaseModel):
    zone: str = Field(
        description=(
            "Zone that must publish this record: the in-addr.arpa zone for "
            "direct /24 NS records, or the parent /24 zone for RFC 2317 NS "
            "and CNAME records."
        ),
    )
    type: Literal["NS", "CNAME"] = Field(description="DNS record type.")
    name: str = Field(
        description=(
            "Owner name (FQDN): the delegated zone name for NS records; the "
            "per-address reverse name 'n.d.c.b.a.in-addr.arpa.' for CNAMEs."
        ),
    )
    target: str = Field(
        description=(
            "Record target (FQDN): an NS host for NS records; the PTR name "
            "inside the RFC 2317 subzone for CNAME records."
        ),
    )
    cidr: str = Field(
        description="Canonical input CIDR this record was generated from.",
    )


class ReverseDelegationsResponse(BaseModel):
    zones: list[ReverseZone] = Field(
        description=(
            "Delegated zones sorted by source network address, then prefix "
            "length; one zone per input CIDR."
        ),
    )
    records: list[ReverseRecord] = Field(
        description=(
            "NS and CNAME records sorted by source network address (then "
            "prefix length), keeping all records of one input CIDR grouped: "
            "its NS records first, then per-address CNAMEs ascending for "
            "RFC 2317 delegations."
        ),
    )


class RoaEntry(BaseModel):
    cidr: str = Field(
        description=(
            "Strict ROA prefix (explicit prefix length required, host bits "
            "must be zero); its address family must match the scope."
        ),
    )
    asn: int = Field(
        ge=0,
        le=4294967295,
        description=(
            "Authorized origin AS number (32-bit unsigned ASN, 0 through "
            "4294967295)."
        ),
    )
    max_length: int = Field(
        ge=0,
        description=(
            "Longest prefix length the ROA authorizes for its prefix; must "
            "be at least the ROA prefix length and at most 32 (IPv4) or 128 "
            "(IPv6)."
        ),
    )

    @field_validator("cidr")
    @classmethod
    def _validate_cidr(cls, value: str) -> str:
        # Strict notation only: a bare address without '/p' is rejected.
        parse_strict_cidr(value)
        return value

    @model_validator(mode="after")
    def _validate_max_length(self) -> "RoaEntry":
        network = parse_strict_cidr(self.cidr)
        max_bits = _MAX_PREFIXLEN[type(network)]
        if self.max_length < network.prefixlen or self.max_length > max_bits:
            raise ValueError(
                f"ROA for {network} has max_length /{self.max_length}; it "
                f"must lie between /{network.prefixlen} and /{max_bits}"
            )
        return self


class RoaCoverageRequest(BaseModel):
    scope: str = Field(
        description=(
            "Single strict CIDR (IPv4 or IPv6) limiting the analysis region. "
            "Only aligned candidate routes fully inside it are partitioned."
        ),
    )
    asn: int = Field(
        ge=0,
        le=4294967295,
        description=(
            "Target origin AS number of the route to be published (32-bit "
            "unsigned ASN, 0 through 4294967295)."
        ),
    )
    prefix_length: int = Field(
        ge=0,
        description=(
            "Prefix length of the route to be published; candidate routes "
            "are every aligned CIDR of this length inside scope. Must be at "
            "least the scope prefix length and at most 32 (IPv4) or 128 "
            "(IPv6)."
        ),
    )
    roas: list[RoaEntry] = Field(
        default_factory=list,
        description=(
            "ROA list; every entry must share the scope address family. "
            "Entries disjoint from the scope do not affect the result."
        ),
    )

    @field_validator("scope")
    @classmethod
    def _validate_scope(cls, value: str) -> str:
        parse_network(value)
        return value

    @model_validator(mode="after")
    def _validate_against_scope(self) -> "RoaCoverageRequest":
        # Cross-entry checks live in the whole-model validator; a ValueError
        # becomes an HTTP 422 just like the per-field validators.
        scope = parse_network(self.scope)
        max_bits = _MAX_PREFIXLEN[type(scope)]
        if self.prefix_length > max_bits:
            raise ValueError(
                f"prefix_length {self.prefix_length} exceeds /{max_bits} "
                f"for the scope address family"
            )
        if self.prefix_length < scope.prefixlen:
            raise ValueError(
                f"prefix_length /{self.prefix_length} is shorter than the "
                f"scope prefix /{scope.prefixlen}; no aligned candidate "
                f"route fits inside {scope}"
            )
        for entry in self.roas:
            network = parse_strict_cidr(entry.cidr)
            if not isinstance(network, type(scope)):
                raise ValueError(
                    f"ROA CIDR {network} does not match the scope address "
                    f"family ({scope})"
                )
        return self


class RoaStatusPartition(BaseModel):
    cidr: str = Field(
        description=(
            "Non-overlapping status-constant region; its prefix length may "
            "be shorter than the requested prefix_length when every aligned "
            "candidate route inside it shares one status."
        ),
    )
    status: Literal["valid", "invalid", "unknown"] = Field(
        description=(
            "'valid' when a same-ASN ROA with sufficient max_length covers "
            "every candidate in cidr; 'invalid' when ROAs cover them but "
            "none authorizes; 'unknown' when no ROA covers them."
        ),
    )


class RoaCoverageResponse(BaseModel):
    partitions: list[RoaStatusPartition] = Field(
        description=(
            "Minimum, non-overlapping, jointly-exhaustive CIDR tiling of the "
            "candidate region, sorted by network address; the pieces tile "
            "the whole scope."
        ),
    )


# ---------------------------------------------------------------------------
# POST /as-relationship-repair
# ---------------------------------------------------------------------------

#: 32-bit AS number. ``strict=True`` also rejects booleans (``true``/``false``
#: coerce to int under Pydantic's default lax mode) and non-integer JSON.
ASN = Annotated[int, Field(strict=True, ge=ASN_MIN, le=ASN_MAX)]


def _as_pair(left: object, right: object) -> tuple[int, int]:
    """Return the canonical undirected ``(lo, hi)`` pair of two ASN values.

    Both values are already range-checked by the strict ASN field type; this
    helper additionally rejects equal endpoints and orders the pair.
    """
    if left == right:
        raise ValueError("a relationship must link two different AS numbers")
    return (left, right) if left < right else (right, left)  # type: ignore[return-value]


class AsRelationship(BaseModel):
    """One undirected AS relationship: a directed c2p link or a peer link.

    Customer-provider entries name the ``customer`` and the ``provider``;
    peer entries name the two equal peers (in either order).  The ``type``
    discriminator selects which fields must be present.
    """

    type: Literal["customer_provider", "peer"] = Field(
        description=(
            "'customer_provider' names a customer and its provider; 'peer' "
            "names two equal peers (no direction)."
        ),
    )
    customer: ASN | None = Field(
        default=None,
        description="Customer ASN; present (and required) for customer_provider.",
    )
    provider: ASN | None = Field(
        default=None,
        description="Provider ASN; present (and required) for customer_provider.",
    )
    peers: list[ASN] | None = Field(
        default=None,
        min_length=2,
        max_length=2,
        description="Exactly two distinct peer ASNs; required for peer.",
    )

    @model_validator(mode="after")
    def _validate_shape(self) -> "AsRelationship":
        if self.type == "customer_provider":
            if self.peers is not None:
                raise ValueError(
                    "a customer_provider relationship must not carry 'peers'"
                )
            if self.customer is None or self.provider is None:
                raise ValueError(
                    "a customer_provider relationship requires 'customer' "
                    "and 'provider'"
                )
            if self.customer == self.provider:
                raise ValueError(
                    "customer and provider must be different AS numbers"
                )
        else:  # peer
            if self.customer is not None or self.provider is not None:
                raise ValueError(
                    "a peer relationship must not carry 'customer'/'provider'"
                )
            if self.peers is None or len(self.peers) != 2:
                raise ValueError(
                    "a peer relationship requires exactly two 'peers'"
                )
            if self.peers[0] == self.peers[1]:
                raise ValueError("the two peers must be different AS numbers")
        return self

    def canonical_pair(self) -> tuple[int, int]:
        """Canonical undirected ``(lo, hi)`` pair of this relationship."""
        if self.type == "customer_provider":
            return _as_pair(self.customer, self.provider)
        return _as_pair(self.peers[0], self.peers[1])

    def token(self) -> int:
        """Canonical relationship token (see ``app.policy``)."""
        if self.type == "peer":
            return REL_PEER
        return as_relationship_token(self.customer, self.provider)


class AsRelationshipRepairRequest(BaseModel):
    relationships: list[AsRelationship] = Field(
        default_factory=list,
        max_length=AS_RELATIONSHIP_LIMIT,
        description=(
            f"Undirected AS relationships, at most {AS_RELATIONSHIP_LIMIT}. "
            "A customer_provider entry names customer/provider; a peer entry "
            "names two equal peers. The same AS pair must be listed once."
        ),
    )
    paths: list[list[ASN]] = Field(
        default_factory=list,
        max_length=AS_PATH_LIMIT,
        description=(
            f"Origin-to-receiver AS paths, at most {AS_PATH_LIMIT}. Every "
            "path is a non-empty list of distinct 32-bit AS numbers; each "
            "consecutive pair must have a relationship."
        ),
    )

    @field_validator("paths")
    @classmethod
    def _validate_paths(cls, values: list[list[int]]) -> list[list[int]]:
        # Element type/range errors already come from the strict ASN item
        # type; this only rejects empty paths and repeated ASes in one path.
        for path in values:
            if not path:
                raise ValueError(
                    "an AS path must contain at least one AS number"
                )
            if len(set(path)) != len(path):
                raise ValueError(
                    f"AS path {path} repeats an AS number; every path must "
                    f"have no duplicate AS"
                )
        return values

    @model_validator(mode="after")
    def _validate_pairs_and_hops(self) -> "AsRelationshipRepairRequest":
        # Cross-entry rules become one whole-model ValueError -> HTTP 422,
        # exactly like the /allocate and /reverse-delegations batches.
        pairs: set[tuple[int, int]] = set()
        for relationship in self.relationships:
            pair = relationship.canonical_pair()
            if pair in pairs:
                raise ValueError(
                    f"duplicate relationship for AS pair {pair[0]}/{pair[1]}; "
                    f"each AS pair must be listed at most once"
                )
            pairs.add(pair)

        for path_index, path in enumerate(self.paths):
            for left, right in zip(path, path[1:]):
                pair = _as_pair(left, right)
                if pair not in pairs:
                    raise ValueError(
                        f"hop {left}->{right} of path {path_index} has no "
                        f"relationship; every hop pair must be listed"
                    )
        return self


class AsRelationshipCorrection(BaseModel):
    """One changed relationship after repair (same shape as an input entry)."""

    type: Literal["customer_provider", "peer"] = Field(
        description="The repaired relationship type.",
    )
    customer: ASN | None = Field(
        default=None,
        description="Customer ASN; null unless type is customer_provider.",
    )
    provider: ASN | None = Field(
        default=None,
        description="Provider ASN; null unless type is customer_provider.",
    )
    peers: list[ASN] | None = Field(
        default=None,
        description="Two distinct peer ASNs; null unless type is peer.",
    )


class AsRelationshipRepairResponse(BaseModel):
    violating_path_indices: list[int] = Field(
        description=(
            "0-based indices of paths that already violated the valley-free "
            "rule under the original relationships, in ascending order."
        ),
    )
    corrections: list[AsRelationshipCorrection] = Field(
        description=(
            "Relationships changed by the unique minimum repair, sorted by "
            "canonical AS pair (lower ASN first)."
        ),
    )
    changes: int = Field(
        description="Number of relationships changed (len(corrections)).",
    )


# ---------------------------------------------------------------------------
# POST /nat64-codec
# ---------------------------------------------------------------------------


class Nat64CodecRequest(BaseModel):
    prefix: str = Field(
        description=(
            "Strict IPv6 Network-Specific Prefix (RFC 6052) with an explicit "
            "prefix length; only /32, /40, /48, /56, /64 and /96 are "
            "accepted and host bits must be zero."
        ),
    )
    encode: list[str] = Field(
        default_factory=list,
        description="Bare IPv4 addresses to encode as mapped IPv6 addresses, in response order.",
    )
    decode: list[str] = Field(
        default_factory=list,
        description=(
            "Bare IPv6 addresses to decode back to embedded IPv4 addresses, "
            "in response order. Each must be a canonical RFC 6052 mapping: it "
            "must match the prefix, the u octet and the remaining suffix bits "
            "must be zero."
        ),
    )

    @field_validator("prefix")
    @classmethod
    def _validate_prefix(cls, value: str) -> str:
        parse_nat64_prefix(value)
        return value

    @field_validator("encode")
    @classmethod
    def _validate_encode_list(cls, values: list[str]) -> list[str]:
        for value in values:
            address = parse_address(value)
            if not isinstance(address, ipaddress.IPv4Address):
                raise ValueError(
                    f"encode address {value!r} must be IPv4, not IPv6"
                )
        return values

    @field_validator("decode")
    @classmethod
    def _validate_decode_list(cls, values: list[str]) -> list[str]:
        for value in values:
            address = parse_address(value)
            if not isinstance(address, ipaddress.IPv6Address):
                raise ValueError(
                    f"decode address {value!r} must be IPv6, not IPv4"
                )
        return values

    @model_validator(mode="after")
    def _validate_canonical_mappings(self) -> "Nat64CodecRequest":
        # The u-octet/suffix canonicality spans the prefix choice, so it lives
        # in the whole-model validator; any non-canonical mapping rejects the
        # whole batch with an HTTP 422.
        prefix = parse_nat64_prefix(self.prefix)
        for value in self.decode:
            _nat64_decode(prefix, parse_address(value))
        return self


class Nat64CodecResponse(BaseModel):
    encoded: list[str] = Field(
        description=(
            "Mapped IPv6 addresses, one per input encode address, in input order."
        ),
    )
    decoded: list[str] = Field(
        description=(
            "Embedded IPv4 addresses, one per input decode address, in input order."
        ),
    )
