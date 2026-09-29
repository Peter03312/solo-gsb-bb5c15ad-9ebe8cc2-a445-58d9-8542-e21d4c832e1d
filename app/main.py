"""FastAPI application exposing POST /normalize, /evaluate, /compare,
/audit-rules, /minimize-policy, /allocate, /free-addresses, /anonymize,
/reverse-delegations, /roa-coverage, /as-relationship-repair and
/nat64-codec."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException

from app.policy import (
    allocate,
    anonymize,
    as_relationship_repair,
    audit_rules,
    compare,
    evaluate,
    locate_free_addresses,
    minimize_policy,
    nat64_codec,
    normalize,
    reverse_delegations,
    roa_coverage,
)
from app.schemas import (
    AddressDecision,
    AllocateRequest,
    AllocateResponse,
    AnonymizeRequest,
    AnonymizeResponse,
    AsRelationshipRepairRequest,
    AsRelationshipRepairResponse,
    AuditRulesRequest,
    AuditRulesResponse,
    CompareRequest,
    CompareResponse,
    EvaluateRequest,
    FreeAddressesRequest,
    FreeAddressesResponse,
    MinimizePolicyRequest,
    MinimizePolicyResponse,
    Nat64CodecRequest,
    Nat64CodecResponse,
    NormalizeResponse,
    PolicyRequest,
    ReverseDelegationsRequest,
    ReverseDelegationsResponse,
    RoaCoverageRequest,
    RoaCoverageResponse,
)

app = FastAPI(
    title="CIDR Policy Normalizer",
    description=(
        "Compute allow-minus-deny for IPv4/IPv6 CIDR lists, returning the "
        "equivalent, non-overlapping, minimum-count CIDR set; evaluate "
        "individual addresses against the same lists via longest-prefix "
        "match; diff two policy sets (baseline vs candidate) over a "
        "scope CIDR; audit each allow/deny rule for its real impact inside "
        "one scope; minimize an allow/deny list to the smallest subset "
        "equivalent inside one scope; allocate non-overlapping subnets "
        "for a list of requests inside one scope, avoiding already-occupied "
        "CIDRs; locate free addresses inside one scope minus the union of "
        "occupied CIDRs by 0-based ascending ordinal; prefix-preservingly "
        "anonymize bare IPv4/IPv6 addresses "
        "and strict CIDRs with an HMAC-SHA256 key for safe list sharing; "
        "and plan reverse-DNS delegations for the IPv4 networks of one /24 "
        "(direct in-addr.arpa NS for a /24, RFC 2317 range-label subzones "
        "plus per-address CNAMEs for /25-/32); map RPKI ROA "
        "valid/invalid/unknown coverage for every candidate route of one "
        "prefix length inside a scope as a minimal CIDR status partition; "
        "and repair the minimum number of undirected AS customer-provider/"
        "peer relationships so every supplied origin-to-receiver AS path is "
        "valley-free (up*, at most one peer, down*); and embed/extract IPv4 "
        "addresses in/from mapped IPv6 addresses per the RFC 6052 "
        "Network-Specific IPv4/IPv6 translation layout."
    ),
    version="1.11.0",
)


@app.get("/health", tags=["ops"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post(
    "/normalize",
    response_model=NormalizeResponse,
    tags=["policy"],
    summary="Normalize allow/deny CIDR lists into allow minus deny",
)
def normalize_policy(request: PolicyRequest) -> dict:
    return normalize(request.allow, request.deny)


@app.post(
    "/evaluate",
    response_model=list[AddressDecision],
    tags=["policy"],
    summary="Evaluate addresses by longest-prefix match against allow/deny",
    openapi_extra={
        # FastAPI drops Body(examples=...) for model-typed parameters, so the
        # named request examples are attached via openapi_extra; FastAPI merges
        # them into the generated requestBody alongside the schema $ref.
        "requestBody": {
            "content": {
                "application/json": {
                    "examples": {
                        "longest_prefix_and_deny_tie_break": {
                            "summary": "Longest prefix wins; deny wins equal-length ties",
                            "value": {
                                "allow": [
                                    "10.0.0.0/24", "10.0.0.0/25",
                                    "2001:db8::/32",
                                ],
                                "deny": ["10.0.0.0/25"],
                                "addresses": [
                                    "10.0.0.1", "10.0.0.200",
                                    "192.0.2.1", "2001:db8::1",
                                ],
                            },
                        },
                        "invalid_address": {
                            "summary": "CIDR notation in addresses -> HTTP 422",
                            "value": {
                                "allow": ["10.0.0.0/8"],
                                "deny": [],
                                "addresses": ["10.0.0.1/24"],
                            },
                        },
                    },
                },
            },
        },
    },
    responses={
        200: {
            "description": "One decision per input address, in input order.",
            "content": {
                "application/json": {
                    "examples": {
                        "longest_prefix_and_deny_tie_break": {
                            "summary": "Longest prefix wins; deny wins ties",
                            "value": [
                                {"decision": "deny",
                                 "matched_cidr": "10.0.0.0/25",
                                 "matched_side": "deny"},
                                {"decision": "allow",
                                 "matched_cidr": "10.0.0.0/24",
                                 "matched_side": "allow"},
                                {"decision": "unmatched",
                                 "matched_cidr": None,
                                 "matched_side": None},
                                {"decision": "allow",
                                 "matched_cidr": "2001:db8::/32",
                                 "matched_side": "allow"},
                            ],
                        },
                    },
                },
            },
        },
        422: {"description": "An address or CIDR in the request is invalid."},
    },
)
def evaluate_policy(request: EvaluateRequest) -> list[dict]:
    return evaluate(request.allow, request.deny, request.addresses)


@app.post(
    "/compare",
    response_model=CompareResponse,
    tags=["policy"],
    summary="Diff baseline vs candidate decisions within a scope CIDR",
    openapi_extra={
        # See /evaluate: named body examples survive only via openapi_extra
        # for model-typed parameters.
        "requestBody": {
            "content": {
                "application/json": {
                    "examples": {
                        "deny_supernet_holes": {
                            "summary": (
                                "Candidate denies a /26 inside the baseline "
                                "allow; deny wins the equal-length tie below"
                            ),
                            "value": {
                                "scope": "10.0.0.0/24",
                                "baseline": {
                                    "allow": ["10.0.0.0/24"],
                                    "deny": [],
                                },
                                "candidate": {
                                    "allow": ["10.0.0.0/25"],
                                    "deny": ["10.0.0.128/26"],
                                },
                            },
                        },
                        "identical_policies": {
                            "summary": "Identical sets -> no differences",
                            "value": {
                                "scope": "10.0.0.0/24",
                                "baseline": {"allow": ["10.0.0.0/24"]},
                                "candidate": {"allow": ["10.0.0.0/24"]},
                            },
                        },
                    },
                },
            },
        },
    },
    responses={
        200: {
            "description": (
                "Differing regions within scope, sibling-merged per "
                "transition type, plus per-transition address totals."
            ),
            "content": {
                "application/json": {
                    "examples": {
                        "deny_supernet_holes": {
                            "summary": "Two allow->deny regions",
                            "value": {
                                "differences": [
                                    {"cidr": "10.0.0.128/26",
                                     "baseline_decision": "allow",
                                     "candidate_decision": "deny"},
                                    {"cidr": "10.0.0.192/26",
                                     "baseline_decision": "allow",
                                     "candidate_decision": "unmatched"},
                                ],
                                "transition_counts": {
                                    "allow->deny": "64",
                                    "allow->unmatched": "64",
                                    "deny->allow": "0",
                                    "deny->unmatched": "0",
                                    "unmatched->allow": "0",
                                    "unmatched->deny": "0",
                                },
                            },
                        },
                    },
                },
            },
        },
        422: {"description": "The scope or a CIDR entry is invalid."},
    },
)
def compare_policies(request: CompareRequest) -> dict:
    return compare(
        request.scope,
        request.baseline.allow,
        request.baseline.deny,
        request.candidate.allow,
        request.candidate.deny,
    )


@app.post(
    "/audit-rules",
    response_model=AuditRulesResponse,
    tags=["policy"],
    summary="Classify each allow/deny rule by its real impact inside a scope",
    openapi_extra={
        # See /evaluate: named body examples survive only via openapi_extra
        # for model-typed parameters.
        "requestBody": {
            "content": {
                "application/json": {
                    "examples": {
                        "effective_shadowed_and_out_of_scope": {
                            "summary": (
                                "A broad allow wins where no deny reaches; an "
                                "equal-length allow is shadowed by the deny; "
                                "a disjoint rule is out of scope; duplicate "
                                "allows keep the earliest copy"
                            ),
                            "value": {
                                "scope": "10.0.0.0/24",
                                "allow": [
                                    "10.0.0.0/24",
                                    "10.0.0.0/25",
                                    "10.0.0.0/25",
                                ],
                                "deny": [
                                    "10.0.0.0/25",
                                    "10.1.0.0/16",
                                ],
                            },
                        },
                    },
                },
            },
        },
    },
    responses={
        200: {
            "description": (
                "One audit result per input rule, grouped by input side and "
                "kept in input order."
            ),
            "content": {
                "application/json": {
                    "examples": {
                        "effective_shadowed_and_out_of_scope": {
                            "summary": "Witness IPs and shadower index sets",
                            "value": {
                                "allow": [
                                    {"side": "allow", "index": 0,
                                     "cidr": "10.0.0.0/24",
                                     "status": "effective",
                                     "witness": "10.0.0.128"},
                                    {"side": "allow", "index": 1,
                                     "cidr": "10.0.0.0/25",
                                     "status": "shadowed",
                                     "shadowed_by": [
                                         {"side": "deny", "index": 0}]},
                                    {"side": "allow", "index": 2,
                                     "cidr": "10.0.0.0/25",
                                     "status": "shadowed",
                                     "shadowed_by": [
                                         {"side": "deny", "index": 0}]},
                                ],
                                "deny": [
                                    {"side": "deny", "index": 0,
                                     "cidr": "10.0.0.0/25",
                                     "status": "effective",
                                     "witness": "10.0.0.0"},
                                    {"side": "deny", "index": 1,
                                     "cidr": "10.1.0.0/16",
                                     "status": "out_of_scope"},
                                ],
                            },
                        },
                    },
                },
            },
        },
        422: {
            "description": (
                "Invalid scope/rule CIDR, or a rule whose address family does "
                "not match the scope."
            ),
        },
    },
)
def audit_policy_rules(request: AuditRulesRequest) -> dict:
    return audit_rules(request.scope, request.allow, request.deny)


@app.post(
    "/minimize-policy",
    response_model=MinimizePolicyResponse,
    tags=["policy"],
    summary=(
        "Reduce allow/deny rules to the minimum subset equivalent in a scope"
    ),
    openapi_extra={
        # See /evaluate: named body examples survive only via openapi_extra
        # for model-typed parameters.
        "requestBody": {
            "content": {
                "application/json": {
                    "examples": {
                        "minimum_subset_with_witnesses": {
                            "summary": (
                                "Two overlapping allows are redundant; "
                                "lexicographically smallest (side, index) "
                                "set is retained with witnesses"
                            ),
                            "value": {
                                "scope": "10.0.0.0/24",
                                "allow": [
                                    "10.0.0.0/24",
                                    "10.0.0.0/25",
                                ],
                                "deny": ["10.0.0.128/25"],
                            },
                        },
                        "too_many_rules": {
                            "summary": "More than 16 rules total -> HTTP 422",
                            "value": {
                                "scope": "10.0.0.0/24",
                                "allow": [
                                    "10.0.0.0/26", "10.0.0.64/26",
                                    "10.0.0.128/26", "10.0.0.192/26",
                                    "10.0.0.0/27", "10.0.0.32/27",
                                    "10.0.0.64/27", "10.0.0.96/27",
                                    "10.0.0.128/27",
                                ],
                                "deny": [
                                    "10.0.0.160/27", "10.0.0.192/27",
                                    "10.0.0.224/27", "10.0.0.0/28",
                                    "10.0.0.16/28", "10.0.0.32/28",
                                    "10.0.0.48/28", "10.0.0.80/28",
                                ],
                            },
                        },
                    },
                },
            },
        },
    },
    responses={
        200: {
            "description": (
                "The unique minimum-cardinality rule subset, with retained "
                "and removed references in original input order."
            ),
            "content": {
                "application/json": {
                    "examples": {
                        "minimum_subset_with_witnesses": {
                            "summary": "allow index 0 covers the lower half",
                            "value": {
                                "retained": [
                                    {"side": "allow", "index": 0,
                                     "cidr": "10.0.0.0/24",
                                     "witness": "10.0.0.0"},
                                    {"side": "deny", "index": 0,
                                     "cidr": "10.0.0.128/25",
                                     "witness": "10.0.0.128"},
                                ],
                                "removed": [
                                    {"side": "allow", "index": 1,
                                     "cidr": "10.0.0.0/25"},
                                ],
                            },
                        },
                    },
                },
            },
        },
        422: {
            "description": (
                "Invalid scope/rule CIDR, a rule whose address family does "
                "not match the scope, or more than 16 allow/deny rules in "
                "total."
            ),
        },
    },
)
def minimize_policy_rules(request: MinimizePolicyRequest) -> dict:
    return minimize_policy(request.scope, request.allow, request.deny)


@app.post(
    "/allocate",
    response_model=AllocateResponse,
    tags=["policy"],
    summary="Allocate non-overlapping subnets for requests inside a scope",
    openapi_extra={
        # See /evaluate: named body examples survive only via openapi_extra
        # for model-typed parameters.
        "requestBody": {
            "content": {
                "application/json": {
                    "examples": {
                        "lexicographic_with_backtracking": {
                            "summary": (
                                "Greedy first-fit for 'small' would block "
                                "'big'; backtracking finds the lexicographically"
                                " smallest complete plan"
                            ),
                            "value": {
                                "scope": "10.0.0.0/23",
                                "occupied": ["10.0.1.0/25"],
                                "requests": [
                                    {"id": "small", "prefix_length": 25},
                                    {"id": "big", "prefix_length": 24},
                                ],
                            },
                        },
                        "infeasible": {
                            "summary": "Two /25s do not fit beside the occupied /25 -> HTTP 409",
                            "value": {
                                "scope": "10.0.0.0/24",
                                "occupied": ["10.0.0.0/25"],
                                "requests": [
                                    {"id": "x", "prefix_length": 25},
                                    {"id": "y", "prefix_length": 25},
                                ],
                            },
                        },
                    },
                },
            },
        },
    },
    responses={
        200: {
            "description": (
                "Allocations in request order plus the remaining free space "
                "as a minimal CIDR set with its decimal address count."
            ),
            "content": {
                "application/json": {
                    "examples": {
                        "lexicographic_with_backtracking": {
                            "summary": "Lexicographically smallest complete plan",
                            "value": {
                                "allocations": [
                                    {"id": "small", "cidr": "10.0.1.128/25"},
                                    {"id": "big", "cidr": "10.0.0.0/24"},
                                ],
                                "remaining": [],
                                "remaining_addresses": "0",
                            },
                        },
                    },
                },
            },
        },
        409: {
            "description": (
                "No complete assignment exists; no partial allocation is "
                "returned."
            ),
        },
        422: {
            "description": (
                "Invalid scope/occupied CIDR, occupied entry outside the "
                "scope or of the wrong family, overlapping occupied CIDRs, "
                "duplicate request id, or invalid prefix length."
            ),
        },
    },
)
def allocate_subnets(request: AllocateRequest) -> dict:
    result = allocate(
        request.scope,
        request.occupied,
        [(item.id, item.prefix_length) for item in request.requests],
    )
    if result is None:
        raise HTTPException(
            status_code=409,
            detail=(
                f"no complete allocation satisfies all requests within "
                f"scope {request.scope!r}; no partial allocation returned"
            ),
        )
    return result


@app.post(
    "/free-addresses",
    response_model=FreeAddressesResponse,
    tags=["policy"],
    summary="Locate free addresses in a scope by 0-based ascending ordinal",
    openapi_extra={
        # See /evaluate: named body examples survive only via openapi_extra
        # for model-typed parameters.
        "requestBody": {
            "content": {
                "application/json": {
                    "examples": {
                        "overlapping_and_out_of_scope_occupied": {
                            "summary": (
                                "Overlapping occupied CIDRs union first; the "
                                "outside-scope /26 is clipped away"
                            ),
                            "value": {
                                "scope": "192.0.2.0/29",
                                "occupied": [
                                    "192.0.2.2/31",
                                    "192.0.2.3/32",
                                    "203.0.113.64/26",
                                ],
                                "indices": [0, 1, 2, 0],
                            },
                        },
                        "ipv6_huge_ordinal_as_string": {
                            "summary": (
                                "IPv6 ::/0 with one ::/1 occupied; ordinals "
                                "past JSON's safe-integer range use strings"
                            ),
                            "value": {
                                "scope": "::/0",
                                "occupied": ["::/1"],
                                "indices": [
                                    0,
                                    1,
                                    "170141183460469231731687303715884105726",
                                ],
                            },
                        },
                        "index_at_free_total_rejected": {
                            "summary": "Ordinal equal to the free total -> HTTP 422",
                            "value": {
                                "scope": "10.0.0.0/30",
                                "occupied": ["10.0.0.0/32"],
                                "indices": [3],
                            },
                        },
                    },
                },
            },
        },
    },
    responses={
        200: {
            "description": (
                "The free-address total plus one address per requested "
                "ordinal, in input order."
            ),
            "content": {
                "application/json": {
                    "examples": {
                        "overlapping_and_out_of_scope_occupied": {
                            "summary": "Free addresses are .0 .1 .4..7; repeats allowed",
                            "value": {
                                "free_total": "6",
                                "addresses": [
                                    "192.0.2.0",
                                    "192.0.2.1",
                                    "192.0.2.4",
                                    "192.0.2.0",
                                ],
                            },
                        },
                        "ipv6_huge_ordinal_as_string": {
                            "summary": "Upper half of the IPv6 space, string ordinals",
                            "value": {
                                "free_total": "170141183460469231731687303715884105728",
                                "addresses": [
                                    "8000::",
                                    "8000::1",
                                    "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe",
                                ],
                            },
                        },                    },
                },
            },
        },
        422: {
            "description": (
                "Invalid scope/occupied CIDR, an occupied entry whose address "
                "family differs from the scope, or an ordinal that is "
                "negative/malformed or at or past the free total; the whole "
                "batch is rejected."
            ),
        },
    },
)
def locate_free(request: FreeAddressesRequest) -> dict:
    try:
        return locate_free_addresses(
            request.scope, request.occupied, request.indices
        )
    except ValueError as exc:
        # Cross-field failures (wrong family, ordinal >= free total) are only
        # decidable after parsing the scope; surface them as 422 like the
        # per-field schema validators, rejecting the whole batch.
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post(
    "/anonymize",
    response_model=AnonymizeResponse,
    tags=["policy"],
    summary="Prefix-preserving keyed anonymization of addresses and CIDRs",
    openapi_extra={
        # See /evaluate: named body examples survive only via openapi_extra
        # for model-typed parameters.
        "requestBody": {
            "content": {
                "application/json": {
                    "examples": {
                        "prefix_preserving_v4_and_v6": {
                            "summary": (
                                "Stable one-to-one mapping; the /24 keeps its "
                                "anonymized network address prefix and length"
                            ),
                            "value": {
                                "key_hex": (
                                    "0123456789abcdef"
                                    "0123456789abcdef"
                                    "0123456789abcdef"
                                    "0123456789abcdef"
                                ),
                                "addresses": [
                                    "10.0.0.1", "10.0.0.2",
                                    "192.0.2.1", "2001:db8::1",
                                ],
                                "cidrs": ["10.0.0.0/24", "2001:db8::/32"],
                            },
                        },
                        "host_bits_set": {
                            "summary": "Non-zero host bits in a CIDR -> HTTP 422",
                            "value": {
                                "key_hex": "0" * 64,
                                "addresses": [],
                                "cidrs": ["10.0.0.1/24"],
                            },
                        },
                    },
                },
            },
        },
    },
    responses={
        200: {
            "description": (
                "One anonymized entry per input address and per input CIDR, "
                "each list in input order."
            ),
            "content": {
                "application/json": {
                    "examples": {
                        "prefix_preserving_v4_and_v6": {
                            "summary": (
                                "Stable one-to-one outputs; the two /24-mates "
                                "keep their /30 longest common prefix and stay "
                                "inside the anonymized 77.249.170.0/24"
                            ),
                            "value": {
                                "addresses": [
                                    "77.249.170.48",
                                    "77.249.170.51",
                                    "236.60.54.68",
                                    "d5af:46c8:beb3:e56d:c681:ca26:c4a4:9e2a",
                                ],
                                "cidrs": [
                                    "77.249.170.0/24",
                                    "d5af:46c8::/32",
                                ],
                            },
                        },
                    },
                },
            },
        },
        422: {
            "description": (
                "key_hex is not 64 hexadecimal characters, an address is "
                "invalid, or a CIDR is invalid, lacks a prefix length, or "
                "has non-zero host bits."
            ),
        },
    },
)
def anonymize_addresses(request: AnonymizeRequest) -> dict:
    return anonymize(request.key_hex, request.addresses, request.cidrs)


@app.post(
    "/reverse-delegations",
    response_model=ReverseDelegationsResponse,
    tags=["policy"],
    summary="Plan reverse-DNS delegations for IPv4 /24-/32 networks in one /24",
    openapi_extra={
        # See /evaluate: named body examples survive only via openapi_extra
        # for model-typed parameters.
        "requestBody": {
            "content": {
                "application/json": {
                    "examples": {
                        "direct_slash24": {
                            "summary": (
                                "A /24 delegates its in-addr.arpa zone "
                                "directly with NS records"
                            ),
                            "value": {
                                "delegations": [
                                    {"cidr": "192.0.2.0/24",
                                     "nameservers": ["ns1.example.net",
                                                     "ns2.example.net"]},
                                ],
                            },
                        },
                        "rfc2317_subzones": {
                            "summary": (
                                "Disjoint /25-/32 networks in one /24 use RFC "
                                "2317 range labels, each with NS records and "
                                "per-address parent-zone CNAMEs"
                            ),
                            "value": {
                                "delegations": [
                                    {"cidr": "10.0.0.128/30",
                                     "nameservers": ["ns1.cust.example",
                                                     "ns2.cust.example"]},
                                    {"cidr": "10.0.0.5/32",
                                     "nameservers": ["host-5.example.org"]},
                                ],
                            },
                        },
                        "overlapping_cidrs_rejected": {
                            "summary": "Intersecting CIDRs -> HTTP 422, whole batch rejected",
                            "value": {
                                "delegations": [
                                    {"cidr": "10.0.0.0/25",
                                     "nameservers": ["ns1.example.net"]},
                                    {"cidr": "10.0.0.64/26",
                                     "nameservers": ["ns2.example.net"]},
                                ],
                            },
                        },
                        "different_parent_24_rejected": {
                            "summary": "CIDRs from two /24s -> HTTP 422",
                            "value": {
                                "delegations": [
                                    {"cidr": "10.0.0.0/25",
                                     "nameservers": ["ns1.example.net"]},
                                    {"cidr": "10.0.1.0/25",
                                     "nameservers": ["ns2.example.net"]},
                                ],
                            },
                        },
                    },
                },
            },
        },
    },
    responses={
        200: {
            "description": (
                "One delegated zone per input CIDR plus the NS/CNAME records, "
                "sorted by network address; each record carries its source "
                "input CIDR."
            ),
            "content": {
                "application/json": {
                    "examples": {
                        "direct_slash24": {
                            "summary": "Direct in-addr.arpa NS delegation for a /24",
                            "value": {
                                "zones": [{
                                    "zone": "2.0.192.in-addr.arpa.",
                                    "method": "direct",
                                    "parent_zone": None,
                                    "cidr": "192.0.2.0/24",
                                    "nameservers": [
                                        "ns1.example.net.",
                                        "ns2.example.net.",
                                    ],
                                }],
                                "records": [
                                    {
                                        "zone": "2.0.192.in-addr.arpa.",
                                        "type": "NS",
                                        "name": "2.0.192.in-addr.arpa.",
                                        "target": "ns1.example.net.",
                                        "cidr": "192.0.2.0/24",
                                    },
                                    {
                                        "zone": "2.0.192.in-addr.arpa.",
                                        "type": "NS",
                                        "name": "2.0.192.in-addr.arpa.",
                                        "target": "ns2.example.net.",
                                        "cidr": "192.0.2.0/24",
                                    },
                                ],
                            },
                        },
                        "rfc2317_subzones": {
                            "summary": "Two RFC 2317 subzones (/32 and /30) in one /24",
                            "value": {
                                "zones": [
                                    {
                                        "zone": "5/32.0.0.10.in-addr.arpa.",
                                        "method": "rfc2317",
                                        "parent_zone": "0.0.10.in-addr.arpa.",
                                        "cidr": "10.0.0.5/32",
                                        "nameservers": ["host-5.example.org."],
                                    },
                                    {
                                        "zone": "128/30.0.0.10.in-addr.arpa.",
                                        "method": "rfc2317",
                                        "parent_zone": "0.0.10.in-addr.arpa.",
                                        "cidr": "10.0.0.128/30",
                                        "nameservers": [
                                            "ns1.cust.example.",
                                            "ns2.cust.example.",
                                        ],
                                    },
                                ],
                                "records": [
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
                                    {
                                        "zone": "0.0.10.in-addr.arpa.",
                                        "type": "NS",
                                        "name": "128/30.0.0.10.in-addr.arpa.",
                                        "target": "ns1.cust.example.",
                                        "cidr": "10.0.0.128/30",
                                    },
                                    {
                                        "zone": "0.0.10.in-addr.arpa.",
                                        "type": "NS",
                                        "name": "128/30.0.0.10.in-addr.arpa.",
                                        "target": "ns2.cust.example.",
                                        "cidr": "10.0.0.128/30",
                                    },
                                    {
                                        "zone": "0.0.10.in-addr.arpa.",
                                        "type": "CNAME",
                                        "name": "128.0.0.10.in-addr.arpa.",
                                        "target": (
                                            "128.128/30.0.0.10.in-addr.arpa."
                                        ),
                                        "cidr": "10.0.0.128/30",
                                    },
                                    {
                                        "zone": "0.0.10.in-addr.arpa.",
                                        "type": "CNAME",
                                        "name": "129.0.0.10.in-addr.arpa.",
                                        "target": (
                                            "129.128/30.0.0.10.in-addr.arpa."
                                        ),
                                        "cidr": "10.0.0.128/30",
                                    },
                                    {
                                        "zone": "0.0.10.in-addr.arpa.",
                                        "type": "CNAME",
                                        "name": "130.0.0.10.in-addr.arpa.",
                                        "target": (
                                            "130.128/30.0.0.10.in-addr.arpa."
                                        ),
                                        "cidr": "10.0.0.128/30",
                                    },
                                    {
                                        "zone": "0.0.10.in-addr.arpa.",
                                        "type": "CNAME",
                                        "name": "131.0.0.10.in-addr.arpa.",
                                        "target": (
                                            "131.128/30.0.0.10.in-addr.arpa."
                                        ),
                                        "cidr": "10.0.0.128/30",
                                    },
                                ],
                            },
                        },
                    },
                },
            },
        },
        422: {
            "description": (
                "A CIDR is not a strict IPv4 /24-/32 network, a nameserver is "
                "not a valid domain name, two CIDRs intersect, or the CIDRs "
                "do not share one parent /24."
            ),
        },
    },
)
def plan_reverse_delegations(request: ReverseDelegationsRequest) -> dict:
    return reverse_delegations(
        [(item.cidr, item.nameservers) for item in request.delegations]
    )


@app.post(
    "/roa-coverage",
    response_model=RoaCoverageResponse,
    tags=["policy"],
    summary="Map ROA valid/invalid/unknown coverage for candidate routes in a scope",
    openapi_extra={
        # See /evaluate: named body examples survive only via openapi_extra
        # for model-typed parameters.
        "requestBody": {
            "content": {
                "application/json": {
                    "examples": {
                        "valid_invalid_and_unknown": {
                            "summary": (
                                "Four /26 candidates: the whole lower /25 is "
                                "authorized by one /25 ROA (one valid piece "
                                "shorter than /26), the third candidate is a "
                                "wrong-ASN invalid, the last is not covered"
                            ),
                            "value": {
                                "scope": "203.0.113.0/24",
                                "asn": 64500,
                                "prefix_length": 26,
                                "roas": [
                                    {"cidr": "203.0.113.0/25",
                                     "asn": 64500, "max_length": 26},
                                    {"cidr": "203.0.113.128/26",
                                     "asn": 64501, "max_length": 26},
                                ],
                            },
                        },
                        "length_invalid_merges_to_scope": {
                            "summary": (
                                "The ROA max_length /24 is too short for the "
                                "proposed /25: both candidates are invalid "
                                "and merge into the single scope piece"
                            ),
                            "value": {
                                "scope": "203.0.113.0/24",
                                "asn": 64500,
                                "prefix_length": 25,
                                "roas": [
                                    {"cidr": "203.0.113.0/24",
                                     "asn": 64500, "max_length": 24},
                                ],
                            },
                        },
                        "cross_family_roa_rejected": {
                            "summary": "An IPv6 ROA against an IPv4 scope -> HTTP 422",
                            "value": {
                                "scope": "203.0.113.0/24",
                                "asn": 64500,
                                "prefix_length": 26,
                                "roas": [
                                    {"cidr": "2001:db8::/32",
                                     "asn": 64500, "max_length": 48},
                                ],
                            },
                        },
                    },
                },
            },
        },
    },
    responses={
        200: {
            "description": (
                "Minimum non-overlapping CIDR tiling of the candidate "
                "region, each piece labelled with the status shared by "
                "every aligned candidate route inside it."
            ),
            "content": {
                "application/json": {
                    "examples": {
                        "valid_invalid_and_unknown": {
                            "summary": (
                                "The two lower /26 candidates are both "
                                "authorized by the single /25 ROA, so they "
                                "collapse to one valid /25 piece (shorter "
                                "than the requested /26)"
                            ),
                            "value": {
                                "partitions": [
                                    {"cidr": "203.0.113.0/25",
                                     "status": "valid"},
                                    {"cidr": "203.0.113.128/26",
                                     "status": "invalid"},
                                    {"cidr": "203.0.113.192/26",
                                     "status": "unknown"},
                                ],
                            },
                        },
                    },
                },
            },
        },
        422: {
            "description": (
                "Invalid scope/ROA CIDR, a prefix_length outside the scope "
                "family bounds or shorter than the scope prefix, a ROA "
                "whose address family differs from the scope, a max_length "
                "outside [ROA prefix length, family width], or an ASN "
                "outside the 32-bit range."
            ),
        },
    },
)
def roa_coverage_report(request: RoaCoverageRequest) -> dict:
    return roa_coverage(
        request.scope,
        request.asn,
        request.prefix_length,
        [(item.cidr, item.asn, item.max_length) for item in request.roas],
    )


@app.post(
    "/as-relationship-repair",
    response_model=AsRelationshipRepairResponse,
    tags=["policy"],
    summary="Repair the fewest AS relationships so all paths are valley-free",
    openapi_extra={
        # See /evaluate: named body examples survive only via openapi_extra
        # for model-typed parameters.
        "requestBody": {
            "content": {
                "application/json": {
                    "examples": {
                        "one_shared_repair": {
                            "summary": (
                                "Both paths form the same provider->customer "
                                "then customer->provider valley; flipping the "
                                "shared relationship repairs both at once"
                            ),
                            "value": {
                                "relationships": [
                                    {"type": "customer_provider",
                                     "customer": 200, "provider": 100},
                                    {"type": "customer_provider",
                                     "customer": 200, "provider": 300},
                                    {"type": "customer_provider",
                                     "customer": 200, "provider": 400},
                                ],
                                "paths": [
                                    [100, 200, 300],
                                    [400, 200, 300],
                                ],
                            },
                        },
                        "no_feasible_repair": {
                            "summary": (
                                "Four paths jointly demand contradictory "
                                "orientations for every relabeling -> "
                                "HTTP 409"
                            ),
                            "value": {
                                "relationships": [
                                    {"type": "customer_provider",
                                     "customer": 1, "provider": 2},
                                    {"type": "customer_provider",
                                     "customer": 3, "provider": 1},
                                    {"type": "peer",
                                     "peers": [1, 4]},
                                    {"type": "customer_provider",
                                     "customer": 2, "provider": 3},
                                    {"type": "customer_provider",
                                     "customer": 4, "provider": 3},
                                ],
                                "paths": [
                                    [4, 3, 2, 1],
                                    [2, 1, 3, 4],
                                    [4, 1, 3, 2],
                                    [3, 4, 1, 2],
                                ],
                            },
                        },
                        "missing_relationship": {
                            "summary": "A hop without a relationship -> HTTP 422",
                            "value": {
                                "relationships": [
                                    {"type": "customer_provider",
                                     "customer": 200, "provider": 100},
                                ],
                                "paths": [[100, 200, 300]],
                            },
                        },
                    },
                },
            },
        },
    },
    responses={
        200: {
            "description": (
                "Indices of paths violating the original relationships, the "
                "unique minimum-cardinality repair, and its change count."
            ),
            "content": {
                "application/json": {
                    "examples": {
                        "one_shared_repair": {
                            "summary": "One flipped relationship repairs both paths",
                            "value": {
                                "violating_path_indices": [0, 1],
                                "corrections": [
                                    {"type": "customer_provider",
                                     "customer": 300, "provider": 200},
                                ],
                                "changes": 1,
                            },
                        },
                    },
                },
            },
        },
        409: {
            "description": (
                "No assignment of the relationships makes every supplied "
                "path valley-free; no repair is returned."
            ),
        },
        422: {
            "description": (
                "More than 9 relationships or 20 paths, a malformed "
                "relationship entry, a duplicate AS pair, an empty path, a "
                "repeated AS inside one path, a hop pair without a "
                "relationship, or an ASN outside the 32-bit range."
            ),
        },
    },
)
def repair_as_relationships(request: AsRelationshipRepairRequest) -> dict:
    result = as_relationship_repair(
        [
            (entry.canonical_pair(), entry.token())
            for entry in request.relationships
        ],
        [list(path) for path in request.paths],
    )
    if result is None:
        raise HTTPException(
            status_code=409,
            detail=(
                "no assignment of the supplied relationships makes every AS "
                "path valley-free (up*, at most one peer, down*)"
            ),
        )
    return result


@app.post(
    "/nat64-codec",
    response_model=Nat64CodecResponse,
    tags=["policy"],
    summary="RFC 6052 IPv4-in-IPv6 encode/decode under one translation prefix",
    openapi_extra={
        # See /evaluate: named body examples survive only via openapi_extra
        # for model-typed parameters.
        "requestBody": {
            "content": {
                "application/json": {
                    "examples": {
                        "rfc6052_slash32_roundtrip": {
                            "summary": (
                                "/32 prefix: the IPv4 bits straddle the bit-64 "
                                "boundary around the zero u octet"
                            ),
                            "value": {
                                "prefix": "2001:db8::/32",
                                "encode": ["192.0.2.33", "198.51.100.7"],
                                "decode": [
                                    "2001:db8:c000:221::",
                                    "2001:db8:c633:6407::",
                                ],
                            },
                        },
                        "slash96_direct_append": {
                            "summary": "/96 prefix: IPv4 follows the prefix directly",
                            "value": {
                                "prefix": "2001:db8:1:2::/96",
                                "encode": ["192.0.2.33"],
                                "decode": ["2001:db8:1:2::c000:221"],
                            },
                        },
                        "non_canonical_suffix_rejected": {
                            "summary": "Non-zero suffix bits in a /32 decode address -> HTTP 422",
                            "value": {
                                "prefix": "2001:db8::/32",
                                "encode": [],
                                "decode": ["2001:db8:c000:221::1"],
                            },
                        },
                    },
                },
            },
        },
    },
    responses={
        200: {
            "description": (
                "One mapped IPv6 address per encode input and one embedded "
                "IPv4 address per decode input, each list in input order."
            ),
            "content": {
                "application/json": {
                    "examples": {
                        "rfc6052_slash32_roundtrip": {
                            "summary": "Encode and decode lists keep input order",
                            "value": {
                                "encoded": [
                                    "2001:db8:c000:221::",
                                    "2001:db8:c633:6407::",
                                ],
                                "decoded": ["192.0.2.33", "198.51.100.7"],
                            },
                        },
                    },
                },
            },
        },
        422: {
            "description": (
                "The prefix is not a strict IPv6 CIDR of /32, /40, /48, /56, "
                "/64 or /96, an encode entry is not a bare IPv4 address, a "
                "decode entry is not a bare IPv6 address, or a decode "
                "address is not a canonical RFC 6052 mapping (prefix mismatch, "
                "non-zero u octet or non-zero suffix)."
            ),
        },
    },
)
def nat64_translate(request: Nat64CodecRequest) -> dict:
    return nat64_codec(request.prefix, request.encode, request.decode)
