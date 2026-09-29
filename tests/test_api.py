"""API-level tests for POST /normalize using FastAPI's TestClient."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_normalize_basic():
    response = client.post(
        "/normalize",
        json={
            "allow": ["10.0.0.0/24", "10.0.0.0/24", "2001:db8::/32"],
            "deny": ["10.0.0.128/25"],
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["ipv4"] == ["10.0.0.0/25"]
    assert data["ipv6"] == ["2001:db8::/32"]
    assert data["stats"]["allow"] == {
        "input": 3, "unique": 2, "duplicates_removed": 1,
        "ipv4": 1, "ipv6": 1,
    }
    assert data["stats"]["deny"] == {
        "input": 1, "unique": 1, "duplicates_removed": 0,
        "ipv4": 1, "ipv6": 0,
    }
    assert data["stats"]["output"] == {"ipv4": 1, "ipv6": 1, "total": 2}


def test_empty_body_defaults_to_empty_lists():
    response = client.post("/normalize", json={})
    assert response.status_code == 200
    assert response.json() == {
        "ipv4": [],
        "ipv6": [],
        "stats": {
            "allow": {"input": 0, "unique": 0, "duplicates_removed": 0,
                      "ipv4": 0, "ipv6": 0},
            "deny": {"input": 0, "unique": 0, "duplicates_removed": 0,
                     "ipv4": 0, "ipv6": 0},
            "output": {"ipv4": 0, "ipv6": 0, "total": 0},
        },
    }


def test_invalid_cidr_returns_422():
    response = client.post(
        "/normalize",
        json={"allow": ["10.0.0.0/24", "bogus"], "deny": []},
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(err["loc"][-1] == "allow" for err in detail)


def test_host_bits_return_422():
    response = client.post(
        "/normalize",
        json={"allow": [], "deny": ["10.0.0.1/24"]},
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "deny" for err in response.json()["detail"])


def test_wrong_type_returns_422():
    response = client.post(
        "/normalize",
        json={"allow": [10], "deny": []},
    )
    assert response.status_code == 422


def test_doc_and_openapi_available():
    assert client.get("/docs").status_code == 200
    spec = client.get("/openapi.json").json()
    assert "/normalize" in spec["paths"]
    assert "/evaluate" in spec["paths"]


# --------------------------------------------------------------------------
# POST /evaluate
# --------------------------------------------------------------------------


def test_evaluate_longest_prefix_deny_tie_and_unmatched():
    response = client.post(
        "/evaluate",
        json={
            "allow": ["10.0.0.0/24", "10.0.0.0/25", "2001:db8::/32"],
            "deny": ["10.0.0.0/25"],
            "addresses": [
                "10.0.0.1",       # equal-length deny beats allow
                "10.0.0.200",     # only the broader allow covers this
                "192.0.2.1",      # no match at all
                "2001:db8::1",    # IPv6 allow
            ],
        },
    )
    assert response.status_code == 200
    assert response.json() == [
        {"decision": "deny", "matched_cidr": "10.0.0.0/25",
         "matched_side": "deny"},
        {"decision": "allow", "matched_cidr": "10.0.0.0/24",
         "matched_side": "allow"},
        {"decision": "unmatched", "matched_cidr": None, "matched_side": None},
        {"decision": "allow", "matched_cidr": "2001:db8::/32",
         "matched_side": "allow"},
    ]


def test_evaluate_longer_prefix_beats_broader_deny():
    response = client.post(
        "/evaluate",
        json={
            "allow": ["10.0.0.0/24"],
            "deny": ["10.0.0.0/16"],
            "addresses": ["10.0.0.1"],
        },
    )
    assert response.status_code == 200
    assert response.json() == [
        {"decision": "allow", "matched_cidr": "10.0.0.0/24",
         "matched_side": "allow"},
    ]


def test_evaluate_preserves_address_order():
    response = client.post(
        "/evaluate",
        json={
            "allow": ["10.0.0.0/24"],
            "deny": ["10.1.0.0/16"],
            "addresses": ["10.1.0.5", "10.0.0.5", "172.16.0.1", "10.0.0.6"],
        },
    )
    assert response.status_code == 200
    assert [item["decision"] for item in response.json()] == [
        "deny", "allow", "unmatched", "allow",
    ]


def test_evaluate_empty_body_defaults_to_empty_lists():
    response = client.post("/evaluate", json={})
    assert response.status_code == 200
    assert response.json() == []


def test_evaluate_invalid_address_returns_422():
    response = client.post(
        "/evaluate",
        json={"allow": [], "deny": [], "addresses": ["10.0.0.1", "bogus"]},
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(err["loc"][-1] == "addresses" for err in detail)


def test_evaluate_address_with_cidr_notation_returns_422():
    response = client.post(
        "/evaluate",
        json={"allow": [], "deny": [], "addresses": ["10.0.0.1/24"]},
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "addresses" for err in response.json()["detail"])


def test_evaluate_invalid_cidr_returns_422():
    response = client.post(
        "/evaluate",
        json={"allow": ["10.0.0.1/24"], "deny": [], "addresses": ["10.0.0.1"]},
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(err["loc"][-1] == "allow" for err in detail)

    response = client.post(
        "/evaluate",
        json={"allow": [], "deny": ["not-a-cidr"], "addresses": []},
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "deny" for err in response.json()["detail"])


def test_evaluate_wrong_type_returns_422():
    response = client.post(
        "/evaluate",
        json={"allow": [], "deny": [], "addresses": [10]},
    )
    assert response.status_code == 422


def test_evaluate_openapi_documents_decision_enum():
    spec = client.get("/openapi.json").json()
    operation = spec["paths"]["/evaluate"]["post"]
    # The response model is a bare array of AddressDecision.
    response_schema = spec["components"]["schemas"]["AddressDecision"]
    decision_enum = response_schema["properties"]["decision"]["enum"]
    assert decision_enum == ["allow", "deny", "unmatched"]
    side_variants = response_schema["properties"]["matched_side"]["anyOf"]
    side_enum = next(v["enum"] for v in side_variants if "enum" in v)
    assert side_enum == ["allow", "deny"]
    # Named request/response examples are exposed in the OpenAPI document.
    request_json = operation["requestBody"]["content"]["application/json"]
    assert "longest_prefix_and_deny_tie_break" in request_json["examples"]
    response_json = operation["responses"]["200"]["content"]["application/json"]
    assert "longest_prefix_and_deny_tie_break" in response_json["examples"]


# --------------------------------------------------------------------------
# POST /compare
# --------------------------------------------------------------------------


def test_compare_basic():
    response = client.post(
        "/compare",
        json={
            "scope": "10.0.0.0/24",
            "baseline": {"allow": ["10.0.0.0/24"], "deny": []},
            "candidate": {
                "allow": ["10.0.0.0/25"],
                "deny": ["10.0.0.128/26"],
            },
        },
    )
    assert response.status_code == 200
    assert response.json() == {
        "differences": [
            {"cidr": "10.0.0.128/26", "baseline_decision": "allow",
             "candidate_decision": "deny"},
            {"cidr": "10.0.0.192/26", "baseline_decision": "allow",
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
    }


def test_compare_sibling_halves_merge():
    response = client.post(
        "/compare",
        json={
            "scope": "10.0.0.0/24",
            "baseline": {"allow": ["10.0.0.0/24"]},
            "candidate": {"deny": ["10.0.0.128/26", "10.0.0.192/26"]},
        },
    )
    assert response.status_code == 200
    data = response.json()
    # The two equal-transition /26 halves merge into the upper /25.
    assert data["differences"] == [
        {"cidr": "10.0.0.0/25", "baseline_decision": "allow",
         "candidate_decision": "unmatched"},
        {"cidr": "10.0.0.128/25", "baseline_decision": "allow",
         "candidate_decision": "deny"},
    ]
    assert data["transition_counts"]["allow->deny"] == "128"


def test_compare_identical_policies_return_empty():
    response = client.post(
        "/compare",
        json={
            "scope": "10.0.0.0/24",
            "baseline": {"allow": ["10.0.0.0/24"], "deny": ["10.0.0.0/25"]},
            "candidate": {"allow": ["10.0.0.0/24"], "deny": ["10.0.0.0/25"]},
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["differences"] == []
    assert set(data["transition_counts"]) == {
        "allow->deny", "allow->unmatched", "deny->allow",
        "deny->unmatched", "unmatched->allow", "unmatched->deny",
    }
    assert all(value == "0" for value in data["transition_counts"].values())


def test_compare_defaults_missing_policies_to_empty():
    response = client.post("/compare", json={"scope": "10.0.0.0/24"})
    assert response.status_code == 200
    assert response.json()["differences"] == []


def test_compare_ipv6_decimal_string_counts():
    response = client.post(
        "/compare",
        json={
            "scope": "2001:db8::/32",
            "candidate": {"allow": ["2001:db8::/32"]},
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["differences"] == [
        {"cidr": "2001:db8::/32", "baseline_decision": "unmatched",
         "candidate_decision": "allow"},
    ]
    assert data["transition_counts"]["unmatched->allow"] == str(2 ** 96)


def test_compare_invalid_scope_cidr_returns_422():
    response = client.post(
        "/compare",
        json={"scope": "bogus", "baseline": {}, "candidate": {}},
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "scope" for err in response.json()["detail"])


def test_compare_scope_host_bits_return_422():
    response = client.post(
        "/compare",
        json={"scope": "10.0.0.1/24", "baseline": {}, "candidate": {}},
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "scope" for err in response.json()["detail"])


def test_compare_missing_scope_returns_422():
    response = client.post("/compare", json={"baseline": {}, "candidate": {}})
    assert response.status_code == 422
    assert any("scope" in err["loc"] for err in response.json()["detail"])


def test_compare_wrong_scope_type_returns_422():
    response = client.post("/compare", json={"scope": 10})
    assert response.status_code == 422


def test_compare_invalid_nested_cidr_returns_422():
    response = client.post(
        "/compare",
        json={
            "scope": "10.0.0.0/24",
            "baseline": {"allow": ["10.0.0.1/24"]},
            "candidate": {},
        },
    )
    assert response.status_code == 422
    locs = [tuple(err["loc"]) for err in response.json()["detail"]]
    assert any(loc[-1] == "allow" and "baseline" in loc for loc in locs)

    response = client.post(
        "/compare",
        json={
            "scope": "10.0.0.0/24",
            "candidate": {"deny": ["not-a-cidr"]},
        },
    )
    assert response.status_code == 422
    locs = [tuple(err["loc"]) for err in response.json()["detail"]]
    assert any(loc[-1] == "deny" and "candidate" in loc for loc in locs)


def test_compare_is_documented_in_openapi():
    spec = client.get("/openapi.json").json()
    assert "/compare" in spec["paths"]
    assert spec["components"]["schemas"]["CompareDifference"]["properties"][
        "baseline_decision"
    ]["enum"] == ["allow", "deny", "unmatched"]
    operation = spec["paths"]["/compare"]["post"]
    examples = operation["requestBody"]["content"]["application/json"][
        "examples"
    ]
    assert "deny_supernet_holes" in examples


# --------------------------------------------------------------------------
# POST /audit-rules
# --------------------------------------------------------------------------


def test_audit_rules_basic_effective_shadowed_and_out_of_scope():
    response = client.post(
        "/audit-rules",
        json={
            "scope": "10.0.0.0/24",
            "allow": [
                "10.0.0.0/24",     # wins the upper half
                "10.0.0.0/25",     # deny beats it at equal length
                "10.0.0.0/25",     # duplicate, also loses
            ],
            "deny": [
                "10.0.0.0/25",     # wins the lower half
                "10.1.0.0/16",     # disjoint from scope
            ],
        },
    )
    assert response.status_code == 200
    assert response.json() == {
        "allow": [
            {"side": "allow", "index": 0, "cidr": "10.0.0.0/24",
             "status": "effective", "witness": "10.0.0.128",
             "shadowed_by": None},
            {"side": "allow", "index": 1, "cidr": "10.0.0.0/25",
             "status": "shadowed", "witness": None,
             "shadowed_by": [{"side": "deny", "index": 0}]},
            {"side": "allow", "index": 2, "cidr": "10.0.0.0/25",
             "status": "shadowed", "witness": None,
             "shadowed_by": [{"side": "deny", "index": 0}]},
        ],
        "deny": [
            {"side": "deny", "index": 0, "cidr": "10.0.0.0/25",
             "status": "effective", "witness": "10.0.0.0",
             "shadowed_by": None},
            {"side": "deny", "index": 1, "cidr": "10.1.0.0/16",
             "status": "out_of_scope", "witness": None,
             "shadowed_by": None},
        ],
    }


def test_audit_rules_response_follows_input_order():
    response = client.post(
        "/audit-rules",
        json={
            "scope": "10.0.0.0/24",
            # Deliberately unordered by address.
            "allow": ["10.0.0.128/25", "10.0.0.0/25", "10.0.0.0/24"],
            "deny": ["10.0.0.192/26", "10.0.0.0/25"],
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert [item["cidr"] for item in data["allow"]] == [
        "10.0.0.128/25", "10.0.0.0/25", "10.0.0.0/24",
    ]
    assert [item["index"] for item in data["allow"]] == [0, 1, 2]
    assert [item["cidr"] for item in data["deny"]] == [
        "10.0.0.192/26", "10.0.0.0/25",
    ]
    assert [item["index"] for item in data["deny"]] == [0, 1]


def test_audit_rules_witness_is_numerically_smallest_winning_address():
    response = client.post(
        "/audit-rules",
        json={
            "scope": "10.0.0.0/24",
            "allow": ["10.0.0.0/24"],
            "deny": ["10.0.0.0/26", "10.0.0.64/26", "10.0.0.128/26"],
        },
    )
    assert response.status_code == 200
    allow = response.json()["allow"][0]
    # Only the top /26 survives for the allow.
    assert allow["status"] == "effective"
    assert allow["witness"] == "10.0.0.192"


def test_audit_rules_duplicate_denies_keep_earliest_priority():
    response = client.post(
        "/audit-rules",
        json={
            "scope": "10.0.0.0/24",
            "allow": [],
            "deny": ["10.0.0.0/24", "10.0.0.0/24"],
        },
    )
    assert response.status_code == 200
    deny = response.json()["deny"]
    assert deny[0]["status"] == "effective"
    assert deny[0]["witness"] == "10.0.0.0"
    assert deny[1] == {
        "side": "deny", "index": 1, "cidr": "10.0.0.0/24",
        "status": "shadowed", "witness": None,
        "shadowed_by": [{"side": "deny", "index": 0}],
    }


def test_audit_rules_ipv6():
    response = client.post(
        "/audit-rules",
        json={
            "scope": "2001:db8::/126",
            "allow": ["2001:db8::/126", "2001:db8::3/128"],
            "deny": ["2001:db8::3/128"],
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["allow"][0] == {
        "side": "allow", "index": 0, "cidr": "2001:db8::/126",
        "status": "effective", "witness": "2001:db8::",
        "shadowed_by": None}
    assert data["allow"][1]["status"] == "shadowed"
    assert data["allow"][1]["shadowed_by"] == [
        {"side": "deny", "index": 0}]
    assert data["deny"][0] == {
        "side": "deny", "index": 0, "cidr": "2001:db8::3/128",
        "status": "effective", "witness": "2001:db8::3",
        "shadowed_by": None}


def test_audit_rules_empty_rules():
    response = client.post("/audit-rules", json={"scope": "10.0.0.0/24"})
    assert response.status_code == 200
    assert response.json() == {"allow": [], "deny": []}


def test_audit_rules_invalid_scope_returns_422():
    response = client.post(
        "/audit-rules",
        json={"scope": "bogus", "allow": [], "deny": []},
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "scope" for err in response.json()["detail"])


def test_audit_rules_scope_host_bits_return_422():
    response = client.post(
        "/audit-rules",
        json={"scope": "10.0.0.1/24", "allow": [], "deny": []},
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "scope" for err in response.json()["detail"])


def test_audit_rules_missing_scope_returns_422():
    response = client.post("/audit-rules", json={"allow": [], "deny": []})
    assert response.status_code == 422
    assert any("scope" in err["loc"] for err in response.json()["detail"])


def test_audit_rules_invalid_rule_cidr_returns_422():
    response = client.post(
        "/audit-rules",
        json={"scope": "10.0.0.0/24", "allow": ["10.0.0.1/24"]},
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "allow" for err in response.json()["detail"])

    response = client.post(
        "/audit-rules",
        json={"scope": "10.0.0.0/24", "deny": ["not-a-cidr"]},
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "deny" for err in response.json()["detail"])


def test_audit_rules_family_mismatch_returns_422():
    # Unlike /compare, a rule of the other family is a hard 422 here.
    response = client.post(
        "/audit-rules",
        json={"scope": "10.0.0.0/24", "allow": ["2001:db8::/32"]},
    )
    assert response.status_code == 422
    msg = response.json()["detail"][0]["msg"]
    assert "address family" in msg

    response = client.post(
        "/audit-rules",
        json={"scope": "2001:db8::/32", "deny": ["10.0.0.0/8"]},
    )
    assert response.status_code == 422
    assert "address family" in response.json()["detail"][0]["msg"]


def test_audit_rules_wrong_type_returns_422():
    response = client.post("/audit-rules", json={"scope": 10})
    assert response.status_code == 422


def test_audit_rules_is_documented_in_openapi():
    spec = client.get("/openapi.json").json()
    assert "/audit-rules" in spec["paths"]
    operation = spec["paths"]["/audit-rules"]["post"]
    assert "422" in operation["responses"]
    examples = operation["requestBody"]["content"]["application/json"][
        "examples"
    ]
    assert "effective_shadowed_and_out_of_scope" in examples
    schema = spec["components"]["schemas"]["RuleAuditResult"]
    assert schema["properties"]["status"]["enum"] == [
        "effective", "shadowed", "out_of_scope"]
    ref_schema = spec["components"]["schemas"]["RuleReference"]
    assert ref_schema["properties"]["side"]["enum"] == ["allow", "deny"]


# --------------------------------------------------------------------------
# POST /minimize-policy
# --------------------------------------------------------------------------


def test_minimize_policy_basic_subset_with_witnesses():
    response = client.post(
        "/minimize-policy",
        json={
            "scope": "10.0.0.0/24",
            "allow": ["10.0.0.0/24", "10.0.0.0/25"],
            "deny": ["10.0.0.128/25"],
        },
    )
    assert response.status_code == 200
    assert response.json() == {
        "retained": [
            {"side": "allow", "index": 0, "cidr": "10.0.0.0/24",
             "witness": "10.0.0.0"},
            {"side": "deny", "index": 0, "cidr": "10.0.0.128/25",
             "witness": "10.0.0.128"},
        ],
        "removed": [
            {"side": "allow", "index": 1, "cidr": "10.0.0.0/25"},
        ],
    }


def test_minimize_policy_drops_out_of_scope_and_shadowed_rules():
    response = client.post(
        "/minimize-policy",
        json={
            "scope": "10.0.0.0/24",
            "allow": ["10.0.0.0/24", "10.0.0.0/25"],
            "deny": ["10.0.0.0/25", "10.1.0.0/16"],
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert [(item["side"], item["index"]) for item in data["retained"]] == [
        ("allow", 0), ("deny", 0),
    ]
    assert [(item["side"], item["index"]) for item in data["removed"]] == [
        ("allow", 1), ("deny", 1),
    ]
    # Removed references never carry a witness.
    assert all("witness" not in item for item in data["removed"])
    # allow /24 wins only the upper half once the narrow allow is dropped.
    assert data["retained"][0]["witness"] == "10.0.0.128"


def test_minimize_policy_references_follow_original_input_order():
    response = client.post(
        "/minimize-policy",
        json={
            "scope": "10.0.0.0/30",
            "allow": ["10.0.0.0/32", "10.0.0.1/32", "10.0.0.2/32"],
            "deny": ["10.0.0.3/32"],
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert [(item["side"], item["index"]) for item in data["retained"]] == [
        ("allow", 0), ("allow", 1), ("allow", 2), ("deny", 0),
    ]
    assert [item["witness"] for item in data["retained"]] == [
        "10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3",
    ]
    assert data["removed"] == []


def test_minimize_policy_empty_rules():
    response = client.post(
        "/minimize-policy",
        json={"scope": "10.0.0.0/24", "allow": [], "deny": []},
    )
    assert response.status_code == 200
    assert response.json() == {"retained": [], "removed": []}


def test_minimize_policy_ipv6():
    response = client.post(
        "/minimize-policy",
        json={
            "scope": "2001:db8::/120",
            "allow": ["2001:db8::/120"],
            "deny": ["2001:db8::/121"],
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert [(item["side"], item["index"]) for item in data["retained"]] == [
        ("allow", 0), ("deny", 0),
    ]
    assert data["retained"][0]["witness"] == "2001:db8::80"
    assert data["retained"][1]["witness"] == "2001:db8::"


def test_minimize_policy_more_than_16_rules_returns_422():
    response = client.post(
        "/minimize-policy",
        json={
            "scope": "10.0.0.0/24",
            "allow": ["10.0.0.0/26"] * 9,
            "deny": ["10.0.0.64/26"] * 8,
        },
    )
    assert response.status_code == 422
    assert "16" in response.json()["detail"][0]["msg"]


def test_minimize_policy_exactly_16_rules_is_accepted():
    response = client.post(
        "/minimize-policy",
        json={
            "scope": "10.0.0.0/24",
            "allow": ["10.0.0.0/24"] * 16,
            "deny": [],
        },
    )
    assert response.status_code == 200
    # Duplicates collapse to the single earliest copy.
    assert [(item["side"], item["index"])
            for item in response.json()["retained"]] == [("allow", 0)]
    assert len(response.json()["removed"]) == 15


def test_minimize_policy_family_mismatch_returns_422():
    response = client.post(
        "/minimize-policy",
        json={"scope": "10.0.0.0/24", "allow": ["2001:db8::/32"]},
    )
    assert response.status_code == 422
    assert "address family" in response.json()["detail"][0]["msg"]

    response = client.post(
        "/minimize-policy",
        json={"scope": "2001:db8::/32", "deny": ["10.0.0.0/8"]},
    )
    assert response.status_code == 422
    assert "address family" in response.json()["detail"][0]["msg"]


def test_minimize_policy_invalid_scope_returns_422():
    response = client.post(
        "/minimize-policy",
        json={"scope": "bogus", "allow": [], "deny": []},
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "scope" for err in response.json()["detail"])


def test_minimize_policy_scope_host_bits_return_422():
    response = client.post(
        "/minimize-policy",
        json={"scope": "10.0.0.1/24", "allow": [], "deny": []},
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "scope" for err in response.json()["detail"])


def test_minimize_policy_missing_scope_returns_422():
    response = client.post("/minimize-policy", json={"allow": [], "deny": []})
    assert response.status_code == 422
    assert any("scope" in err["loc"] for err in response.json()["detail"])


def test_minimize_policy_invalid_rule_cidr_returns_422():
    response = client.post(
        "/minimize-policy",
        json={"scope": "10.0.0.0/24", "allow": ["10.0.0.1/24"]},
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "allow" for err in response.json()["detail"])

    response = client.post(
        "/minimize-policy",
        json={"scope": "10.0.0.0/24", "deny": ["not-a-cidr"]},
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "deny" for err in response.json()["detail"])


def test_minimize_policy_wrong_type_returns_422():
    response = client.post("/minimize-policy", json={"scope": 10})
    assert response.status_code == 422


def test_minimize_policy_is_documented_in_openapi():
    spec = client.get("/openapi.json").json()
    assert "/minimize-policy" in spec["paths"]
    operation = spec["paths"]["/minimize-policy"]["post"]
    assert "422" in operation["responses"]
    examples = operation["requestBody"]["content"]["application/json"][
        "examples"
    ]
    assert "minimum_subset_with_witnesses" in examples
    assert "too_many_rules" in examples
    response_schema = spec["components"]["schemas"]["MinimizePolicyResponse"]
    assert set(response_schema["properties"]) == {"retained", "removed"}
    retained_schema = spec["components"]["schemas"]["RetainedRule"]
    assert set(retained_schema["properties"]) == {
        "side", "index", "cidr", "witness"}


# --------------------------------------------------------------------------
# POST /allocate
# --------------------------------------------------------------------------


def test_allocate_basic_preserves_request_order():
    response = client.post(
        "/allocate",
        json={
            "scope": "10.0.0.0/24",
            "occupied": ["10.0.0.0/25"],
            "requests": [
                {"id": "b", "prefix_length": 26},
                {"id": "a", "prefix_length": 26},
            ],
        },
    )
    assert response.status_code == 200
    data = response.json()
    # Response follows request order (b before a), not id or address order.
    assert data["allocations"] == [
        {"id": "b", "cidr": "10.0.0.128/26"},
        {"id": "a", "cidr": "10.0.0.192/26"},
    ]
    assert data["remaining"] == []
    assert data["remaining_addresses"] == "0"


def test_allocate_backtracks_to_lexicographically_smallest_plan():
    # Free space: 10.0.0.0/24 and 10.0.1.128/25.  Giving "small" the
    # lowest /25 (10.0.0.0/25 or 10.0.0.128/25) leaves no room for the
    # /24, so the search must backtrack and place "small" at 10.0.1.128/25.
    response = client.post(
        "/allocate",
        json={
            "scope": "10.0.0.0/23",
            "occupied": ["10.0.1.0/25"],
            "requests": [
                {"id": "small", "prefix_length": 25},
                {"id": "big", "prefix_length": 24},
            ],
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["allocations"] == [
        {"id": "small", "cidr": "10.0.1.128/25"},
        {"id": "big", "cidr": "10.0.0.0/24"},
    ]
    assert data["remaining"] == []
    assert data["remaining_addresses"] == "0"


def test_allocate_remaining_is_minimal_cidr_set():
    response = client.post(
        "/allocate",
        json={
            "scope": "10.0.0.0/24",
            "occupied": ["10.0.0.64/26", "10.0.0.128/26"],
            "requests": [{"id": "first", "prefix_length": 26}],
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["allocations"] == [{"id": "first", "cidr": "10.0.0.0/26"}]
    # 10.0.0.192/26 survives whole; the freed /26 siblings are not merged
    # across the occupied blocks.
    assert data["remaining"] == ["10.0.0.192/26"]
    assert data["remaining_addresses"] == "64"


def test_allocate_empty_requests_returns_free_space():
    response = client.post(
        "/allocate",
        json={"scope": "10.0.0.0/24", "occupied": ["10.0.0.0/25"]},
    )
    assert response.status_code == 200
    assert response.json() == {
        "allocations": [],
        "remaining": ["10.0.0.128/25"],
        "remaining_addresses": "128",
    }


def test_allocate_ipv6_decimal_string_count():
    response = client.post(
        "/allocate",
        json={
            "scope": "2001:db8::/126",
            "occupied": ["2001:db8::1/128"],
            "requests": [{"id": "node", "prefix_length": 128}],
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["allocations"] == [{"id": "node", "cidr": "2001:db8::/128"}]
    assert data["remaining"] == ["2001:db8::2/127"]
    assert data["remaining_addresses"] == "2"


def test_allocate_infeasible_returns_409_without_partial_allocation():
    response = client.post(
        "/allocate",
        json={
            "scope": "10.0.0.0/24",
            "occupied": ["10.0.0.0/25"],
            "requests": [
                {"id": "x", "prefix_length": 25},
                {"id": "y", "prefix_length": 25},
            ],
        },
    )
    assert response.status_code == 409
    body = response.json()
    assert "allocations" not in body
    assert "remaining" not in body


def test_allocate_prefix_shorter_than_scope_returns_409():
    # A /16 can never be a subnet of a /24 scope: unsatisfiable, not invalid.
    response = client.post(
        "/allocate",
        json={
            "scope": "10.0.0.0/24",
            "requests": [{"id": "wan", "prefix_length": 16}],
        },
    )
    assert response.status_code == 409


def test_allocate_duplicate_id_returns_422():
    response = client.post(
        "/allocate",
        json={
            "scope": "10.0.0.0/24",
            "requests": [
                {"id": "dup", "prefix_length": 25},
                {"id": "dup", "prefix_length": 26},
            ],
        },
    )
    assert response.status_code == 422
    assert "dup" in response.json()["detail"][0]["msg"]


def test_allocate_invalid_prefix_length_returns_422():
    for bad in (-1, 33):
        response = client.post(
            "/allocate",
            json={
                "scope": "10.0.0.0/24",
                "requests": [{"id": "x", "prefix_length": bad}],
            },
        )
        assert response.status_code == 422, bad
    # /33 is fine for an IPv6 scope, /129 is not.
    response = client.post(
        "/allocate",
        json={
            "scope": "2001:db8::/32",
            "requests": [{"id": "x", "prefix_length": 129}],
        },
    )
    assert response.status_code == 422


def test_allocate_invalid_scope_or_occupied_cidr_returns_422():
    response = client.post(
        "/allocate",
        json={"scope": "10.0.0.1/24", "requests": []},
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "scope" for err in response.json()["detail"])

    response = client.post(
        "/allocate",
        json={"scope": "10.0.0.0/24", "occupied": ["bogus"]},
    )
    assert response.status_code == 422
    assert any(
        err["loc"][-1] == "occupied" for err in response.json()["detail"]
    )


def test_allocate_occupied_wrong_family_returns_422():
    response = client.post(
        "/allocate",
        json={"scope": "10.0.0.0/24", "occupied": ["2001:db8::/32"]},
    )
    assert response.status_code == 422


def test_allocate_occupied_outside_scope_returns_422():
    response = client.post(
        "/allocate",
        json={"scope": "10.0.0.0/24", "occupied": ["10.0.1.0/24"]},
    )
    assert response.status_code == 422


def test_allocate_overlapping_occupied_returns_422():
    response = client.post(
        "/allocate",
        json={
            "scope": "10.0.0.0/24",
            "occupied": ["10.0.0.0/25", "10.0.0.64/26"],
        },
    )
    assert response.status_code == 422
    assert "overlap" in response.json()["detail"][0]["msg"]


def test_allocate_missing_scope_returns_422():
    response = client.post("/allocate", json={"requests": []})
    assert response.status_code == 422
    assert any("scope" in err["loc"] for err in response.json()["detail"])


def test_allocate_is_documented_in_openapi():
    spec = client.get("/openapi.json").json()
    operation = spec["paths"]["/allocate"]["post"]
    assert "409" in operation["responses"]
    assert "422" in operation["responses"]
    examples = operation["requestBody"]["content"]["application/json"][
        "examples"
    ]
    assert "lexicographic_with_backtracking" in examples
    schema = spec["components"]["schemas"]["AllocateResponse"]
    assert set(schema["properties"]) == {
        "allocations", "remaining", "remaining_addresses",
    }


# --------------------------------------------------------------------------
# POST /anonymize
# --------------------------------------------------------------------------

KEY = "0123456789abcdef" * 4


def test_anonymize_basic_v4_v6_addresses_and_cidrs():
    response = client.post(
        "/anonymize",
        json={
            "key_hex": KEY,
            "addresses": [
                "10.0.0.1", "10.0.0.2", "192.0.2.1", "2001:db8::1",
            ],
            "cidrs": ["10.0.0.0/24", "2001:db8::/32"],
        },
    )
    assert response.status_code == 200
    assert response.json() == {
        "addresses": [
            "77.249.170.48",
            "77.249.170.51",
            "236.60.54.68",
            "d5af:46c8:beb3:e56d:c681:ca26:c4a4:9e2a",
        ],
        "cidrs": ["77.249.170.0/24", "d5af:46c8::/32"],
    }


def test_anonymize_is_stable_and_prefix_preserving():
    payload = {
        "key_hex": KEY,
        "addresses": ["10.0.0.1", "10.0.0.2"],
        "cidrs": [],
    }
    first = client.post("/anonymize", json=payload).json()
    second = client.post("/anonymize", json=payload).json()
    assert first == second
    # The two inputs share 10.0.0.0/30 (last octets 1 and 2 differ at bit 6):
    # outputs 77.249.170.48 and .51 share the same /30 prefix too.
    assert first["addresses"] == ["77.249.170.48", "77.249.170.51"]


def test_anonymize_defaults_to_empty_lists():
    response = client.post("/anonymize", json={"key_hex": KEY})
    assert response.status_code == 200
    assert response.json() == {"addresses": [], "cidrs": []}


def test_anonymize_preserves_input_order():
    response = client.post(
        "/anonymize",
        json={
            "key_hex": KEY,
            "addresses": ["2001:db8::1", "10.0.0.1", "10.0.0.2"],
            "cidrs": ["2001:db8::/32", "10.0.0.0/24"],
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["addresses"] == [
        "d5af:46c8:beb3:e56d:c681:ca26:c4a4:9e2a",
        "77.249.170.48",
        "77.249.170.51",
    ]
    assert data["cidrs"] == ["d5af:46c8::/32", "77.249.170.0/24"]


def test_anonymize_cidr_host_bits_return_422():
    response = client.post(
        "/anonymize",
        json={"key_hex": KEY, "cidrs": ["10.0.0.1/24"]},
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "cidrs" for err in response.json()["detail"])


def test_anonymize_bare_address_in_cidrs_returns_422():
    response = client.post(
        "/anonymize",
        json={"key_hex": KEY, "cidrs": ["10.0.0.1"]},
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "cidrs" for err in response.json()["detail"])


def test_anonymize_invalid_address_returns_422():
    response = client.post(
        "/anonymize",
        json={"key_hex": KEY, "addresses": ["bogus"]},
    )
    assert response.status_code == 422
    assert any(
        err["loc"][-1] == "addresses" for err in response.json()["detail"]
    )


def test_anonymize_cidr_notation_in_addresses_returns_422():
    response = client.post(
        "/anonymize",
        json={"key_hex": KEY, "addresses": ["10.0.0.1/32"]},
    )
    assert response.status_code == 422
    assert any(
        err["loc"][-1] == "addresses" for err in response.json()["detail"]
    )


@pytest.mark.parametrize(
    "bad_key",
    ["", "00", "z" * 64, "g" + "0" * 63, "0" * 63, "0" * 65, None],
)
def test_anonymize_invalid_key_returns_422(bad_key):
    response = client.post(
        "/anonymize",
        json={"key_hex": bad_key, "addresses": ["10.0.0.1"]},
    )
    assert response.status_code == 422
    assert any(
        err["loc"][-1] == "key_hex" for err in response.json()["detail"]
    )


def test_anonymize_missing_key_returns_422():
    response = client.post("/anonymize", json={"addresses": []})
    assert response.status_code == 422
    assert any(
        "key_hex" in err["loc"] for err in response.json()["detail"]
    )


def test_anonymize_wrong_type_returns_422():
    response = client.post(
        "/anonymize",
        json={"key_hex": 123, "addresses": []},
    )
    assert response.status_code == 422

    response = client.post(
        "/anonymize",
        json={"key_hex": KEY, "addresses": [10]},
    )
    assert response.status_code == 422


def test_anonymize_is_documented_in_openapi():
    spec = client.get("/openapi.json").json()
    assert "/anonymize" in spec["paths"]
    operation = spec["paths"]["/anonymize"]["post"]
    assert "422" in operation["responses"]
    examples = operation["requestBody"]["content"]["application/json"][
        "examples"
    ]
    assert "prefix_preserving_v4_and_v6" in examples
    assert "host_bits_set" in examples
    schema = spec["components"]["schemas"]["AnonymizeResponse"]
    assert set(schema["properties"]) == {"addresses", "cidrs"}

# --------------------------------------------------------------------------
# POST /reverse-delegations
# --------------------------------------------------------------------------


def test_reverse_delegations_direct_slash24():
    response = client.post(
        "/reverse-delegations",
        json={"delegations": [
            {"cidr": "192.0.2.0/24",
             "nameservers": ["NS1.Example.net", "ns1.example.net."]},
        ]},
    )
    assert response.status_code == 200
    assert response.json() == {
        "zones": [{
            "zone": "2.0.192.in-addr.arpa.",
            "method": "direct",
            "parent_zone": None,
            "cidr": "192.0.2.0/24",
            "nameservers": ["ns1.example.net."],
        }],
        "records": [{
            "zone": "2.0.192.in-addr.arpa.",
            "type": "NS",
            "name": "2.0.192.in-addr.arpa.",
            "target": "ns1.example.net.",
            "cidr": "192.0.2.0/24",
        }],
    }


def test_reverse_delegations_rfc2317_cnames_and_sorting():
    response = client.post(
        "/reverse-delegations",
        json={"delegations": [
            # Shuffled input; sorting is by network address, not input order.
            {"cidr": "10.0.0.128/30", "nameservers": ["ns-b.example"]},
            {"cidr": "10.0.0.5/32", "nameservers": ["ns-a.example"]},
        ]},
    )
    assert response.status_code == 200
    data = response.json()
    assert [zone["cidr"] for zone in data["zones"]] == [
        "10.0.0.5/32", "10.0.0.128/30",
    ]
    assert data["zones"][0]["zone"] == "5/32.0.0.10.in-addr.arpa."
    assert data["zones"][1]["zone"] == "128/30.0.0.10.in-addr.arpa."

    records = data["records"]
    # /32: 1 NS + 1 CNAME; /30: 1 NS + 4 CNAMEs.
    assert len(records) == 7
    by_cidr = {}
    for record in records:
        by_cidr.setdefault(record["cidr"], []).append(record)
    assert [r["type"] for r in by_cidr["10.0.0.5/32"]] == ["NS", "CNAME"]
    assert [r["type"] for r in by_cidr["10.0.0.128/30"]] == [
        "NS", "CNAME", "CNAME", "CNAME", "CNAME",
    ]
    cname_128 = next(
        r for r in records
        if r["cidr"] == "10.0.0.128/30" and r["type"] == "CNAME"
        and r["name"] == "128.0.0.10.in-addr.arpa."
    )
    assert cname_128["target"] == "128.128/30.0.0.10.in-addr.arpa."
    assert cname_128["zone"] == "0.0.10.in-addr.arpa."
    # Every record carries its source CIDR.
    assert all(record["cidr"] in ("10.0.0.5/32", "10.0.0.128/30")
               for record in records)


def test_reverse_delegations_slash25_full_cname_coverage():
    response = client.post(
        "/reverse-delegations",
        json={"delegations": [
            {"cidr": "172.16.9.128/25",
             "nameservers": ["ns1.cust.example", "ns2.cust.example"]},
        ]},
    )
    assert response.status_code == 200
    records = response.json()["records"]
    ns_records = [r for r in records if r["type"] == "NS"]
    cnames = [r for r in records if r["type"] == "CNAME"]
    assert [r["target"] for r in ns_records] == [
        "ns1.cust.example.", "ns2.cust.example.",
    ]
    assert [r["name"] for r in ns_records] == [
        "128/25.9.16.172.in-addr.arpa.",
        "128/25.9.16.172.in-addr.arpa.",
    ]
    assert len(cnames) == 128
    assert cnames[0] == {
        "zone": "9.16.172.in-addr.arpa.",
        "type": "CNAME",
        "name": "128.9.16.172.in-addr.arpa.",
        "target": "128.128/25.9.16.172.in-addr.arpa.",
        "cidr": "172.16.9.128/25",
    }
    assert cnames[-1]["name"] == "255.9.16.172.in-addr.arpa."


def test_reverse_delegations_empty_batch():
    response = client.post("/reverse-delegations", json={})
    assert response.status_code == 200
    assert response.json() == {"zones": [], "records": []}


def test_reverse_delegations_disjoint_same_24_accepted():
    # Two /25 halves together partition the parent /24.
    response = client.post(
        "/reverse-delegations",
        json={"delegations": [
            {"cidr": "10.0.0.0/25", "nameservers": ["low.example"]},
            {"cidr": "10.0.0.128/25", "nameservers": ["high.example"]},
        ]},
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data["zones"]) == 2
    cnames = [r for r in data["records"] if r["type"] == "CNAME"]
    owners = sorted(int(r["name"].split(".", 1)[0]) for r in cnames)
    assert owners == list(range(256))


@pytest.mark.parametrize(
    "cidr",
    ["10.0.0.0/23", "10.0.0.0/8", "10.0.0.0/0", "9.9.9.0/33"],
)
def test_reverse_delegations_bad_prefix_returns_422(cidr):
    response = client.post(
        "/reverse-delegations",
        json={"delegations": [{"cidr": cidr, "nameservers": ["ns.a"]}]},
    )
    assert response.status_code == 422
    assert any(
        err["loc"][-1] == "cidr" for err in response.json()["detail"]
    )


def test_reverse_delegations_ipv6_returns_422():
    response = client.post(
        "/reverse-delegations",
        json={"delegations": [
            {"cidr": "2001:db8::/120", "nameservers": ["ns.a"]},
        ]},
    )
    assert response.status_code == 422
    assert any(
        err["loc"][-1] == "cidr" for err in response.json()["detail"]
    )


def test_reverse_delegations_host_bits_return_422():
    response = client.post(
        "/reverse-delegations",
        json={"delegations": [
            {"cidr": "10.0.0.1/24", "nameservers": ["ns.a"]},
        ]},
    )
    assert response.status_code == 422
    assert any(
        err["loc"][-1] == "cidr" for err in response.json()["detail"]
    )


def test_reverse_delegations_bare_address_returns_422():
    response = client.post(
        "/reverse-delegations",
        json={"delegations": [
            {"cidr": "10.0.0.1", "nameservers": ["ns.a"]},
        ]},
    )
    assert response.status_code == 422
    assert any(
        err["loc"][-1] == "cidr" for err in response.json()["detail"]
    )


def test_reverse_delegations_overlapping_cidrs_return_422():
    response = client.post(
        "/reverse-delegations",
        json={"delegations": [
            {"cidr": "10.0.0.0/25", "nameservers": ["ns.a"]},
            {"cidr": "10.0.0.64/26", "nameservers": ["ns.b"]},
        ]},
    )
    assert response.status_code == 422
    # The overlap is a cross-entry, whole-model rule: its loc is the body,
    # not one entry (same pattern as /allocate's occupied overlap check).
    assert response.json()["detail"][0]["loc"] == ["body"]
    assert "overlap" in response.json()["detail"][0]["msg"]


def test_reverse_delegations_slash24_beside_other_cidr_returns_422():
    response = client.post(
        "/reverse-delegations",
        json={"delegations": [
            {"cidr": "10.0.0.0/24", "nameservers": ["ns.a"]},
            {"cidr": "10.0.0.5/32", "nameservers": ["ns.b"]},
        ]},
    )
    assert response.status_code == 422
    assert "overlap" in response.json()["detail"][0]["msg"]


def test_reverse_delegations_different_parent_24_returns_422():
    response = client.post(
        "/reverse-delegations",
        json={"delegations": [
            {"cidr": "10.0.0.0/25", "nameservers": ["ns.a"]},
            {"cidr": "10.0.1.0/25", "nameservers": ["ns.b"]},
        ]},
    )
    assert response.status_code == 422
    assert "parent /24" in response.json()["detail"][0]["msg"]


def test_reverse_delegations_invalid_nameserver_returns_422():
    response = client.post(
        "/reverse-delegations",
        json={"delegations": [
            {"cidr": "10.0.0.0/25", "nameservers": ["not a name"]},
        ]},
    )
    assert response.status_code == 422
    assert any(
        err["loc"][-1] == "nameservers"
        for err in response.json()["detail"]
    )


def test_reverse_delegations_ip_nameserver_returns_422():
    response = client.post(
        "/reverse-delegations",
        json={"delegations": [
            {"cidr": "10.0.0.0/25", "nameservers": ["10.0.0.1"]},
        ]},
    )
    assert response.status_code == 422


def test_reverse_delegations_empty_nameservers_returns_422():
    response = client.post(
        "/reverse-delegations",
        json={"delegations": [
            {"cidr": "10.0.0.0/25", "nameservers": []},
        ]},
    )
    assert response.status_code == 422


def test_reverse_delegations_wrong_types_return_422():
    response = client.post(
        "/reverse-delegations",
        json={"delegations": [{"cidr": 10, "nameservers": ["ns.a"]}]},
    )
    assert response.status_code == 422

    response = client.post(
        "/reverse-delegations",
        json={"delegations": [{"cidr": "10.0.0.0/25", "nameservers": [10]}]},
    )
    assert response.status_code == 422


def test_reverse_delegations_is_documented_in_openapi():
    spec = client.get("/openapi.json").json()
    assert "/reverse-delegations" in spec["paths"]
    operation = spec["paths"]["/reverse-delegations"]["post"]
    assert "422" in operation["responses"]
    examples = operation["requestBody"]["content"]["application/json"][
        "examples"
    ]
    assert "direct_slash24" in examples
    assert "rfc2317_subzones" in examples
    assert "overlapping_cidrs_rejected" in examples
    response_examples = operation["responses"]["200"]["content"][
        "application/json"
    ]["examples"]
    assert set(response_examples) == {"direct_slash24", "rfc2317_subzones"}
    zone_schema = spec["components"]["schemas"]["ReverseZone"]
    assert zone_schema["properties"]["method"]["enum"] == [
        "direct", "rfc2317"]
    record_schema = spec["components"]["schemas"]["ReverseRecord"]
    assert record_schema["properties"]["type"]["enum"] == ["NS", "CNAME"]

# --------------------------------------------------------------------------
# POST /roa-coverage
# --------------------------------------------------------------------------


def test_roa_coverage_valid_invalid_and_unknown_partition():
    response = client.post(
        "/roa-coverage",
        json={
            "scope": "203.0.113.0/24",
            "asn": 64500,
            "prefix_length": 26,
            "roas": [
                {"cidr": "203.0.113.0/25", "asn": 64500, "max_length": 26},
                {"cidr": "203.0.113.128/26", "asn": 64501, "max_length": 26},
            ],
        },
    )
    assert response.status_code == 200
    assert response.json() == {
        "partitions": [
            {"cidr": "203.0.113.0/25", "status": "valid"},
            {"cidr": "203.0.113.128/26", "status": "invalid"},
            {"cidr": "203.0.113.192/26", "status": "unknown"},
        ],
    }


def test_roa_coverage_piece_can_be_shorter_than_requested_length():
    # max_length /24 is too short for /25: both candidates are invalid and
    # merge back to the single /24 scope piece.
    response = client.post(
        "/roa-coverage",
        json={
            "scope": "203.0.113.0/24",
            "asn": 64500,
            "prefix_length": 25,
            "roas": [
                {"cidr": "203.0.113.0/24", "asn": 64500, "max_length": 24},
            ],
        },
    )
    assert response.status_code == 200
    assert response.json() == {
        "partitions": [
            {"cidr": "203.0.113.0/24", "status": "invalid"},
        ],
    }


def test_roa_coverage_no_roas_whole_scope_unknown():
    response = client.post(
        "/roa-coverage",
        json={"scope": "10.0.0.0/24", "asn": 65000, "prefix_length": 28},
    )
    assert response.status_code == 200
    assert response.json() == {
        "partitions": [{"cidr": "10.0.0.0/24", "status": "unknown"}],
    }


def test_roa_coverage_disjoint_roas_are_ignored():
    response = client.post(
        "/roa-coverage",
        json={
            "scope": "10.0.0.0/24",
            "asn": 64500,
            "prefix_length": 26,
            "roas": [{"cidr": "11.0.0.0/16", "asn": 64500, "max_length": 32}],
        },
    )
    assert response.status_code == 200
    assert response.json() == {
        "partitions": [{"cidr": "10.0.0.0/24", "status": "unknown"}],
    }


def test_roa_coverage_ipv6_huge_scope_does_not_enumerate():
    # ::/0 with /128 candidates must return immediately as a small tiling.
    response = client.post(
        "/roa-coverage",
        json={
            "scope": "::/0",
            "asn": 64500,
            "prefix_length": 128,
            "roas": [
                {"cidr": "2001:db8::/32", "asn": 64500, "max_length": 128},
                {"cidr": "2001:db9::/32", "asn": 64501, "max_length": 48},
            ],
        },
    )
    assert response.status_code == 200
    partitions = response.json()["partitions"]
    assert len(partitions) < 100
    by_cidr = {p["cidr"]: p["status"] for p in partitions}
    assert by_cidr["2001:db8::/32"] == "valid"
    assert by_cidr["2001:db9::/32"] == "invalid"


def test_roa_coverage_default_roas_empty():
    response = client.post(
        "/roa-coverage",
        json={"scope": "192.0.2.0/24", "asn": 0, "prefix_length": 24, "roas": []},
    )
    assert response.status_code == 200
    assert response.json() == {
        "partitions": [{"cidr": "192.0.2.0/24", "status": "unknown"}],
    }


def test_roa_coverage_invalid_scope_returns_422():
    response = client.post(
        "/roa-coverage",
        json={"scope": "bogus", "asn": 1, "prefix_length": 24, "roas": []},
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "scope" for err in response.json()["detail"])


def test_roa_coverage_scope_host_bits_return_422():
    response = client.post(
        "/roa-coverage",
        json={"scope": "10.0.0.1/24", "asn": 1, "prefix_length": 24, "roas": []},
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "scope" for err in response.json()["detail"])


def test_roa_coverage_missing_required_fields_returns_422():
    response = client.post("/roa-coverage", json={"scope": "10.0.0.0/24"})
    assert response.status_code == 422
    locs = {tuple(err["loc"]) for err in response.json()["detail"]}
    assert any("asn" in loc for loc in locs)
    assert any("prefix_length" in loc for loc in locs)


def test_roa_coverage_prefix_length_beyond_family_returns_422():
    response = client.post(
        "/roa-coverage",
        json={"scope": "10.0.0.0/24", "asn": 1, "prefix_length": 33, "roas": []},
    )
    assert response.status_code == 422
    assert "/32" in response.json()["detail"][0]["msg"]

    response = client.post(
        "/roa-coverage",
        json={"scope": "2001:db8::/32", "asn": 1, "prefix_length": 129, "roas": []},
    )
    assert response.status_code == 422
    assert "/128" in response.json()["detail"][0]["msg"]


def test_roa_coverage_prefix_length_shorter_than_scope_returns_422():
    response = client.post(
        "/roa-coverage",
        json={"scope": "10.0.0.0/24", "asn": 1, "prefix_length": 23, "roas": []},
    )
    assert response.status_code == 422
    assert "shorter than the scope prefix" in response.json()["detail"][0]["msg"]


def test_roa_coverage_cross_family_roa_returns_422():
    response = client.post(
        "/roa-coverage",
        json={
            "scope": "10.0.0.0/24",
            "asn": 1,
            "prefix_length": 26,
            "roas": [{"cidr": "2001:db8::/32", "asn": 1, "max_length": 48}],
        },
    )
    assert response.status_code == 422
    assert "address family" in response.json()["detail"][0]["msg"]

    response = client.post(
        "/roa-coverage",
        json={
            "scope": "2001:db8::/32",
            "asn": 1,
            "prefix_length": 48,
            "roas": [{"cidr": "10.0.0.0/8", "asn": 1, "max_length": 24}],
        },
    )
    assert response.status_code == 422
    assert "address family" in response.json()["detail"][0]["msg"]


def test_roa_coverage_invalid_roa_cidr_returns_422():
    response = client.post(
        "/roa-coverage",
        json={
            "scope": "10.0.0.0/24",
            "asn": 1,
            "prefix_length": 26,
            "roas": [{"cidr": "10.0.0.1/24", "asn": 1, "max_length": 26}],
        },
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "cidr" for err in response.json()["detail"])


def test_roa_coverage_bare_roa_address_returns_422():
    # Strict CIDR is required for ROAs; a bare address lacks a prefix length.
    response = client.post(
        "/roa-coverage",
        json={
            "scope": "10.0.0.0/24",
            "asn": 1,
            "prefix_length": 26,
            "roas": [{"cidr": "10.0.0.0", "asn": 1, "max_length": 26}],
        },
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "cidr" for err in response.json()["detail"])


def test_roa_coverage_max_length_below_prefix_returns_422():
    response = client.post(
        "/roa-coverage",
        json={
            "scope": "10.0.0.0/24",
            "asn": 1,
            "prefix_length": 26,
            "roas": [{"cidr": "10.0.0.0/25", "asn": 1, "max_length": 24}],
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any("max_length" in err["msg"] for err in detail)


def test_roa_coverage_max_length_above_family_width_returns_422():
    response = client.post(
        "/roa-coverage",
        json={
            "scope": "10.0.0.0/24",
            "asn": 1,
            "prefix_length": 26,
            "roas": [{"cidr": "10.0.0.0/24", "asn": 1, "max_length": 33}],
        },
    )
    assert response.status_code == 422
    assert any("max_length" in err["msg"] for err in response.json()["detail"])

    response = client.post(
        "/roa-coverage",
        json={
            "scope": "2001:db8::/32",
            "asn": 1,
            "prefix_length": 48,
            "roas": [{"cidr": "2001:db8::/32", "asn": 1, "max_length": 129}],
        },
    )
    assert response.status_code == 422
    assert any("max_length" in err["msg"] for err in response.json()["detail"])


@pytest.mark.parametrize("bad_asn", [-1, 2 ** 32])
def test_roa_coverage_target_asn_out_of_range_returns_422(bad_asn):
    response = client.post(
        "/roa-coverage",
        json={
            "scope": "10.0.0.0/24",
            "asn": bad_asn,
            "prefix_length": 26,
            "roas": [],
        },
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "asn" for err in response.json()["detail"])


@pytest.mark.parametrize("bad_asn", [-1, 2 ** 32])
def test_roa_coverage_roa_asn_out_of_range_returns_422(bad_asn):
    response = client.post(
        "/roa-coverage",
        json={
            "scope": "10.0.0.0/24",
            "asn": 1,
            "prefix_length": 26,
            "roas": [{"cidr": "10.0.0.0/24", "asn": bad_asn, "max_length": 26}],
        },
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "asn" for err in response.json()["detail"])


def test_roa_coverage_asn_boundaries_accepted():
    # 0 and 4294967295 are syntactically valid 32-bit AS numbers.
    for asn in (0, 4294967295):
        response = client.post(
            "/roa-coverage",
            json={"scope": "10.0.0.0/24", "asn": asn, "prefix_length": 24,
                  "roas": [{"cidr": "10.0.0.0/24", "asn": asn, "max_length": 24}]},
        )
        assert response.status_code == 200, asn
        assert response.json()["partitions"] == [
            {"cidr": "10.0.0.0/24", "status": "valid"}
        ]


def test_roa_coverage_wrong_types_return_422():
    response = client.post(
        "/roa-coverage",
        json={"scope": 10, "asn": 1, "prefix_length": 24, "roas": []},
    )
    assert response.status_code == 422

    response = client.post(
        "/roa-coverage",
        json={"scope": "10.0.0.0/24", "asn": "AS64500",
              "prefix_length": 24, "roas": []},
    )
    assert response.status_code == 422


def test_roa_coverage_is_documented_in_openapi():
    spec = client.get("/openapi.json").json()
    assert "/roa-coverage" in spec["paths"]
    operation = spec["paths"]["/roa-coverage"]["post"]
    assert "422" in operation["responses"]
    examples = operation["requestBody"]["content"]["application/json"][
        "examples"
    ]
    assert "valid_invalid_and_unknown" in examples
    assert "cross_family_roa_rejected" in examples
    response_examples = operation["responses"]["200"]["content"][
        "application/json"
    ]["examples"]
    assert "valid_invalid_and_unknown" in response_examples
    partition_schema = spec["components"]["schemas"]["RoaStatusPartition"]
    assert partition_schema["properties"]["status"]["enum"] == [
        "valid", "invalid", "unknown",
    ]
    response_schema = spec["components"]["schemas"]["RoaCoverageResponse"]
    assert set(response_schema["properties"]) == {"partitions"}

# --------------------------------------------------------------------------
# POST /as-relationship-repair
# --------------------------------------------------------------------------

AS_REPAIR_SHARED = {
    "relationships": [
        {"type": "customer_provider", "customer": 200, "provider": 100},
        {"type": "customer_provider", "customer": 200, "provider": 300},
        {"type": "customer_provider", "customer": 200, "provider": 400},
    ],
    "paths": [[100, 200, 300], [400, 200, 300]],
}

AS_REPAIR_INFEASIBLE = {
    "relationships": [
        {"type": "customer_provider", "customer": 1, "provider": 2},
        {"type": "customer_provider", "customer": 3, "provider": 1},
        {"type": "peer", "peers": [1, 4]},
        {"type": "customer_provider", "customer": 2, "provider": 3},
        {"type": "customer_provider", "customer": 4, "provider": 3},
    ],
    "paths": [
        [4, 3, 2, 1],
        [2, 1, 3, 4],
        [4, 1, 3, 2],
        [3, 4, 1, 2],
    ],
}


def test_as_relationship_repair_shared_single_flip():
    response = client.post("/as-relationship-repair", json=AS_REPAIR_SHARED)
    assert response.status_code == 200
    assert response.json() == {
        "violating_path_indices": [0, 1],
        "corrections": [
            {"type": "customer_provider", "customer": 300,
             "provider": 200, "peers": None},
        ],
        "changes": 1,
    }


def test_as_relationship_repair_already_valley_free():
    response = client.post(
        "/as-relationship-repair",
        json={
            "relationships": [
                {"type": "customer_provider", "customer": 1, "provider": 2},
                {"type": "customer_provider", "customer": 3, "provider": 2},
            ],
            "paths": [[1, 2, 3]],
        },
    )
    assert response.status_code == 200
    assert response.json() == {
        "violating_path_indices": [],
        "corrections": [],
        "changes": 0,
    }


def test_as_relationship_repair_peer_summit_path():
    # up, peer, down needs no repair.
    response = client.post(
        "/as-relationship-repair",
        json={
            "relationships": [
                {"type": "customer_provider", "customer": 1, "provider": 2},
                {"type": "peer", "peers": [2, 3]},
                {"type": "customer_provider", "customer": 4, "provider": 3},
            ],
            "paths": [[1, 2, 3, 4]],
        },
    )
    assert response.status_code == 200
    assert response.json()["changes"] == 0
    assert response.json()["violating_path_indices"] == []


def test_as_relationship_repair_peer_endpoint_order_is_directionless():
    # Listing peers in either order is the same undirected relationship.
    body = {
        "relationships": [{"type": "peer", "peers": [300, 100]}],
        "paths": [[100, 300]],
    }
    response = client.post("/as-relationship-repair", json=body)
    assert response.status_code == 200
    assert response.json()["changes"] == 0


def test_as_relationship_repair_single_as_and_empty_body():
    response = client.post(
        "/as-relationship-repair",
        json={"relationships": [], "paths": [[7]]},
    )
    assert response.status_code == 200
    assert response.json() == {
        "violating_path_indices": [], "corrections": [], "changes": 0,
    }
    response = client.post("/as-relationship-repair", json={})
    assert response.status_code == 200
    assert response.json()["changes"] == 0


def test_as_relationship_repair_lexicographic_tie_break():
    # Two one-flip repairs; the full sorted new-relationship sequence flips
    # the smaller pair (100,200) to customer 100/provider 200.
    response = client.post(
        "/as-relationship-repair",
        json={
            "relationships": [
                {"type": "customer_provider", "customer": 200,
                 "provider": 100},
                {"type": "customer_provider", "customer": 200,
                 "provider": 300},
            ],
            "paths": [[100, 200, 300]],
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["changes"] == 1
    assert data["corrections"] == [
        {"type": "customer_provider", "customer": 100, "provider": 200,
         "peers": None},
    ]


def test_as_relationship_repair_unused_relationship_is_left_untouched():
    response = client.post(
        "/as-relationship-repair",
        json={
            "relationships": [
                {"type": "customer_provider", "customer": 200,
                 "provider": 100},
                {"type": "customer_provider", "customer": 200,
                 "provider": 300},
                {"type": "peer", "peers": [900, 901]},
            ],
            "paths": [[100, 200, 300]],
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["changes"] == 1
    assert all(
        item.get("customer", item.get("peers")) not in (900, 901)
        and item.get("provider") not in (900, 901)
        for item in data["corrections"]
    )


def test_as_relationship_repair_infeasible_returns_409():
    response = client.post(
        "/as-relationship-repair", json=AS_REPAIR_INFEASIBLE
    )
    assert response.status_code == 409
    body = response.json()
    assert "violating_path_indices" not in body
    assert "corrections" not in body
    assert "changes" not in body
    assert "valley-free" in body["detail"]


def test_as_relationship_repair_409_example_has_five_edges_four_paths():
    # The documented infeasible witness uses exactly 5 relationships/4 paths.
    assert len(AS_REPAIR_INFEASIBLE["relationships"]) == 5
    assert len(AS_REPAIR_INFEASIBLE["paths"]) == 4


def test_as_relationship_repair_missing_relationship_returns_422():
    response = client.post(
        "/as-relationship-repair",
        json={
            "relationships": [
                {"type": "customer_provider", "customer": 200,
                 "provider": 100},
            ],
            "paths": [[100, 200, 300]],
        },
    )
    assert response.status_code == 422
    # Cross-entry check fails at the whole-model validator.
    assert response.json()["detail"][0]["loc"] == ["body"]
    assert "no relationship" in response.json()["detail"][0]["msg"]


def test_as_relationship_repair_duplicate_as_in_path_returns_422():
    response = client.post(
        "/as-relationship-repair",
        json={
            "relationships": [{"type": "peer", "peers": [1, 2]}],
            "paths": [[1, 2, 1]],
        },
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "paths" for err in response.json()["detail"])
    assert "duplicate AS" in response.json()["detail"][0]["msg"]


def test_as_relationship_repair_empty_path_returns_422():
    response = client.post(
        "/as-relationship-repair",
        json={"relationships": [], "paths": [[]]},
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "paths" for err in response.json()["detail"])


def test_as_relationship_repair_duplicate_pair_returns_422():
    response = client.post(
        "/as-relationship-repair",
        json={
            "relationships": [
                {"type": "customer_provider", "customer": 1,
                 "provider": 2},
                {"type": "peer", "peers": [2, 1]},
            ],
            "paths": [],
        },
    )
    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == ["body"]
    assert "duplicate relationship" in response.json()["detail"][0]["msg"]


def test_as_relationship_repair_self_relationship_returns_422():
    response = client.post(
        "/as-relationship-repair",
        json={"relationships": [{"type": "peer", "peers": [5, 5]}],
              "paths": []},
    )
    assert response.status_code == 422
    locs = [tuple(err["loc"]) for err in response.json()["detail"]]
    assert any(loc[-2:] == ("relationships", 0) for loc in locs)


def test_as_relationship_repair_shape_errors_return_422():
    cases = [
        # customer_provider must not carry peers
        {"relationships": [
            {"type": "customer_provider", "customer": 1, "peers": [2, 3]}],
         "paths": []},
        # customer_provider missing provider
        {"relationships": [
            {"type": "customer_provider", "customer": 1}], "paths": []},
        # peer missing peers
        {"relationships": [{"type": "peer"}], "paths": []},
        # peer carrying customer/provider
        {"relationships": [
            {"type": "peer", "customer": 1, "provider": 2, "peers": [3, 4]}],
         "paths": []},
        # three peers
        {"relationships": [
            {"type": "peer", "peers": [1, 2, 3]}], "paths": []},
        # unknown type
        {"relationships": [{"type": "sibling", "a": 1}], "paths": []},
    ]
    for body in cases:
        response = client.post("/as-relationship-repair", json=body)
        assert response.status_code == 422, body


def test_as_relationship_repair_asn_errors_return_422():
    cases = [
        {"relationships": [], "paths": [[4294967296]]},
        {"relationships": [], "paths": [[-1]]},
        {"relationships": [{"type": "peer", "peers": [True, 2]}],
         "paths": []},
        {"relationships": [{"type": "peer", "peers": ["1", 2]}],
         "paths": []},
        {"relationships": [
            {"type": "customer_provider", "customer": None,
             "provider": 2}],
         "paths": []},
        {"relationships": [
            {"type": "customer_provider", "customer": 1.5,
             "provider": 2}],
         "paths": []},
    ]
    for body in cases:
        response = client.post("/as-relationship-repair", json=body)
        assert response.status_code == 422, body


def test_as_relationship_repair_asn_boundaries_accepted():
    response = client.post(
        "/as-relationship-repair",
        json={
            "relationships": [
                {"type": "customer_provider", "customer": 4294967295,
                 "provider": 0},
            ],
            "paths": [[4294967295, 0]],
        },
    )
    assert response.status_code == 200


def test_as_relationship_repair_limit_boundaries():
    # Exactly 9 relationships accepted; a 9-edge chain valley-free with 20
    # paths must stay inside both limits.
    relationships = [
        {"type": "peer", "peers": [i, i + 100]} for i in range(1, 10)
    ]
    paths = [[i, i + 100] for i in range(1, 10)]
    response = client.post(
        "/as-relationship-repair",
        json={"relationships": relationships, "paths": paths},
    )
    assert response.status_code == 200

    response = client.post(
        "/as-relationship-repair",
        json={
            "relationships": [
                {"type": "peer", "peers": [1, 2]}],
            "paths": [[1, 2]] * 20,
        },
    )
    assert response.status_code == 200


def test_as_relationship_repair_more_than_nine_relationships_returns_422():
    response = client.post(
        "/as-relationship-repair",
        json={
            "relationships": [
                {"type": "peer", "peers": [i, 100 + i]} for i in range(10)
            ],
            "paths": [],
        },
    )
    assert response.status_code == 422
    assert "9" in response.json()["detail"][0]["msg"]


def test_as_relationship_repair_more_than_twenty_paths_returns_422():
    response = client.post(
        "/as-relationship-repair",
        json={
            "relationships": [{"type": "peer", "peers": [1, 2]}],
            "paths": [[1, 2]] * 21,
        },
    )
    assert response.status_code == 422
    assert "20" in response.json()["detail"][0]["msg"]


def test_as_relationship_repair_wrong_container_types_return_422():
    for body in (
        {"relationships": {}, "paths": []},
        {"relationships": [], "paths": {}},
        {"relationships": "x", "paths": []},
        {"paths": [{"not": "a list"}]},
        {"paths": [123]},
    ):
        response = client.post("/as-relationship-repair", json=body)
        assert response.status_code == 422, body


def test_as_relationship_repair_is_documented_in_openapi():
    spec = client.get("/openapi.json").json()
    assert "/as-relationship-repair" in spec["paths"]
    operation = spec["paths"]["/as-relationship-repair"]["post"]
    assert "200" in operation["responses"]
    assert "409" in operation["responses"]
    assert "422" in operation["responses"]
    examples = operation["requestBody"]["content"]["application/json"][
        "examples"
    ]
    assert "one_shared_repair" in examples
    assert "no_feasible_repair" in examples
    assert "missing_relationship" in examples
    response_examples = operation["responses"]["200"]["content"][
        "application/json"
    ]["examples"]
    assert "one_shared_repair" in response_examples
    schema = spec["components"]["schemas"]["AsRelationshipRepairResponse"]
    assert set(schema["properties"]) == {
        "violating_path_indices", "corrections", "changes",
    }
    correction_schema = spec["components"]["schemas"][
        "AsRelationshipCorrection"
    ]
    assert set(correction_schema["properties"]) == {
        "type", "customer", "provider", "peers",
    }
    assert correction_schema["properties"]["type"]["enum"] == [
        "customer_provider", "peer",
    ]


def test_nat64_codec_roundtrip_all_prefix_lengths():
    for prefix, mapped in [
        ("2001:db8::/32", "2001:db8:c000:221::"),
        ("2001:db8:100::/40", "2001:db8:1c0:2:21::"),
        ("2001:db8:1::/48", "2001:db8:1:c000:2:2100::"),
        ("2001:db8:1:100::/56", "2001:db8:1:1c0:0:221::"),
        ("2001:db8:1:2::/64", "2001:db8:1:2:c0:2:2100:0"),
        ("2001:db8:1:2::/96", "2001:db8:1:2::c000:221"),
    ]:
        response = client.post(
            "/nat64-codec",
            json={"prefix": prefix,
                  "encode": ["192.0.2.33"], "decode": [mapped]},
        )
        assert response.status_code == 200, (prefix, response.text)
        assert response.json() == {
            "encoded": [mapped], "decoded": ["192.0.2.33"],
        }


def test_nat64_codec_keeps_order_and_equal_length():
    response = client.post(
        "/nat64-codec",
        json={
            "prefix": "2001:db8::/96",
            "encode": ["10.0.0.1", "10.0.0.2", "192.0.2.33"],
            "decode": [
                "2001:db8::a00:1", "2001:db8::a00:2",
                "2001:db8::c000:221",
            ],
        },
    )
    assert response.status_code == 200, response.text
    assert response.json() == {
        "encoded": [
            "2001:db8::a00:1", "2001:db8::a00:2",
            "2001:db8::c000:221"],
        "decoded": ["10.0.0.1", "10.0.0.2", "192.0.2.33"],
    }


def test_nat64_codec_empty_lists_accepted():
    response = client.post(
        "/nat64-codec", json={"prefix": "2001:db8::/96"})
    assert response.status_code == 200
    assert response.json() == {"encoded": [], "decoded": []}


def test_nat64_codec_invalid_prefixes_return_422():
    for prefix in [
        "2001:db8::/31", "2001:db8::/47", "2001:db8::/65",
        "2001:db8::/97", "2001:db8::/128", "2001:db8::/0",
        "2001:db8::1/96", "10.0.0.0/32", "2001:db8::",
    ]:
        response = client.post(
            "/nat64-codec", json={"prefix": prefix})
        assert response.status_code == 422, prefix


def test_nat64_codec_invalid_or_wrong_family_addresses_return_422():
    cases = [
        {"prefix": "2001:db8::/96", "encode": ["2001:db8::1"]},
        {"prefix": "2001:db8::/96", "decode": ["10.0.0.1"]},
        {"prefix": "2001:db8::/96", "encode": ["10.0.0.1/32"]},
        {"prefix": "2001:db8::/96", "decode": ["2001:db8::1/128"]},
        {"prefix": "2001:db8::/96", "encode": ["not-an-ip"]},
        {"prefix": "2001:db8::/96", "decode": [None]},
        {"prefix": None, "encode": [], "decode": []},
    ]
    for body in cases:
        response = client.post("/nat64-codec", json=body)
        assert response.status_code == 422, body


@pytest.mark.parametrize("prefix,address", [
    # non-zero u octet for each straddling prefix length
    ("2001:db8::/32", "2001:db8:c000:221:ff00::"),
    ("2001:db8:100::/40", "2001:db8:c0:2:ff21::"),
    ("2001:db8:1::/48", "2001:db8:0:c000:ff02:2100::"),
    ("2001:db8:1:100::/56", "2001:db8:0:c0:ff00:221::"),
    ("2001:db8:1:2::/64", "2001:db8:1:2:ffc0:2:2100:0"),
    # non-zero suffix
    ("2001:db8::/32", "2001:db8:c000:221::1"),
    ("2001:db8:100::/40", "2001:db8:c0:2:21::1"),
    ("2001:db8:1::/48", "2001:db8:0:c000:2:2100:0:1"),
    ("2001:db8:1:100::/56", "2001:db8:0:c0:0:221:0:1"),
    ("2001:db8:1:2::/64", "2001:db8:1:2:c0:2:2100:1"),
    # outside the translation prefix
    ("2001:db8::/96", "2001:db9::1"),
])
def test_nat64_codec_non_canonical_mappings_return_422(prefix, address):
    response = client.post(
        "/nat64-codec", json={"prefix": prefix, "decode": [address]})
    assert response.status_code == 422, (address, response.text)


def test_nat64_codec_slash96_has_no_u_octet_or_suffix():
    # Bytes 12-15 are all IPv4 under /96: a non-zero byte 8 position is just
    # part of the embedded IPv4 address and stays valid.
    response = client.post(
        "/nat64-codec",
        json={"prefix": "2001:db8::/96",
              "decode": ["2001:db8:0:0:0:0:0:c0"]},
    )
    assert response.status_code == 200
    assert response.json() == {"encoded": [], "decoded": ["0.0.0.192"]}


def test_nat64_codec_is_documented_in_openapi():
    spec = client.get("/openapi.json").json()
    assert "/nat64-codec" in spec["paths"]
    operation = spec["paths"]["/nat64-codec"]["post"]
    assert "200" in operation["responses"]
    assert "422" in operation["responses"]
    examples = operation["requestBody"]["content"]["application/json"][
        "examples"
    ]
    assert "rfc6052_slash32_roundtrip" in examples
    assert "slash96_direct_append" in examples
    assert "non_canonical_suffix_rejected" in examples
    response_examples = operation["responses"]["200"]["content"][
        "application/json"
    ]["examples"]
    assert "rfc6052_slash32_roundtrip" in response_examples
    schema = spec["components"]["schemas"]["Nat64CodecResponse"]
    assert set(schema["properties"]) == {"encoded", "decoded"}


# ---------------------------------------------------------------------------
# POST /free-addresses
# ---------------------------------------------------------------------------


def test_free_addresses_basic_ordinal_walk():
    response = client.post(
        "/free-addresses",
        json={"scope": "192.0.2.0/29", "indices": [0, 1, 7]},
    )
    assert response.status_code == 200
    assert response.json() == {
        "free_total": "8",
        "addresses": ["192.0.2.0", "192.0.2.1", "192.0.2.7"],
    }


def test_free_addresses_union_then_clip_overlapping_and_out_of_scope():
    response = client.post(
        "/free-addresses",
        json={
            "scope": "192.0.2.0/29",
            "occupied": [
                "192.0.2.2/31",
                "192.0.2.3/32",      # duplicate inside the /31
                "203.0.113.64/26",    # disjoint, beyond scope, clipped away
            ],
            "indices": [0, 1, 2, 0],
        },
    )
    assert response.status_code == 200
    assert response.json() == {
        "free_total": "6",
        "addresses": ["192.0.2.0", "192.0.2.1", "192.0.2.4", "192.0.2.0"],
    }


def test_free_addresses_empty_query_returns_total_only():
    response = client.post(
        "/free-addresses",
        json={"scope": "10.0.0.0/24", "occupied": ["10.0.0.0/30"]},
    )
    assert response.status_code == 200
    assert response.json() == {"free_total": "252", "addresses": []}

    response = client.post(
        "/free-addresses",
        json={"scope": "10.0.0.0/24", "occupied": ["10.0.0.0/30"],
              "indices": []},
    )
    assert response.status_code == 200
    assert response.json() == {"free_total": "252", "addresses": []}


def test_free_addresses_every_address_bit_counts_ipv4():
    response = client.post(
        "/free-addresses",
        json={"scope": "192.0.2.0/30", "indices": [0, 3]},
    )
    assert response.status_code == 200
    assert response.json() == {
        "free_total": "4",
        "addresses": ["192.0.2.0", "192.0.2.3"],
    }


def test_free_addresses_ipv6_slash0_with_decimal_string_ordinals():
    response = client.post(
        "/free-addresses",
        json={
            "scope": "::/0",
            "occupied": ["::/1"],
            "indices": [0, 1, "170141183460469231731687303715884105726"],
        },
    )
    assert response.status_code == 200
    assert response.json() == {
        "free_total": "170141183460469231731687303715884105728",
        "addresses": [
            "8000::",
            "8000::1",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe",
        ],
    }


def test_free_addresses_ipv6_slash0_no_occupied_extremes():
    response = client.post(
        "/free-addresses",
        json={"scope": "::/0", "indices": [0, 340282366920938463463374607431768211455]},
    )
    assert response.status_code == 200
    assert response.json()["free_total"] == "340282366920938463463374607431768211456"
    assert response.json()["addresses"] == [
        "::",
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    ]


def test_free_addresses_duplicate_and_unordered_indices_keep_input_order():
    response = client.post(
        "/free-addresses",
        json={"scope": "10.0.0.0/29", "occupied": ["10.0.0.4/32"],
              "indices": [3, 0, 4, 6]},
    )
    assert response.status_code == 200
    assert response.json()["addresses"] == [
        "10.0.0.3", "10.0.0.0", "10.0.0.5", "10.0.0.7",
    ]


def test_free_addresses_host_prefix_scope():
    response = client.post(
        "/free-addresses",
        json={"scope": "10.0.0.1", "indices": [0]},
    )
    assert response.status_code == 200
    assert response.json() == {"free_total": "1", "addresses": ["10.0.0.1"]}


def test_free_addresses_occupied_supernet_covers_scope():
    response = client.post(
        "/free-addresses",
        json={"scope": "10.0.0.0/24",
              "occupied": ["0.0.0.0/0", "10.0.0.5/32"]},
    )
    assert response.status_code == 200
    assert response.json() == {"free_total": "0", "addresses": []}


def test_free_addresses_index_equal_to_total_returns_422():
    response = client.post(
        "/free-addresses",
        json={"scope": "10.0.0.0/30", "occupied": ["10.0.0.0/32"],
              "indices": [3]},
    )
    assert response.status_code == 422
    assert "out of range" in response.json()["detail"]


def test_free_addresses_index_when_zero_free_returns_422():
    response = client.post(
        "/free-addresses",
        json={"scope": "10.0.0.0/30", "occupied": ["10.0.0.0/30"],
              "indices": [0]},
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert isinstance(detail, str)
    assert "0 free addresses" in detail


def test_free_addresses_negative_index_returns_422():
    response = client.post(
        "/free-addresses",
        json={"scope": "10.0.0.0/24", "indices": [-1]},
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "indices" for err in response.json()["detail"])


def test_free_addresses_invalid_scope_returns_422():
    response = client.post(
        "/free-addresses", json={"scope": "10.0.0.1/24"}
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "scope" for err in response.json()["detail"])


def test_free_addresses_missing_scope_returns_422():
    response = client.post("/free-addresses", json={"indices": [0]})
    assert response.status_code == 422


def test_free_addresses_invalid_occupied_cidr_returns_422():
    response = client.post(
        "/free-addresses",
        json={"scope": "10.0.0.0/24", "occupied": ["bogus"]},
    )
    assert response.status_code == 422
    assert any(
        err["loc"][-1] == "occupied" for err in response.json()["detail"]
    )


def test_free_addresses_wrong_family_occupied_returns_422():
    response = client.post(
        "/free-addresses",
        json={"scope": "10.0.0.0/24", "occupied": ["2001:db8::/32"]},
    )
    assert response.status_code == 422
    assert "address family" in response.json()["detail"]


@pytest.mark.parametrize("bad", ["abc", "-1", "", " 1", "1.0", True, 1.5, None])
def test_free_addresses_malformed_index_returns_422(bad):
    response = client.post(
        "/free-addresses",
        json={"scope": "10.0.0.0/24", "indices": [bad]},
    )
    assert response.status_code == 422, bad
    assert any(err["loc"][-1] == "indices" for err in response.json()["detail"])


def test_free_addresses_indices_not_a_list_returns_422():
    response = client.post(
        "/free-addresses",
        json={"scope": "10.0.0.0/24", "indices": 3},
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "indices" for err in response.json()["detail"])


def test_free_addresses_is_documented_in_openapi():
    spec = client.get("/openapi.json").json()
    assert "/free-addresses" in spec["paths"]
    operation = spec["paths"]["/free-addresses"]["post"]
    assert "200" in operation["responses"]
    assert "422" in operation["responses"]
    examples = operation["requestBody"]["content"]["application/json"][
        "examples"
    ]
    assert "overlapping_and_out_of_scope_occupied" in examples
    assert "ipv6_huge_ordinal_as_string" in examples
    assert "index_at_free_total_rejected" in examples
    response_examples = operation["responses"]["200"]["content"][
        "application/json"
    ]["examples"]
    assert "overlapping_and_out_of_scope_occupied" in response_examples
    schema = spec["components"]["schemas"]["FreeAddressesResponse"]
    assert set(schema["properties"]) == {"free_total", "addresses"}
