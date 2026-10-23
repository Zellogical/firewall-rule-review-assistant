"""Check the basic input and first-match behavior."""

from dataclasses import replace
from ipaddress import IPv4Network

import pytest

from engine.policy_analysis import InputValidationError, evaluate_policy, load_assets_csv, validate_inputs
from schemas.firewall_rule import Service
from tests.sample_data import DNS, make_dataset, make_flow, make_rule


def test_csv_requires_the_expected_columns(tmp_path):
    path = tmp_path / "assets.csv"
    path.write_text("asset_id\nworkstation\n", encoding="utf-8")
    with pytest.raises(InputValidationError):
        load_assets_csv(path)


def test_validation_rejects_duplicate_assets_and_unknown_references():
    dataset = make_dataset()
    validate_inputs(dataset)
    with pytest.raises(InputValidationError):
        validate_inputs(replace(dataset, assets=dataset.assets + [dataset.assets[0]]))
    unknown = replace(dataset.required_communications[0], destination_asset_id="missing")
    with pytest.raises(InputValidationError):
        validate_inputs(replace(dataset, required_communications=[unknown]))


def test_first_match_wins_and_unmatched_traffic_is_denied():
    flow = make_flow(make_dataset())
    deny = make_rule("protect_pacs", "deny")
    allow = make_rule()
    assert evaluate_policy([deny, allow], flow).matched_rule_id == "protect_pacs"
    assert evaluate_policy([allow, deny], flow).action == "allow"
    assert evaluate_policy([], flow).action == "deny"
    assert evaluate_policy([], flow).used_default


def test_matching_checks_subnets_zones_protocols_ports_and_any():
    flow = make_flow(make_dataset())
    rule = replace(make_rule(), source_addresses=[IPv4Network("10.1.1.0/24")])
    assert evaluate_policy([rule], flow).action == "allow"
    assert evaluate_policy([rule], replace(flow, source_zone="guest")).action == "deny"
    assert evaluate_policy([rule], replace(flow, service=Service("udp", 443))).action == "deny"
    assert evaluate_policy([rule], replace(flow, service=Service("tcp", 80))).action == "deny"
    wildcard = replace(rule, source_zones=["any"], destination_addresses=["any"], services=["any"])
    assert evaluate_policy([wildcard], replace(flow, service=DNS)).action == "allow"
