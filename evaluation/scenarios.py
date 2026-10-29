"""Load the separate answer keys and check one rule removal at a time."""

import csv
from pathlib import Path

from engine.policy_analysis import DatasetInputs, TrafficFlow, evaluate_policy
from schemas.firewall_rule import Service


def _read_csv(path: Path, columns: set[str]) -> list[dict]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        headings = list(reader.fieldnames or [])
        if set(headings) != columns or len(headings) != len(columns):
            raise ValueError(f"{path.name}: incorrect column headings.")
        rows = list(reader)
    for row in rows:
        if None in row or any(value is None or not value.strip() for value in row.values()):
            raise ValueError(f"{path.name}: a row has missing or extra values.")
    return [{key: value.strip() for key, value in row.items()} for row in rows]


def load_scenarios(path: Path, truth: DatasetInputs) -> list[dict]:
    rows = _read_csv(path, {
        "scenario_id", "scenario_type", "source_asset_id", "destination_asset_id",
        "service_protocol", "service_destination_port", "expected_action", "description",
    })
    known_assets = {asset.asset_id for asset in truth.assets}
    seen_ids = set()
    for row in rows:
        if row["scenario_id"] in seen_ids:
            raise ValueError(f"Duplicate scenario ID: {row['scenario_id']}.")
        seen_ids.add(row["scenario_id"])
        if row["source_asset_id"] not in known_assets or row["destination_asset_id"] not in known_assets:
            raise ValueError("A scenario references an unknown asset.")
        desired_action = {"use": "allow", "attack": "deny"}.get(row["scenario_type"])
        if desired_action is None or row["expected_action"] != desired_action:
            raise ValueError("Use scenarios must expect allow; attack scenarios must expect deny.")
        port = int(row["service_destination_port"])
        if row["service_protocol"] not in {"tcp", "udp"} or not 1 <= port <= 65535:
            raise ValueError("A scenario has an unsupported protocol or port.")
    if not rows:
        raise ValueError("At least one evaluation scenario is required.")
    return rows


def load_expected_recommendations(path: Path, truth: DatasetInputs) -> dict[str, dict]:
    rows = _read_csv(path, {"rule_id", "expected_recommendation", "justification"})
    answers = {}
    for row in rows:
        if row["rule_id"] in answers:
            raise ValueError(f"Duplicate expected rule ID: {row['rule_id']}.")
        if row["expected_recommendation"] not in {"retain", "removal_candidate", "investigate"}:
            raise ValueError("An expected recommendation has an unsupported label.")
        answers[row["rule_id"]] = row
    if set(answers) != {rule.rule_id for rule in truth.firewall_policy}:
        raise ValueError("Expected recommendations must contain exactly one answer per rule.")
    return answers


def scenario_removal_results(
    truth: DatasetInputs, scenarios: list[dict], rule_id: str,
) -> list[dict]:
    """
    Evaluate each scenario against the original policy and one removed rule.
    """

    assets = {asset.asset_id: asset for asset in truth.assets}
    results = []
    for scenario in scenarios:
        source = assets[scenario["source_asset_id"]]
        destination = assets[scenario["destination_asset_id"]]
        service = Service(scenario["service_protocol"], int(scenario["service_destination_port"]))
        flow = TrafficFlow(
            source.asset_id, destination.asset_id, source.zone, destination.zone,
            source.ip_address, destination.ip_address, service,
        )
        before = evaluate_policy(truth.firewall_policy, flow)
        after = evaluate_policy(truth.firewall_policy, flow, excluded_rule_id=rule_id)
        attack = scenario["scenario_type"] == "attack"
        if not attack and before.action != "allow":
            raise ValueError(f"{scenario['scenario_id']}: required use is already blocked.")
        results.append({
            "scenario_id": scenario["scenario_id"],
            "scenario_type": scenario["scenario_type"],
            "expected_action": scenario["expected_action"],
            "before_action": before.action,
            "after_action": after.action,
            "before_rule_id": before.matched_rule_id or "<default>",
            "after_rule_id": after.matched_rule_id or "<default>",
            "blocked_use": not attack and before.action == "allow" and after.action == "deny",
            "newly_allowed_attack": attack and before.action == "deny" and after.action == "allow",
            "preexisting_attack_exposure": attack and before.action == "allow",
            "closed_attack_exposure": attack and before.action == "allow" and after.action == "deny",
        })
    return results
