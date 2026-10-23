"""A small, handmade example shared by the engine tests."""

from datetime import date, timedelta
from ipaddress import IPv4Address
from typing import Literal

from engine.policy_analysis import DatasetInputs, communication_flow, TrafficFlow
from schemas.asset import Asset
from schemas.communication import RequiredCommunication
from schemas.firewall_rule import FirewallRule, Service
from schemas.usage import RuleUsage

REVIEW_DATE = date(2026, 10, 22)
HTTPS = Service("tcp", 443)
DNS = Service("udp", 53)


def make_rule(
    rule_id: str = "allow_pacs",
    action: Literal["allow", "deny"] = "allow",
) -> FirewallRule:
    return FirewallRule(
        rule_id,
        ["staff"],
        ["servers"],
        [IPv4Address("10.1.1.10")],
        [IPv4Address("10.2.1.10")],
        [HTTPS],
        action
    )


def make_dataset(rules=None, required=True) -> DatasetInputs:
    assets = [
        Asset("workstation", "workstation", IPv4Address("10.1.1.10"), "staff", "low"),
        Asset("pacs", "pacs", IPv4Address("10.2.1.10"), "servers", "critical"),
        Asset("legacy", "server", IPv4Address("10.2.1.20"), "servers", "high")
    ]
    rules = [make_rule()] if rules is None else rules
    communication = RequiredCommunication(
        "view_images",
        "workstation",
        "pacs",
        HTTPS,
        "View patient images",
        "Handmade test example"
    )
    usage = [
        RuleUsage(rule.rule_id, REVIEW_DATE - timedelta(days=day), 0)
        for rule in rules for day in range(90)
    ]
    return DatasetInputs(assets, rules, usage, [communication] if required else [])


def make_flow(dataset) -> TrafficFlow:
    communication = RequiredCommunication("test", "workstation", "pacs", HTTPS, "Test", "Test")
    return communication_flow(communication, {asset.asset_id: asset for asset in dataset.assets})
