"""
Load and analyze a simplified ordered firewall policy.

The analyzer is driven by the structure of the supplied datasets, not by the
healthcare-specific values used by this project's synthetic data generator.
For example, asset_type and zone may contain any non-empty labels, not just
the healthcare-specific values used in the synthetic datasets.

The analysis uses only these four inputs:

* ``assets.csv`` - assets, IP addresses, zones, and criticality
* ``firewall_policy.csv`` - ordered allow/deny rules
* ``rule_usage.csv`` - rule hit history
* ``required_communications.csv`` - communications that must be preserved

At a high level the engine does the following:

1. Load the CSV files and validate their required columns and relationships.
2. Match traffic against zone, address, protocol, and destination-port fields.
3. Evaluate rules from top to bottom; the first match wins.
4. Re-evaluate the policy with one rule temporarily removed.
5. Report what changed: required traffic blocked, traffic newly allowed,
   undocumented traffic removed, and which rule/default action takes over.

Evaluation scenarios and expected recommendations are deliberately not read by
this module so they can be an answer key for later evaluation.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import date
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from pathlib import Path
from typing import Literal, cast

from schemas.asset import Asset, Criticality
from schemas.communication import RequiredCommunication
from schemas.firewall_rule import Address, FirewallPolicy, FirewallRule, Service, ServiceMatch
from schemas.usage import RuleUsage, RuleUsageHistory


PolicyAction = Literal["allow", "deny"]
CRITICALITIES = {"low", "medium", "high", "critical"}
SUPPORTED_PROTOCOLS = {"tcp", "udp"}


class InputValidationError(ValueError):
    """
    Custom error raised when an input CSV cannot be loaded correctly.
    """


@dataclass(frozen=True)
class DatasetInputs:
    """
    Each of these represents a dataset available to the policy analysis engine.

    Attributes:
        assets: A list of all assets in the modeled environment.
        firewall_policy: The ordered firewall policy to analyze.
        rule_usage: The observed daily hit history for policy rules.
        required_communications: The communications that the modeled environment must preserve.
    """

    assets: list[Asset]
    firewall_policy: FirewallPolicy
    rule_usage: RuleUsageHistory
    required_communications: list[RequiredCommunication]


@dataclass(frozen=True)
class TrafficFlow:
    """
    Represents a single observed or simulated network flow between two assets.

    Attributes:
        source_asset_id: The unique identifier of the asset that initiated the flow.
        destination_asset_id: The unique identifier of the asset that received the flow.
        source_zone: The zone to which the source asset belongs.
        destination_zone: The zone to which the destination asset belongs.
        source_address: The IP address of the source asset.
        destination_address: The IP address of the destination asset.
        service: The network service used for the flow, for example, TCP port 443 for HTTPS.
    """

    source_asset_id: str
    destination_asset_id: str
    source_zone: str
    destination_zone: str
    source_address: IPv4Address
    destination_address: IPv4Address
    service: Service

    @property
    def key(self) -> tuple[str, str, str, int]:
        """
        Return a stable key for comparing the flow with documented requirements.
        """

        return (
            self.source_asset_id,
            self.destination_asset_id,
            self.service.protocol,
            self.service.destination_port,
        )


@dataclass(frozen=True)
class PolicyDecision:
    """
    Represents the result of evaluating a traffic flow against the firewall policy.

    For example, if a flow is allowed by the policy, the action will be "allow" and the matched_rule_id will indicate which rule permitted the flow.
    If the flow is denied, the action will be "deny" and matched_rule_id will indicate which rule blocked it, or None if no rule matched.

    Attributes:
        action: The action taken by the firewall policy for this flow, either "allow" or "deny".
        matched_rule_id: The identifier of the firewall rule that matched this flow, or None if no rule matched.
    """

    action: PolicyAction
    matched_rule_id: str | None

    @property
    def used_default(self) -> bool:
        return self.matched_rule_id is None


@dataclass(frozen=True)
class FlowChange:
    """
    A flow whose allow/deny behavior changed after a rule was removed.
    """

    flow: TrafficFlow
    before: PolicyDecision
    after: PolicyDecision
    destination_criticality: Criticality


@dataclass(frozen=True)
class RuleRemovalAnalysis:
    """
    Counterfactual result for removing exactly one firewall rule.

    ``observed_replacement_rule_ids`` contains rules (or ``<default>``) that still
    produce the target rule's action for modeled flows matching the target
    after it is removed. This intentionally also captures a fully shadowed
    rule: an earlier rule may already be handling all of the target's traffic.
    """

    rule_id: str
    rule_action: PolicyAction
    blocked_required_communication_ids: tuple[str, ...]
    newly_allowed_flows: tuple[FlowChange, ...]
    newly_allowed_critical_flows: tuple[FlowChange, ...]
    removed_undocumented_flows: tuple[FlowChange, ...]
    removed_undocumented_critical_flows: tuple[FlowChange, ...]
    changed_flows: tuple[FlowChange, ...]
    observed_replacement_rule_ids: tuple[str, ...]

    @property
    def has_modeled_effect(self) -> bool:
        """
        Whether removing the rule changes allow/deny behavior for a modeled flow.
        """

        return bool(self.changed_flows)

    @property
    def is_behaviorally_redundant(self) -> bool:
        """
        Whether modeled target traffic keeps the same action without the rule.
        """

        return not self.changed_flows and bool(self.observed_replacement_rule_ids)


# ---------------------------------------------------------------------------
# CSV loading helpers
# ---------------------------------------------------------------------------


def _read_csv(path: Path, required_columns: set[str]) -> list[dict[str, str]]:
    """
    Helpers for reading CSV files and validating their structure.

    Args:
        list[str]: path: The path to the CSV file to read.
        list[str]: required_columns: A set of column names that must be present in the CSV
    """

    if not path.is_file():
        raise InputValidationError(f"Required input file does not exist: {path}")

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        columns = set(reader.fieldnames or [])

        duplicate_columns = _duplicate_values(list(reader.fieldnames or []))
        if duplicate_columns:
            raise InputValidationError(
                f"{path.name} has duplicate columns: {', '.join(duplicate_columns)}"
            )

        missing = required_columns - columns
        if missing:
            raise InputValidationError(
                f"{path.name} is missing required columns: {', '.join(sorted(missing))}"
            )

        rows: list[dict[str, str]] = []
        for row_number, row in enumerate(reader, start=2):
            if None in row:
                raise InputValidationError(
                    f"{path.name} row {row_number}: row contains more values than columns."
                )
            rows.append({key: (value or "").strip() for key, value in row.items()})

        return rows


def _required_text(
    row: dict[str, str],
    column: str,
    file_name: str,
    row_number: int,
) -> str:
    """
    Helper to validate that a required column in a CSV row is not empty.

    For example, if the "asset_id" column is empty in row 5 of "assets.csv",
    this function will raise an InputValidationError indicating that the value cannot be empty.
    """

    value = row[column].strip()
    if not value:
        raise InputValidationError(f"{file_name} row {row_number}: {column} cannot be empty.")

    return value


def _split_values(value: str, field_name: str) -> list[str]:
    """
    Helper to split a semicolon-separated string into a list of values, while validating that the
    list is not empty and does not contain "any" alongside other values.

    For example, "value1; value2" becomes ["value1", "value2"], while "any" becomes ["any"].
    """

    values = [item.strip() for item in value.split(";") if item.strip()]
    if not values:
        raise InputValidationError(f"{field_name} must contain at least one value.")

    contains_any = any(item.casefold() == "any" for item in values)
    if contains_any:
        if len(values) > 1:
            raise InputValidationError(f"{field_name} cannot combine 'any' with specific values.")
        return ["any"]

    return values


def _parse_port(value: str, context: str) -> int:
    """
    Helper to validate that a port number is an integer between 1 and 65535.
    """

    try:
        port = int(value)
    except ValueError as error:
        raise InputValidationError(f"{context}: destination port must be an integer.") from error

    if not 1 <= port <= 65535:
        raise InputValidationError(f"{context}: destination port must be between 1 and 65535.")

    return port


def _parse_service(value: str, context: str) -> ServiceMatch:
    """
    Helper to parse a service string into a ServiceMatch object.

    For example, "tcp:443" becomes ServiceMatch(protocol="tcp", destination_port=443).
    """

    value = value.strip().lower()
    if value == "any":
        return "any"

    parts = value.split(":", maxsplit=1)
    if len(parts) != 2:
        raise InputValidationError(
            f"{context}: service must be 'any' or use protocol:destination_port."
        )

    protocol, port_text = parts
    if protocol not in SUPPORTED_PROTOCOLS:
        raise InputValidationError(f"{context}: protocol must be tcp or udp.")

    return Service(
        cast(Literal["tcp", "udp"], protocol),
        _parse_port(port_text, context),
    )


def _parse_address(value: str, context: str) -> Address:
    """
    Helper to parse an address string into an Address object.

    The value must be either a single IPv4 address, an IPv4 subnet in CIDR notation, or the string "any".
    """

    value = value.strip().lower()
    if value == "any":
        return "any"

    try:
        parsed = ip_network(value, strict=False) if "/" in value else ip_address(value)
    except ValueError as error:
        raise InputValidationError(
            f"{context}: invalid IPv4 address or subnet '{value}'."
        ) from error

    if not isinstance(parsed, (IPv4Address, IPv4Network)):
        raise InputValidationError(f"{context}: IPv6 is outside this prototype's scope.")

    return parsed

# Loading functions for each of the four CSV files used by the policy analysis engine.
# Each function reads the corresponding CSV file, validates its structure and contents,
# and returns a list of dataclass instances representing the data.


def load_assets_csv(path: Path) -> list[Asset]:
    """
    Load assets while allowing arbitrary non-empty asset types and zones.
    """

    columns = {"asset_id", "asset_type", "ip_address", "zone", "criticality"}
    rows = _read_csv(path, columns)
    assets: list[Asset] = []

    for row_number, row in enumerate(rows, start=2):
        context = f"{path.name} row {row_number}"

        asset_id = _required_text(row, "asset_id", path.name, row_number)
        asset_type = _required_text(row, "asset_type", path.name, row_number)
        address = _parse_address(row["ip_address"], context)
        zone = _required_text(row, "zone", path.name, row_number)
        criticality = _required_text(row, "criticality", path.name, row_number).lower()

        if criticality not in CRITICALITIES:
            raise InputValidationError(f"{context}: unsupported criticality '{criticality}'.")

        if not isinstance(address, IPv4Address):
            raise InputValidationError(f"{context}: asset IP must be one IPv4 address.")

        assets.append(
            Asset(
                asset_id,
                asset_type,
                address,
                zone,
                cast(Criticality, criticality)
            )
        )

    return assets


def load_firewall_policy_csv(path: Path) -> FirewallPolicy:
    """
    Load an ordered firewall policy from CSV.
    """

    columns = {
        "rule_id",
        "source_zones",
        "destination_zones",
        "source_addresses",
        "destination_addresses",
        "services",
        "action"
    }
    rows = _read_csv(path, columns)
    policy: FirewallPolicy = []

    for row_number, row in enumerate(rows, start=2):
        context = f"{path.name} row {row_number}"
        rule_id = _required_text(row, "rule_id", path.name, row_number)
        action = _required_text(row, "action", path.name, row_number).lower()

        if action not in {"allow", "deny"}:
            raise InputValidationError(f"{context}: action must be allow or deny.")

        source_zones = _split_values(row["source_zones"], f"{context} source_zones")

        destination_zones = _split_values(
            row["destination_zones"], f"{context} destination_zones"
        )

        source_addresses = _split_values(
            row["source_addresses"], f"{context} source_addresses"
        )

        destination_addresses = _split_values(
            row["destination_addresses"], f"{context} destination_addresses"
        )

        services = _split_values(row["services"], f"{context} services")

        policy.append(
            FirewallRule(
                rule_id,
                source_zones,
                destination_zones,
                [_parse_address(value, context) for value in source_addresses],
                [_parse_address(value, context) for value in destination_addresses],
                [_parse_service(value, context) for value in services],
                cast(PolicyAction, action)
            )
        )

    return policy


def load_rule_usage_csv(path: Path) -> RuleUsageHistory:
    """
    Load the observed daily hit history for policy rules.
    """

    columns = {"rule_id", "observed_on", "hit_count"}

    rows = _read_csv(path, columns)
    usage: RuleUsageHistory = []

    for row_number, row in enumerate(rows, start=2):
        context = f"{path.name} row {row_number}"
        try:
            observed_on = date.fromisoformat(
                _required_text(row, "observed_on", path.name, row_number)
            )
            hit_count = int(_required_text(row, "hit_count", path.name, row_number))
        except ValueError as error:
            raise InputValidationError(
                f"{context}: observed_on must be YYYY-MM-DD and hit_count must be an integer."
            ) from error

        try:
            usage.append(
                RuleUsage(
                    _required_text(row, "rule_id", path.name, row_number),
                    observed_on,
                    hit_count,
                )
            )
        except ValueError as error:
            raise InputValidationError(f"{context}: {error}") from error

    return usage


def load_required_communications_csv(path: Path) -> list[RequiredCommunication]:
    """Load the communications that the modeled environment must preserve."""

    columns = {
        "communication_id",
        "source_asset_id",
        "destination_asset_id",
        "service_protocol",
        "service_destination_port",
        "purpose",
        "source_reference"
    }

    rows = _read_csv(path, columns)
    communications: list[RequiredCommunication] = []

    for row_number, row in enumerate(rows, start=2):
        context = f"{path.name} row {row_number}"
        protocol = _required_text(
            row, "service_protocol", path.name, row_number
        ).lower()
        if protocol not in SUPPORTED_PROTOCOLS:
            raise InputValidationError(f"{context}: service_protocol must be tcp or udp.")

        service = Service(
            cast(Literal["tcp", "udp"], protocol),
            _parse_port(
                _required_text(
                    row, "service_destination_port", path.name, row_number
                ),
                context
            )
        )

        communications.append(
            RequiredCommunication(
                _required_text(row, "communication_id", path.name, row_number),
                _required_text(row, "source_asset_id", path.name, row_number),
                _required_text(row, "destination_asset_id", path.name, row_number),
                service,
                _required_text(row, "purpose", path.name, row_number),
                _required_text(row, "source_reference", path.name, row_number)
            )
        )

    return communications


def load_dataset(input_directory: str | Path) -> DatasetInputs:
    """
    Load the four analyzer inputs from a dataset directory.

    Args:
        input_directory: The path to the directory containing the four CSV files.

    Returns:
        A DatasetInputs object containing the loaded assets, firewall policy, rule usage, and required communications.
    """

    directory = Path(input_directory)

    inputs = DatasetInputs(
        assets=load_assets_csv(directory / "assets.csv"),
        firewall_policy=load_firewall_policy_csv(directory / "firewall_policy.csv"),
        rule_usage=load_rule_usage_csv(directory / "rule_usage.csv"),
        required_communications=load_required_communications_csv(
            directory / "required_communications.csv"
        )
    )
    validate_inputs(inputs)

    return inputs


# ---------------------------------------------------------------------------
# Cross-file validation
# ---------------------------------------------------------------------------


def _duplicate_values(values: list[str]) -> list[str]:
    """
    Helper to find duplicate values in a list and return them as a sorted list of strings.
    """

    seen = set()
    duplicates = set()

    for value in values:
        if value in seen:
            duplicates.add(value)
        else:
            seen.add(value)

    return sorted(duplicates)


def _valid_service(service: object) -> bool:
    """
    Helper to validate that a service object is a Service instance with a supported protocol and a valid destination port.
    """

    return (
        isinstance(service, Service)
        and service.protocol in SUPPORTED_PROTOCOLS
        and isinstance(service.destination_port, int)
        and 1 <= service.destination_port <= 65535
    )


def validate_inputs(inputs: DatasetInputs) -> None:
    """
    Validate relationships that cannot be checked while loading one CSV.

    Args:
        inputs: The DatasetInputs object containing all four datasets to validate.
    """

    errors: list[str] = []

    # Check for duplicate IDs in each dataset
    asset_ids = [asset.asset_id for asset in inputs.assets]
    asset_addresses = [asset.ip_address for asset in inputs.assets]
    rule_ids = [rule.rule_id for rule in inputs.firewall_policy]
    communication_ids = [
        communication.communication_id for communication in inputs.required_communications
    ]

    # Report any duplicates found in the datasets
    for label, duplicates in (
        ("asset IDs", _duplicate_values(asset_ids)),
        ("asset IP addresses", _duplicate_values([str(addr) for addr in asset_addresses])),
        ("rule IDs", _duplicate_values(rule_ids)),
        ("communication IDs", _duplicate_values(communication_ids)),
    ):
        if duplicates:
            errors.append(f"Duplicate {label}: {', '.join(duplicates)}")

    known_assets = set(asset_ids)
    known_rules = set(rule_ids)

    # Validate that each asset has a non-empty asset_type and zone, and that required communications reference known assets.
    for asset in inputs.assets:
        # Asset type and zone are dataset-defined labels.  They only need to
        # exist; the policy engine does not require a predefined vocabulary.
        if not isinstance(asset.asset_type, str) or not asset.asset_type.strip():
            errors.append(f"{asset.asset_id} must have a non-empty asset_type.")
        if not isinstance(asset.zone, str) or not asset.zone.strip():
            errors.append(f"{asset.asset_id} must have a non-empty zone.")
        if asset.criticality not in CRITICALITIES:
            errors.append(f"{asset.asset_id} has unsupported criticality {asset.criticality}.")
        if not isinstance(asset.ip_address, IPv4Address):
            errors.append(f"{asset.asset_id} must use one IPv4 address.")

    # Validate that each required communication references known source and destination assets.
    for communication in inputs.required_communications:
        if communication.source_asset_id not in known_assets:
            errors.append(
                f"{communication.communication_id} has unknown source asset "
                f"{communication.source_asset_id}."
            )
        if communication.destination_asset_id not in known_assets:
            errors.append(
                f"{communication.communication_id} has unknown destination asset "
                f"{communication.destination_asset_id}."
            )
        if not _valid_service(communication.service):
            errors.append(f"{communication.communication_id} has an invalid service.")

    # Validate rule usage history
    usage_dates: set[tuple[str, date]] = set()
    for usage in inputs.rule_usage:
        usage_key = (usage.rule_id, usage.observed_on)
        if usage_key in usage_dates:
            errors.append(
                f"Usage history for {usage.rule_id} has duplicate date {usage.observed_on}."
            )
        usage_dates.add(usage_key)
        if usage.rule_id not in known_rules:
            errors.append(f"Usage history references unknown rule {usage.rule_id}.")
        if usage.hit_count < 0:
            errors.append(f"Usage history for {usage.rule_id} has a negative hit count.")

    # Validate each firewall rule's action, zones, addresses, and services.
    for rule in inputs.firewall_policy:
        if rule.action not in {"allow", "deny"}:
            errors.append(f"{rule.rule_id} has unsupported action {rule.action}.")

        for field_name, zones in (
            ("source_zones", rule.source_zones),
            ("destination_zones", rule.destination_zones),
        ):
            if not zones:
                errors.append(f"{rule.rule_id} has an empty {field_name} list.")
                continue

            any_count = sum(
                1
                for zone in zones
                if isinstance(zone, str) and zone.casefold() == "any"
            )
            if any_count and len(zones) > 1:
                errors.append(f"{rule.rule_id} mixes 'any' with specific {field_name}.")

            for zone in zones:
                if not isinstance(zone, str) or not zone.strip():
                    errors.append(
                        f"{rule.rule_id} has an empty or invalid {field_name} value."
                    )

        for field_name, addresses in (
            ("source_addresses", rule.source_addresses),
            ("destination_addresses", rule.destination_addresses),
        ):
            if not addresses:
                errors.append(f"{rule.rule_id} has an empty {field_name} list.")
                continue
            if "any" in addresses and len(addresses) > 1:
                errors.append(f"{rule.rule_id} mixes 'any' with specific {field_name}.")
            for address in addresses:
                if address != "any" and not isinstance(address, (IPv4Address, IPv4Network)):
                    errors.append(f"{rule.rule_id} has an invalid {field_name} value {address}.")

        if not rule.services:
            errors.append(f"{rule.rule_id} has an empty services list.")
        elif "any" in rule.services and len(rule.services) > 1:
            errors.append(f"{rule.rule_id} mixes 'any' with specific services.")
        else:
            for service in rule.services:
                if service != "any" and not _valid_service(service):
                    errors.append(f"{rule.rule_id} has an invalid service {service}.")

    # If any validation errors were found, raise an InputValidationError with a summary of all issues.
    if errors:
        raise InputValidationError(
            "Input validation failed:\n- " + "\n- ".join(sorted(set(errors)))
        )


# ---------------------------------------------------------------------------
# Matching and ordered policy evaluation
# ---------------------------------------------------------------------------


def _zone_matches(rule_zones: list[str], flow_zone: str) -> bool:
    """
    Helper to determine if a flow's zone matches any of the zones specified in a rule.

    For example, if a rule specifies ["core_network_zone", "guest_network_zone"] and the flow's zone is
    "core_network_zone", this function will return True.

    If the flow's zone is "business_office_zone", it will return False. If the rule specifies ["any"], it will match any flow zone.
    """

    flow_zone_key = flow_zone.casefold()
    return any(
        zone.casefold() == "any" or zone.casefold() == flow_zone_key
        for zone in rule_zones
    )


def _address_matches(
    rule_addresses: list[Address],
    flow_address: IPv4Address,
) -> bool:
    """
    Helper to determine if a flow's IP address matches any of the addresses specified in a rule.

    For example, if a rule specifies ["192.168.1.0/24"], this function will return True for any flow originating from that subnet.
    """

    for rule_address in rule_addresses:
        if rule_address == "any":
            return True
        if isinstance(rule_address, IPv4Address) and rule_address == flow_address:
            return True
        if isinstance(rule_address, IPv4Network) and flow_address in rule_address:
            return True
    return False


def _service_matches(
    rule_services: list[ServiceMatch],
    flow_service: Service,
) -> bool:
    """
    Helper to determine if a flow's service matches any of the services specified in a rule.

    For example, if a rule specifies ["tcp:443"], this function will return True for any flow using TCP port 443.
    If the rule specifies ["any"], it will match any flow service.
    """

    for rule_service in rule_services:
        if rule_service == "any":
            return True
        if (
            rule_service.protocol == flow_service.protocol
            and rule_service.destination_port == flow_service.destination_port
        ):
            return True
    return False


def _rule_matches(rule: FirewallRule, flow: TrafficFlow) -> bool:
    """
    Main helper to determine if a flow matches a firewall rule based on zones, addresses, and services.

    All of the following must be true for a match:
        - The flow's source zone matches one of the rule's source zones.
        - The flow's destination zone matches one of the rule's destination zones.
        - The flow's source address matches one of the rule's source addresses.
        - The flow's destination address matches one of the rule's destination addresses.
        - The flow's service matches one of the rule's services.
    """

    return (
        _zone_matches(rule.source_zones, flow.source_zone)
        and _zone_matches(rule.destination_zones, flow.destination_zone)
        and _address_matches(rule.source_addresses, flow.source_address)
        and _address_matches(rule.destination_addresses, flow.destination_address)
        and _service_matches(rule.services, flow.service)
    )


def evaluate_policy(
    policy: FirewallPolicy,
    flow: TrafficFlow,
    default_action: PolicyAction = "deny",
    excluded_rule_id: str | None = None,
) -> PolicyDecision:
    """
    Evaluate a traffic flow against the firewall policy, returning the action taken and the matched rule ID.

    Args:
        policy: The ordered list of firewall rules to evaluate against.
        flow: The traffic flow to evaluate.
        default_action: The action to take if no rules match the flow, either "allow" or "deny".
        excluded_rule_id: An optional rule ID to ignore during evaluation, useful for testing rule changes.

    Returns:
        A PolicyDecision object indicating whether the flow is allowed or denied, and which rule (if any) matched.
    """

    if default_action not in {"allow", "deny"}:
        raise ValueError("default_action must be 'allow' or 'deny'.")

    # Look at each rule in order, skipping the excluded rule if specified, and return the first matching rule's action.
    for rule in policy:
        if rule.rule_id == excluded_rule_id:
            continue
        if _rule_matches(rule, flow):
            return PolicyDecision(rule.action, rule.rule_id)

    return PolicyDecision(default_action, None)


def communication_flow(
    communication: RequiredCommunication,
    assets_by_id: dict[str, Asset],
) -> TrafficFlow:
    """
    Takes a RequiredCommunication and a mapping of asset IDs to Asset objects, and returns a TrafficFlow object representing the communication.

    Used to convert a RequiredCommunication into a TrafficFlow for policy evaluation,
    ensuring that the source and destination assets exist in the provided mapping.

    Args:
        communication: The RequiredCommunication object to convert.
        assets_by_id: A dictionary mapping asset IDs to Asset objects.

    Returns:
        A TrafficFlow object representing the communication between the source and destination assets.
    """

    # Validate that the source and destination asset IDs exist in the provided mapping.
    try:
        source = assets_by_id[communication.source_asset_id]
        destination = assets_by_id[communication.destination_asset_id]
    except KeyError as error:
        raise InputValidationError(
            f"Required communication {communication.communication_id} references "
            f"unknown asset {error.args[0]}."
        ) from error

    return TrafficFlow(
        source.asset_id,
        destination.asset_id,
        source.zone,
        destination.zone,
        source.ip_address,
        destination.ip_address,
        communication.service,
    )


# ---------------------------------------------------------------------------
# Counterfactual rule-removal analysis
# ---------------------------------------------------------------------------


def candidate_services(
    policy: FirewallPolicy,
    required_communications: list[RequiredCommunication],
) -> tuple[Service, ...]:
    """
    Return the specific services that will be used to test traffic flows.

    Services are collected from the firewall policy and required communications.
    Rules using "any" are not added because "any" is not a specific service.
    """

    services = {communication.service for communication in required_communications}
    for rule in policy:
        for service in rule.services:
            if service != "any":
                services.add(service)

    if any(service == "any" for rule in policy for service in rule.services):
        for protocol in sorted(SUPPORTED_PROTOCOLS):
            used_ports = {
                service.destination_port for service in services if service.protocol == protocol
            }
            unused_port = next((port for port in range(1, 65536) if port not in used_ports), None)
            if unused_port is not None:
                services.add(Service(cast(Literal["tcp", "udp"], protocol), unused_port))

    return tuple(sorted(services, key=lambda item: (item.protocol, item.destination_port)))


def candidate_flows(
    assets: list[Asset],
    services: tuple[Service, ...],
) -> tuple[TrafficFlow, ...]:
    """
    Enumerate known asset pairs across the concrete modeled services.
    """

    flows: list[TrafficFlow] = []
    for source in assets:
        for destination in assets:
            if source.asset_id == destination.asset_id:
                continue
            for service in services:
                flows.append(
                    TrafficFlow(
                        source.asset_id,
                        destination.asset_id,
                        source.zone,
                        destination.zone,
                        source.ip_address,
                        destination.ip_address,
                        service,
                    )
                )
    return tuple(flows)


def _required_flow_keys(
    communications: list[RequiredCommunication],
    assets_by_id: dict[str, Asset],
) -> set[tuple[str, str, str, int]]:
    return {
        communication_flow(communication, assets_by_id).key
        for communication in communications
    }


def _blocked_required_communications(
    inputs: DatasetInputs,
    assets_by_id: dict[str, Asset],
    rule_id: str,
    default_action: PolicyAction,
) -> set[str]:
    """
    Return every required communication newly blocked by the removal.

    Communications are evaluated individually instead of through a dictionary
    keyed by flow so duplicate requirements with the same flow are preserved.
    """

    blocked: set[str] = set()
    for communication in inputs.required_communications:
        flow = communication_flow(communication, assets_by_id)
        before = evaluate_policy(inputs.firewall_policy, flow, default_action)
        after = evaluate_policy(
            inputs.firewall_policy,
            flow,
            default_action,
            excluded_rule_id=rule_id,
        )
        if before.action == "allow" and after.action == "deny":
            blocked.add(communication.communication_id)
    return blocked


def analyze_rule_removal(
    inputs: DatasetInputs,
    rule_id: str,
    default_action: PolicyAction = "deny",
) -> RuleRemovalAnalysis:
    """
    Analyze the effect of removing one rule.

    The function builds concrete flows from the supplied asset inventory and
    concrete services found in the policy/required communications.  Each flow
    is evaluated twice: once with the full ordered policy and once with the
    target rule skipped.  Only differences between those two decisions are
    reported as removal effects.
    """

    validate_inputs(inputs)

    matches = [rule for rule in inputs.firewall_policy if rule.rule_id == rule_id]
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one rule named {rule_id}; found {len(matches)}.")

    target_rule = matches[0]
    assets_by_id = {asset.asset_id: asset for asset in inputs.assets}
    required_keys = _required_flow_keys(inputs.required_communications, assets_by_id)
    blocked_required = _blocked_required_communications(
        inputs,
        assets_by_id,
        rule_id,
        default_action,
    )

    changed: list[FlowChange] = []
    newly_allowed: list[FlowChange] = []
    newly_allowed_critical: list[FlowChange] = []
    removed_undocumented: list[FlowChange] = []
    removed_undocumented_critical: list[FlowChange] = []
    replacements: set[str] = set()

    services = candidate_services(inputs.firewall_policy, inputs.required_communications)
    for flow in candidate_flows(inputs.assets, services):
        # A replacement/takeover is meaningful only for traffic the target
        # rule itself is capable of matching. Evaluating with the target
        # removed also detects fully shadowed rules: an earlier rule will be
        # returned here even though the target was never first-match effective.
        if _rule_matches(target_rule, flow):
            without_target = evaluate_policy(
                inputs.firewall_policy,
                flow,
                default_action,
                excluded_rule_id=rule_id,
            )
            if without_target.action == target_rule.action:
                replacements.add(without_target.matched_rule_id or "<default>")

        before = evaluate_policy(inputs.firewall_policy, flow, default_action)
        after = evaluate_policy(
            inputs.firewall_policy,
            flow,
            default_action,
            excluded_rule_id=rule_id,
        )

        if before.action == after.action:
            continue

        criticality = assets_by_id[flow.destination_asset_id].criticality
        change = FlowChange(flow, before, after, criticality)
        changed.append(change)

        if before.action == "allow" and after.action == "deny":
            # Required communications are reported by ID above. Everything
            # else in the closed-world synthetic model is called undocumented,
            # not automatically malicious.
            if flow.key not in required_keys:
                removed_undocumented.append(change)
                if criticality == "critical":
                    removed_undocumented_critical.append(change)

        elif before.action == "deny" and after.action == "allow":
            newly_allowed.append(change)
            if criticality == "critical":
                newly_allowed_critical.append(change)

    return RuleRemovalAnalysis(
        rule_id=rule_id,
        rule_action=target_rule.action,
        blocked_required_communication_ids=tuple(sorted(blocked_required)),
        newly_allowed_flows=tuple(newly_allowed),
        newly_allowed_critical_flows=tuple(newly_allowed_critical),
        removed_undocumented_flows=tuple(removed_undocumented),
        removed_undocumented_critical_flows=tuple(removed_undocumented_critical),
        changed_flows=tuple(changed),
        observed_replacement_rule_ids=tuple(sorted(replacements)),
    )


def analyze_all_rules(
    inputs: DatasetInputs,
    default_action: PolicyAction = "deny",
) -> list[RuleRemovalAnalysis]:
    """
    Run the one-rule-at-a-time removal analysis for the whole policy.
    """

    validate_inputs(inputs)
    return [
        analyze_rule_removal(inputs, rule.rule_id, default_action)
        for rule in inputs.firewall_policy
    ]


class PolicyAnalyzer:
    """
    A class that encapsulates the policy analysis engine, providing methods to evaluate traffic
    flows against a firewall policy and analyze the effects of rule removals.

    Attributes:
        dataset (DatasetInputs): The dataset containing assets, firewall policy, rule usage, and required communications.
        default_action (PolicyAction): The default action to take when no rules match a traffic flow.
    """

    def __init__(
        self,
        dataset: DatasetInputs | str | Path,
        default_action: PolicyAction = "deny",
    ) -> None:

        self.dataset = load_dataset(dataset) if isinstance(dataset, (str, Path)) else dataset
        validate_inputs(self.dataset)
        self.default_action: PolicyAction = default_action

    def analyze_rule(self, rule_id: str) -> RuleRemovalAnalysis:
        return analyze_rule_removal(self.dataset, rule_id, self.default_action)

    def analyze_all(self) -> list[RuleRemovalAnalysis]:
        return analyze_all_rules(self.dataset, self.default_action)
