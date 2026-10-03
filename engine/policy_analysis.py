"""
Load the datasets used by the firewall policy analysis engine.

The generator creates healthcare-focused examples, but the analyzer only
expects the supplied CSV files to follow the project's schema. Asset types and
zone names are therefore treated as dataset-defined labels.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import date
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from pathlib import Path
from typing import Literal, cast

from schemas.asset import Asset, AssetType, AssetZone, Criticality
from schemas.communication import RequiredCommunication
from schemas.firewall_rule import Address, FirewallPolicy, FirewallRule, Service, ServiceMatch
from schemas.usage import RuleUsage, RuleUsageHistory


PolicyAction = Literal["allow", "deny"]
CRITICALITIES = {"low", "medium", "high", "critical"}
SUPPORTED_PROTOCOLS = {"tcp", "udp"}


class InputValidationError(ValueError):
    """
    Custom error raised when an input CSV cannot be loaded safely.
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
        criticality = _required_text(row, "criticality", path.name, row_number).lower()
        if criticality not in CRITICALITIES:
            raise InputValidationError(f"{context}: unsupported criticality '{criticality}'.")

        address = _parse_address(row["ip_address"], context)
        if not isinstance(address, IPv4Address):
            raise InputValidationError(f"{context}: asset IP must be one IPv4 address.")

        assets.append(
            Asset(
                _required_text(row, "asset_id", path.name, row_number),
                cast(
                    AssetType,
                    _required_text(row, "asset_type", path.name, row_number),
                ),
                address,
                cast(
                    AssetZone,
                    _required_text(row, "zone", path.name, row_number),
                ),
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
                _required_text(row, "rule_id", path.name, row_number),
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
    """

    directory = Path(input_directory)
    if (directory / "inputs").is_dir() and not (directory / "assets.csv").is_file():
        directory = directory / "inputs"

    return DatasetInputs(
        assets=load_assets_csv(directory / "assets.csv"),
        firewall_policy=load_firewall_policy_csv(directory / "firewall_policy.csv"),
        rule_usage=load_rule_usage_csv(directory / "rule_usage.csv"),
        required_communications=load_required_communications_csv(
            directory / "required_communications.csv"
        )
    )


class PolicyAnalyzer:
    """Initial interface for working with one loaded policy dataset."""

    def __init__(self, dataset: DatasetInputs | str | Path):
        self.dataset = load_dataset(dataset) if isinstance(dataset, (str, Path)) else dataset
        self.assets_by_id = {asset.asset_id: asset for asset in self.dataset.assets}