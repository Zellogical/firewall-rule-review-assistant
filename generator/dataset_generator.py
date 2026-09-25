"""Generate deterministic CSV datasets for the firewall review assistant to consume.

Make sure to run this module from the repository root:

    python -m generator.dataset_generator
    python -m generator.dataset_generator --profile mixed --variations-per-profile 5
    python -m generator.dataset_generator --seed 100 --history-days 180

Each generated dataset has two directories:

    inputs/ - CSV files that represent the firewall policy, assets, and required communications.
    evaluation/ - CSV files that represent the rule usage history, evaluation scenarios, and expected recommendations

Asset roles and healthcare workflows are adapted from NIST SP 1800-8 and
SP 1800-24. Firewall fields follow the simplified Palo Alto-style schemas in
this repository. Exact addresses, quantities, ports, rule conditions, usage
patterns, and test combinations are documented synthetic modeling choices.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import random
from collections import Counter
from dataclasses import dataclass
from datetime import date, timedelta
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Literal

from schemas.asset import Asset, AssetType, AssetZone, Criticality
from schemas.communication import RequiredCommunication
from schemas.firewall_rule import Address, FirewallPolicy, FirewallRule, Service, ServiceMatch
from schemas.recommendation import ExpectedRecommendation, RecommendationLabel
from schemas.scenario import EvaluationScenario
from schemas.usage import RuleUsage, RuleUsageHistory

GENERATOR_VERSION = "1.0"

# The seed is used to derive a unique random number generator for each generated dataset.

DEFAULT_SEED = 62201

# The end date is used to generate the rule usage history and evaluation scenarios.

DEFAULT_END_DATE = date(2026, 11, 19)

# The default history days is used to generate the rule usage history.
# The default variations per profile is used to generate multiple variations of each profile.
# The incomplete history days is used to generate the incomplete usage history for the "incomplete_usage" profile.
# The list separator is used to join multiple values in the manifest.csv file.

DEFAULT_HISTORY_DAYS = 120
DEFAULT_VARIATIONS_PER_PROFILE = 3
INCOMPLETE_HISTORY_DAYS = 21
LIST_SEPARATOR = ";"

# Profile names represent the major conditions that can be injected into a generated dataset.
# For example, a "redundant" profile will include a rule that is shadowed by an earlier allow rule,
# while an "obsolete" profile will include a legacy rule with no current requirement.

ProfileName = Literal[
    "clean",
    "redundant",
    "obsolete",
    "overly_permissive",
    "protective_deny",
    "rare_required",
    "incomplete_usage",
    "mixed",
]


@dataclass(frozen=True)
class Profile:
    """
    A profile represents a specific set of conditions that can be injected into a generated dataset.

    Attributes:
        name (ProfileName): The name of the profile.
        description (str): A brief description of the profile.
        injected_conditions (tuple[str, ...]): A tuple of strings representing the conditions that are injected into the dataset.
    """

    name: ProfileName
    description: str
    injected_conditions: tuple[str, ...]


@dataclass(frozen=True)
class GeneratedDataset:
    """
    All data necessary for one generated variation of a profile, eventually written as CSV files.

    Attributes:
        dataset_id (str): A unique identifier for the dataset.
        profile (Profile): The profile used to generate the dataset.
        seed (int): The seed used to generate the dataset.
        end_date (date): The end date used to generate the rule usage history and evaluation scenarios.
        history_days (int): The number of days of rule usage history to generate.
        assets (list[Asset]): A list of assets in the dataset.
        firewall_policy (FirewallPolicy): The firewall policy for the dataset.
        rule_usage (RuleUsageHistory): The rule usage history for the dataset.
        required_communications (list[RequiredCommunication]): A list of required communications in the dataset.
        evaluation_scenarios (list[EvaluationScenario]): A list of evaluation scenarios in the dataset.
        expected_recommendations (list[ExpectedRecommendation]): A list of expected recommendations in the dataset.
    """

    dataset_id: str
    profile: Profile
    variation_num: int
    seed: int
    end_date: date
    history_days: int
    assets: list[Asset]
    firewall_policy: FirewallPolicy
    rule_usage: RuleUsageHistory
    required_communications: list[RequiredCommunication]
    evaluation_scenarios: list[EvaluationScenario]
    expected_recommendations: list[ExpectedRecommendation]


# Define the profiles that can be generated. Each profile has a name, description, and a tuple of injected conditions.
# An injected condition is a string that describes a specific condition that is intentionally added to the dataset for testing purposes.
PROFILES = (
    Profile(
        "clean",
        "Only rules supporting documented communications.",
        ("required rules",)
    ),
    Profile(
        "redundant",
        "Adds a duplicate rule shadowed by an earlier allow rule.",
        ("required rules", "redundant rule")
    ),
    Profile(
        "obsolete",
        "Adds a legacy rule with old activity and no current requirement.",
        ("required rules", "obsolete rule")
    ),
    Profile(
        "overly_permissive",
        "Replaces a narrow EHR rule with broad clinical web access.",
        ("required rules", "overly permissive rule", "operational-security trade-off")
    ),
    Profile(
        "protective_deny",
        "Places a protective deny before broad clinical web access.",
        ("required rules", "overly permissive rule", "protective deny rule")
    ),
    Profile(
        "rare_required",
        "Includes a required maintenance rule with no observed hits.",
        ("required rules", "inactive but required rule")
    ),
    Profile(
        "incomplete_usage",
        "Adds an undocumented rule with only 21 days of usage data.",
        ("required rules", "incomplete usage history")
    ),
    Profile(
        "mixed",
        "Combines all major rule-review conditions in one ordered policy.",
        (
            "required rules",
            "redundant rule",
            "obsolete rule",
            "overly permissive rule",
            "protective deny rule",
            "inactive but required rule",
            "incomplete usage history"
        )
    )
)

# Map each asset zone to a unique octet for IP address generation.
# This ensures that each zone has a distinct subnet in the 10.x.x.x private IP range.
ZONE_OCTETS: dict[AssetZone, int] = {
    "core_network_zone": 1,
    "guest_network_zone": 10,
    "business_office_zone": 20,
    "enterprise_services_zone": 30,
    "database_server_zone": 40,
    "clinical_services_zone": 50,
    "biomedical_engineering_zone": 60,
    "medical_devices_zone": 70,
    "remote_access_zone": 80,
}


def _derived_seed(base_seed: int, profile_name: str, variation_num: int) -> int:
    """
    Derive a unique seed for each dataset variation based on the base seed, profile name, and variation number.

    Args:
        base_seed (int): The base seed for the random number generator.
        profile_name (str): The name of the profile being generated.
        variation_num (int): The number of the variation.

    Returns:
        int: A unique seed for the dataset variation.
    """

    value = f"{base_seed}|{profile_name}|{variation_num}".encode("utf-8")
    return int.from_bytes(hashlib.sha256(value).digest()[:8], "big")


def _create_ip(site: int, zone: AssetZone, host: int) -> IPv4Address:
    """
    Create an IPv4 address for a given site, zone, and host.

    Args:
        site (int): The site number.
        zone (AssetZone): The asset zone.
        host (int): The host number.

    Returns:
        IPv4Address: An IPv4 address for the specified parameters.
    """

    return IPv4Address(f"10.{site}.{ZONE_OCTETS[zone]}.{host}")


def generate_assets(rng: random.Random, site: int) -> list[Asset]:
    """
    Generate a list of assets for the dataset based on the provided random number generator and site number.

    Args:
        rng (random.Random): A random number generator for deterministic asset generation.
        site (int): The site number to use for generating IP addresses.
    """

    assets: list[Asset] = []

    def add(
        asset_id: str,
        asset_type: AssetType,
        zone: AssetZone,
        host: int,
        criticality: Criticality,
    ) -> None:
        assets.append(Asset(asset_id, asset_type, _create_ip(site, zone, host), zone, criticality))

    add("core_firewall_001", "network_device", "core_network_zone", 1, "critical")
    add("database_001", "database_server", "database_server_zone", 10, "critical")
    add("dns_001", "dns_server", "enterprise_services_zone", 10, "high")
    add("directory_001", "directory_service", "enterprise_services_zone", 11, "critical")
    add("ehr_001", "ehr_system", "clinical_services_zone", 10, "critical")
    add("pharmacy_001", "pharmacy_system", "clinical_services_zone", 11, "critical")
    add("pacs_001", "pacs_server", "clinical_services_zone", 20, "critical")
    add("vna_001", "vna_server", "clinical_services_zone", 21, "high")
    add("ris_001", "ris_system", "clinical_services_zone", 22, "high")
    add("legacy_reporting_001", "database_server", "clinical_services_zone", 30, "medium")
    add("pump_server_001", "pump_server", "biomedical_engineering_zone", 10, "high")
    add("remote_proxy_001", "remote_access_proxy", "remote_access_zone", 10, "high")

    for index in range(1, rng.randint(1, 3) + 1):
        add(f"guest_{index:03d}", "guest_device", "guest_network_zone", 9 + index, "low")

    for index in range(1, rng.randint(2, 5) + 1):
        add(
            f"staff_{index:03d}",
            "staff_workstation",
            "business_office_zone",
            9 + index,
            "medium",
        )

    for index in range(1, rng.randint(1, 3) + 1):
        add(
            f"viewer_{index:03d}",
            "viewer_workstation",
            "business_office_zone",
            29 + index,
            "medium",
        )

    for index in range(1, rng.randint(2, 5) + 1):
        add(f"pump_{index:03d}", "infusion_pump", "medical_devices_zone", 9 + index, "critical")

    for index in range(1, rng.randint(1, 2) + 1):
        add(
            f"modality_{index:03d}",
            "imaging_modality",
            "medical_devices_zone",
            29 + index,
            "high",
        )

    return assets


def _to_tcp_service(port: int) -> Service:
    """
    Helper function to create a TCP service for the given port.
    """

    return Service(protocol="tcp", destination_port=port)


def _to_network(site: int, zone: AssetZone) -> IPv4Network:
    """
    Helper function to create a network for the given site and zone.
    """

    return IPv4Network(f"10.{site}.{ZONE_OCTETS[zone]}.0/24")


def _by_type(assets: list[Asset], asset_type: AssetType) -> list[Asset]:
    """
    Helper function to filter assets by type.
    """

    return [asset for asset in assets if asset.asset_type == asset_type]


def generate_required_communications(assets: list[Asset]) -> list[RequiredCommunication]:
    communications: list[RequiredCommunication] = []

    # Add required communications for staff workstations
    for asset in _by_type(assets, "staff_workstation"):
        communications.append(
            RequiredCommunication(
                f"REQ-{asset.asset_id.upper()}-EHR",
                asset.asset_id,
                "ehr_001",
                _to_tcp_service(443),
                "Staff workstation accesses the EHR web application.",
                "Healthcare workflow; TCP/443 is a documented modeling choice."
            )
        )

    # Add required communications for viewer workstations
    for asset in _by_type(assets, "viewer_workstation"):
        communications.append(
            RequiredCommunication(
                f"REQ-{asset.asset_id.upper()}-PACS",
                asset.asset_id,
                "pacs_001",
                _to_tcp_service(443),
                "Viewer workstation retrieves medical images from PACS.",
                "NIST SP 1800-24 architecture; TCP/443 is a modeling choice."
            )
        )

    # Add required communications for imaging modalities
    for asset in _by_type(assets, "imaging_modality"):
        communications.append(
            RequiredCommunication(
                f"REQ-{asset.asset_id.upper()}-PACS",
                asset.asset_id,
                "pacs_001",
                _to_tcp_service(104),
                "Imaging modality sends a study to PACS.",
                "NIST SP 1800-24 architecture; the DICOM port is a modeling choice."
            )
        )

    # Add required communications for infusion pumps
    for asset in _by_type(assets, "infusion_pump"):
        communications.append(
            RequiredCommunication(
                f"REQ-{asset.asset_id.upper()}-PUMP-SERVER",
                asset.asset_id,
                "pump_server_001",
                _to_tcp_service(8443),
                "Infusion pump exchanges configuration data with the pump server.",
                "NIST SP 1800-8 architecture; TCP/8443 is a modeling choice."
            )
        )

    # Add required communications for the remote access proxy and pump server
    communications.extend(
        [
            RequiredCommunication(
                "REQ-REMOTE-PUMP-SERVER",
                "remote_proxy_001",
                "pump_server_001",
                _to_tcp_service(443),
                "Remote proxy supports infrequent pump-server maintenance.",
                "NIST SP 1800-8 remote-access concept; port and frequency are modeling choices."
            ),
            RequiredCommunication(
                "REQ-PACS-VNA",
                "pacs_001",
                "vna_001",
                _to_tcp_service(104),
                "PACS transfers medical images to the vendor-neutral archive.",
                "NIST SP 1800-24 imaging workflow; the DICOM port is a modeling choice."
            ),
            RequiredCommunication(
                "REQ-RIS-PACS",
                "ris_001",
                "pacs_001",
                _to_tcp_service(443),
                "The radiology information system exchanges study information with PACS.",
                "NIST SP 1800-24 imaging workflow; TCP/443 is a modeling choice."
            )
        ]
    )

    return communications


def _by_id(assets: list[Asset], asset_id: str) -> Asset:
    """
    Helper function to find an asset by its ID.
    """

    return next(asset for asset in assets if asset.asset_id == asset_id)


def _create_rule(
    rule_id: str,
    source_zones: list[str],
    destination_zones: list[str],
    source_addresses: list[Address],
    destination_addresses: list[Address],
    services: list[ServiceMatch],
    action: Literal["allow", "deny"],
) -> FirewallRule:
    """
    Helper function to create a firewall rule with the specified parameters.
    """

    return FirewallRule(
        rule_id,
        source_zones,
        destination_zones,
        source_addresses,
        destination_addresses,
        services,
        action
    )


def generate_firewall_policy(
    profile: ProfileName,
    assets: list[Asset],
    site: int
) -> FirewallPolicy:
    """
    Generate a firewall policy based on the specified profile, assets, and site number.

    Args:
        profile (ProfileName): The name of the profile to generate.
        assets (list[Asset]): A list of assets in the dataset.
        site (int): The site number to use for generating IP addresses.

    Returns:
        FirewallPolicy: A list of firewall rules representing the policy for the dataset.
    """

    staff: list[Address] = [asset.ip_address for asset in _by_type(assets, "staff_workstation")]
    viewers: list[Address] = [asset.ip_address for asset in _by_type(assets, "viewer_workstation")]
    pumps: list[Address] = [asset.ip_address for asset in _by_type(assets, "infusion_pump")]
    modalities: list[Address] = [asset.ip_address for asset in _by_type(assets, "imaging_modality")]

    def address(asset_id: str) -> IPv4Address:
        return _by_id(assets, asset_id).ip_address

    broad = profile in {"overly_permissive", "protective_deny", "mixed"}
    protective = profile in {"protective_deny", "mixed"}
    policy: FirewallPolicy = []

    # A protective policy will include a deny rule for staff workstations to PACS web access.
    if protective:
        policy.append(
            _create_rule(
                "deny_staff_pacs_web",
                ["business_office_zone"],
                ["clinical_services_zone"],
                staff,
                [address("pacs_001")],
                [_to_tcp_service(443)],
                "deny"
            )
        )

    # A broad policy will include a rule that allows staff workstations to access any web service in the clinical services zone.
    if broad:
        policy.append(
            _create_rule(
                "allow_broad_clinical_web",
                ["business_office_zone"],
                ["clinical_services_zone"],
                staff,
                [_to_network(site, "clinical_services_zone")],
                [_to_tcp_service(443)],
                "allow"
            )
        )

    # A clean policy will include a rule that allows staff workstations to access the EHR web application.
    else:
        policy.append(
            _create_rule(
                "allow_staff_ehr",
                ["business_office_zone"],
                ["clinical_services_zone"],
                staff,
                [address("ehr_001")],
                [_to_tcp_service(443)],
                "allow"
            )
        )

    # These rules are common to all profiles and represent the required communications for viewers, modalities, pumps, and the remote proxy.
    policy.extend(
        [
            _create_rule(
                "allow_viewers_pacs",
                ["business_office_zone"],
                ["clinical_services_zone"],
                viewers,
                [address("pacs_001")],
                [_to_tcp_service(443)],
                "allow"
            ),
            _create_rule(
                "allow_modalities_pacs",
                ["medical_devices_zone"],
                ["clinical_services_zone"],
                modalities,
                [address("pacs_001")],
                [_to_tcp_service(104)],
                "allow"
            ),
            _create_rule(
                "allow_pumps_pump_server",
                ["medical_devices_zone"],
                ["biomedical_engineering_zone"],
                pumps,
                [address("pump_server_001")],
                [_to_tcp_service(8443)],
                "allow"
            ),
            _create_rule(
                "allow_remote_pump_server",
                ["remote_access_zone"],
                ["biomedical_engineering_zone"],
                [address("remote_proxy_001")],
                [address("pump_server_001")],
                [_to_tcp_service(443)],
                "allow"
            ),
            _create_rule(
                "allow_pacs_vna",
                ["clinical_services_zone"],
                ["clinical_services_zone"],
                [address("pacs_001")],
                [address("vna_001")],
                [_to_tcp_service(104)],
                "allow"
            ),
            _create_rule(
                "allow_ris_pacs",
                ["clinical_services_zone"],
                ["clinical_services_zone"],
                [address("ris_001")],
                [address("pacs_001")],
                [_to_tcp_service(443)],
                "allow"
            )
        ]
    )

    # Add a rule with redundant usage for the "redundant" and "mixed" profiles.
    if profile in {"redundant", "mixed"}:
        policy.append(
            _create_rule(
                "redundant_staff_ehr",
                ["business_office_zone"],
                ["clinical_services_zone"],
                [staff[0]],
                [address("ehr_001")],
                [_to_tcp_service(443)],
                "allow"
            )
        )

    # Add a rule with no current requirement for the "obsolete" and "mixed" profiles.
    if profile in {"obsolete", "mixed"}:
        policy.append(
            _create_rule(
                "obsolete_legacy_reporting",
                ["business_office_zone"],
                ["clinical_services_zone"],
                staff,
                [address("legacy_reporting_001")],
                [_to_tcp_service(8443)],
                "allow"
            )
        )

    # Add a rule with incomplete usage history for the "incomplete_usage" and "mixed" profiles.
    if profile in {"incomplete_usage", "mixed"}:
        policy.append(
            _create_rule(
                "incomplete_ssh_management",
                ["business_office_zone"],
                ["biomedical_engineering_zone"],
                [staff[0]],
                [address("pump_server_001")],
                [_to_tcp_service(22)],
                "allow"
            )
        )

    return policy


def _usage_kind(profile: ProfileName, rule_id: str) -> str:
    """
    Helper function to determine the usage kind for a given rule based on the profile and rule ID.

    For example, a rule that is inactive but required will have a usage kind of "inactive".

    A rule that is obsolete will have a usage kind of "obsolete".
    """

    if rule_id in {"redundant_staff_ehr", "deny_staff_pacs_web"}:
        return "inactive"
    if rule_id == "obsolete_legacy_reporting":
        return "obsolete"
    if rule_id == "incomplete_ssh_management":
        return "incomplete"
    if rule_id == "allow_remote_pump_server":
        return "inactive" if profile in {"rare_required", "mixed"} else "periodic"
    if rule_id in {"allow_modalities_pacs", "allow_pacs_vna", "allow_ris_pacs"}:
        return "moderate"

    return "routine"


def _rng_for(seed: int, value: str) -> random.Random:
    """
    Helper function to create a deterministic random number generator for a given seed and value.

    Specifically used to generate rule usage history for a specific rule in a dataset.
    """

    material = f"{seed}|{value}".encode("utf-8")
    return random.Random(int.from_bytes(hashlib.sha256(material).digest()[:8], "big"))


def generate_rule_usage(
    profile: ProfileName,
    policy: FirewallPolicy,
    seed: int,
    end_date: date,
    history_days: int
) -> RuleUsageHistory:
    """
    Generate usage history for each rule in the policy.

    Args:
        profile (ProfileName): The name of the profile being generated.
        policy (FirewallPolicy): The firewall policy for the dataset.
        seed (int): The seed used to generate the dataset.
        end_date (date): The end date used to generate the rule usage history.
        history_days (int): The number of days of rule usage history to generate.

    Returns:
        RuleUsageHistory: A list of RuleUsage objects representing the usage history for each rule in the policy.
    """

    history: RuleUsageHistory = []
    for firewall_rule in policy:
        kind = _usage_kind(profile, firewall_rule.rule_id)
        recorded_days = min(INCOMPLETE_HISTORY_DAYS, history_days) if kind == "incomplete" else history_days
        rng = _rng_for(seed, firewall_rule.rule_id)

        for days_ago in range(recorded_days - 1, -1, -1):
            hits = 0
            if kind == "routine":
                hits = rng.randint(60, 160)
            elif kind == "moderate":
                hits = rng.randint(10, 60)
            elif kind == "periodic" and days_ago in {30, 60, 90, 120, 150}:
                hits = rng.randint(1, 5)
            elif kind == "obsolete" and days_ago >= max(60, history_days // 2):
                hits = rng.randint(5, 25)

            history.append(RuleUsage(firewall_rule.rule_id, end_date - timedelta(days=days_ago), hits))

    return history


def generate_evaluation_scenarios(
    assets: list[Asset],
    required_communications: list[RequiredCommunication]
) -> list[EvaluationScenario]:
    """
    Generate evaluation scenarios for each required communication and some additional attack scenarios.

    Args:
        assets (list[Asset]): A list of assets in the dataset.
        required_communications (list[RequiredCommunication]): A list of required communications in the dataset.

    Returns:
        list[EvaluationScenario]: A list of EvaluationScenario objects representing the evaluation scenarios for the dataset.
    """

    scenarios = [
        EvaluationScenario(
            f"USE-{communication.communication_id}",
            "use",
            communication.source_asset_id,
            communication.destination_asset_id,
            communication.service,
            "allow",
            communication.purpose,
        )
        for communication in required_communications
    ]

    guest = _by_type(assets, "guest_device")[0].asset_id
    staff = _by_type(assets, "staff_workstation")[0].asset_id
    modality = _by_type(assets, "imaging_modality")[0].asset_id

    scenarios.extend(
        [
            EvaluationScenario(
                "ATK-GUEST-EHR",
                "attack",
                guest,
                "ehr_001",
                _to_tcp_service(443),
                "deny",
                "A guest device attempts to access the EHR."
            ),
            EvaluationScenario(
                "ATK-GUEST-PACS",
                "attack",
                guest,
                "pacs_001",
                _to_tcp_service(443),
                "deny",
                "A guest device attempts to access PACS."
            ),
            EvaluationScenario(
                "ATK-GUEST-PUMP",
                "attack",
                guest,
                "pump_server_001",
                _to_tcp_service(8443),
                "deny",
                "A guest device attempts to reach the pump server."
            ),
            EvaluationScenario(
                "ATK-STAFF-PACS",
                "attack",
                staff,
                "pacs_001",
                _to_tcp_service(443),
                "deny",
                "A general staff workstation attempts direct PACS access."
            ),
            EvaluationScenario(
                "ATK-STAFF-LEGACY-WEB",
                "attack",
                staff,
                "legacy_reporting_001",
                _to_tcp_service(443),
                "deny",
                "A staff workstation attempts undocumented web access to a legacy server."
            ),
            EvaluationScenario(
                "ATK-STAFF-LEGACY-ALT",
                "attack",
                staff,
                "legacy_reporting_001",
                _to_tcp_service(8443),
                "deny",
                "A staff workstation attempts undocumented alternate-port access."
            ),
            EvaluationScenario(
                "ATK-STAFF-PUMP-SSH",
                "attack",
                staff,
                "pump_server_001",
                _to_tcp_service(22),
                "deny",
                "A staff workstation attempts undocumented SSH access to the pump server."
            ),
            EvaluationScenario(
                "ATK-MODALITY-EHR",
                "attack",
                modality,
                "ehr_001",
                _to_tcp_service(443),
                "deny",
                "An imaging modality attempts to access the EHR web application."
            )
        ]
    )

    return scenarios


def generate_expected_recommendations(
    profile: ProfileName,
    firewall_policy: FirewallPolicy
) -> list[ExpectedRecommendation]:
    """
    Generate expected recommendations for each firewall rule.

    Args:
        profile (ProfileName): The name of the profile being generated.
        firewall_policy (FirewallPolicy): The firewall policy for the dataset.

    Returns:
        list[ExpectedRecommendation]: A list of ExpectedRecommendation objects representing the expected recommendations for each rule in the policy.
    """

    expected: list[ExpectedRecommendation] = []
    special: dict[str, tuple[RecommendationLabel, str]] = {
        "redundant_staff_ehr": (
            "removal_candidate",
            "An earlier rule already permits the same staff-to-EHR communication.",
        ),
        "obsolete_legacy_reporting": (
            "removal_candidate",
            "No required communication depends on the legacy rule and it has no recent usage.",
        ),
        "incomplete_ssh_management": (
            "investigate",
            "No requirement is documented, but only 21 days of usage data are available.",
        ),
        "allow_broad_clinical_web": (
            "investigate",
            "The rule supports required EHR access but also permits undocumented clinical access.",
        ),
        "deny_staff_pacs_web": (
            "retain",
            "Removal exposes staff-to-PACS access through the later broad allow rule.",
        )
    }

    for firewall_rule in firewall_policy:
        rule_id = firewall_rule.rule_id
        if rule_id in special:
            label, reason = special[rule_id]
        elif rule_id == "allow_remote_pump_server" and profile in {"rare_required", "mixed"}:
            label = "retain"
            reason = "The inactive rule preserves documented, infrequent maintenance communication."
        else:
            label = "retain"
            reason = "Removing the rule interrupts at least one documented required communication."

        expected.append(ExpectedRecommendation(rule_id, label, reason))

    return expected


def generate_dataset(
    profile: Profile,
    case_number: int,
    base_seed: int = DEFAULT_SEED,
    end_date: date = DEFAULT_END_DATE,
    history_days: int = DEFAULT_HISTORY_DAYS
) -> GeneratedDataset:
    dataset_seed = _derived_seed(base_seed, profile.name, case_number)
    rng = random.Random(dataset_seed)
    site = rng.randint(20, 220)

    assets = generate_assets(rng, site)
    required_communications = generate_required_communications(assets)
    firewall_policy = generate_firewall_policy(profile.name, assets, site)
    rule_usage = generate_rule_usage(profile.name, firewall_policy, dataset_seed, end_date, history_days)
    evaluation_scenarios = generate_evaluation_scenarios(assets, required_communications)
    expected_recommendations = generate_expected_recommendations(profile.name, firewall_policy)

    dataset = GeneratedDataset(
        dataset_id=f"{profile.name}_{case_number:03d}",
        profile=profile,
        variation_num=case_number,
        seed=dataset_seed,
        end_date=end_date,
        history_days=history_days,
        assets=assets,
        firewall_policy=firewall_policy,
        rule_usage=rule_usage,
        required_communications=required_communications,
        evaluation_scenarios=evaluation_scenarios,
        expected_recommendations=expected_recommendations
    )

    # TODO: Add validation of the generated dataset to ensure that it meets the expected conditions for the profile.

    return dataset


def validate_dataset(dataset: GeneratedDataset) -> None:
    pass


def _join(values: list[object] | tuple[str, ...]) -> str:
    """
    Wrapper for joining a list of values into a single string using the LIST_SEPARATOR.
    """

    return LIST_SEPARATOR.join(str(value) for value in values)


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, object]]) -> None:
    """
    Wrapper for writing CSV files.
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _create_service_text(service: ServiceMatch) -> str:
    """
    Helper function to create a string representation of a service match for CSV output.
    """

    if service == "any":
        return "any"
    return f"{service.protocol}:{service.destination_port}"


def write_dataset(dataset: GeneratedDataset, output_root: Path) -> Path:
    """
    Write one generated variation as CSV inputs, evaluation files, and metadata.
    """

    root = output_root / dataset.dataset_id
    inputs = root / "inputs"
    evaluation = root / "evaluation"

    _write_csv(
        inputs / "assets.csv",
        ["asset_id", "asset_type", "ip_address", "zone", "criticality"],
        [
            {
                "asset_id": asset.asset_id,
                "asset_type": asset.asset_type,
                "ip_address": asset.ip_address,
                "zone": asset.zone,
                "criticality": asset.criticality,
            }
            for asset in dataset.assets
        ]
    )

    _write_csv(
        inputs / "firewall_policy.csv",
        [
            "rule_id",
            "source_zones",
            "destination_zones",
            "source_addresses",
            "destination_addresses",
            "services",
            "action"
        ],
        [
            {
                "rule_id": rule.rule_id,
                "source_zones": _join(list(rule.source_zones)),
                "destination_zones": _join(list(rule.destination_zones)),
                "source_addresses": _join(list(rule.source_addresses)),
                "destination_addresses": _join(list(rule.destination_addresses)),
                "services": _join([_create_service_text(service) for service in rule.services]),
                "action": rule.action,
            }
            for rule in dataset.firewall_policy
        ]
    )

    _write_csv(
        inputs / "required_communications.csv",
        [
            "communication_id",
            "source_asset_id",
            "destination_asset_id",
            "service_protocol",
            "service_destination_port",
            "purpose",
            "source_reference"
        ],
        [
            {
                "communication_id": communication.communication_id,
                "source_asset_id": communication.source_asset_id,
                "destination_asset_id": communication.destination_asset_id,
                "service_protocol": communication.service.protocol,
                "service_destination_port": communication.service.destination_port,
                "purpose": communication.purpose,
                "source_reference": communication.source_reference
            }
            for communication in dataset.required_communications
        ]
    )

    _write_csv(
        inputs / "rule_usage.csv",
        ["rule_id", "observed_on", "hit_count"],
        [
            {
                "rule_id": record.rule_id,
                "observed_on": record.observed_on.isoformat(),
                "hit_count": record.hit_count,
            }
            for record in dataset.rule_usage
        ]
    )

    _write_csv(
        evaluation / "scenarios.csv",
        [
            "scenario_id",
            "scenario_type",
            "source_asset_id",
            "destination_asset_id",
            "service_protocol",
            "service_destination_port",
            "expected_action",
            "description"
        ],
        [
            {
                "scenario_id": scenario.scenario_id,
                "scenario_type": scenario.scenario_type,
                "source_asset_id": scenario.source_asset_id,
                "destination_asset_id": scenario.destination_asset_id,
                "service_protocol": scenario.service.protocol,
                "service_destination_port": scenario.service.destination_port,
                "expected_action": scenario.expected_action,
                "description": scenario.description,
            }
            for scenario in dataset.evaluation_scenarios
        ]
    )

    _write_csv(
        evaluation / "expected_recommendations.csv",
        ["rule_id", "expected_recommendation", "justification"],
        [
            {
                "rule_id": item.rule_id,
                "expected_recommendation": item.expected_recommendation,
                "justification": item.justification,
            }
            for item in dataset.expected_recommendations
        ]
    )

    counts = {
        "asset_count": len(dataset.assets),
        "rule_count": len(dataset.firewall_policy),
        "required_communication_count": len(dataset.required_communications),
        "rule_usage_count": len(dataset.rule_usage),
        "use_scenario_count": sum(s.scenario_type == "use" for s in dataset.evaluation_scenarios),
        "attack_scenario_count": sum(s.scenario_type == "attack" for s in dataset.evaluation_scenarios)
    }

    metadata: list[tuple[str, object]] = [
        ("generator_version", GENERATOR_VERSION),
        ("dataset_id", dataset.dataset_id),
        ("profile", dataset.profile.name),
        ("profile_description", dataset.profile.description),
        ("injected_conditions", _join(dataset.profile.injected_conditions)),
        ("case_number", dataset.variation_num),
        ("seed", dataset.seed),
        ("end_date", dataset.end_date.isoformat()),
        ("history_days", dataset.history_days),
        ("default_policy_action", "deny"),
        ("list_separator", LIST_SEPARATOR),
        ("service_format", "protocol:destination_port"),
        ("research_basis", "NIST SP 1800-8;NIST SP 1800-24;Palo Alto security-rule documentation"),
        (
            "documented_modeling_choices",
            "IP addresses;asset quantities;criticality;ports;rule conditions;usage patterns;test combinations",
        ),
        *counts.items()
    ]

    _write_csv(
        root / "manifest.csv",
        ["field", "value"],
        [{"field": field, "value": value} for field, value in metadata]
    )

    return root


def _selected_profiles(name: str) -> list[Profile]:
    """
    Return the list of profiles to generate based on the provided name.

    If 'all' is specified, return all available profiles.
    """

    if name == "all":
        return list(PROFILES)
    for profile in PROFILES:
        if profile.name == name:
            return [profile]
    raise ValueError(f"Unknown profile: {name}")


def _positive_int(value: str) -> int:
    """
    Convert a string to an integer, ensuring it is a positive value.

    Used to specify the number of variations to generate per profile in the dataset.
    """

    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be at least 1")
    return parsed


def _history_days(value: str) -> int:
    """
    Convert a string to an integer, ensuring it is between 90 and 180.

    Used to specify the number of days of rule usage history to generate for the dataset.
    """

    parsed = int(value)
    if not 90 <= parsed <= 180:
        raise argparse.ArgumentTypeError("history days must be between 90 and 180")
    return parsed


def main(argv: list[str] | None = None) -> None:
    profile_names = [profile.name for profile in PROFILES]
    parser = argparse.ArgumentParser(description="Generate synthetic healthcare firewall CSV datasets.")
    parser.add_argument("--output-dir", type=Path, default=Path("datasets"))
    parser.add_argument("--profile", choices=["all", *profile_names], default="all")
    parser.add_argument("--variations-per-profile", type=_positive_int, default=DEFAULT_VARIATIONS_PER_PROFILE)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--end-date", type=date.fromisoformat, default=DEFAULT_END_DATE)
    parser.add_argument("--history-days", type=_history_days, default=DEFAULT_HISTORY_DAYS)
    args = parser.parse_args(argv)

    # Index rows will be used to create a manifest of all generated datasets, including their profiles, seeds, and paths.
    index_rows: list[dict[str, object]] = []

    # Loop over the selected profiles and generate the specified number of variations for each profile.
    for profile in _selected_profiles(args.profile):
        for variation_num in range(1, args.variations_per_profile + 1):
            dataset = generate_dataset(
                profile,
                variation_num,
                base_seed=args.seed,
                end_date=args.end_date,
                history_days=args.history_days,
            )
            output_path = write_dataset(dataset, args.output_dir)
            labels = Counter(item.expected_recommendation for item in dataset.expected_recommendations)

            index_rows.append(
                {
                    "dataset_id": dataset.dataset_id,
                    "profile": profile.name,
                    "seed": dataset.seed,
                    "path": output_path,
                    "assets": len(dataset.assets),
                    "rules": len(dataset.firewall_policy),
                    "retain": labels["retain"],
                    "removal_candidate": labels["removal_candidate"],
                    "investigate": labels["investigate"]
                }
            )

            print(
                f"{dataset.dataset_id}: {len(dataset.assets)} assets, "
                f"{len(dataset.firewall_policy)} rules -> {output_path}"
            )

    _write_csv(
        args.output_dir / "index.csv",
        [
            "dataset_id",
            "profile",
            "seed",
            "path",
            "assets",
            "rules",
            "retain",
            "removal_candidate",
            "investigate"
        ],
        index_rows
    )

    print(f"Generated and validated {len(index_rows)} CSV datasets.")

    return


if __name__ == "__main__":
    main()
