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
from datetime import date
from ipaddress import IPv4Address
from pathlib import Path
from typing import Literal

from schemas.asset import Asset, AssetType, AssetZone, Criticality
from schemas.communication import RequiredCommunication
from schemas.firewall_rule import FirewallPolicy
from schemas.recommendation import ExpectedRecommendation
from schemas.scenario import EvaluationScenario
from schemas.usage import RuleUsageHistory

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


def generate_required_communications(assets: list[Asset]) -> list[RequiredCommunication]:
    return []


def generate_firewall_policy(
    profile: ProfileName,
    assets: list[Asset]
) -> FirewallPolicy:
    return FirewallPolicy([])


def generate_rule_usage(
    profile: ProfileName,
    policy: FirewallPolicy,
    seed: int,
    end_date: date,
    history_days: int
) -> RuleUsageHistory:
    return RuleUsageHistory([])


def generate_evaluation_scenarios(
    assets: list[Asset],
    required_communications: list[RequiredCommunication]
) -> list[EvaluationScenario]:
    return []


def generate_expected_recommendations(
    profile: ProfileName,
    firewall_policy: FirewallPolicy
) -> list[ExpectedRecommendation]:
    return []


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

    # TODO: Add logic to generate the firewall policy based on the profile and assets.
    # TODO: Add logic to generate the required communications based on the profile and assets.

    dataset = GeneratedDataset(
        dataset_id=f"{profile.name}_{case_number:03d}",
        profile=profile,
        variation_num=case_number,
        seed=dataset_seed,
        end_date=end_date,
        history_days=history_days,
        assets=assets,
        firewall_policy=FirewallPolicy([]),
        rule_usage=RuleUsageHistory([]),
        required_communications=list(),
        evaluation_scenarios=list(),
        expected_recommendations=list()
    )

    # TODO: Add validation of the generated dataset to ensure that it meets the expected conditions for the profile.

    return dataset


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


def write_dataset(dataset: GeneratedDataset, output_root: Path) -> Path:
    """
    Write one generated variation as CSV inputs, evaluation files, and metadata.
    """

    root = output_root / dataset.dataset_id
    inputs = root / "inputs"

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

    counts = {
        "asset_count": len(dataset.assets)
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
            "investigate",
        ],
        index_rows
    )

    print(f"Generated and validated {len(index_rows)} CSV datasets.")

    return


if __name__ == "__main__":
    main()
