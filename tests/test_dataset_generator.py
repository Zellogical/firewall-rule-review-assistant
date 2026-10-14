import csv
import random
from datetime import date, timedelta

from generator.dataset_generator import (
    PROFILES,
    generate_assets,
    generate_dataset,
    generate_required_communications,
    write_dataset,
)

TEST_SEED = 12345
TEST_SITE = 50
TEST_END_DATE = date(2026, 11, 19)
TEST_HISTORY_DAYS = 120
TEST_PROFILE = next(profile for profile in PROFILES if profile.name == "mixed")


def test_generate_assets_is_reproducible():
    """
    Ensures that generating assets with the same random seed and site produces the same results each time.
    """

    assets_1 = generate_assets(random.Random(TEST_SEED), TEST_SITE)
    assets_2 = generate_assets(random.Random(TEST_SEED), TEST_SITE)

    assert assets_1 == assets_2


def test_generate_assets_have_unique_ids_and_ip_addresses():
    """
    Ensures that generated assets have unique asset IDs and IP addresses.
    """

    assets = generate_assets(random.Random(TEST_SEED), TEST_SITE)

    asset_ids = [asset.asset_id for asset in assets]
    ip_addresses = [asset.ip_address for asset in assets]

    assert len(asset_ids) == len(set(asset_ids))
    assert len(ip_addresses) == len(set(ip_addresses))


def test_generate_assets_contains_expected_core_systems():
    """
    Ensures that generated assets contain the expected core systems.
    """

    assets = generate_assets(random.Random(TEST_SEED), TEST_SITE)
    asset_ids = {asset.asset_id for asset in assets}

    expected_core_assets = {
        "core_firewall_001",
        "database_001",
        "dns_001",
        "directory_001",
        "ehr_001",
        "pharmacy_001",
        "pacs_001",
        "vna_001",
        "ris_001",
        "legacy_reporting_001",
        "pump_server_001",
        "remote_proxy_001",
    }

    assert expected_core_assets.issubset(asset_ids)


def test_required_communications_reference_known_assets():
    """
    Ensures that generated required communications reference known assets.
    """

    assets = generate_assets(random.Random(TEST_SEED), TEST_SITE)
    communications = generate_required_communications(assets)

    asset_ids = {asset.asset_id for asset in assets}

    for communication in communications:
        assert communication.source_asset_id in asset_ids
        assert communication.destination_asset_id in asset_ids


def _generate_test_dataset(profile):
    """
    Helper function to generate a dataset for a given profile with fixed parameters for testing.
    """

    return generate_dataset(
        profile,
        case_number=1,
        base_seed=TEST_SEED,
        end_date=TEST_END_DATE,
        history_days=TEST_HISTORY_DAYS,
    )


def test_generate_dataset_is_reproducible():
    """
    Ensures that each profile produces the same dataset with the same settings.
    """

    for profile in PROFILES:
        dataset_1 = _generate_test_dataset(profile)
        dataset_2 = _generate_test_dataset(profile)

        assert dataset_1 == dataset_2


def test_usage_and_expected_recommendations_reference_known_rules():
    """
    Ensures that usage and expected recommendations match the generated policy.
    """

    for profile in PROFILES:
        dataset = _generate_test_dataset(profile)
        rule_ids = [rule.rule_id for rule in dataset.firewall_policy]
        expected_ids = [item.rule_id for item in dataset.expected_recommendations]

        assert len(rule_ids) == len(set(rule_ids))
        assert sorted(expected_ids) == sorted(rule_ids)
        assert {record.rule_id for record in dataset.rule_usage} == set(rule_ids)


def test_rule_usage_has_expected_dates_and_nonnegative_hits():
    """
    Ensures that normal rules have 120 days of history and the incomplete rule has 21.
    """

    dataset = _generate_test_dataset(TEST_PROFILE)

    for rule in dataset.firewall_policy:
        records = [record for record in dataset.rule_usage if record.rule_id == rule.rule_id]
        expected_days = 21 if rule.rule_id == "incomplete_ssh_management" else TEST_HISTORY_DAYS
        expected_dates = {TEST_END_DATE - timedelta(days=day) for day in range(expected_days)}

        assert len(records) == expected_days
        assert {record.observed_on for record in records} == expected_dates
        assert all(record.hit_count >= 0 for record in records)


def test_evaluation_scenarios_cover_required_and_prohibited_communications():
    """
    Ensures that use scenarios cover requirements and attack scenarios are distinct.
    """

    dataset = _generate_test_dataset(TEST_PROFILE)
    asset_ids = {asset.asset_id for asset in dataset.assets}
    required_flows = {
        (communication.source_asset_id, communication.destination_asset_id, communication.service)
        for communication in dataset.required_communications
    }
    use_scenarios = [scenario for scenario in dataset.evaluation_scenarios if scenario.scenario_type == "use"]
    attack_scenarios = [scenario for scenario in dataset.evaluation_scenarios if scenario.scenario_type == "attack"]

    assert len(use_scenarios) == len(dataset.required_communications)
    assert {
        (scenario.source_asset_id, scenario.destination_asset_id, scenario.service)
        for scenario in use_scenarios
    } == required_flows
    assert attack_scenarios

    for scenario in dataset.evaluation_scenarios:
        assert scenario.source_asset_id in asset_ids
        assert scenario.destination_asset_id in asset_ids
        assert scenario.scenario_type in {"use", "attack"}
        assert scenario.expected_action == ("allow" if scenario.scenario_type == "use" else "deny")

    for scenario in attack_scenarios:
        assert (scenario.source_asset_id, scenario.destination_asset_id, scenario.service) not in required_flows


def test_write_dataset_creates_readable_csv_files(tmp_path):
    """
    Ensures that all dataset files are written as readable CSVs with the expected rows.
    """

    dataset = _generate_test_dataset(TEST_PROFILE)
    output = write_dataset(dataset, tmp_path)
    expected_files = {
        "inputs/assets.csv": len(dataset.assets),
        "inputs/firewall_policy.csv": len(dataset.firewall_policy),
        "inputs/rule_usage.csv": len(dataset.rule_usage),
        "inputs/required_communications.csv": len(dataset.required_communications),
        "evaluation/scenarios.csv": len(dataset.evaluation_scenarios),
        "evaluation/expected_recommendations.csv": len(dataset.expected_recommendations),
    }

    for file_name, expected_rows in expected_files.items():
        with (output / file_name).open(encoding="utf-8", newline="") as file:
            reader = csv.DictReader(file)
            rows = list(reader)

        assert len(rows) == expected_rows
        assert all(None not in row and None not in row.values() for row in rows)

    with (output / "inputs/assets.csv").open(encoding="utf-8", newline="") as file:
        first_asset = next(csv.DictReader(file))

    assert first_asset["asset_id"] == dataset.assets[0].asset_id
    assert first_asset["ip_address"] == str(dataset.assets[0].ip_address)
    assert (output / "manifest.csv").is_file()
