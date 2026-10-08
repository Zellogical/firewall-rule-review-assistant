import random
from datetime import date

from generator.dataset_generator import (
    generate_assets,
    generate_required_communications
)


TEST_SEED = 12345
TEST_SITE = 50
TEST_END_DATE = date(2026, 11, 19)
TEST_HISTORY_DAYS = 120


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
