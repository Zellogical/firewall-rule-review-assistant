# Asset types adapted from NIST SP 1800-8 and SP 1800-24.
# Network zones are adapted primarily from NIST SP 1800-8.
# Criticality levels are project modeling choices.

# Sources:
# https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.1800-8.pdf
# https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.1800-24.pdf

from dataclasses import dataclass
from ipaddress import IPv4Address
from typing import Literal


AssetType = Literal[
    "network_device",
    "guest_device",
    "staff_workstation",
    "viewer_workstation",
    "database_server",
    "dns_server",
    "directory_service",
    "ehr_system",
    "pharmacy_system",
    "pump_server",
    "infusion_pump",
    "remote_access_proxy",
    "imaging_modality",
    "pacs_server",
    "vna_server",
    "ris_system",
]


AssetZone = Literal[
    "core_network_zone",
    "guest_network_zone",
    "business_office_zone",
    "database_server_zone",
    "enterprise_services_zone",
    "clinical_services_zone",
    "biomedical_engineering_zone",
    "medical_devices_zone",
    "remote_access_zone",
]


Criticality = Literal["low", "medium", "high", "critical"]


@dataclass(frozen=True)
class Asset:
    asset_id: str
    asset_type: AssetType
    ip_address: IPv4Address
    zone: AssetZone
    criticality: Criticality
