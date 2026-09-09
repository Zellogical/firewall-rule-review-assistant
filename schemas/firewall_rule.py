# Simplified Palo Alto firewall rule schema.
# Source: https://docs.paloaltonetworks.com/network-security/security-policy/administration/security-rules

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
from typing import Literal

Address = IPv4Address | IPv4Network | Literal["any"]


@dataclass(frozen=True)
class Service:
    protocol: Literal["tcp", "udp"]
    destination_port: int


ServiceMatch = Service | Literal["any"]


@dataclass(frozen=True)
class FirewallRule:
    rule_id: str
    source_zones: list[str]
    destination_zones: list[str]
    source_addresses: list[Address]
    destination_addresses: list[Address]
    services: list[ServiceMatch]
    action: Literal["allow", "deny"]


FirewallPolicy = list[FirewallRule]
