# A RequiredCommunication represents a legitimate network communication that the modeled healthcare environment must
# preserve during firewall-rule review.

# The schema is project-defined using the information needed to evaluate a communication against a firewall policy:
# source asset, destination asset,  protocol, destination port port, and operational purpose.

# The communication relationships are adapted from healthcare workflows in NIST SP 1800-8 and NIST SP 1800-24.
# Generated asset IDs and any ports not specified by the sources are documented modeling choices.

# Sources:
# https://nvlpubs.nist.gov/nistpubs/SpecialPublicSolPublications/NIST.SP.1800-8.pdf
# https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.1800-24.pdf

from dataclasses import dataclass

from schemas.firewall_rule import Service


@dataclass(frozen=True)
class RequiredCommunication:
    communication_id: str
    source_asset_id: str
    destination_asset_id: str
    service: Service
    purpose: str
    source_reference: str
