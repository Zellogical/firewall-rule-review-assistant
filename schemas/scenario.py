# Evaluation scenarios used to test the firewall rule review assistant.

# A use scenario represents legitimate communication that should be allowed.
# An attack scenario represents prohibited communication that should be denied.

# These scenarios are used by the evaluator and are not provided to the recommendation engine.
# Attack scenarios represent network communication attempts, not simulations of malware or exploitation.

# Use scenarios are adapted from NIST healthcare workflows.
# Attack scenarios are based on documented network boundaries and project modeling choices.

from dataclasses import dataclass
from typing import Literal

from schemas.firewall_rule import Service


ScenarioType = Literal["use", "attack"]
ExpectedAction = Literal["allow", "deny"]


@dataclass(frozen=True)
class EvaluationScenario:
    scenario_id: str
    scenario_type: ScenarioType
    source_asset_id: str
    destination_asset_id: str
    service: Service
    expected_action: ExpectedAction
    description: str

    def __post_init__(self) -> None:
        if self.scenario_type == "use" and self.expected_action != "allow":
            raise ValueError("Use scenarios must expect allow.")

        if self.scenario_type == "attack" and self.expected_action != "deny":
            raise ValueError("Attack scenarios must expect deny.")
