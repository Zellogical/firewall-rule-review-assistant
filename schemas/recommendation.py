# Recommendation models for the firewall rule review assistant.

# The recommendation categories are project-defined:
# - retain: Evidence indicates that the rule should remain in the policy.
# - removal_candidate: No identified requirement depends on the rule, and the available evidence indicates that it
#   may be removed safely.
# - investigate: The available information is incomplete, conflicting, or insufficient to make a
#   confident recommendation.

# RuleRecommendation represents the result produced by the assistant.
# ExpectedRecommendation represents the predefined answer used only during evaluation.
# The assistant must not use the expected recommendation when analyzing a rule.

from dataclasses import dataclass
from typing import Literal


RecommendationLabel = Literal[
    "retain",
    "removal_candidate",
    "investigate",
]


@dataclass(frozen=True)
class RuleRecommendation:
    rule_id: str
    recommendation: RecommendationLabel
    evidence: list[str]


@dataclass(frozen=True)
class ExpectedRecommendation:
    rule_id: str
    expected_recommendation: RecommendationLabel
    justification: str
