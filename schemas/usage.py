# Synthetic rule-usage history for the modeled firewall policy.

# Each record represents the number of times a rule matched traffic on one day.
# This is aggregated synthetic usage data, not a packet-level traffic log or
# a field taken directly from a Palo Alto security rule.

# Hit counts and usage patterns are project modeling choices.

from dataclasses import dataclass
from datetime import date


@dataclass(frozen=True)
class RuleUsage:
    rule_id: str
    observed_on: date
    hit_count: int

    def __post_init__(self) -> None:
        if self.hit_count < 0:
            raise ValueError("Hit count cannot be negative.")


RuleUsageHistory = list[RuleUsage]
