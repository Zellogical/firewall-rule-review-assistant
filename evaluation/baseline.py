"""Make recommendations using only daily rule usage."""

from datetime import date, timedelta

from engine.policy_analysis import DatasetInputs
from schemas.recommendation import RuleRecommendation


def usage_only_recommendations(
    inputs: DatasetInputs,
    as_of_date: date,
    minimum_history_days: int = 90,
    recent_window_days: int = 30,
) -> list[RuleRecommendation]:
    """
    Use the assistant's history windows, but no policy or asset context.
    """

    if recent_window_days < 1 or minimum_history_days < recent_window_days:
        raise ValueError("History days must cover the positive recent window.")

    expected_dates = {
        as_of_date - timedelta(days=day)
        for day in range(minimum_history_days)
    }
    recent_start = as_of_date - timedelta(days=recent_window_days - 1)
    recommendations = []

    for rule in inputs.firewall_policy:
        records = [record for record in inputs.rule_usage if record.rule_id == rule.rule_id]
        complete = expected_dates.issubset({record.observed_on for record in records})
        recent_hits = sum(
            record.hit_count for record in records
            if recent_start <= record.observed_on <= as_of_date
        )
        if not complete:
            label = "investigate"
        elif recent_hits == 0:
            label = "removal_candidate"
        else:
            label = "retain"
        recommendations.append(RuleRecommendation(rule.rule_id, label, [
            f"Usage-only baseline: {recent_hits} recent hits through {as_of_date}.",
            f"Complete daily history for {minimum_history_days} days: {complete}.",
        ]))

    return recommendations
