"""
Recommend retain, removal_candidate, or investigate from policy evidence.
"""

from datetime import date, timedelta
from pathlib import Path

from engine.policy_analysis import DatasetInputs, PolicyAnalyzer, RuleRemovalAnalysis
from schemas.recommendation import RecommendationLabel, RuleRecommendation


class RecommendationEngine:
    def __init__(
        self,
        dataset: DatasetInputs | str | Path,
        minimum_history_days: int = 90,
        recent_window_days: int = 30,
        as_of_date: date | None = None,
    ) -> None:
        if recent_window_days < 1 or minimum_history_days < recent_window_days:
            raise ValueError("History days must be at least the recent window, which must be positive.")

        self.analyzer = PolicyAnalyzer(dataset)
        self.dataset = self.analyzer.dataset
        self.minimum_history_days = minimum_history_days
        self.recent_window_days = recent_window_days
        self.as_of_date = as_of_date if as_of_date is not None else max(
            (record.observed_on for record in self.dataset.rule_usage),
            default=date.today(),
        )

    def _summarize_usage(self, rule_id: str) -> tuple[bool, int]:
        """
        Return whether daily history is complete and the number of recent hits.
        """

        records = [record for record in self.dataset.rule_usage if record.rule_id == rule_id]
        expected_dates = {
            self.as_of_date - timedelta(days=day)
            for day in range(self.minimum_history_days)
        }
        observed_dates = {record.observed_on for record in records}
        complete_history = expected_dates.issubset(observed_dates)

        recent_start = self.as_of_date - timedelta(days=self.recent_window_days - 1)
        recent_hits = sum(
            record.hit_count
            for record in records
            if recent_start <= record.observed_on <= self.as_of_date
        )
        return complete_history, recent_hits

    def recommend_rule(self, analysis: RuleRemovalAnalysis) -> RuleRecommendation:
        """
        Apply the decision matrix in order, using the first matching condition.
        """

        complete_history, recent_hits = self._summarize_usage(analysis.rule_id)
        blocks_required = bool(analysis.blocked_required_communication_ids)
        opens_critical_access = bool(analysis.newly_allowed_critical_flows)
        removes_critical_access = bool(analysis.removed_undocumented_critical_flows)

        evidence = [
            f"Recent usage: {recent_hits} hits in the {self.recent_window_days} days through {self.as_of_date}.",
            f"Complete daily history for the last {self.minimum_history_days} days: {complete_history}.",
        ]

        if blocks_required:
            evidence.append(
                "Removal blocks required communications: "
                + ", ".join(analysis.blocked_required_communication_ids)
                + "."
            )

        if analysis.newly_allowed_flows:
            evidence.append(f"Removal newly allows {len(analysis.newly_allowed_flows)} modeled flows.")

        if opens_critical_access:
            destinations = sorted({
                change.flow.destination_asset_id
                for change in analysis.newly_allowed_critical_flows
            })
            evidence.append("Removal opens access to critical assets: " + ", ".join(destinations) + ".")

        if analysis.removed_undocumented_flows:
            evidence.append(
                f"Removal closes {len(analysis.removed_undocumented_flows)} undocumented modeled flows."
            )

        if removes_critical_access:
            destinations = sorted({
                change.flow.destination_asset_id
                for change in analysis.removed_undocumented_critical_flows
            })
            evidence.append("The rule permits undocumented access to critical assets: " + ", ".join(destinations) + ".")

        if analysis.observed_replacement_rule_ids:
            evidence.append(
                "Observed replacement rules or default action: "
                + ", ".join(analysis.observed_replacement_rule_ids)
                + "."
            )

        # Decision matrix, in order of precedence. The first matching condition determines the recommendation.
        recommendation: RecommendationLabel
        if blocks_required and removes_critical_access:
            recommendation = "investigate"
            reason = "Required communication and undocumented critical access conflict. Do not remove as-is; review narrowing."
        elif blocks_required:
            recommendation = "retain"
            reason = "Keep the rule to preserve the listed required communications, regardless of usage."
        elif opens_critical_access:
            recommendation = "retain"
            reason = "Keep the rule because removal exposes a critical asset."
        elif not complete_history:
            recommendation = "investigate"
            reason = f"Daily usage coverage is missing within the {self.minimum_history_days} days through {self.as_of_date}."
        elif not analysis.has_modeled_effect and not analysis.is_behaviorally_redundant:
            recommendation = "investigate"
            reason = "No changed flows or replacement evidence were found; modeled coverage is insufficient to justify removal."
        elif analysis.is_behaviorally_redundant:
            recommendation = "removal_candidate"
            reason = "Another rule or the default supplies the same behavior for the modeled traffic."
        elif analysis.removed_undocumented_flows and not analysis.newly_allowed_flows and recent_hits == 0:
            recommendation = "removal_candidate"
            reason = "No recent hits, no required communication interrupted, and no new access; removal closes undocumented access."
        elif analysis.newly_allowed_flows:
            recommendation = "investigate"
            reason = "Removal creates new access, so inactivity alone cannot justify removing the rule."
        elif recent_hits > 0:
            recommendation = "investigate"
            reason = "Recent usage exists, but no documented required communication depends on keeping this rule."
        else:
            recommendation = "investigate"
            reason = "The available evidence does not justify a retain or removal recommendation."

        evidence.append(reason)
        if recommendation == "investigate":
            priority = "high" if opens_critical_access or removes_critical_access else "normal"
            evidence.append(f"Investigation priority: {priority}.")

        return RuleRecommendation(analysis.rule_id, recommendation, evidence)

    def recommend_all(self) -> list[RuleRecommendation]:
        """
        Return one explained recommendation per rule, in policy order.
        """

        return [self.recommend_rule(analysis) for analysis in self.analyzer.analyze_all()]
