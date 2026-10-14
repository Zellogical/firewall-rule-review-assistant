"""
Recommend retain, removal_candidate, or investigate from policy evidence.
"""

from datetime import date, timedelta
from pathlib import Path

from engine.policy_analysis import DatasetInputs, PolicyAnalyzer


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
