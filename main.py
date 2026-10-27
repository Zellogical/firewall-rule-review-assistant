"""Save recommendations from the four input CSVs to a results CSV."""

import argparse
import csv

from engine.policy_analysis import load_dataset
from engine.recommendation_engine import RecommendationEngine


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", help="Directory containing the four input CSVs.")
    parser.add_argument("--output", default="recommendations.csv")
    parser.add_argument("--requirements-verified-complete", action="store_true")
    args = parser.parse_args()

    try:
        dataset = load_dataset(args.inputs)
        if not dataset.rule_usage:
            raise ValueError("Rule usage must contain at least one dated record.")
        engine = RecommendationEngine(
            dataset, requirements_verified_complete=args.requirements_verified_complete
        )
        rows = [
            {"rule_id": result.rule_id, "recommendation": result.recommendation,
             "evidence": " | ".join(result.evidence)}
            for result in engine.recommend_all()
        ]
        with open(args.output, "w", newline="", encoding="utf-8") as output:
            writer = csv.DictWriter(output, fieldnames=["rule_id", "recommendation", "evidence"])
            writer.writeheader()
            writer.writerows(rows)
        print(f"Saved {len(rows)} recommendations to {args.output} (review date: {engine.as_of_date}).")
    except (ValueError, OSError) as error:
        parser.error(str(error))
