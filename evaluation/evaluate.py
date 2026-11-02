"""Compare the assistant and usage-only baseline, then save CSV results."""

import argparse
import csv
from datetime import date
from pathlib import Path

from engine.policy_analysis import load_dataset
from engine.recommendation_engine import RecommendationEngine
from evaluation.baseline import usage_only_recommendations
from evaluation.experiments import build_cases
from evaluation.metrics import summarize_results
from evaluation.scenarios import load_expected_recommendations, load_scenarios, scenario_removal_results


def write_csv(path, rows):
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def run_evaluation(datasets, output, include_missing_context=False, seed=12345):
    source, destination = Path(datasets).resolve(), Path(output).resolve()
    if destination == source or source in destination.parents:
        raise ValueError("Save results outside the source datasets directory.")
    directories = [source] if (source / "manifest.csv").exists() else sorted(
        path for path in source.iterdir() if (path / "manifest.csv").is_file()
    )
    if not directories:
        raise ValueError("No generated datasets were found.")
    rule_rows, scenario_rows, conditions = [], [], []
    seen_ids = set()

    for directory in directories:
        with (directory / "manifest.csv").open(newline="", encoding="utf-8-sig") as file:
            metadata = {row["field"]: row["value"] for row in csv.DictReader(file)}
        dataset_id, profile = metadata["dataset_id"], metadata["profile"]
        review_date = date.fromisoformat(metadata["end_date"])
        if dataset_id in seen_ids or profile == "all":
            raise ValueError("Dataset IDs must be unique and profile 'all' is reserved for totals.")
        if metadata["default_policy_action"] != "deny":
            raise ValueError("This evaluation uses default deny.")
        seen_ids.add(dataset_id)
        truth = load_dataset(directory / "inputs")
        scenarios = load_scenarios(directory / "evaluation/scenarios.csv", truth)
        answers = load_expected_recommendations(directory / "evaluation/expected_recommendations.csv", truth)

        # Policy and full truth stay unchanged, so check each removal once.
        checks = {}
        for rule in truth.firewall_policy:
            checks[rule.rule_id] = scenario_removal_results(truth, scenarios, rule.rule_id)
            for result in checks[rule.rule_id]:
                scenario_rows.append({"dataset_id": dataset_id, "rule_id": rule.rule_id, **result})

        for condition, inputs, verified in build_cases(truth, dataset_id, profile, seed, include_missing_context):
            supplied_ids = {item.communication_id for item in inputs.required_communications}
            conditions.append({
                "dataset_id": dataset_id, "condition": condition, "seed": seed,
                "review_date": review_date, "requirements_verified_complete": verified,
                "removed_usage_rows": len(truth.rule_usage) - len(inputs.rule_usage),
                "removed_requirement_ids": ";".join(
                    item.communication_id for item in truth.required_communications
                    if item.communication_id not in supplied_ids
                ),
            })
            methods = {
                "assistant": RecommendationEngine(
                    inputs, as_of_date=review_date, requirements_verified_complete=verified
                ).recommend_all(),
                "usage_only": usage_only_recommendations(inputs, review_date),
            }
            for method, recommendations in methods.items():
                for result in recommendations:
                    effects = checks[result.rule_id]
                    rule_rows.append({
                        "dataset_id": dataset_id, "profile": profile, "condition": condition,
                        "method": method, "rule_id": result.rule_id,
                        "recommendation": result.recommendation,
                        "expected_recommendation": answers[result.rule_id]["expected_recommendation"],
                        "compare_labels": condition == "complete",
                        "blocked_use_count": sum(item["blocked_use"] for item in effects),
                        "new_attack_count": sum(item["newly_allowed_attack"] for item in effects),
                        "preexisting_attack_count": sum(item["preexisting_attack_exposure"] for item in effects),
                        "closed_attack_count": sum(item["closed_attack_exposure"] for item in effects),
                        "evidence": " | ".join(result.evidence),
                    })

    destination.mkdir(parents=True, exist_ok=True)
    write_csv(destination / "rule_results.csv", rule_rows)
    write_csv(destination / "scenario_results.csv", scenario_rows)
    write_csv(destination / "summary.csv", summarize_results(rule_rows))
    write_csv(destination / "conditions.csv", conditions)
    return len(directories), len(conditions), len(rule_rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--datasets", default="datasets")
    parser.add_argument("--output", default="results")
    parser.add_argument("--include-missing-context", action="store_true")
    parser.add_argument("--seed", type=int, default=12345)
    args = parser.parse_args()
    datasets, conditions, rows = run_evaluation(args.datasets, args.output, args.include_missing_context, args.seed)
    print(f"Evaluated {datasets} datasets and {conditions} conditions. Saved {rows} rule results to {args.output}.")
