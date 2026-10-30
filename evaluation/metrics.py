"""Count useful cleanup, unsafe removals, and rules needing investigation."""


def _rate(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def calculate_metrics(rows: list[dict]) -> dict:
    """
    Rates are proportions; None means there was no applicable denominator.

    Safety counts apply only to removal candidates. Scenario counts represent
    removal-scenario pairs, since every rule is removed independently.
    """

    candidates = [row for row in rows if row["recommendation"] == "removal_candidate"]
    unsafe = [row for row in candidates if row["blocked_use_count"] or row["new_attack_count"]]
    useful = [
        row for row in candidates
        if not row["blocked_use_count"] and not row["new_attack_count"]
        and row["expected_recommendation"] == "removal_candidate"
    ]
    compared = [row for row in rows if row["compare_labels"]]
    matches = sum(row["recommendation"] == row["expected_recommendation"] for row in compared)
    expected_cleanup = sum(row["expected_recommendation"] == "removal_candidate" for row in rows)
    investigated = sum(row["recommendation"] == "investigate" for row in rows)

    # Original exposure is counted once per dataset, not once per removed rule.
    original_exposure = {
        row["dataset_id"]: row["preexisting_attack_count"] for row in rows
    }

    return {
        "rule_count": len(rows),
        "label_comparison_count": len(compared),
        "matching_labels": matches,
        "label_agreement_rate": _rate(matches, len(compared)),
        "removal_candidate_count": len(candidates),
        "unsafe_removal_count": len(unsafe),
        "unsafe_removal_rate": _rate(len(unsafe), len(candidates)),
        "expected_cleanup_count": expected_cleanup,
        "correct_cleanup_count": len(useful),
        "cleanup_recall": _rate(len(useful), expected_cleanup),
        "cleanup_precision": _rate(len(useful), len(candidates)),
        "investigate_count": investigated,
        "investigation_rate": _rate(investigated, len(rows)),
        "disrupted_required_scenarios": sum(row["blocked_use_count"] for row in candidates),
        "newly_exposed_attack_scenarios": sum(row["new_attack_count"] for row in candidates),
        "closed_attack_scenarios": sum(row["closed_attack_count"] for row in candidates),
        "preexisting_attack_scenarios": sum(original_exposure.values()),
    }


def summarize_results(rows: list[dict]) -> list[dict]:
    """
    Summarize each method and condition, both per profile and overall.
    """

    groups = {}
    for row in rows:
        for profile in (row["profile"], "all"):
            key = (row["method"], row["condition"], profile)
            groups.setdefault(key, []).append(row)
    return [
        {"method": method, "condition": condition, "profile": profile, **calculate_metrics(group)}
        for (method, condition, profile), group in sorted(groups.items())
    ]
