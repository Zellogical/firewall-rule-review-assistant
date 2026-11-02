"""A few small known-answer checks for the evaluation code."""

from dataclasses import replace

from evaluation.baseline import usage_only_recommendations
from evaluation.metrics import calculate_metrics
from evaluation.scenarios import scenario_removal_results
from schemas.usage import RuleUsage
from tests.sample_data import REVIEW_DATE, make_dataset, make_rule


def test_baseline_uses_recent_hits_and_does_not_treat_missing_days_as_zero():
    dataset = make_dataset()
    assert usage_only_recommendations(dataset, REVIEW_DATE)[0].recommendation == "removal_candidate"
    active = replace(dataset, rule_usage=[RuleUsage("allow_pacs", REVIEW_DATE, 2)] + dataset.rule_usage[1:])
    assert usage_only_recommendations(active, REVIEW_DATE)[0].recommendation == "retain"
    missing = replace(dataset, rule_usage=dataset.rule_usage[1:])
    assert usage_only_recommendations(missing, REVIEW_DATE)[0].recommendation == "investigate"


def test_scenario_checks_distinguish_new_exposure_from_existing_exposure():
    attack = {"scenario_id": "prohibited", "scenario_type": "attack", "expected_action": "deny",
              "source_asset_id": "workstation", "destination_asset_id": "pacs",
              "service_protocol": "tcp", "service_destination_port": "443"}
    protected = make_dataset([make_rule("protect", "deny"), make_rule()], required=False)
    result = scenario_removal_results(protected, [attack], "protect")[0]
    assert result["newly_allowed_attack"] and not result["preexisting_attack_exposure"]
    assert result["after_rule_id"] == "allow_pacs"
    result = scenario_removal_results(make_dataset(), [attack], "allow_pacs")[0]
    assert result["preexisting_attack_exposure"] and result["closed_attack_exposure"]
    assert not result["newly_allowed_attack"]
    use = {**attack, "scenario_type": "use", "expected_action": "allow"}
    assert scenario_removal_results(make_dataset(), [use], "allow_pacs")[0]["blocked_use"]


def test_metrics_count_only_selected_removals_and_handle_empty_denominators():
    common = {"dataset_id": "example", "compare_labels": True, "blocked_use_count": 0,
              "new_attack_count": 0, "closed_attack_count": 0, "preexisting_attack_count": 2}
    rows = [
        {**common, "recommendation": "removal_candidate", "expected_recommendation": "retain",
         "blocked_use_count": 1, "new_attack_count": 1},
        {**common, "recommendation": "removal_candidate", "expected_recommendation": "removal_candidate",
         "closed_attack_count": 1},
        {**common, "recommendation": "investigate", "expected_recommendation": "investigate", "new_attack_count": 5},
    ]
    result = calculate_metrics(rows)
    assert result["matching_labels"] == 2
    assert result["unsafe_removal_count"] == 1 and result["unsafe_removal_rate"] == 0.5
    assert result["correct_cleanup_count"] == 1 and result["cleanup_recall"] == 1
    assert result["newly_exposed_attack_scenarios"] == 1
    assert result["preexisting_attack_scenarios"] == 2
    assert result["investigate_count"] == 1
    assert calculate_metrics([])["unsafe_removal_rate"] is None
