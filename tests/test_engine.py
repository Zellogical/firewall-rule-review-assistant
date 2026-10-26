"""Check the main removal effects and recommendation decisions."""

from dataclasses import replace

from engine.policy_analysis import PolicyAnalyzer
from engine.recommendation_engine import RecommendationEngine
from schemas.usage import RuleUsage
from tests.sample_data import REVIEW_DATE, make_dataset, make_rule


def test_required_communication_is_retained_even_with_zero_hits():
    dataset = make_dataset()
    analysis = PolicyAnalyzer(dataset).analyze_rule("allow_pacs")
    assert analysis.blocked_required_communication_ids == ("view_images",)
    recommendation = RecommendationEngine(dataset).recommend_all()[0]
    assert recommendation.recommendation == "retain"
    assert recommendation.evidence


def test_removing_a_protective_deny_exposes_a_critical_asset():
    dataset = make_dataset([make_rule("protect_pacs", "deny"), make_rule()], required=False)
    analysis = PolicyAnalyzer(dataset).analyze_rule("protect_pacs")
    assert len(analysis.newly_allowed_critical_flows) == 1
    assert analysis.newly_allowed_flows[0].after.matched_rule_id == "allow_pacs"
    assert RecommendationEngine(dataset).recommend_all()[0].recommendation == "retain"


def test_redundant_rule_is_a_candidate_when_another_rule_takes_over():
    dataset = make_dataset([make_rule(), make_rule("backup_allow")])
    analyzer = PolicyAnalyzer(dataset)
    analysis = analyzer.analyze_rule("allow_pacs")
    assert not analysis.has_modeled_effect
    assert analysis.observed_replacement_rule_ids == ("backup_allow",)
    assert RecommendationEngine(dataset).recommend_all()[0].recommendation == "removal_candidate"
    assert analyzer.dataset.firewall_policy == [make_rule(), make_rule("backup_allow")]


def test_missing_history_is_not_treated_as_zero_usage():
    dataset = make_dataset(required=False)
    engine = RecommendationEngine(dataset, as_of_date=REVIEW_DATE)
    assert engine._summarize_usage("allow_pacs") == (True, 0)
    assert engine.recommend_all()[0].recommendation == "removal_candidate"
    missing = replace(dataset, rule_usage=dataset.rule_usage[1:])
    engine = RecommendationEngine(missing, as_of_date=REVIEW_DATE)
    assert engine._summarize_usage("allow_pacs") == (False, 0)
    assert engine.recommend_all()[0].recommendation == "investigate"


def test_recent_usage_without_a_requirement_needs_investigation():
    dataset = make_dataset(required=False)
    usage = [RuleUsage("allow_pacs", REVIEW_DATE, 5)] + dataset.rule_usage[1:]
    engine = RecommendationEngine(replace(dataset, rule_usage=usage), as_of_date=REVIEW_DATE)
    assert engine._summarize_usage("allow_pacs") == (True, 5)
    assert engine.recommend_all()[0].recommendation == "investigate"


def test_an_undocumented_requirement_is_not_assumed_unnecessary():
    dataset = make_dataset()
    hidden = replace(dataset, required_communications=[])
    assert RecommendationEngine(dataset).recommend_all()[0].recommendation == "retain"
    assert RecommendationEngine(hidden).recommend_all()[0].recommendation == "removal_candidate"
    engine = RecommendationEngine(hidden, requirements_verified_complete=False)
    assert engine.recommend_all()[0].recommendation == "investigate"
    assert len(dataset.required_communications) == 1
