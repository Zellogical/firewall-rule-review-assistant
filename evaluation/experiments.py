"""Create missing-data copies without changing the full evaluation truth."""

from dataclasses import replace
from math import ceil
import random


def remove_records(records, fraction, seed):
    """Use the same seed to remove the same records each time."""
    indexes = list(range(len(records)))
    random.Random(seed).shuffle(indexes)
    removed = set(indexes[:ceil(len(records) * fraction)])
    return [record for index, record in enumerate(records) if index not in removed]


def build_cases(truth, dataset_id, profile, seed, include_missing_context=False):
    """Return (condition, assistant inputs, requirements verified) for each case."""
    cases = [("complete", truth, True)]
    if not include_missing_context:
        return cases

    usage = sorted(truth.rule_usage, key=lambda record: (record.rule_id, record.observed_on))
    required = sorted(truth.required_communications, key=lambda record: record.communication_id)
    for fraction in (0.25, 0.50):
        percent = int(fraction * 100)
        cases.append((
            f"missing_usage_{percent}pct",
            replace(truth, rule_usage=remove_records(usage, fraction, f"{seed}:{dataset_id}:usage")),
            True,
        ))
        cases.append((
            f"missing_requirements_{percent}pct_unverified",
            replace(truth, required_communications=remove_records(required, fraction, f"{seed}:{dataset_id}:requirements")),
            False,
        ))

    if profile == "rare_required":
        # Keep the hidden requirement in the full truth used to judge removals.
        hidden = [record for record in required if record.communication_id != "REQ-REMOTE-PUMP-SERVER"]
        if len(hidden) == len(required):
            raise ValueError("Rare-required dataset is missing the maintenance requirement.")
        inputs = replace(truth, required_communications=hidden)
        cases.append(("hidden_rare_requirement_trusted", inputs, True))
        cases.append(("hidden_rare_requirement_unverified", inputs, False))
    return cases
