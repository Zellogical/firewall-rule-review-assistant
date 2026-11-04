# firewall-rule-review-assistant
A prototype tool that reviews existing firewall rules using usage history, asset criticality, documented communication requirements, and modeled removal impact. Built with synthetic healthcare data to support retain, remove, or investigate decisions.

## Run the project

Use Python 3.10 or newer. From the repository folder:

```text
python -m pip install -r requirements.txt
python -m pytest -q
python -m streamlit run streamlit_app.py
```

Upload `assets.csv`, `firewall_policy.csv`, `rule_usage.csv`, and `required_communications.csv` from one dataset's `inputs` folder. The supplied datasets are ready to use. Evaluation scenarios and expected recommendations are answer keys, not assistant inputs.

The interface displays each recommendation and its evidence, and lets you download the table. It does not change a firewall. Leave the completeness checkbox unchecked when communication documentation may be missing. Checking it is your assertion, not proof that the list is complete.

For a simple command-line review:

```text
python main.py datasets/mixed_001/inputs --output recommendations.csv
```

Add `--requirements-verified-complete` only if requirements were checked. Both entry points use the latest usage date, 90 days of history, and a 30-day recent window. Zero-hit days must still have daily records missing records are not zero usage. The Python class retains its original complete-context default for compatibility. External callers should explicitly set `requirements_verified_complete=False` when unsure.

## What is supported

One ordered IPv4 policy, source/destination zones and addresses/subnets, TCP/UDP destination ports, `any`, allow/deny actions, and default deny. Lists in policy CSVs use semicolons. Services use values such as `tcp:443`. Asset types and zones may be any nonempty labels. Criticality is `low`, `medium`, `high`, or `critical`.

The engine removes one rule at a time and compares behavior with the original policy. It checks known asset pairs and modeled services, not every possible address or port. NAT, routing, stateful sessions, application/user matching, IPv6, and multiple-firewall paths are outside scope. An undocumented flow is not automatically unnecessary.
  
The existing decision matrix remains in place: preserve required communication and protective rules. Investigate missing or conflicting evidence. Identify modeled redundancy and inactive unnecessary access. Critical-access conflicts may need narrowing rather than removal. An inactive undocumented rule needs verified requirements before becoming a candidate. Redundancy findings still require checking unmodeled traffic. Every candidate requires human review. Iindividually removable rules are not necessarily safe to remove together.

## Run the evaluation

```text
python -m evaluation.evaluate --include-missing-context
```

Both methods use the same fixed review date from each dataset's manifest. The usage-only baseline returns Investigate for incomplete history, Removal Candidate for no recent hits with complete history, and Retain otherwise.

The evaluation checks two things: whether complete-context recommendations match the answer key, and whether recommended removals interrupt use scenarios or newly permit prohibited access. Each removal starts from the original policy. Attack scenarios already permitted before removal are recorded separately from exposure caused by removal.

Missing-data tests remove 25% and 50% of usage records or communication requirements from the assistant's copy. The full truth remains unchanged. The rare-required profile also tests one hidden requirement with documentation falsely trusted versus marked unverified. The default seed is 12345. Use `--seed` to change it. Missing-context label agreement is left blank because Investigate can be an appropriate response to missing evidence.

| Output in `results/` | What it contains |
| --- | --- |
| `rule_results.csv` | Each method's recommendation, expected label, effects, and evidence |
| `scenario_results.csv` | Before/after results for each rule/scenario, saved once because policy and truth stay fixed |
| `summary.csv` | Counts and rates by method, condition, and profile, plus overall totals |
| `conditions.csv` | Seed, review date, missing usage count, removed requirement IDs, and documentation status |

Safety totals count only Removal Candidate decisions. Scenario counts are removal/scenario pairs. Rates are proportions from 0 to 1. Blank means no denominator. Unsafe rate = unsafe candidates / all candidates. Cleanup recall = correct safe cleanup candidates / expected cleanup candidates. Investigation rate = Investigate decisions / reviewed rules. Label agreement uses complete controls only.

To generate another suite without replacing the supplied one:

```text
python -m generator.dataset_generator --output-dir datasets_alternate --seed 100
python -m evaluation.evaluate --datasets datasets_alternate --output results_alternate --include-missing-context
```

## Findings and limits

The saved run covers 24 datasets and 126 dataset/condition combinations, using both methods. Complete-context assistant results matched 192/192 labels, with 12 candidates and no unsafe candidates in the defined scenarios. The usage-only baseline matched 153/192 labels, with 42 candidates and 30 unsafe candidates. Falsely trusting the hidden rare requirement produced three unsafe assistant candidates. Marking the same inputs unverified produced three Investigate decisions instead.

These are controlled variations of one modeled healthcare environment, not independent hospitals. The generator adapts selected roles and workflows from NIST SP 1800-8 and SP 1800-24. Addresses, quantities, criticality, ports, usage patterns, and injected rule conditions are project modeling choices. Generated labels share the author's assumptions, and scenario checks reuse the policy matcher. Small handmade tests check the main behavior independently, but real-world safety and representativeness still need independent review. No sensitive employer data or live firewall access is used.
