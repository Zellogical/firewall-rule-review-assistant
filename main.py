# For testing
from engine.policy_analysis import PolicyAnalyzer

if __name__ == "__main__":
    policy_analyzer = PolicyAnalyzer("./datasets/clean_001/inputs")

    print("Loaded dataset successfully")
    print(f"Assets: {len(policy_analyzer.dataset.assets)}")
    print(f"Rules: {len(policy_analyzer.dataset.firewall_policy)}")
    print(f"Communications: {len(policy_analyzer.dataset.required_communications)}")

    communication = policy_analyzer.dataset.required_communications[0]

    print("\nTesting communication:")
    print(communication)

    flow = policy_analyzer.flow_for_communication(communication)

    print("\nConverted flow:")
    print(flow)

    decision = policy_analyzer.evaluate(flow)

    print("\nPolicy decision:")
    print(decision)

    pass
