# For testing
from engine.policy_analysis import PolicyAnalyzer

if __name__ == "__main__":
    policy_analyzer = PolicyAnalyzer("./datasets/clean_001/inputs")

    analysis = policy_analyzer.analyze_all()
    pass
