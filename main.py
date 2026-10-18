# For testing
from engine.recommendation_engine import RecommendationEngine


if __name__ == "__main__":
    engine = RecommendationEngine("datasets/mixed_001/inputs")
    recommendations = engine.recommend_all()
    pass
