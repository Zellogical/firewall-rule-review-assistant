"""Upload the four input CSVs and review the assistant's recommendations."""

import csv
import io
from pathlib import Path
from tempfile import TemporaryDirectory

import streamlit as st

from engine.policy_analysis import load_dataset
from engine.recommendation_engine import RecommendationEngine


st.title("Firewall Rule Review Assistant")
st.caption("Reviews one simplified policy. It does not change a live firewall.")
files = {
    name: st.file_uploader(name, type="csv")
    for name in ("assets.csv", "firewall_policy.csv", "rule_usage.csv", "required_communications.csv")
}
complete = st.checkbox(
    "I have verified that the required communication list is complete.",
    value=False,
    help="Leave unchecked if requirements may be missing. The assistant cannot verify completeness itself.",
)
st.caption("Uses 90 days of daily history and a 30-day recent window, ending on the latest usage date.")

if st.button("Analyze policy"):
    if any(upload is None for upload in files.values()):
        st.error("Upload all four CSV files before analyzing the policy.")
    else:
        try:
            with TemporaryDirectory() as directory:
                for name, upload in files.items():
                    if upload is not None:
                        Path(directory, name).write_bytes(upload.getvalue())
                dataset = load_dataset(directory)
            if not dataset.rule_usage:
                raise ValueError("Rule usage must contain at least one dated record.")
            engine = RecommendationEngine(dataset, requirements_verified_complete=complete)
            rows = [
                {"rule_id": result.rule_id, "recommendation": result.recommendation,
                 "evidence": " | ".join(result.evidence)}
                for result in engine.recommend_all()
            ]
            st.caption(f"Review date: {engine.as_of_date}. Candidates still require human approval.")
            st.dataframe(rows, hide_index=True)
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=["rule_id", "recommendation", "evidence"])
            writer.writeheader()
            writer.writerows(rows)
            st.download_button("Download results", output.getvalue(), "recommendations.csv", "text/csv", on_click="ignore")
        except (ValueError, OSError) as error:
            st.error(str(error))
