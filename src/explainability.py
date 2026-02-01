"""
Explainability utilities for ZeroBit using SHAP.
Loads the trained ETA model and SHAP explainer, and produces
human-readable reasons plus waterfall plots for single flows.
"""

from __future__ import annotations

import os
import pickle
from pathlib import Path
from typing import Any, Optional
import pandas as pd

import matplotlib.pyplot as plt  # type: ignore
import numpy as np
import shap  # type: ignore


class TrafficExplainer:
    """Provides SHAP-based explanations for ETA model predictions."""

    def __init__(
        self,
        model_path: Path | str = Path("models/eta_model.pkl"),
        explainer_path: Path | str = Path("models/shap_explainer.pkl"),
    ) -> None:
        self.model_path = Path(model_path)
        self.explainer_path = Path(explainer_path)
        self.model = None
        self.explainer = None
        
        # Try to load model and explainer, but don't fail if they don't exist
        try:
            if self.model_path.exists():
                with self.model_path.open("rb") as f:
                    self.model = pickle.load(f)
        except Exception:
            pass
            
        try:
            if self.explainer_path.exists():
                with self.explainer_path.open("rb") as f:
                    self.explainer = pickle.load(f)
        except Exception:
            pass

    def generate_explanation(self, flow_vector: pd.DataFrame, output_dir: str = "static/alerts") -> str:
        """
        Compute SHAP values for a single flow vector and return a text summary
        of the top 3 features driving a malicious classification.
        """
        if self.explainer is None or self.model is None:
            return "Reason: Model or explainer not available. Using default explanation."
        
        try:
            shap_values = self.explainer(flow_vector)
            contribs = shap_values.values[0] if hasattr(shap_values, 'values') else shap_values[0]
            feature_names = flow_vector.columns

            # Top 3 positive contributions
            pos_idxs = np.argsort(contribs)[::-1]
            top_idxs = [idx for idx in pos_idxs if contribs[idx] > 0][:3]

            if len(top_idxs) == 0:
                return "Reason: No positive contributors; prediction driven by neutral/negative features."

            total = np.sum(np.abs(contribs)) or 1.0
            parts = []
            for idx in top_idxs:
                perc = (contribs[idx] / total) * 100
                parts.append(f"{feature_names[idx]} (+{perc:.1f}%)")
            return "Reason: " + ", ".join(parts)
        except Exception as e:
            return f"Reason: Explanation generation failed: {str(e)}"

    def save_plot(self, flow_vector: pd.DataFrame, timestamp: str, output_dir: str = "static/alerts") -> Path:
        """
        Save a SHAP waterfall plot for the provided flow_vector.
        """
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"alert_{timestamp}.png"

        if self.explainer is None:
            # Create a simple placeholder plot
            plt.figure(figsize=(8, 6))
            plt.text(0.5, 0.5, "SHAP explainer not available", 
                    ha='center', va='center', fontsize=14)
            plt.tight_layout()
            plt.savefig(out_path, bbox_inches="tight")
            plt.close()
            return out_path

        try:
            shap_values = self.explainer(flow_vector)
            shap.plots.waterfall(shap_values[0], show=False)
            plt.tight_layout()
            plt.savefig(out_path, bbox_inches="tight")
            plt.close()
        except Exception:
            # Fallback to placeholder plot
            plt.figure(figsize=(8, 6))
            plt.text(0.5, 0.5, "SHAP plot generation failed", 
                    ha='center', va='center', fontsize=14)
            plt.tight_layout()
            plt.savefig(out_path, bbox_inches="tight")
            plt.close()
        
        return out_path
