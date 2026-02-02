"""
Model explainability utilities using SHAP for ZeroBit.
Provides text summaries and waterfall plots for single-flow ETA predictions.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import joblib  # type: ignore
import matplotlib.pyplot as plt  # type: ignore
import numpy as np
import shap  # type: ignore
from xgboost import XGBClassifier  # type: ignore


def load_model(model_path: Path) -> XGBClassifier:
    """Load a persisted XGBoost model from disk."""
    if not model_path.exists():
        raise FileNotFoundError(f"Model not found: {model_path}")
    model = joblib.load(model_path)
    if not isinstance(model, XGBClassifier):
        raise TypeError("Loaded model is not an XGBClassifier.")
    return model


def load_explainer(explainer_path: Path) -> shap.Explainer:
    """Load a persisted SHAP explainer from disk."""
    if not explainer_path.exists():
        raise FileNotFoundError(f"Explainer not found: {explainer_path}")
    explainer = joblib.load(explainer_path)
    if not isinstance(explainer, shap.Explainer):
        raise TypeError("Loaded explainer is not a SHAP Explainer.")
    return explainer


def explain_prediction(
    model: XGBClassifier,
    explainer: shap.Explainer,
    single_flow: Dict[str, float],
    top_k: int = 3,
) -> str:
    """
    Generate a text summary of top-k contributing features for a single flow.
    
    Args:
        model: XGBoost classifier model
        explainer: SHAP explainer instance
        single_flow: dict of feature_name -> value
        top_k: number of top contributing features to include
        
    Returns:
        String summary of top contributing features
    """
    feature_names = list(single_flow.keys())
    x = np.array([list(single_flow.values())])
    shap_values = explainer(x)
    
    # shap_values values are shaped (1, n_features)
    contributions = shap_values.values[0]
    indices = np.argsort(np.abs(contributions))[::-1][:top_k]
    
    parts = []
    for idx in indices:
        fname = feature_names[idx]
        contrib = contributions[idx]
        direction = "increased" if contrib > 0 else "decreased"
        parts.append(f"{fname} {direction} risk by {abs(contrib):.3f}")
    
    return " | ".join(parts)


def generate_shap_plot(
    model: XGBClassifier,
    explainer: shap.Explainer,
    single_flow: Dict[str, float],
    output_path: Path = Path("static/explanation.png"),
) -> Path:
    """
    Create a SHAP waterfall plot for a single flow and save to output_path.
    
    Args:
        model: XGBoost classifier model
        explainer: SHAP explainer instance
        single_flow: dict of feature_name -> value
        output_path: where to save the plot
        
    Returns:
        Path to the saved image
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    feature_names = list(single_flow.keys())
    x = np.array([list(single_flow.values())])
    shap_values = explainer(x)
    
    plt.figure(figsize=(8, 6))
    shap.plots.waterfall(shap_values[0], feature_names=feature_names, show=False)
    plt.tight_layout()
    plt.savefig(output_path, bbox_inches="tight")
    plt.close()
    
    return output_path


def main() -> None:
    """Minimal CLI-style example (adjust paths as needed)."""
    model_path = Path("models/eta_model.pkl")
    explainer_path = Path("models/shap_explainer.pkl")
    
    model = load_model(model_path)
    explainer = load_explainer(explainer_path)

    # Example single flow (placeholder values). Replace with real flow features.
    dummy_flow = {
        "size_mean": 200.0,
        "size_std": 15.0,
        "iat_mean": 0.05,
        "iat_std": 0.02,
        "ja3_hash": 123456.0,
        "ja3_present": 1.0,
        "ja3s_hash": 78910.0,
        "ja3s_present": 1.0,
    }
    
    summary = explain_prediction(model, explainer, dummy_flow)
    print("Top contributors:", summary)
    
    output = generate_shap_plot(model, explainer, dummy_flow)
    print(f"Saved SHAP plot to {output}")


if __name__ == "__main__":
    main()
