"""
Explainability utilities for ZeroBit using SHAP.
Loads the trained ETA model and SHAP explainer, and produces
human-readable reasons plus waterfall plots for single flows.
"""

from __future__ import annotations

import os
import pickle
from pathlib import Path
from typing import Any

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
        with self.model_path.open("rb") as f:
            self.model = pickle.load(f)
        with self.explainer_path.open("rb") as f:
            self.explainer = pickle.load(f)

    def generate_explanation(self, flow_vector, output_dir: str = "static/alerts") -> str:
        """
        Compute SHAP values for a single flow vector and return a text summary
        of the top 3 features driving a malicious classification.
        """
        shap_values = self.explainer(flow_vector)
        contribs = shap_values.values[0]
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

    def save_plot(self, flow_vector, timestamp: str, output_dir: str = "static/alerts") -> Path:
        """
        Save a SHAP waterfall plot for the provided flow_vector.
        """
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"alert_{timestamp}.png"

        shap_values = self.explainer(flow_vector)
        shap.plots.waterfall(shap_values[0], show=False)
        plt.tight_layout()
        plt.savefig(out_path, bbox_inches="tight")
        plt.close()
        return out_path
"""
Explainability helpers for ZeroBit using SHAP.
- Load a trained XGBoost model and generate human-friendly explanations.
- Produce text summaries and waterfall plots for single-flow predictions.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, List, Tuple

import joblib  # type: ignore
import matplotlib.pyplot as plt  # type: ignore
import numpy as np
import shap  # type: ignore
import pandas as pd


def load_model(model_path: Path):
    """Load a persisted model (e.g., XGBoost) from disk."""
    return joblib.load(model_path)


def load_explainer(explainer_path: Path):
    """Load a persisted SHAP explainer from disk."""
    return joblib.load(explainer_path)


def explain_prediction(model, single_flow_data: pd.DataFrame, top_n: int = 3) -> str:
    """
    Return a short text summary of the top features contributing to a 'Malicious' prediction.
    - single_flow_data: DataFrame with a single row (feature vector).
    """
    if len(single_flow_data) != 1:
        raise ValueError("single_flow_data must contain exactly one row.")

    explainer = shap.TreeExplainer(model)
    shap_values = explainer(single_flow_data)
    values = shap_values.values[0]
    feature_names = single_flow_data.columns

    # Sort by absolute contribution
    idxs = np.argsort(np.abs(values))[::-1][:top_n]
    parts = []
    for i in idxs:
        contrib = values[i]
        direction = "increased" if contrib > 0 else "decreased"
        parts.append(f"{feature_names[i]} {direction} risk by {contrib:+.3f}")
    return "; ".join(parts)


def generate_shap_plot(model, single_flow_data: pd.DataFrame, out_path: Path) -> Path:
    """
    Generate a SHAP waterfall plot for a single flow and save to out_path.
    """
    if len(single_flow_data) != 1:
        raise ValueError("single_flow_data must contain exactly one row.")

    explainer = shap.TreeExplainer(model)
    shap_values = explainer(single_flow_data)
    shap.plots.waterfall(shap_values[0], show=False)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    plt.savefig(out_path, bbox_inches="tight")
    plt.close()
    return out_path
"""
Explainability utilities using SHAP for ZeroBit ETA models.
Provides text summaries and waterfall plots for single-flow predictions.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Optional

import joblib  # type: ignore
import matplotlib.pyplot as plt  # type: ignore
import numpy as np
import pandas as pd
import shap  # type: ignore


def load_model(model_path: Path) -> Any:
    """Load a persisted model (e.g., XGBoost) from disk."""
    if not model_path.exists():
        raise FileNotFoundError(f"Model not found: {model_path}")
    return joblib.load(model_path)


def load_explainer(explainer_path: Path) -> shap.Explainer:
    """Load a persisted SHAP explainer from disk."""
    if not explainer_path.exists():
        raise FileNotFoundError(f"Explainer not found: {explainer_path}")
    return joblib.load(explainer_path)


def _to_dataframe(single_flow_data: Any) -> pd.DataFrame:
    """Ensure input is a single-row DataFrame."""
    if isinstance(single_flow_data, pd.Series):
        return single_flow_data.to_frame().T
    if isinstance(single_flow_data, dict):
        return pd.DataFrame([single_flow_data])
    if isinstance(single_flow_data, pd.DataFrame):
        if len(single_flow_data) != 1:
            raise ValueError("Expected a single flow (one row).")
        return single_flow_data
    raise TypeError("single_flow_data must be a dict, Series, or single-row DataFrame.")


def explain_prediction(
    model: Any,
    single_flow_data: Any,
    explainer: Optional[shap.Explainer] = None,
    top_k: int = 3,
) -> str:
    """
    Generate a text summary of the top-k contributing features.
    Returns a human-readable string.
    """
    df = _to_dataframe(single_flow_data)
    explainer = explainer or shap.TreeExplainer(model)
    explanation = explainer(df)
    # For binary classification, shap values shape: (1, features)
    shap_values = np.array(explanation.values)[0]
    feature_names = list(df.columns)
    order = np.argsort(np.abs(shap_values))[::-1]
    parts = []
    for idx in order[:top_k]:
        feat = feature_names[idx]
        contribution = shap_values[idx]
        sign = "increased" if contribution > 0 else "decreased"
        parts.append(f"{feat} {sign} risk by {abs(contribution):.4f}")
    return "; ".join(parts)


def generate_shap_plot(
    model: Any,
    flow_vector: Any,
    save_path: Path = Path("static/explanation.png"),
    explainer: Optional[shap.Explainer] = None,
) -> Path:
    """
    Create a SHAP waterfall plot for a single flow and save to disk.
    Returns the path to the saved image.
    """
    df = _to_dataframe(flow_vector)
    explainer = explainer or shap.TreeExplainer(model)
    explanation = explainer(df)

    save_path.parent.mkdir(parents=True, exist_ok=True)
    shap.plots.waterfall(explanation[0], show=False)
    plt.tight_layout()
    plt.savefig(save_path, bbox_inches="tight")
    plt.close()
    return save_path
"""
Model explainability utilities using SHAP for ZeroBit.
Provides text summaries and waterfall plots for single-flow ETA predictions.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Tuple

import joblib  # type: ignore
import matplotlib.pyplot as plt  # type: ignore
import numpy as np
import shap  # type: ignore
from xgboost import XGBClassifier  # type: ignore


def load_model(model_path: Path) -> XGBClassifier:
    if not model_path.exists():
        raise FileNotFoundError(f"Model not found: {model_path}")
    model = joblib.load(model_path)
    if not isinstance(model, XGBClassifier):
        raise TypeError("Loaded model is not an XGBClassifier.")
    return model


def load_explainer(explainer_path: Path) -> shap.Explainer:
    if not explainer_path.exists():
        raise FileNotFoundError(f"Explainer not found: {explainer_path}")
    explainer = joblib.load(explainer_path)
    if not isinstance(explainer, shap.Explainer):
        raise TypeError("Loaded explainer is not a SHAP Explainer.")
    return explainer


def explain_prediction(
    model: XGBClassifier, explainer: shap.Explainer, single_flow: Dict[str, float], top_k: int = 3
) -> str:
    """
    Generate a text summary of top-k contributing features for a single flow.
    single_flow: dict of feature_name -> value
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
    # Minimal CLI-style example (adjust paths as needed).
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

