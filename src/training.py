"""
Training script for ZeroBit.
- NSL-KDD mode: tabular supervised training on the NSL-KDD dataset.
- ETA mode: flow-level encrypted traffic analysis using Joy JSON exports.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable, List, Tuple

import joblib  # type: ignore
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from xgboost import XGBClassifier  # type: ignore
import shap  # type: ignore

from .eta_features import build_eta_frame
from .feedback import IncidentManager
import shap  # type: ignore

# Official NSL-KDD column names (42 cols). Some versions add an extra "difficulty".
NSL_KDD_COLUMNS: List[str] = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
    "label",
]


def _maybe_assign_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Assign NSL-KDD column names if the dataset is headerless."""
    if "label" in df.columns:
        return df
    if df.shape[1] == 43:  # includes difficulty column
        df.columns = NSL_KDD_COLUMNS + ["difficulty"]
    elif df.shape[1] == 42:
        df.columns = NSL_KDD_COLUMNS
    else:
        raise ValueError(
            f"Unexpected column count ({df.shape[1]}). Provide a dataset with headers or 42/43 columns."
        )
    return df


def load_dataset(csv_path: Path) -> Tuple[pd.DataFrame, pd.Series]:
    """Load NSL-KDD CSV and split features/labels."""
    df = pd.read_csv(csv_path, header=None)
    df = _maybe_assign_columns(df)
    if "label" not in df.columns:
        raise ValueError("Dataset must contain a 'label' column.")
    X = df.drop(columns=["label", "difficulty"], errors="ignore")
    y = df["label"]
    return X, y


def build_preprocessor(cat_cols: Iterable[str], num_cols: Iterable[str]) -> ColumnTransformer:
    """Create column-wise preprocessing for categorical and numeric features."""
    categorical = Pipeline(
        steps=[
            ("onehot", OneHotEncoder(handle_unknown="ignore")),
        ]
    )
    numeric = Pipeline(
        steps=[
            ("scale", StandardScaler()),
        ]
    )
    return ColumnTransformer(
        transformers=[
            ("cat", categorical, list(cat_cols)),
            ("num", numeric, list(num_cols)),
        ]
    )


def build_model(cat_cols: Iterable[str], num_cols: Iterable[str]) -> Pipeline:
    """Create the full pipeline with preprocessing and classifier."""
    preprocessor = build_preprocessor(cat_cols, num_cols)
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        n_jobs=-1,
        random_state=42,
    )
    return Pipeline(
        steps=[
            ("preprocess", preprocessor),
            ("clf", clf),
        ]
    )


def train_nslkdd(csv_path: Path, model_path: Path) -> None:
    X, y = load_dataset(csv_path)
    cat_cols = ["protocol_type", "service", "flag"]
    num_cols = [c for c in X.columns if c not in cat_cols]
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    model = build_model(cat_cols, num_cols)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_val)
    print(classification_report(y_val, y_pred))

    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_path)
    print(f"Model saved to {model_path}")


def train_eta(json_path: Path, model_path: Path) -> None:
    """Train an ETA model from Joy JSON flow exports."""
    X, y = build_eta_frame(json_path)
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )
    clf = XGBClassifier(
        n_estimators=400,
        max_depth=8,
        learning_rate=0.05,
        subsample=0.9,
        colsample_bytree=0.9,
        n_jobs=-1,
        random_state=42,
        objective="binary:logistic",
        eval_metric="logloss",
    )
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_val)
    print(classification_report(y_val, y_pred))
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, model_path)
    print(f"ETA model saved to {model_path}")

    # Prepare and persist SHAP explainer for real-time use.
    explainer = shap.TreeExplainer(clf)
    explainer_path = model_path.parent / "shap_explainer.pkl"
    joblib.dump(explainer, explainer_path)
    print(f"SHAP explainer saved to {explainer_path}")

    # Prepare and persist SHAP explainer for fast downstream explanations.
    explainer = shap.TreeExplainer(clf)
    explainer_path = model_path.parent / "shap_explainer.pkl"
    joblib.dump(explainer, explainer_path)
    print(f"SHAP explainer saved to {explainer_path}")


def retrain_on_feedback(
    original_dataset: Path | None = None,
    model_path: Path = Path("models/eta_model.pkl"),
    output_model_path: Path | None = None,
) -> str:
    """
    Retrain the model using feedback from IncidentManager.
    Combines original dataset with human-labeled feedback data.
    Returns status message with accuracy.
    """
    manager = IncidentManager()
    feedback_df = manager.get_feedback_data()

    if feedback_df.empty:
        return "No feedback data available. Mark some incidents as True/False Positive first."

    # Load original model to get feature structure
    if not model_path.exists():
        return f"Original model not found at {model_path}. Train a base model first."

    try:
        original_model = joblib.load(model_path)
    except Exception as exc:
        return f"Failed to load original model: {exc}"

    # Parse feedback data
    feedback_features = []
    feedback_labels = []

    for _, row in feedback_df.iterrows():
        try:
            feature_dict = json.loads(row["feature_vector"])
            feedback_features.append(feature_dict)
            feedback_labels.append(int(row["human_label"]))
        except Exception:
            continue

    if not feedback_features:
        return "No valid feedback features found."

    feedback_X = pd.DataFrame(feedback_features)
    feedback_y = pd.Series(feedback_labels)

    # Load original dataset if provided
    if original_dataset and original_dataset.exists():
        try:
            X_orig, y_orig = build_eta_frame(original_dataset)
            # Combine original and feedback data
            X_combined = pd.concat([X_orig, feedback_X], ignore_index=True)
            y_combined = pd.concat([y_orig, feedback_y], ignore_index=True)
        except Exception:
            # If original dataset fails, use only feedback
            X_combined = feedback_X
            y_combined = feedback_y
    else:
        # Use only feedback data
        X_combined = feedback_X
        y_combined = feedback_y

    # Split for validation
    X_train, X_val, y_train, y_val = train_test_split(
        X_combined, y_combined, test_size=0.2, stratify=y_combined, random_state=42
    )

    # Retrain with XGBoost (same as ETA training)
    clf = XGBClassifier(
        n_estimators=400,
        max_depth=8,
        learning_rate=0.05,
        subsample=0.9,
        colsample_bytree=0.9,
        n_jobs=-1,
        random_state=42,
        objective="binary:logistic",
        eval_metric="logloss",
    )

    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_val)
    accuracy = (y_pred == y_val).mean() * 100

    # Save new model
    output_path = output_model_path or model_path.parent / "eta_model_v2.pkl"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, output_path)

    # Update SHAP explainer
    explainer = shap.TreeExplainer(clf)
    explainer_path = output_path.parent / "shap_explainer.pkl"
    joblib.dump(explainer, explainer_path)

    return f"Retraining Complete. Accuracy is now {accuracy:.2f}%. Model saved to {output_path}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train ZeroBit model.")
    parser.add_argument(
        "--dataset",
        type=Path,
        help="Path to NSL-KDD CSV dataset (tabular mode).",
    )
    parser.add_argument(
        "--eta-json",
        type=Path,
        help="Path to Joy JSON flow export for ETA training (encrypted traffic).",
    )
    parser.add_argument(
        "--model-path",
        type=Path,
        default=Path("model.pkl"),
        help="Where to write the model (default: model.pkl).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.dataset and args.eta_json:
        raise ValueError("Specify only one of --dataset or --eta-json.")
    if args.eta_json:
        train_eta(args.eta_json, args.model_path)
    elif args.dataset:
        train_nslkdd(args.dataset, args.model_path)
    else:
        raise ValueError("Provide --dataset for NSL-KDD or --eta-json for encrypted traffic.")


if __name__ == "__main__":
    main()

