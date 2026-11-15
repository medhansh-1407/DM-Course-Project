"""
ml_classification.py
Train a Random Forest classifier on centrality features to predict botnet vs normal nodes.
Outputs per-node predictions with confidence probabilities.
"""

import numpy as np
import pandas as pd


def run_ml_detection_pipeline(df_phase2_flagged: pd.DataFrame):
    """
    Train a scikit-learn Random Forest on phase 2 flagged node data and return
    per-node ML anomaly probability and prediction.

    If sklearn is unavailable, returns a fallback using a simple heuristic.

    Returns:
        df_ml: DataFrame with columns ip, ml_probability, ml_prediction, combined_risk
        info: dict with model accuracy stats
    """
    feature_cols = [c for c in df_phase2_flagged.columns if c not in ("risk_level", "flag_count")]
    # Ensure all features are numeric
    for c in feature_cols:
        df_phase2_flagged[c] = pd.to_numeric(df_phase2_flagged[c], errors="coerce").fillna(0)

    X = df_phase2_flagged[feature_cols].values
    labels = df_phase2_flagged["risk_level"].values

    positive = (labels == "High Risk").astype(int)
    if positive.sum() == 0 or positive.sum() == len(positive):
        # No signal — fall back to heuristic
        return _fallback_prediction(df_phase2_flagged)

    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import cross_val_score
        from sklearn.preprocessing import StandardScaler

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        rf = RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42, class_weight="balanced")
        scores = cross_val_score(rf, X_scaled, positive, cv=min(3, positive.sum(), len(positive) - positive.sum()))

        rf.fit(X_scaled, positive)
        proba = rf.predict_proba(X_scaled)[:, 1]
        pred = (proba >= 0.5).astype(int)

        info = {
            "model": "RandomForest",
            "cv_accuracy_mean": round(float(scores.mean()), 4),
            "n_estimators": 100,
        }
    except Exception:
        # Fallback without sklearn
        return _fallback_prediction(df_phase2_flagged)

    rows = []
    for i, node in enumerate(df_phase2_flagged.index):
        rows.append({
            "ip": str(node),
            "ml_probability": round(float(proba[i]), 4),
            "ml_prediction": int(pred[i]),
            "combined_risk": "High Risk" if pred[i] == 1 else "Normal",
        })
    return pd.DataFrame(rows), info


def _fallback_prediction(df: pd.DataFrame):
    """Simple rule-based fallback when sklearn is unavailable."""
    composite = pd.to_numeric(df.get("composite_risk_score", df.get("degree_centrality", 0)), errors="coerce").fillna(0)
    flag_cnt = pd.to_numeric(df.get("flag_count", 0), errors="coerce").fillna(0)
    proba = (composite + 0.1 * flag_cnt).rank(pct=True)
    pred = (proba >= 0.5).astype(int)
    rows = []
    for i, node in enumerate(df.index):
        rows.append({
            "ip": str(node),
            "ml_probability": round(float(proba.iloc[i]), 4),
            "ml_prediction": int(pred.iloc[i]),
            "combined_risk": "High Risk" if pred.iloc[i] == 1 else "Normal",
        })
    return pd.DataFrame(rows), {"model": "heuristic", "cv_accuracy_mean": None}


if __name__ == "__main__":
    from graph_builder import load_graph_from_csv
    from centrality_metrics import compute_phase1_centralities, flag_centrality_anomalies
    from centrality_phase2 import compute_phase2_centralities
    from pathlib import Path
    csv_path = Path(__file__).parent / "data" / "sample_network_flows.csv"
    G, _ = load_graph_from_csv(csv_path)
    df_p1 = compute_phase1_centralities(G)
    df_p1_flagged, _, _ = flag_centrality_anomalies(df_p1)
    df_p2 = compute_phase2_centralities(G)
    merged = df_p2.join(df_p1_flagged[["flag_count", "risk_level"]], how="left")
    df_ml, info = run_ml_detection_pipeline(merged)
    print(f"ML model: {info['model']}, CV acc: {info.get('cv_accuracy_mean')}")
    print(df_ml.sort_values("ml_probability", ascending=False).head(10))
