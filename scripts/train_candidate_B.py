"""Experimental (NOT official) retrain of D05-E00 with split-policy Candidate B:
stratified validation quota — malicious rows are split into two strata
(real-campaign vs. individual-compromise/generic-bucket) and each is targeted at
VAL_SIZE independently, instead of one combined "malicious" quota. This fixes
individual-compromise cases getting zero validation representation when a big
campaign alone already overshoots the combined quota (see chat discussion).

Everything else (features, LightGBM params, num_boost_round/early-stopping,
threshold, RANDOM_STATE, package-level leakage prevention, real-campaign
grouping via assign_components(), Train/Test boundary) is identical to
train_model.py. Only the validation-selection step changes.

This script does NOT touch any official artifact: it writes to paths suffixed
"_candidateB" and does NOT append to results/experiments.csv. It is a
throwaway comparison run, not a replacement for train_model.py.

Usage (from anywhere): python scripts/train_candidate_B.py
"""

from __future__ import annotations

import random
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

import lightgbm as lgb
import pandas as pd
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import train_model as tm  # noqa: E402 - reuse constants/helpers, don't duplicate logic

EXPERIMENT_TAG = "D05_E00_candidateB"
CANDIDATE_SPLIT_PATH = tm.BASE_DIR / "splits" / "train_val_split_assignment_candidateB.csv"
CANDIDATE_MODEL_PATH = tm.BASE_DIR / "models" / f"{EXPERIMENT_TAG}.txt"
CANDIDATE_FEATURE_IMPORTANCE_PATH = tm.BASE_DIR / "results" / "feature_importance" / f"{EXPERIMENT_TAG}.csv"


def stratum_of_row(row) -> str:
    """Like train_model's per-class target, but malicious splits into two strata:
    real-campaign (shared-attack evidence) vs individual-compromise (generic bucket)."""
    if row["class"] != "malicious":
        return row["class"]
    if pd.notna(row["splitGroup"]) and tm.GENERIC_BUCKET_SPLIT_GROUP.match(row["splitGroup"]):
        return "malicious_individual_compromise"
    return "malicious_real_campaign"


def choose_validation_components_stratified(merged: pd.DataFrame) -> Set[str]:
    """Same brute-force combinatorial search as train_model.choose_validation_components,
    generalized to 4 strata (benign, hard_benign, malicious_real_campaign,
    malicious_individual_compromise) instead of 3 classes, so individual-compromise gets
    its own VAL_SIZE quota independent of how large the real-campaign quota is."""
    merged = merged.copy()
    merged["stratum"] = merged.apply(stratum_of_row, axis=1)

    sizes = merged.groupby("component").size()
    multi_components = sizes[sizes > 1].index.tolist()
    singleton_components = sizes[sizes == 1].index.tolist()

    target_val = {s: round(n * tm.VAL_SIZE) for s, n in merged["stratum"].value_counts().items()}
    multi_stratum_counts = {
        comp: merged.loc[merged["component"] == comp, "stratum"].value_counts().to_dict()
        for comp in multi_components
    }

    candidates = list(multi_stratum_counts.items())
    best_cost = float("inf")
    best_subsets: List[Tuple[str, ...]] = []
    for mask in range(1 << len(candidates)):
        achieved: Dict[str, int] = {}
        subset = []
        for i, (comp, counts) in enumerate(candidates):
            if mask & (1 << i):
                subset.append(comp)
                for s, n in counts.items():
                    achieved[s] = achieved.get(s, 0) + n
        cost = sum(abs(achieved.get(s, 0) - target_val.get(s, 0)) for s in target_val)
        subset_key = tuple(sorted(subset))
        if cost < best_cost:
            best_cost, best_subsets = cost, [subset_key]
        elif cost == best_cost:
            best_subsets.append(subset_key)

    chosen = random.Random(tm.RANDOM_STATE).choice(sorted(set(best_subsets)))
    val_components: Set[str] = set(chosen)

    achieved_val: Dict[str, int] = {}
    for comp in val_components:
        for s, n in multi_stratum_counts[comp].items():
            achieved_val[s] = achieved_val.get(s, 0) + n

    singleton_df = merged[merged["component"].isin(singleton_components)]
    for s in target_val:
        remaining = max(target_val[s] - achieved_val.get(s, 0), 0)
        pool = sorted(
            singleton_df.loc[singleton_df["stratum"] == s, tm.ID_COLS + ["component"]].itertuples(
                index=False, name=None
            )
        )
        picked = random.Random(tm.RANDOM_STATE).sample(pool, min(remaining, len(pool)))
        val_components.update(row[-1] for row in picked)

    return val_components


def split_train_validation_candidate_b(full_train_df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
    merged = tm.load_merged_assignment(full_train_df)
    merged["component"] = tm.assign_components(merged)  # unchanged: reuses the individual-compromise fix
    val_components = choose_validation_components_stratified(merged)

    out = merged[tm.ID_COLS + ["class", "splitGroup", "component"]].copy()
    out["split"] = out["component"].apply(lambda c: "validation" if c in val_components else "train")
    out["assignedBy"] = out["component"].map(merged.groupby("component").size() > 1).map(
        {True: "connectedComponent", False: f"random(seed={tm.RANDOM_STATE})"}
    )
    CANDIDATE_SPLIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    out.drop(columns="component").to_csv(CANDIDATE_SPLIT_PATH, index=False)
    print(f"Candidate-B split assignment saved to {CANDIDATE_SPLIT_PATH}")

    assignment = merged[tm.ID_COLS + ["component"]].copy()
    assignment["split"] = assignment["component"].apply(
        lambda c: "validation" if c in val_components else "train"
    )
    full_train_df = full_train_df.merge(assignment[tm.ID_COLS + ["split"]], on=tm.ID_COLS, how="left")
    train_df = full_train_df[full_train_df["split"] == "train"].drop(columns="split").reset_index(drop=True)
    val_df = full_train_df[full_train_df["split"] == "validation"].drop(columns="split").reset_index(drop=True)
    return train_df, val_df


def main() -> None:
    full_train_df = pd.read_csv(tm.TRAIN_PATH)
    test_df = pd.read_csv(tm.TEST_PATH)  # untouched: same test.csv, same Train/Test boundary as official run

    train_df, val_df = split_train_validation_candidate_b(full_train_df)

    X_train, y_train, feature_cols = tm.build_features(train_df)
    X_val, y_val, _ = tm.build_features(val_df)
    X_test, y_test, _ = tm.build_features(test_df)

    train_set = lgb.Dataset(
        X_train, label=y_train, categorical_feature=tm.CATEGORICAL_COLS, feature_name=feature_cols
    )
    val_set = lgb.Dataset(
        X_val, label=y_val, categorical_feature=tm.CATEGORICAL_COLS, feature_name=feature_cols,
        reference=train_set,
    )

    params = {"objective": "binary", "metric": ["binary_logloss", "auc"], "verbosity": -1}

    booster = lgb.train(
        params,
        train_set,
        num_boost_round=500,
        valid_sets=[train_set, val_set],
        valid_names=["train", "val"],
        callbacks=[lgb.early_stopping(stopping_rounds=50), lgb.log_evaluation(50)],
    )

    val_pred_proba = booster.predict(X_val, num_iteration=booster.best_iteration)
    val_pred = (val_pred_proba >= 0.5).astype(int)
    val_recall = recall_score(y_val, val_pred)
    val_precision = precision_score(y_val, val_pred)
    val_f1 = f1_score(y_val, val_pred)
    val_pr_auc = average_precision_score(y_val, val_pred_proba)

    print(f"[val] Recall:    {val_recall:.4f}")
    print(f"[val] Precision: {val_precision:.4f}")
    print(f"[val] F1:        {val_f1:.4f}")
    print(f"[val] PR-AUC:    {val_pr_auc:.4f}")

    y_pred_proba = booster.predict(X_test, num_iteration=booster.best_iteration)
    y_pred = (y_pred_proba >= 0.5).astype(int)

    recall = recall_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    pr_auc = average_precision_score(y_test, y_pred_proba)

    print(f"[test] Recall:    {recall:.4f}")
    print(f"[test] Precision: {precision:.4f}")
    print(f"[test] F1:        {f1:.4f}")
    print(f"[test] PR-AUC:    {pr_auc:.4f}")

    CANDIDATE_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    booster.save_model(CANDIDATE_MODEL_PATH)
    print(f"Model saved to {CANDIDATE_MODEL_PATH}")

    importance = pd.DataFrame(
        {"feature": booster.feature_name(), "importance": booster.feature_importance()}
    ).sort_values("importance", ascending=False)
    CANDIDATE_FEATURE_IMPORTANCE_PATH.parent.mkdir(parents=True, exist_ok=True)
    importance.to_csv(CANDIDATE_FEATURE_IMPORTANCE_PATH, index=False)
    print(f"Feature importance saved to {CANDIDATE_FEATURE_IMPORTANCE_PATH}")

    print()
    print("NOTE: this is an exploratory run. It does NOT write to results/experiments.csv")
    print("and does NOT touch any official D05-E00 / D05-E00_pre-fix artifact.")

    print()
    print("train_samples", len(train_df), "val_samples", len(val_df), "test_samples", len(test_df))
    print("best_iteration", booster.best_iteration)


if __name__ == "__main__":
    main()
