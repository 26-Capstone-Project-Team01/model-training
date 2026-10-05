"""Post-hoc analysis (plots + SHAP) for an already-trained experiment.

Loads the saved model for the experiment currently configured in train_model.py
(DATA_VERSION/EXPERIMENT_ID/EXPERIMENT_NAME) and the splits/feature importance it
already produced — no re-training. Reconstructs train/val/test the same way
train_model.py did (reading the already-saved splits/train_val_split_assignment.csv
instead of recomputing it) and writes PNGs to results/plots/<DATA_VERSION>_<EXPERIMENT_ID>/.

Usage (from anywhere): python scripts/analyze_experiment.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import lightgbm as lgb
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import shap
from sklearn.metrics import confusion_matrix

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from train_model import (  # noqa: E402
    BASE_DIR,
    DATA_VERSION,
    EXPERIMENT_ID,
    EXPERIMENT_KEY,
    FEATURE_IMPORTANCE_PATH,
    EXPERIMENTS_LOG_PATH,
    ID_COLS,
    MODEL_PATH,
    SPLIT_ASSIGNMENT_PATH,
    TEST_PATH,
    TRAIN_PATH,
    build_features,
)

PLOTS_DIR = BASE_DIR / "results" / "plots" / f"{DATA_VERSION}_{EXPERIMENT_ID}"
THRESHOLD = 0.5

BENIGN_COLOR = "#4C72B0"
MALICIOUS_COLOR = "#C44E52"


def load_splits():
    full_train_df = pd.read_csv(TRAIN_PATH)
    test_df = pd.read_csv(TEST_PATH)
    assignment = pd.read_csv(SPLIT_ASSIGNMENT_PATH)[ID_COLS + ["split"]]
    merged = full_train_df.merge(assignment, on=ID_COLS, how="left")
    train_df = merged[merged["split"] == "train"].drop(columns="split").reset_index(drop=True)
    val_df = merged[merged["split"] == "validation"].drop(columns="split").reset_index(drop=True)
    return train_df, val_df, test_df


def load_best_iteration() -> int:
    log = pd.read_csv(EXPERIMENTS_LOG_PATH)
    rows = log[log["experiment_id"] == EXPERIMENT_KEY]
    if rows.empty:
        raise SystemExit(f"{EXPERIMENTS_LOG_PATH}에 {EXPERIMENT_KEY} 기록이 없습니다")
    return int(rows.iloc[-1]["best_iteration"])


def plot_confusion_matrix(y_true, y_pred, title: str, out_path: Path) -> None:
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    fig, ax = plt.subplots(figsize=(4.5, 4))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(["Benign (0)", "Malicious (1)"])
    ax.set_yticklabels(["Benign (0)", "Malicious (1)"])
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title(title)
    for i in range(2):
        for j in range(2):
            color = "white" if cm[i, j] > cm.max() / 2 else "black"
            ax.text(j, i, str(cm[i, j]), ha="center", va="center", color=color, fontsize=14)
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def plot_prediction_distribution(y_true, y_proba, title: str, out_path: Path) -> None:
    fig, ax = plt.subplots(figsize=(7, 4.5))
    bins = np.linspace(0, 1, 41)
    ax.hist(
        y_proba[y_true == 0], bins=bins, alpha=0.6, label="Actual: benign (0)",
        color=BENIGN_COLOR, edgecolor="white",
    )
    ax.hist(
        y_proba[y_true == 1], bins=bins, alpha=0.6, label="Actual: malicious (1)",
        color=MALICIOUS_COLOR, edgecolor="white",
    )
    ax.axvline(THRESHOLD, color="black", linestyle="--", linewidth=1.5, label=f"threshold = {THRESHOLD}")
    ax.set_xlabel("Predicted probability (malicious)")
    ax.set_ylabel("Count")
    ax.set_title(title)
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def plot_feature_importance(out_path: Path) -> None:
    importance = pd.read_csv(FEATURE_IMPORTANCE_PATH).sort_values("importance", ascending=True)
    fig, ax = plt.subplots(figsize=(8, 0.35 * len(importance) + 1))
    ax.barh(importance["feature"], importance["importance"], color="#55A868")
    ax.set_xlabel("Split count (importance)")
    ax.set_title(f"LightGBM feature importance — {EXPERIMENT_KEY}")
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def main() -> None:
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)

    train_df, val_df, test_df = load_splits()
    X_val, y_val, _ = build_features(val_df)
    X_test, y_test, _ = build_features(test_df)

    booster = lgb.Booster(model_file=str(MODEL_PATH))
    best_iteration = load_best_iteration()

    val_proba = booster.predict(X_val, num_iteration=best_iteration)
    test_proba = booster.predict(X_test, num_iteration=best_iteration)
    val_pred = (val_proba >= THRESHOLD).astype(int)
    test_pred = (test_proba >= THRESHOLD).astype(int)

    plot_confusion_matrix(
        y_val.to_numpy(), val_pred, f"Validation confusion matrix — {EXPERIMENT_KEY}",
        PLOTS_DIR / "confusion_matrix_validation.png",
    )
    plot_confusion_matrix(
        y_test.to_numpy(), test_pred, f"Test confusion matrix — {EXPERIMENT_KEY}",
        PLOTS_DIR / "confusion_matrix_test.png",
    )
    plot_prediction_distribution(
        y_val.to_numpy(), val_proba, f"Validation prediction distribution — {EXPERIMENT_KEY}",
        PLOTS_DIR / "prediction_distribution_validation.png",
    )
    plot_prediction_distribution(
        y_test.to_numpy(), test_proba, f"Test prediction distribution — {EXPERIMENT_KEY}",
        PLOTS_DIR / "prediction_distribution_test.png",
    )
    plot_feature_importance(PLOTS_DIR / "feature_importance.png")

    # SHAP on the test set: the only split untouched by training/early-stopping, so it's
    # the most reliable read on what actually drives real-world (vs. memorized) predictions.
    explainer = shap.TreeExplainer(booster)
    shap_values = explainer.shap_values(X_test)
    if isinstance(shap_values, list):  # some shap/lightgbm version combos return [class0, class1]
        shap_values = shap_values[1]

    X_test_display = X_test.copy()
    if str(X_test_display["updateType"].dtype) == "category":
        X_test_display["updateType"] = X_test_display["updateType"].cat.codes.astype(float)

    plt.figure()
    shap.summary_plot(shap_values, X_test_display, show=False, max_display=29)
    plt.title(f"SHAP summary (beeswarm) — {EXPERIMENT_KEY} (test set)")
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "shap_summary.png", dpi=150, bbox_inches="tight")
    plt.close()

    mean_abs_shap = pd.DataFrame(
        {"feature": X_test.columns, "mean_abs_shap": np.abs(shap_values).mean(axis=0)}
    ).sort_values("mean_abs_shap", ascending=True)
    fig, ax = plt.subplots(figsize=(8, 0.35 * len(mean_abs_shap) + 1))
    ax.barh(mean_abs_shap["feature"], mean_abs_shap["mean_abs_shap"], color="#8172B2")
    ax.set_xlabel("mean(|SHAP value|)")
    ax.set_title(f"SHAP feature importance — {EXPERIMENT_KEY} (test set)")
    fig.tight_layout()
    fig.savefig(PLOTS_DIR / "shap_bar.png", dpi=150)
    plt.close(fig)

    mean_abs_shap.sort_values("mean_abs_shap", ascending=False).to_csv(
        PLOTS_DIR / "shap_mean_abs.csv", index=False
    )

    print(f"Plots written to {PLOTS_DIR}")


if __name__ == "__main__":
    main()
