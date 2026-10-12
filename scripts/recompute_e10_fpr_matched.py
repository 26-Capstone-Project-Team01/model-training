"""Recompute D06-E10's FPR-matched recall analysis from the already-saved
results/e10/d06_e10_pair_predictions.csv -- no retraining, no new model calls.

Fixes the FPR-matching bug in the first pass of run_e10_campaign_weight_alpha.py: that version
picked the ROC point nearest to the target FPR by absolute difference, which on ties returns the
*first* matching index (sklearn's roc_curve prepends a degenerate threshold=+inf point at
fpr=0, tpr=0). When several real thresholds also land at fpr=0, that bug silently picked the
degenerate recall=0 point instead of the real, higher-recall one at the same fpr -- visible on
fold 0, where E06's actual threshold=0.5 operating point is fpr=0, recall=0.693, but the old
logic reported recall=0 for every alpha there.

This version enforces fpr <= target_fpr (never exceeding it) and takes the highest-recall point
under that constraint, using run_e10_campaign_weight_alpha.fpr_matched_point() -- the same fix is
also applied in run_e10_campaign_weight_alpha.py itself, so a future from-scratch rerun of that
script would produce this same corrected output directly. This script exists only to regenerate
results/e10/d06_e10_fpr_matched_recall.csv from the already-saved pair predictions, without
repeating the 6 lgb.train() calls.

Writes directly to the canonical results/e10/d06_e10_fpr_matched_recall.csv (overwriting the
buggy first pass -- that one is not kept, to avoid it being mistaken for an official result).

Usage (from the repo root):
    python scripts/recompute_e10_fpr_matched.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
from sklearn.metrics import roc_curve

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import run_cv_e06_e09 as cv  # noqa: E402
from run_e10_campaign_weight_alpha import (  # noqa: E402
    E10_DIR, FOLD_METRICS_PATH, PAIR_PRED_PATH, FPR_MATCHED_RECALL_PATH, fpr_matched_point,
)



def main() -> None:
    pair_df = pd.read_csv(PAIR_PRED_PATH)
    fold_df = pd.read_csv(FOLD_METRICS_PATH)

    rows = []
    for fold in range(cv.K):
        target_fpr = fold_df[(fold_df["alpha"] == 0.0) & (fold_df["outer_fold"] == fold)]["fpr"].iloc[0]
        for alpha in [0.0, 0.25, 0.5, 0.75]:
            # ROC/FPR needs the full eval set (benign+hard_benign+malicious), not malicious-only.
            sub = pair_df[(pair_df["alpha"] == alpha) & (pair_df["fold"] == fold)]
            fpr_arr, tpr_arr, thr_arr = roc_curve(sub["label"], sub["proba"])
            idx = fpr_matched_point(fpr_arr, tpr_arr, thr_arr, target_fpr)
            default_row = fold_df[(fold_df["alpha"] == alpha) & (fold_df["outer_fold"] == fold)].iloc[0]
            e06_default_recall = fold_df[(fold_df["alpha"] == 0.0) & (fold_df["outer_fold"] == fold)]["recall"].iloc[0]
            rows.append({
                "fold": fold,
                "alpha": alpha,
                "target_fpr": target_fpr,
                "achieved_fpr": fpr_arr[idx],
                "fpr_gap": target_fpr - fpr_arr[idx],  # always >= 0: achieved never exceeds target
                "threshold_used": thr_arr[idx],
                "recall_at_matched_fpr": tpr_arr[idx],
                "recall_vs_e06_default": tpr_arr[idx] - e06_default_recall,
                "pr_auc": default_row["pr_auc"],
                "default_threshold_fpr": default_row["fpr"],
                "default_threshold_recall": default_row["recall"],
            })

    result_df = pd.DataFrame(rows)
    result_df.to_csv(FPR_MATCHED_RECALL_PATH, index=False)

    print("=== FPR-matched recall (FPR <= 목표, 그 안에서 recall 최대) ===")
    print(result_df.to_string(index=False))
    print()
    print(f"저장: {FPR_MATCHED_RECALL_PATH}")
    assert (result_df["achieved_fpr"] <= result_df["target_fpr"] + 1e-9).all(), "achieved_fpr이 target_fpr을 초과하는 행이 있습니다"
    print("검증: 모든 행에서 achieved_fpr <= target_fpr (초과 없음)")


if __name__ == "__main__":
    main()
