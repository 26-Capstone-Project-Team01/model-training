"""D06-DIAG01: reproduce D06-CV01 (scripts/run_cv_e06_e09.py) with no change to data, features,
weighting, hyperparameters, seed, or early stopping -- only to additionally persist per-pair
predictions, which the original CV run did not save.

This is a diagnostic REPRODUCTION, not a new experiment: it imports and reuses
run_cv_e06_e09.py's own functions (train_and_eval, build_features, compute_sample_weights, the
obfuscation-feature exclusion list) unchanged, so there is no risk of silently drifting from
D06-CV01's actual configuration.

Writes under results/diagnostics/ only -- never touches results/cv/d06_e06_e09_3fold_cv.csv,
results/cv/d06_e06_e09_3fold_cv_campaign_breakdown.json, results/experiments.csv, or any model
file. Never reads test.csv.

Usage (from the repo root):
    python scripts/reproduce_cv_pair_predictions.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pandas as pd

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import run_cv_e06_e09 as cv  # noqa: E402  (reuse the exact D06-CV01 implementation)

DIAG_DIR = cv.BASE_DIR / "results" / "diagnostics"
PAIR_PRED_PATH = DIAG_DIR / "d06_diag01_pair_predictions.csv"
REPRO_FOLD_METRICS_PATH = DIAG_DIR / "d06_diag01_reproduced_fold_metrics.csv"


def main() -> None:
    full_df = pd.read_csv(cv.TRAIN_PATH)
    folds = pd.read_csv(cv.FOLD_PATH)
    df = full_df.merge(folds[cv.ID_COLS + ["fold"]], on=cv.ID_COLS, how="left")
    if df["fold"].isna().any():
        raise ValueError("train.csv의 일부 pair가 cv_3fold_assignment.csv에 없습니다.")

    upstream = pd.read_csv(cv.UPSTREAM_SPLIT_ASSIGNMENT_PATH)
    GENERIC_BUCKET = cv.GENERIC_BUCKET_SPLIT_GROUP

    fold_rows = []
    pair_rows = []
    for variant, use_weighting in [("E06", False), ("E09", True)]:
        for outer in range(cv.K):
            train_df = df[df["fold"] != outer].drop(columns="fold").reset_index(drop=True)
            eval_df = df[df["fold"] == outer].drop(columns="fold").reset_index(drop=True)
            metrics, pred, proba = cv.train_and_eval(train_df, eval_df, use_weighting)
            metrics.update({"variant": variant, "outer_fold": outer})
            fold_rows.append(metrics)

            eval_meta = eval_df[cv.ID_COLS + [cv.TARGET_COL]].merge(
                upstream[cv.ID_COLS + ["class", "splitGroup"]], on=cv.ID_COLS, how="left"
            )
            eval_meta["campaign"] = eval_meta.apply(
                lambda r: r["splitGroup"]
                if r["class"] == "malicious" and pd.notna(r["splitGroup"]) and not GENERIC_BUCKET.match(r["splitGroup"])
                else ("individuals_case" if r["splitGroup"] == "individuals_case" else None),
                axis=1,
            )
            eval_meta["fold"] = outer
            eval_meta["variant"] = variant
            eval_meta["pred"] = pred
            eval_meta["proba"] = proba
            eval_meta = eval_meta.rename(columns={cv.TARGET_COL: "label"})
            pair_rows.append(
                eval_meta[cv.ID_COLS + ["class", "campaign", "fold", "variant", "label", "pred", "proba"]]
            )

            print(
                f"[{variant} outer_fold={outer}] P={metrics['precision']:.4f} R={metrics['recall']:.4f} "
                f"F1={metrics['f1']:.4f} PR-AUC={metrics['pr_auc']:.4f} FPR={metrics['fpr']:.4f} "
                f"TN={metrics['tn']} FP={metrics['fp']} FN={metrics['fn']} TP={metrics['tp']} "
                f"best_iter={metrics['best_iteration']}"
            )

    fold_df = pd.DataFrame(fold_rows)[
        ["variant", "outer_fold", "train_rows", "train_malicious", "eval_rows", "eval_malicious",
         "precision", "recall", "f1", "pr_auc", "fpr", "tn", "fp", "fn", "tp", "best_iteration"]
    ]
    pair_df = pd.concat(pair_rows, ignore_index=True)

    DIAG_DIR.mkdir(parents=True, exist_ok=True)
    fold_df.to_csv(REPRO_FOLD_METRICS_PATH, index=False)
    pair_df.to_csv(PAIR_PRED_PATH, index=False)
    print()
    print(f"재현된 fold 지표: {REPRO_FOLD_METRICS_PATH}")
    print(f"pair별 예측값: {PAIR_PRED_PATH} ({len(pair_df)}행)")

    # Compare against the originally committed D06-CV01 metrics.
    original = pd.read_csv(cv.FOLD_METRICS_PATH)
    merged = original.merge(fold_df, on=["variant", "outer_fold"], suffixes=("_orig", "_repro"))
    numeric_cols = ["precision", "recall", "f1", "pr_auc", "fpr", "tn", "fp", "fn", "tp", "best_iteration"]
    print()
    print("=== 기존 D06-CV01 결과와 비교 ===")
    all_match = True
    for _, row in merged.iterrows():
        mismatches = [c for c in numeric_cols if abs(row[f"{c}_orig"] - row[f"{c}_repro"]) > 1e-9]
        status = "일치" if not mismatches else f"불일치: {mismatches}"
        if mismatches:
            all_match = False
        print(f"  {row['variant']} fold{row['outer_fold']}: {status}")
    print()
    print("전체 일치" if all_match else "!!! 불일치 발견 -- 아래 분석 전에 원인 확인 필요 !!!")


if __name__ == "__main__":
    main()
