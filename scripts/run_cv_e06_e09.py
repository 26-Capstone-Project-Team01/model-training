"""3-fold campaign-aware CV comparing D06-E06 (package.json only) vs D06-E09 (package.json only
+ campaign sample weighting), using the saved splits/cv_3fold_assignment.csv.

Purpose: an EXPLORATORY comparison of E06 vs E09's *relative* performance across several
campaign splits -- not a final generalization-performance estimate. Uses "Approach A": the
outer evaluation fold is also used for early stopping, so num_boost_round is picked by looking
at the very fold being scored. This can make the reported CV metrics optimistic relative to a
fully held-out evaluation; see the printed caveat and README.md for detail.

- Never reads test.csv (677 pairs) -- CV only touches the Train+Validation pool (2,767 pairs).
- Does not modify train_model.py, the existing D06-E06/E09 models, or results/experiments.csv.
  Writes its own output under results/cv/.
- Campaign sample weighting (E09) is recomputed from scratch for each fold using only that
  fold's actual training rows (the other two folds), exactly like compute_sample_weights() in
  train_model.py.

Usage (from the repo root):
    python scripts/run_cv_e06_e09.py
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List, Tuple

import lightgbm as lgb
import pandas as pd
from sklearn.metrics import average_precision_score, confusion_matrix, f1_score, precision_score, recall_score

BASE_DIR = Path(__file__).resolve().parent.parent
RAW_DATA_DIR = BASE_DIR / "data" / "raw"
TRAIN_PATH = RAW_DATA_DIR / "train.csv"
UPSTREAM_SPLIT_ASSIGNMENT_PATH = RAW_DATA_DIR / "split_assignment.csv"
FOLD_PATH = BASE_DIR / "splits" / "cv_3fold_assignment.csv"

CV_OUTPUT_DIR = BASE_DIR / "results" / "cv"
FOLD_METRICS_PATH = CV_OUTPUT_DIR / "d06_e06_e09_3fold_cv.csv"
CAMPAIGN_BREAKDOWN_PATH = CV_OUTPUT_DIR / "d06_e06_e09_3fold_cv_campaign_breakdown.json"

ID_COLS = ["package", "old_version", "new_version"]
TARGET_COL = "label"
DROP_COLS = ID_COLS + [TARGET_COL]
CATEGORICAL_COLS = ["updateType"]
K = 3

# Same obfuscation-feature list excluded in D06-E06/E09 (package.json-only feature set).
OBFUSCATION_FEATURES: List[str] = [
    "obfChangedFileCount",
    "obfHexIdentRatioNew", "obfHexIdentRatioChange", "obfHexIdentRatioChangedCode",
    "obfHexNumberRatioNew", "obfHexNumberRatioChange", "obfHexNumberRatioChangedCode",
    "obfBracketAccessRatioNew", "obfBracketAccessRatioChange", "obfBracketAccessRatioChangedCode",
    "obfEscapeDensityNew", "obfEscapeDensityChange", "obfEscapeDensityChangedCode",
    "obfShortIdentRatioNew", "obfShortIdentRatioChange", "obfShortIdentRatioChangedCode",
    "obfMeanIdentLengthNew", "obfMeanIdentLengthChange", "obfMeanIdentLengthChangedCode",
    "obfWhitespaceRatioNew", "obfWhitespaceRatioChange", "obfWhitespaceRatioChangedCode",
]

GENERIC_BUCKET_SPLIT_GROUP = re.compile(r"^(individual-compromise(-\d+(?:st|nd|rd|th))?|individuals_case)$")


def is_shared_attack_split_group(split_group) -> bool:
    return bool(split_group) and not GENERIC_BUCKET_SPLIT_GROUP.match(split_group)


def load_merged_assignment(df: pd.DataFrame) -> pd.DataFrame:
    upstream = pd.read_csv(UPSTREAM_SPLIT_ASSIGNMENT_PATH)
    return df[ID_COLS].merge(upstream[ID_COLS + ["class", "splitGroup"]], on=ID_COLS, how="left")


def compute_sample_weights(train_df: pd.DataFrame) -> pd.Series:
    """Identical logic to train_model.py's compute_sample_weights(), recomputed from only the
    rows actually passed in (this fold's training data)."""
    merged = load_merged_assignment(train_df)
    weight = pd.Series(1.0, index=train_df.index)
    is_malicious = (merged["class"] == "malicious").to_numpy()
    if not is_malicious.any():
        return weight

    def campaign_key(idx: int, split_group) -> str:
        if pd.notna(split_group) and is_shared_attack_split_group(split_group):
            return split_group
        return f"singleton:{idx}"

    campaign_keys = pd.Series(
        [campaign_key(i, sg) for i, sg in zip(merged.index, merged["splitGroup"])], index=merged.index
    )
    mal_keys = campaign_keys[is_malicious]
    campaign_size = mal_keys.map(mal_keys.value_counts())
    raw_weight = 1.0 / campaign_size.pow(0.5)
    weight.loc[is_malicious] = (raw_weight * (is_malicious.sum() / raw_weight.sum())).to_numpy()
    return weight


def build_features(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series, List[str]]:
    y = df[TARGET_COL]
    X = df.drop(columns=DROP_COLS + OBFUSCATION_FEATURES)
    for col in CATEGORICAL_COLS:
        if col in X.columns:
            X[col] = X[col].astype("category")
    return X, y, list(X.columns)


def train_and_eval(train_df: pd.DataFrame, eval_df: pd.DataFrame, use_weighting: bool):
    X_train, y_train, feature_cols = build_features(train_df)
    X_eval, y_eval, _ = build_features(eval_df)

    train_weight = compute_sample_weights(train_df) if use_weighting else None

    train_set = lgb.Dataset(
        X_train, label=y_train, weight=train_weight, categorical_feature=CATEGORICAL_COLS, feature_name=feature_cols
    )
    # Approach A: the outer eval fold doubles as the early-stopping validation set.
    eval_set = lgb.Dataset(
        X_eval, label=y_eval, categorical_feature=CATEGORICAL_COLS, feature_name=feature_cols, reference=train_set
    )

    params = {"objective": "binary", "metric": ["binary_logloss", "auc"], "verbosity": -1}
    booster = lgb.train(
        params,
        train_set,
        num_boost_round=500,
        valid_sets=[train_set, eval_set],
        valid_names=["train", "eval"],
        callbacks=[lgb.early_stopping(stopping_rounds=50), lgb.log_evaluation(0)],
    )

    proba = booster.predict(X_eval, num_iteration=booster.best_iteration)
    pred = (proba >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_eval, pred, labels=[0, 1]).ravel()

    metrics = {
        "precision": precision_score(y_eval, pred, zero_division=0),
        "recall": recall_score(y_eval, pred, zero_division=0),
        "f1": f1_score(y_eval, pred, zero_division=0),
        "pr_auc": average_precision_score(y_eval, proba),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "fpr": fp / (fp + tn) if (fp + tn) else float("nan"),
        "best_iteration": booster.best_iteration,
        "train_rows": len(train_df), "eval_rows": len(eval_df),
        "train_malicious": int((train_df[TARGET_COL] == 1).sum()),
        "eval_malicious": int((eval_df[TARGET_COL] == 1).sum()),
    }
    return metrics, pred, proba


def campaign_recall_breakdown(eval_df: pd.DataFrame, pred) -> dict:
    # merged preserves eval_df's row order (unique keys, left join), so attaching pred
    # positionally here is safe -- avoids relying on two separately-computed boolean masks
    # (merged["class"]=="malicious" vs eval_df[TARGET_COL]==1) staying in lockstep.
    merged = load_merged_assignment(eval_df)
    merged["pred"] = pred
    mal = merged[merged["class"] == "malicious"]
    is_generic = mal["splitGroup"].apply(lambda s: bool(GENERIC_BUCKET_SPLIT_GROUP.match(s)) if pd.notna(s) else False)
    breakdown = {}
    for sg, grp in mal[~is_generic].groupby("splitGroup"):
        breakdown[sg] = {"n": len(grp), "caught": int(grp["pred"].sum()), "recall": float(grp["pred"].mean())}
    ic = mal[mal["splitGroup"] == "individuals_case"]
    if len(ic):
        breakdown["individuals_case"] = {"n": len(ic), "caught": int(ic["pred"].sum()), "recall": float(ic["pred"].mean())}
    return breakdown


def main() -> None:
    full_df = pd.read_csv(TRAIN_PATH)
    folds = pd.read_csv(FOLD_PATH)
    df = full_df.merge(folds[ID_COLS + ["fold"]], on=ID_COLS, how="left")
    if df["fold"].isna().any():
        raise ValueError("train.csv의 일부 pair가 cv_3fold_assignment.csv에 없습니다 -- fold 파일을 다시 확인하세요.")

    rows = []
    campaign_breakdowns = {}
    for variant, use_weighting in [("E06", False), ("E09", True)]:
        for outer in range(K):
            train_df = df[df["fold"] != outer].drop(columns="fold").reset_index(drop=True)
            eval_df = df[df["fold"] == outer].drop(columns="fold").reset_index(drop=True)
            metrics, pred, _ = train_and_eval(train_df, eval_df, use_weighting)
            metrics.update({"variant": variant, "outer_fold": outer})
            rows.append(metrics)
            campaign_breakdowns[f"{variant}_fold{outer}"] = campaign_recall_breakdown(eval_df, pred)
            print(
                f"[{variant} outer_fold={outer}] n_train={metrics['train_rows']}(mal={metrics['train_malicious']}) "
                f"n_eval={metrics['eval_rows']}(mal={metrics['eval_malicious']}) "
                f"P={metrics['precision']:.4f} R={metrics['recall']:.4f} F1={metrics['f1']:.4f} "
                f"PR-AUC={metrics['pr_auc']:.4f} FPR={metrics['fpr']:.4f} "
                f"TN={metrics['tn']} FP={metrics['fp']} FN={metrics['fn']} TP={metrics['tp']} "
                f"best_iter={metrics['best_iteration']}"
            )

    result_df = pd.DataFrame(rows)[
        ["variant", "outer_fold", "train_rows", "train_malicious", "eval_rows", "eval_malicious",
         "precision", "recall", "f1", "pr_auc", "fpr", "tn", "fp", "fn", "tp", "best_iteration"]
    ]

    print()
    print("=== Fold별 평균 ± 표준편차 ===")
    for variant in ["E06", "E09"]:
        sub = result_df[result_df["variant"] == variant]
        for metric in ["precision", "recall", "f1", "pr_auc", "fpr"]:
            print(f"  {variant} {metric}: {sub[metric].mean():.4f} ± {sub[metric].std():.4f}")

    CV_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    result_df.to_csv(FOLD_METRICS_PATH, index=False)
    CAMPAIGN_BREAKDOWN_PATH.write_text(json.dumps(campaign_breakdowns, indent=2, ensure_ascii=False), encoding="utf-8")
    print()
    print(f"Fold별 지표를 {FOLD_METRICS_PATH}에 저장했습니다.")
    print(f"Campaign별 breakdown을 {CAMPAIGN_BREAKDOWN_PATH}에 저장했습니다.")
    print()
    print("[주의] Approach A: outer 평가 fold가 early stopping에도 사용되므로, 이 CV 점수는 완전히 "
          "분리된 held-out 평가보다 낙관적인 편향이 있을 수 있습니다. 또한 이 CV는 D06-E06/E09의 "
          "최종 일반화 성능 확정이 아니라, 여러 campaign 분할에서 두 방법의 상대적 성능을 탐색적으로 "
          "비교하는 목적입니다. test.csv(677개)는 이 스크립트에서 전혀 사용하지 않았습니다.")


if __name__ == "__main__":
    main()
