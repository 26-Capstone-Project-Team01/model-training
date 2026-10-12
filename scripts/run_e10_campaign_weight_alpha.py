"""D06-E10: campaign sample weighting intensity sweep -- weight ~ 1/campaign_size^alpha.

alpha in {0, 0.25, 0.5, 0.75}, same package.json-only feature set as D06-E06/E09, same
splits/cv_3fold_assignment.csv, same LightGBM hyperparameters/seed/early stopping (Approach A:
the outer eval fold also serves as the early-stopping validation set, same as D06-CV01).

alpha=0 is mathematically identical to D06-E06 (uniform weight=1) and alpha=0.5 is identical to
D06-E09 -- both are reused from results/diagnostics/d06_diag01_pair_predictions.csv instead of
being retrained, since compute_sample_weights_alpha(train_df, 0) / (train_df, 0.5) reduce to the
exact same weights train_model.py's existing compute_sample_weights() produces. Only alpha=0.25
and alpha=0.75 are newly trained (3 folds each = 6 lgb.train() calls total).

Training itself is executed by run_cv_e06_e09.train_and_eval(), unmodified -- this module only
swaps in a parameterized weight function for the duration of each call (restored immediately
after), so there is no duplicated/drifted copy of the LightGBM training code.

Never reads test.csv. Never modifies train_model.py, any D06 model file, results/experiments.csv,
or the D06-CV01/DIAG01 outputs. Writes under results/e10/ only.

Usage (from the repo root):
    python scripts/run_e10_campaign_weight_alpha.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import roc_curve

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import run_cv_e06_e09 as cv  # noqa: E402  (reuse D06-CV01's training/eval code unmodified)

E10_DIR = cv.BASE_DIR / "results" / "e10"
FOLD_METRICS_PATH = E10_DIR / "d06_e10_fold_metrics.csv"
PAIR_PRED_PATH = E10_DIR / "d06_e10_pair_predictions.csv"
CAMPAIGN_BREAKDOWN_PATH = E10_DIR / "d06_e10_campaign_breakdown.json"
FPR_MATCHED_RECALL_PATH = E10_DIR / "d06_e10_fpr_matched_recall.csv"
DIAG01_LINKED_PATH = E10_DIR / "d06_e10_diag01_linked_slices.csv"

DIAG01_PRED_PATH = cv.BASE_DIR / "results" / "diagnostics" / "d06_diag01_pair_predictions.csv"

ALPHAS_TO_TRAIN = [0.25, 0.75]
ALPHA_TO_VARIANT = {0.0: "E06", 0.5: "E09"}  # reused from DIAG01, not retrained


def compute_sample_weights_alpha(train_df: pd.DataFrame, alpha: float) -> pd.Series:
    """Generalizes train_model.py's compute_sample_weights(): weight = 1/campaign_size**alpha
    for malicious rows (normalized so malicious weights sum to the malicious row count),
    weight=1 for benign/hard_benign. alpha=0.5 reduces to the exact D06-E09 formula."""
    merged = cv.load_merged_assignment(train_df)
    weight = pd.Series(1.0, index=train_df.index)
    is_malicious = (merged["class"] == "malicious").to_numpy()
    if not is_malicious.any():
        return weight

    def campaign_key(idx: int, split_group) -> str:
        if pd.notna(split_group) and cv.is_shared_attack_split_group(split_group):
            return split_group
        return f"singleton:{idx}"

    campaign_keys = pd.Series(
        [campaign_key(i, sg) for i, sg in zip(merged.index, merged["splitGroup"])], index=merged.index
    )
    mal_keys = campaign_keys[is_malicious]
    campaign_size = mal_keys.map(mal_keys.value_counts()).astype(float)
    raw_weight = campaign_size ** (-alpha)
    weight.loc[is_malicious] = (raw_weight * (is_malicious.sum() / raw_weight.sum())).to_numpy()
    return weight


def train_eval_alpha(train_df: pd.DataFrame, eval_df: pd.DataFrame, alpha: float):
    """Runs cv.train_and_eval() unmodified, with compute_sample_weights() swapped out for the
    duration of the call so the alpha-weighted version is used. Restored immediately after."""
    original = cv.compute_sample_weights
    cv.compute_sample_weights = lambda train_df_inner: compute_sample_weights_alpha(train_df_inner, alpha)
    try:
        return cv.train_and_eval(train_df, eval_df, use_weighting=True)
    finally:
        cv.compute_sample_weights = original


def fpr_matched_point(fpr_arr, tpr_arr, thr_arr, target_fpr: float):
    """Among ROC points with fpr <= target_fpr (never exceeding it), return the index with the
    highest recall (tpr). sklearn's roc_curve is sorted by non-decreasing fpr, and tpr is also
    non-decreasing along it, so that index is simply the last one satisfying fpr <= target_fpr.

    A naive "nearest fpr by absolute difference" (argmin(abs(fpr - target))) breaks on ties: when
    several thresholds all give the same fpr (e.g. fpr=0 at both threshold=0.5 and the degenerate
    threshold=+inf point roc_curve always prepends), argmin returns the *first* match, which is
    the degenerate inf-threshold point with tpr=0 -- silently discarding a real, better-recall
    point that achieves the exact same fpr. Picking the last point under the constraint instead
    fixes that.

    target_fpr is compared with a small epsilon tolerance: when it comes from a value that has
    been round-tripped through a CSV (text) file, its last bit or two can differ from the in-
    memory float64 that produced it (pandas' default to_csv float formatting is not guaranteed
    bit-exact), so a point that is mathematically an exact fpr match can fail a strict `<=` by a
    sliver (~1e-16) and get wrongly excluded. 1e-9 is far larger than that CSV round-trip error
    but far smaller than any fpr difference that matters here (the smallest nonzero fpr step in
    this dataset is on the order of 1/613, i.e. ~1e-3).
    """
    valid = np.where(fpr_arr <= target_fpr + 1e-9)[0]
    idx = valid[-1] if len(valid) else 0  # len==0 only if target_fpr<0, which can't happen here
    return int(idx)


def campaign_of(row) -> str | None:
    if row["class"] != "malicious" or pd.isna(row["splitGroup"]):
        return None
    if cv.is_shared_attack_split_group(row["splitGroup"]):
        return row["splitGroup"]
    if row["splitGroup"] == "individuals_case":
        return "individuals_case"
    return None


def main() -> None:
    E10_DIR.mkdir(parents=True, exist_ok=True)

    full_df = pd.read_csv(cv.TRAIN_PATH)
    folds = pd.read_csv(cv.FOLD_PATH)
    df = full_df.merge(folds[cv.ID_COLS + ["fold"]], on=cv.ID_COLS, how="left")
    if df["fold"].isna().any():
        raise ValueError("train.csv의 일부 pair가 cv_3fold_assignment.csv에 없습니다.")
    upstream = pd.read_csv(cv.UPSTREAM_SPLIT_ASSIGNMENT_PATH)

    fold_rows = []
    pair_rows = []

    # --- alpha=0.25, 0.75: newly trained (6 runs) ---
    for alpha in ALPHAS_TO_TRAIN:
        for outer in range(cv.K):
            train_df = df[df["fold"] != outer].drop(columns="fold").reset_index(drop=True)
            eval_df = df[df["fold"] == outer].drop(columns="fold").reset_index(drop=True)
            metrics, pred, proba = train_eval_alpha(train_df, eval_df, alpha)
            metrics.update({"alpha": alpha, "outer_fold": outer})
            fold_rows.append(metrics)

            eval_meta = eval_df[cv.ID_COLS + [cv.TARGET_COL]].merge(
                upstream[cv.ID_COLS + ["class", "splitGroup"]], on=cv.ID_COLS, how="left"
            )
            eval_meta["campaign"] = eval_meta.apply(campaign_of, axis=1)
            eval_meta["fold"] = outer
            eval_meta["alpha"] = alpha
            eval_meta["pred"] = pred
            eval_meta["proba"] = proba
            eval_meta = eval_meta.rename(columns={cv.TARGET_COL: "label"})
            pair_rows.append(eval_meta[cv.ID_COLS + ["class", "campaign", "fold", "alpha", "label", "pred", "proba"]])

            print(
                f"[alpha={alpha} fold={outer}] P={metrics['precision']:.4f} R={metrics['recall']:.4f} "
                f"F1={metrics['f1']:.4f} PR-AUC={metrics['pr_auc']:.4f} FPR={metrics['fpr']:.4f} "
                f"TN={metrics['tn']} FP={metrics['fp']} FN={metrics['fn']} TP={metrics['tp']} "
                f"best_iter={metrics['best_iteration']}"
            )

    # --- alpha=0 (E06) / alpha=0.5 (E09): reused from DIAG01, not retrained ---
    diag01 = pd.read_csv(DIAG01_PRED_PATH)
    orig_fold_metrics = pd.read_csv(cv.FOLD_METRICS_PATH)
    for alpha, variant in ALPHA_TO_VARIANT.items():
        sub = diag01[diag01["variant"] == variant].copy()
        sub["alpha"] = alpha
        pair_rows.append(sub[cv.ID_COLS + ["class", "campaign", "fold", "alpha", "label", "pred", "proba"]])

        m = orig_fold_metrics[orig_fold_metrics["variant"] == variant].copy()
        m["alpha"] = alpha
        m = m.rename(columns={"outer_fold": "outer_fold"})
        fold_rows.extend(m.to_dict("records"))
        print(f"[alpha={alpha} ({variant}, 재사용)] D06-CV01/DIAG01 결과 재사용 -- 재학습 없음")

    fold_df = pd.DataFrame(fold_rows)[
        ["alpha", "outer_fold", "train_rows", "train_malicious", "eval_rows", "eval_malicious",
         "precision", "recall", "f1", "pr_auc", "fpr", "tn", "fp", "fn", "tp", "best_iteration"]
    ].sort_values(["alpha", "outer_fold"])
    pair_df = pd.concat(pair_rows, ignore_index=True)

    fold_df.to_csv(FOLD_METRICS_PATH, index=False)
    pair_df.to_csv(PAIR_PRED_PATH, index=False)
    print()
    print(f"Fold별 지표: {FOLD_METRICS_PATH}")
    print(f"pair별 예측값(4개 alpha 전체): {PAIR_PRED_PATH} ({len(pair_df)}행)")

    # --- campaign-level recall breakdown, all 4 alphas ---
    mal = pair_df[pair_df["class"] == "malicious"]
    breakdown = {}
    for (alpha, fold), g in mal.groupby(["alpha", "fold"]):
        key = f"alpha{alpha}_fold{fold}"
        d = {}
        for camp, gc in g.groupby("campaign", dropna=True):
            d[camp] = {"n": len(gc), "caught": int(gc["pred"].sum()), "recall": float(gc["pred"].mean())}
        breakdown[key] = d
    CAMPAIGN_BREAKDOWN_PATH.write_text(json.dumps(breakdown, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Campaign별 breakdown: {CAMPAIGN_BREAKDOWN_PATH}")

    # --- FPR-matched recall (exploratory, per fold, using that fold's own ROC curve) ---
    fpr_rows = []
    for fold in range(cv.K):
        fold_mal = mal[mal["fold"] == fold]
        # Use alpha=0 (E06) threshold=0.5 FPR on this fold as the reference operating point.
        alpha0_fold = pair_df[(pair_df["alpha"] == 0.0) & (pair_df["fold"] == fold)]
        target_fpr = fold_df[(fold_df["alpha"] == 0.0) & (fold_df["outer_fold"] == fold)]["fpr"].iloc[0]
        for alpha in [0.0, 0.25, 0.5, 0.75]:
            sub = pair_df[(pair_df["alpha"] == alpha) & (pair_df["fold"] == fold)]
            fpr_arr, tpr_arr, thr_arr = roc_curve(sub["label"], sub["proba"])
            # Highest-recall point whose fpr does not exceed target_fpr (see fpr_matched_point).
            idx = fpr_matched_point(fpr_arr, tpr_arr, thr_arr, target_fpr)
            fpr_rows.append({
                "fold": fold, "alpha": alpha, "target_fpr": target_fpr,
                "achieved_fpr": fpr_arr[idx], "fpr_gap": abs(fpr_arr[idx] - target_fpr),
                "recall_at_matched_fpr": tpr_arr[idx], "threshold_used": thr_arr[idx],
                "default_threshold_fpr": fold_df[(fold_df["alpha"] == alpha) & (fold_df["outer_fold"] == fold)]["fpr"].iloc[0],
                "default_threshold_recall": fold_df[(fold_df["alpha"] == alpha) & (fold_df["outer_fold"] == fold)]["recall"].iloc[0],
            })
    fpr_df = pd.DataFrame(fpr_rows)
    fpr_df.to_csv(FPR_MATCHED_RECALL_PATH, index=False)
    print(f"FPR-matched recall(탐색적): {FPR_MATCHED_RECALL_PATH}")
    print()
    print("=== FPR-matched recall (reference FPR = 해당 fold의 alpha=0 threshold=0.5 FPR) ===")
    print(fpr_df.to_string(index=False))

    # --- DIAG01-linked slices ---
    features = pd.read_csv(cv.TRAIN_PATH).drop(columns=["label"])
    mal_feat = mal.merge(features, on=cv.ID_COLS, how="left")
    diag01_missed = diag01[(diag01["variant"] == "E06") & (diag01["label"] == 1) & (diag01["pred"] == 0)]
    diag01_missed_e09 = diag01[(diag01["variant"] == "E09") & (diag01["label"] == 1) & (diag01["pred"] == 0)]
    both_missed_keys = diag01_missed.merge(diag01_missed_e09[cv.ID_COLS], on=cv.ID_COLS, how="inner")[cv.ID_COLS]

    slices = {
        "installScriptAdded=False": mal_feat["installScriptAdded"] == False,  # noqa: E712
        "newDependencyAdded=True": mal_feat["newDependencyAdded"] == True,  # noqa: E712
        "individuals_case": mal_feat["campaign"] == "individuals_case",
    }
    slice_rows = []
    for name, mask in slices.items():
        for alpha in [0.0, 0.25, 0.5, 0.75]:
            sub = mal_feat[mask & (mal_feat["alpha"] == alpha)]
            slice_rows.append({"slice": name, "alpha": alpha, "n": len(sub), "recall": sub["pred"].mean() if len(sub) else float("nan")})

    both_missed_mal = mal_feat.merge(both_missed_keys, on=cv.ID_COLS, how="inner")
    for alpha in [0.0, 0.25, 0.5, 0.75]:
        sub = both_missed_mal[both_missed_mal["alpha"] == alpha]
        slice_rows.append({"slice": "E06&E09_both_missed(264)", "alpha": alpha, "n": len(sub), "recall": sub["pred"].mean() if len(sub) else float("nan")})

    for camp in ["sha1-hulud-second-coming_2025-11", "mini-shai-hulud_2026-05", "shai-hulud-original_2025-09"]:
        for alpha in [0.0, 0.25, 0.5, 0.75]:
            sub = mal_feat[(mal_feat["campaign"] == camp) & (mal_feat["alpha"] == alpha)]
            slice_rows.append({"slice": camp, "alpha": alpha, "n": len(sub), "recall": sub["pred"].mean() if len(sub) else float("nan")})

    slice_df = pd.DataFrame(slice_rows)
    slice_df.to_csv(DIAG01_LINKED_PATH, index=False)
    print()
    print(f"DIAG01 연계 slice 분석: {DIAG01_LINKED_PATH}")
    print(slice_df.pivot(index="slice", columns="alpha", values=["n", "recall"]).to_string())


if __name__ == "__main__":
    main()
