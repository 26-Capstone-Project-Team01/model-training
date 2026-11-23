"""Shared loaders for the X1 cause analysis (inference/saved scores only; no training, no Test 677)."""
from __future__ import annotations
from pathlib import Path
import numpy as np, pandas as pd

HERE = Path(__file__).resolve().parent
EXP = HERE.parent
B = EXP / "d06_feature_comparison_18"
C = EXP / "d06_full35_compare"
FULL35 = EXP / "d06_x1_extraction/analysis/d06_full35.csv"
REF, PROC, NET = "installHookRefFileChanged", "addedProcExecCallCount", "addedNetworkCallCount"
X1 = ["installHookNewProgramCount", "installHookArgsChanged", REF, "installHookNewExternalExecCount", PROC, NET]
VARS = ["full29", "full35", "full32", "full29_ref", "full29_proc", "full29_net"]
SEED = {20261109: "split1", 20261110: "split2"}
FOCUS = {"shai-hulud-original_2025-09": "shai-orig", "mini-shai-hulud_2026-05": "mini-shai",
         "autotel-node-env-resolver_2026-06": "autotel", "miasma_2026-06": "miasma", "chaindrop_2026-08": "chaindrop"}


def frame():
    """2,767 rows: metadata + 29 features + X1 encoded exactly as run_full35.py (bool -> 1/0, empty -> NaN)."""
    meta = pd.read_csv(C / "run/row_metadata.csv", keep_default_na=False)
    f = pd.read_csv(FULL35, float_precision="round_trip")
    raw = pd.read_csv(FULL35, dtype=str, keep_default_na=False)
    for c in X1:
        f[c] = raw[c].map({"True": "1", "False": "0", "": np.nan}).fillna(raw[c].replace("", np.nan)).astype(float) \
            if c in (REF, "installHookArgsChanged") else pd.to_numeric(raw[c].replace("", np.nan))
    assert (f.package.values == meta.package.values).all()
    df = pd.concat([meta, f.drop(columns=["package", "old_version", "new_version", "label"])], axis=1)
    df["short"] = df.campaign.map(FOCUS).fillna("")
    return df


def scores():
    """Long table: variant, split, fold, stage, row_id, score. full29 = PR #13 saved scores."""
    s13 = pd.read_csv(B / "scores/saved_scores.csv")
    s13 = s13[s13.model == "full29"][["seed", "fold", "stage", "row_id", "score"]].assign(variant="full29")
    new = pd.read_csv(C / "run/scores.csv")[["variant", "seed", "fold", "stage", "row_id", "score"]]
    s = pd.concat([s13, new], ignore_index=True)
    s["split"] = s.seed.map(SEED)
    return s


def splits():
    s = pd.read_csv(C / "run/splits.csv")
    return s


def model_path(variant, split, fold):
    if variant == "full29":
        mi = pd.read_csv(B / "model_index.csv")
        r = mi[(mi.feature_set == "full29") & (mi.split == split) & (mi.outer_fold == fold)].iloc[0]
        return B / r.bundle_model_path, r.feature_order.split()
    tr = pd.read_csv(C / "run/training.csv")
    r = tr[(tr.variant == variant) & (tr.split == split) & (tr.fold == fold)].iloc[0]
    return C / "run/models" / f"{variant}_{split}_fold{fold}.txt", r.feature_order.split()


def matrix(df, cols):
    x = df[cols].copy()
    for c in cols:
        x[c] = pd.Categorical(x[c], categories=["major", "minor", "patch"]) if c == "updateType" else x[c].astype(float)
    return x
