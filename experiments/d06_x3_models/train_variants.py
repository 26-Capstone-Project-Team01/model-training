"""D06 new feature-set variants (base7+X1, X3, D) under the PR #13 protocol. Only new variants are trained;
base7 / full29 (PR #13) and full35 (d06_full35_compare) scores are reused by evaluate.py.

Everything except the feature columns is taken unchanged from ../d06_full35_compare/run_full35.py (imported by path,
hash-checked): PR #13 snapshot load_data / inner_split / feature_matrix, LightGBM params, 200 rounds, no early stopping,
no sample weight, no value transform, NaN kept. X1 is attached with run_full35.attach_x1 (same encoding).
X3 / D columns are attached by row_id from an extraction CSV after a key and label check (counts/ratios as float, empty -> NaN).
Test is never read. Package code is never executed.

Stage verify retrains full35 through this code path and requires bit-identical scores to the saved full35 run.

Variants are fixed here before any outer result is seen (PLAN.md):
  stage x1  : base7_x1
  stage x3d : full35_x3, base7_x1_x3, full35_d, full35_x3_d, base7_x1_x3_d

Usage: python -I -B train_variants.py --workspace <ws> --stage x1 --out <new dir>
       python -I -B train_variants.py --workspace <ws> --stage x3d --x3d <x3d csv> --out <new dir>
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import platform
import sys
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
import sklearn

HERE = Path(__file__).resolve().parent
RUNNER = HERE.parent / "d06_full35_compare/run_full35.py"
RUNNER_SHA256 = None  # recorded in the manifest; the runner itself hash-checks the PR #13 snapshot

X3 = ["installHookTargetCount", "installHookTargetMaxBytes", "obfHookHexIdentRatio", "obfHookHexNumberRatio",
      "obfHookBracketAccessRatio", "obfHookEscapeDensity", "obfHookShortIdentRatio", "obfHookMeanIdentLength",
      "obfHookWhitespaceRatio", "installHookTargetProcExecCallCount", "installHookTargetNetworkCallCount",
      "addedNetworkCallPer1kAddedTokens", "addedProcExecCallPer1kAddedTokens"]
D = ["dependencyRangeChangedCount", "dependencyChangedRatio"]


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def attach_extra(data, path, cols, require):
    raw = pd.read_csv(path, dtype=str, keep_default_na=False)
    ids = ["package", "old_version", "new_version"]
    require(len(raw) == len(data), "x3d row count differs")
    require((raw[ids].to_numpy() == data[ids].astype(str).to_numpy()).all(), "x3d keys differ from train row order")
    require((raw.label.astype(int).to_numpy() == data.label.to_numpy()).all(), "x3d labels differ")
    out = data.copy()
    for col in cols:
        v = pd.to_numeric(raw[col].replace("", np.nan), errors="raise").astype(float)
        require(not np.isinf(v).any(), f"inf in {col}")
        out[col] = v.to_numpy()
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", type=Path, required=True)
    ap.add_argument("--stage", choices=["verify", "x1", "x3d"], required=True)
    ap.add_argument("--x3d", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    r = load(RUNNER, "run_full35")
    versions = {"lightgbm": lgb.__version__, "pandas": pd.__version__, "numpy": np.__version__, "sklearn": sklearn.__version__}
    r.require(versions == r.PINNED, f"library versions differ from PR #13: {versions}")
    out = a.out
    out.mkdir(parents=True, exist_ok=False)
    (out / "models").mkdir()
    snap = r.load_snapshot()
    spec = json.loads((a.workspace / r.SPEC_REL).read_text(encoding="utf-8"))
    data, features29, paths = snap.load_data(a.workspace, spec)
    r.check_bundle_alignment(data)
    data = r.attach_x1(data)
    mi = pd.read_csv(r.BUNDLE / "model_index.csv")
    base7 = mi[mi.feature_set == "base7"].feature_order.iloc[0].split()
    r.require(features29[:7] == base7 and mi[mi.feature_set == "full29"].feature_order.iloc[0].split() == features29, "feature order differs")
    full35 = features29 + r.X1_ALL
    if a.stage == "verify":
        variants = {"full35": full35}  # must reproduce ../d06_full35_compare/run scores exactly (checked below)
    elif a.stage == "x1":
        variants = {"base7_x1": base7 + r.X1_ALL}
    else:
        r.require(a.x3d is not None, "--x3d required")
        data = attach_extra(data, a.x3d, X3 + D, r.require)
        variants = {"full35_x3": full35 + X3, "base7_x1_x3": base7 + r.X1_ALL + X3, "full35_d": full35 + D,
                    "full35_x3_d": full35 + X3 + D, "base7_x1_x3_d": base7 + r.X1_ALL + X3 + D}
    inputs = {k: sha(v) for k, v in paths.items()} | ({"x3d": sha(a.x3d)} if a.x3d else {})
    scores, splits, training, importance = [], [], [], []
    for split, seed in r.SPLITS.items():
        bundle_split = pd.read_csv(r.BUNDLE / f"splits/{split}.csv")
        for fold in range(3):
            outer = data[data.outer_fold == fold]
            fit, cal = snap.inner_split(data[data.outer_fold != fold], seed + fold)
            snap.check_disjoint(fit, outer)
            snap.check_disjoint(cal, outer)
            ref = bundle_split[(bundle_split.model == "full29") & (bundle_split.fold == fold)]
            for stage, part in [("fit", fit), ("calibration", cal), ("outer", outer)]:
                r.require(set(ref[ref.stage == stage].row_id) == set(part.row_id), f"{split} fold{fold} {stage} rows differ from PR #13")
            for variant, cols in variants.items():
                mats = [snap.feature_matrix(p, cols, "M_full") for p in (fit, cal, outer)]
                ds = lgb.Dataset(mats[0], label=fit.label.to_numpy(), weight=None, categorical_feature=["updateType"], feature_name=cols)
                model = lgb.train(spec["lightgbm"], ds, num_boost_round=spec["rounds"])
                path = out / "models" / f"{variant}_{split}_fold{fold}.txt"
                model.save_model(str(path))
                training.append({"variant": variant, "split": split, "seed": seed, "fold": fold, "feature_count": len(cols),
                                 "requested_rounds": spec["rounds"], "trained_rounds": model.current_iteration(), "early_stopping": False,
                                 "sample_weight": False, "model_sha256": sha(path), "fit_rows": len(fit), "calibration_rows": len(cal),
                                 "outer_rows": len(outer), "feature_order": " ".join(cols)})
                for f, g, c in zip(cols, model.feature_importance("gain"), model.feature_importance("split"), strict=True):
                    importance.append({"variant": variant, "split": split, "fold": fold, "feature": f, "gain": float(g), "split_count": int(c)})
                for stage, part, x in [("calibration", cal, mats[1]), ("outer", outer, mats[2])]:
                    s = model.predict(x, num_threads=2)
                    r.require(np.isfinite(s).all() and ((s >= 0) & (s <= 1)).all(), "invalid predictions")
                    scores.append(pd.DataFrame({"variant": variant, "split": split, "seed": seed, "fold": fold, "stage": stage,
                                                "row_id": part.row_id.to_numpy(), "score": s}))
                print(f"done {variant} {split} fold{fold}", flush=True)
    pd.concat(scores).to_csv(out / "scores.csv", index=False, lineterminator="\n")
    if a.stage == "verify":
        new = pd.read_csv(out / "scores.csv")
        old = pd.read_csv(RUNNER.parent / "run/scores.csv")
        old = old[old.variant == "full35"]
        m = new.merge(old, on=["variant", "split", "seed", "fold", "stage", "row_id"], suffixes=("", "_saved"), validate="one_to_one")
        r.require(len(m) == len(new) == len(old) and (m.score == m.score_saved).all(), "full35 retrain does not reproduce saved scores")
        print("verify: full35 scores identical", len(m), flush=True)
    pd.DataFrame(training).to_csv(out / "training.csv", index=False, lineterminator="\n")
    pd.DataFrame(importance).to_csv(out / "feature_importance.csv", index=False, lineterminator="\n")
    for k, v in paths.items():
        r.require(sha(v) == inputs[k], f"input changed: {k}")
    man = {"experiment_id": "D06-X3-MODELS", "stage": a.stage, "data_commit": "be87ab4cff66fff1980c4a71be8032b6b47225ba",
           "inputs": inputs, "x1_csv_sha256": sha(r.FULL35), "runner": str(RUNNER.relative_to(HERE.parent)), "runner_sha256": sha(RUNNER),
           "snapshot_sha256": r.SNAPSHOT_SHA256, "script_sha256": sha(__file__), "lightgbm_params": spec["lightgbm"], "rounds": spec["rounds"],
           "early_stopping": False, "sample_weight": None, "missing": "NaN", "variants": variants, "packages": versions,
           "python": platform.python_version(), "argv": sys.argv, "read_test": False,
           "outputs": {p.name: sha(p) for p in sorted(out.glob("*.csv"))}}
    (out / "manifest.json").write_text(json.dumps(man, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
