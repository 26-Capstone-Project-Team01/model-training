"""D06 full29 vs full35 (X1 code-context features) comparison.

Reuses the PR #13 run1 training snapshot unchanged (imported by path, hash-checked) for data loading,
component / outer / inner splits, feature matrices and LightGBM parameters, like W1 (run_w1.py).
X1 columns are attached by row_id from experiments/d06_x1_extraction/analysis/d06_full35.csv after an
exact key/label check. Only the feature columns differ between variants: no sample weight, no value
transform, missing X1 stays NaN. Test 677 is never read. Package code is never executed.

Stages (run in order, each into a new empty directory):
  repro: unweighted full29 retrain, compared with PR #13 saved models and scores (verification only,
         not a comparison variant).
  main:  the five pre-registered variants (full35, full32, full29+RefFile, full29+Proc, full29+Net).

Usage:
  python -I -B run_full35.py --workspace <ws> --stage repro --out <new dir>
  python -I -B run_full35.py --workspace <ws> --stage main  --out <new dir>
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
BUNDLE = HERE.parent / "d06_feature_comparison_18"
X1DIR = HERE.parent / "d06_x1_extraction"
SNAPSHOT = BUNDLE / "provenance/phase2_run1_base7_full29/executed_script_snapshot.py"
SNAPSHOT_SHA256 = "049bf00c0269ff9638caad8273f3dc49254ba91cec9da35ebd3c4db87cf62854"
SPEC_REL = "temp/detection-feasibility/phase2/evaluation_spec.json"
FULL35 = X1DIR / "analysis/d06_full35.csv"
SCHEMA = X1DIR / "analysis/d06_full35_schema.json"
X1_MANIFEST = X1DIR / "run_manifest.json"
SPLITS = {"split1": 20261109, "split2": 20261110}
PR13_PYTHON = "3.13.5"
PINNED = {"lightgbm": "4.7.0", "pandas": "3.0.6", "numpy": "2.5.3", "sklearn": "1.9.1"}

REF, PROC, NET = "installHookRefFileChanged", "addedProcExecCallCount", "addedNetworkCallCount"
X1_ALL = ["installHookNewProgramCount", "installHookArgsChanged", REF,
          "installHookNewExternalExecCount", PROC, NET]
X1_BOOL = {"installHookArgsChanged", REF}
# pre-registered before any training (PROJECT_HANDOFF.md section 10); never edited after seeing outer results
VARIANTS_MAIN = {
    "full35": X1_ALL,
    "full32": [REF, PROC, NET],
    "full29_ref": [REF],
    "full29_proc": [PROC],
    "full29_net": [NET],
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def require(cond, msg):
    if not cond:
        raise SystemExit(msg)


def load_snapshot():
    require(sha(SNAPSHOT) == SNAPSHOT_SHA256, "snapshot hash mismatch")
    spec = importlib.util.spec_from_file_location("run1_snapshot", SNAPSHOT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def attach_x1(data):
    """Attach X1 by row_id. Booleans 'True'/'False' -> 1.0/0.0, empty -> NaN; counts -> float. No other change."""
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    require([c["column"] for c in schema if c.get("group") == "x1"] == X1_ALL, "X1 schema order differs")
    raw = pd.read_csv(FULL35, dtype=str, keep_default_na=False)
    ids = ["package", "old_version", "new_version"]
    require(len(raw) == len(data), "row count differs")
    require((raw[ids].to_numpy() == data[ids].astype(str).to_numpy()).all(), "full35 keys differ from train row order")
    require((raw.label.astype(int).to_numpy() == data.label.to_numpy()).all(), "full35 labels differ")
    out = data.copy()
    for col in X1_ALL:
        s = raw[col]
        if col in X1_BOOL:
            require(set(s) <= {"True", "False", ""}, f"unexpected boolean values in {col}")
            v = s.map({"True": 1.0, "False": 0.0, "": np.nan}).astype(float)
        else:
            v = pd.to_numeric(s.replace("", np.nan), errors="raise").astype(float)
        require(not np.isinf(v).any(), f"inf in {col}")
        out[col] = v.to_numpy()
    return out


def check_bundle_alignment(data):
    meta = pd.read_csv(BUNDLE / "scores/row_metadata.csv", keep_default_na=False)
    require((meta.row_id.to_numpy() == data.row_id.to_numpy()).all()
            and (meta.component.to_numpy() == data.component.to_numpy()).all()
            and (meta.outer_fold.to_numpy() == data.outer_fold.to_numpy()).all(),
            "component/outer differ from PR #13 row_metadata")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", type=Path, required=True)
    ap.add_argument("--stage", choices=["repro", "main"], required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    versions = {"lightgbm": lgb.__version__, "pandas": pd.__version__, "numpy": np.__version__, "sklearn": sklearn.__version__}
    require(versions == PINNED, f"library versions differ from PR #13: {versions}")
    out = args.out
    out.mkdir(parents=True, exist_ok=False)
    (out / "models").mkdir()
    snap = load_snapshot()
    spec_path = args.workspace / SPEC_REL
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    data, features29, paths = snap.load_data(args.workspace, spec)  # checks train/groups/classes SHA-256
    require(len(features29) == 29, "expected 29 features")
    check_bundle_alignment(data)
    initial = {k: sha(v) for k, v in paths.items()}
    initial["full35"] = sha(FULL35)
    data = attach_x1(data)
    model_index = pd.read_csv(BUNDLE / "model_index.csv")
    require(model_index[model_index.feature_set == "full29"].feature_order.iloc[0].split() == features29, "full29 order differs")

    variants = {"full29_repro": features29} if args.stage == "repro" else \
        {name: features29 + extra for name, extra in VARIANTS_MAIN.items()}
    scores, splits, training, importance = [], [], [], []
    for split, seed in SPLITS.items():
        bundle_split = pd.read_csv(BUNDLE / f"splits/{split}.csv")
        for fold in range(3):
            outer = data[data.outer_fold == fold]
            fit, cal = snap.inner_split(data[data.outer_fold != fold], seed + fold)
            snap.check_disjoint(fit, outer)
            snap.check_disjoint(cal, outer)
            ref = bundle_split[(bundle_split.model == "full29") & (bundle_split.fold == fold)]
            for stage, part in [("fit", fit), ("calibration", cal), ("outer", outer)]:
                require(set(ref[ref.stage == stage].row_id) == set(part.row_id), f"{split} fold{fold} {stage} rows differ from PR #13")
                splits.append(pd.DataFrame({"split": split, "seed": seed, "fold": fold, "stage": stage, "row_id": part.row_id.to_numpy()}))
            for variant, cols in variants.items():
                matrices = [snap.feature_matrix(p, cols, "M_full") for p in (fit, cal, outer)]
                ds = lgb.Dataset(matrices[0], label=fit.label.to_numpy(), weight=None,
                                 categorical_feature=["updateType"], feature_name=cols)
                model = lgb.train(spec["lightgbm"], ds, num_boost_round=spec["rounds"])
                path = out / "models" / f"{variant}_{split}_fold{fold}.txt"
                model.save_model(str(path))
                row = {"variant": variant, "split": split, "seed": seed, "fold": fold, "feature_count": len(cols),
                       "requested_rounds": spec["rounds"], "trained_rounds": model.current_iteration(),
                       "early_stopping": False, "sample_weight": False, "model_sha256": sha(path),
                       "fit_rows": len(fit), "fit_malicious": int(fit.label.sum()),
                       "calibration_rows": len(cal), "calibration_malicious": int(cal.label.sum()),
                       "outer_rows": len(outer), "outer_malicious": int(outer.label.sum()),
                       "feature_order": " ".join(cols)}
                training.append(row)
                gain = model.feature_importance(importance_type="gain")
                cnt = model.feature_importance(importance_type="split")
                importance.extend({"variant": variant, "split": split, "fold": fold, "feature": f,
                                   "gain": float(g), "split_count": int(c)} for f, g, c in zip(cols, gain, cnt, strict=True))
                for stage, part, x in [("calibration", cal, matrices[1]), ("outer", outer, matrices[2])]:
                    s = model.predict(x, num_threads=2)
                    require(np.isfinite(s).all() and ((s >= 0) & (s <= 1)).all(), "invalid predictions")
                    scores.append(pd.DataFrame({"variant": variant, "split": split, "seed": seed, "fold": fold,
                                                "stage": stage, "row_id": part.row_id.to_numpy(), "score": s}))
                print(f"done {variant} {split} fold{fold} rounds={row['trained_rounds']}", flush=True)
    pd.concat(scores).to_csv(out / "scores.csv", index=False, lineterminator="\n")
    pd.concat(splits).to_csv(out / "splits.csv", index=False, lineterminator="\n")
    pd.DataFrame(training).to_csv(out / "training.csv", index=False, lineterminator="\n")
    pd.DataFrame(importance).to_csv(out / "feature_importance.csv", index=False, lineterminator="\n")
    data[["row_id", "package", "old_version", "new_version", "label", "class", "campaign", "component",
          "outer_fold", "type"]].to_csv(out / "row_metadata.csv", index=False, lineterminator="\n")
    x1_manifest = json.loads(X1_MANIFEST.read_text(encoding="utf-8"))
    for name, path in list(paths.items()) + [("full35", FULL35)]:
        require(sha(path) == initial[name], f"input changed while running: {name}")
    manifest = {
        "experiment_id": "D06-FULL35-COMPARE", "stage": args.stage, "data_version": "D06",
        "data_commit": "be87ab4cff66fff1980c4a71be8032b6b47225ba",
        "inputs": {k: {"path": str(v.relative_to(args.workspace)), "sha256": sha(v)} for k, v in paths.items()},
        "x1": {"path": str(FULL35.relative_to(HERE.parent)), "sha256": sha(FULL35),
               "schema_sha256": sha(SCHEMA), "extractor_commit": x1_manifest["extractor"]["commit"]},
        "snapshot": str(SNAPSHOT.relative_to(HERE.parent)), "snapshot_sha256": SNAPSHOT_SHA256,
        "script_sha256": sha(__file__), "lightgbm_params": spec["lightgbm"], "rounds": spec["rounds"],
        "early_stopping": False, "sample_weight": None, "missing": "NaN (LightGBM default handling)",
        "x1_encoding": "booleans True/False -> 1.0/0.0, empty -> NaN; counts as float; no clipping or log transform",
        "variants": {k: v for k, v in variants.items()},
        "packages": versions, "python": platform.python_version(), "python_pr13": PR13_PYTHON,
        "platform": platform.platform(), "argv": sys.argv, "read_test": False,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
