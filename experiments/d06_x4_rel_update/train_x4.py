"""Train full35+X4 and full35-updateInterval+X4 under the PR #13 protocol (only new variants; full35 reused).

Everything except feature columns comes unchanged from ../d06_full35_compare/run_full35.py (imported by path; it hash-checks
the PR #13 snapshot): load_data, alignment checks, attach_x1, inner_split(seed+fold), feature_matrix, LightGBM params,
200 rounds, no early stopping, no weights, NaN kept. Before the new variants, full35 is retrained through this same code and
must reproduce ../d06_full35_compare/run/scores.csv bit-for-bit (guard). X4 attached by row_id after key and label check.
Variants fixed before any result: full35_x4 = full35 + X4; full34_x4 = full35 without updateInterval + X4.
Usage: python -I -B train_x4.py --workspace <ws> --x4 run/d06_x4.csv --out <new dir>
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
X4 = ["x4RelUpdateIntervalRatio", "x4HistoryGapCount"]


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", type=Path, required=True)
    ap.add_argument("--x4", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    spec_ = importlib.util.spec_from_file_location("run_full35", RUNNER)
    r = importlib.util.module_from_spec(spec_)
    spec_.loader.exec_module(r)
    versions = {"lightgbm": lgb.__version__, "pandas": pd.__version__, "numpy": np.__version__, "sklearn": sklearn.__version__}
    r.require(versions == r.PINNED, f"library versions differ: {versions}")
    out = a.out
    out.mkdir(parents=True, exist_ok=False)
    (out / "models").mkdir()
    snap = r.load_snapshot()
    spec = json.loads((a.workspace / r.SPEC_REL).read_text(encoding="utf-8"))
    data, features29, paths = snap.load_data(a.workspace, spec)
    r.check_bundle_alignment(data)
    data = r.attach_x1(data)
    raw = pd.read_csv(a.x4, dtype=str, keep_default_na=False)
    ids = ["package", "old_version", "new_version"]
    r.require((raw[ids].to_numpy() == data[ids].astype(str).to_numpy()).all() and (raw.label.astype(int).to_numpy() == data.label.to_numpy()).all(), "x4 keys/labels differ")
    for col in X4:
        v = pd.to_numeric(raw[col].replace("", np.nan), errors="raise").astype(float)
        r.require(not np.isinf(v).any(), f"inf in {col}")
        data[col] = v.to_numpy()
    full35 = features29 + r.X1_ALL
    r.require("updateInterval" in full35, "updateInterval missing")
    variants = {"full35": full35, "full35_x4": full35 + X4, "full34_x4": [f for f in full35 if f != "updateInterval"] + X4}
    scores, training = [], []
    for split, seed in r.SPLITS.items():
        bundle_split = pd.read_csv(r.BUNDLE / f"splits/{split}.csv")
        for fold in range(3):
            outer = data[data.outer_fold == fold]
            fit, cal = snap.inner_split(data[data.outer_fold != fold], seed + fold)
            ref = bundle_split[(bundle_split.model == "full29") & (bundle_split.fold == fold)]
            for stage, part in [("fit", fit), ("calibration", cal), ("outer", outer)]:
                r.require(set(ref[ref.stage == stage].row_id) == set(part.row_id), f"{split} fold{fold} {stage} differs from PR #13")
            for variant, cols in variants.items():
                mats = [snap.feature_matrix(p, cols, "M_full") for p in (fit, cal, outer)]
                ds = lgb.Dataset(mats[0], label=fit.label.to_numpy(), categorical_feature=["updateType"], feature_name=cols)
                model = lgb.train(spec["lightgbm"], ds, num_boost_round=spec["rounds"])
                if variant != "full35":
                    path = out / "models" / f"{variant}_{split}_fold{fold}.txt"
                    model.save_model(str(path))
                    training.append({"variant": variant, "split": split, "fold": fold, "feature_count": len(cols), "trained_rounds": model.current_iteration(),
                                     "model_sha256": sha(path), "feature_order": " ".join(cols)})
                for stage, part, x in [("calibration", cal, mats[1]), ("outer", outer, mats[2])]:
                    s = model.predict(x, num_threads=2)
                    scores.append(pd.DataFrame({"variant": variant, "split": split, "seed": seed, "fold": fold, "stage": stage, "row_id": part.row_id.to_numpy(), "score": s}))
    pd.concat(scores).to_csv(out / "all_scores_incl_full35_guard.csv", index=False, lineterminator="\n")
    S = pd.read_csv(out / "all_scores_incl_full35_guard.csv")  # compare after the same CSV round trip as the saved run
    (out / "all_scores_incl_full35_guard.csv").unlink()
    old = pd.read_csv(RUNNER.parent / "run/scores.csv")
    old = old[old.variant == "full35"]
    m = S[S.variant == "full35"].merge(old, on=["variant", "split", "seed", "fold", "stage", "row_id"], suffixes=("", "_saved"))
    r.require(len(m) == len(old) and (m.score == m.score_saved).all(), "full35 guard failed: retrain does not reproduce saved scores")
    S[S.variant != "full35"].to_csv(out / "scores.csv", index=False, lineterminator="\n")
    pd.DataFrame(training).to_csv(out / "training.csv", index=False, lineterminator="\n")
    man = {"guard": "full35 retrain reproduced saved scores bit-for-bit (%d rows); full35 scores not re-saved" % len(m),
           "inputs": {k: sha(v) for k, v in paths.items()} | {"x4": sha(a.x4)}, "runner_sha256": sha(RUNNER), "script_sha256": sha(__file__),
           "lightgbm_params": spec["lightgbm"], "rounds": spec["rounds"], "variants": {k: v for k, v in variants.items() if k != "full35"},
           "packages": versions, "python": platform.python_version(), "argv": sys.argv, "read_test": False,
           "outputs": {p.name: sha(p) for p in sorted(out.glob("*.csv"))}}
    (out / "manifest.json").write_text(json.dumps(man, indent=1) + "\n")
    print(man["guard"])


if __name__ == "__main__":
    main()
