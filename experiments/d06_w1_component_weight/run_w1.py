"""D06-W1: full29 + malicious connected-component weight 1/sqrt(n), compared with PR #13 full29.

Reuses the PR #13 run1 training snapshot unchanged (imported by path) for data loading,
component/outer/inner splits, feature matrices and LightGBM parameters. Only the fit-row
sample weight differs. Test 677 is never read. Package code is never executed.

Usage:
  python -I -B run_w1.py --workspace <ws> --out <new empty dir>
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
BUNDLE = HERE.parent / "d06_feature_comparison_18"
SNAPSHOT = BUNDLE / "provenance/phase2_run1_base7_full29/executed_script_snapshot.py"
SNAPSHOT_SHA256 = "049bf00c0269ff9638caad8273f3dc49254ba91cec9da35ebd3c4db87cf62854"
SPEC_REL = "temp/detection-feasibility/phase2/evaluation_spec.json"
SPLITS = {"split1": 20261109, "split2": 20261110}
SCENARIO = {"split1": "primary", "split2": "calibration_seed"}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_snapshot():
    if sha(SNAPSHOT) != SNAPSHOT_SHA256:
        raise SystemExit("snapshot hash mismatch")
    spec = importlib.util.spec_from_file_location("run1_snapshot", SNAPSHOT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def weights_component(fit):
    """W1: malicious weight 1/sqrt(n), n = malicious fit rows in the same connected component.
    Normalized so malicious weights sum to the malicious fit count; normal/hard benign = 1."""
    w = np.ones(len(fit))
    mal = fit.label.to_numpy() == 1
    keys = fit.loc[mal, "component"]
    raw = 1 / np.sqrt(keys.map(keys.value_counts()).to_numpy())
    w[mal] = raw * mal.sum() / raw.sum()
    return w


def weights_splitgroup(fit, snap):
    """Existing model-training definition (train_model.py compute_sample_weights, E08/E09/E10):
    key = shared splitGroup, generic bucket rows are singletons."""
    w = np.ones(len(fit))
    mal = fit.label.to_numpy() == 1
    keys = pd.Series([sg if snap.shared_campaign(sg) else f"singleton:{rid}"
                      for sg, rid in zip(fit.loc[mal, "splitGroup"], fit.loc[mal, "row_id"])], index=fit.index[mal])
    raw = 1 / np.sqrt(keys.map(keys.value_counts()).to_numpy())
    w[mal] = raw * mal.sum() / raw.sum()
    return w


VARIANTS = {
    "full29_repro": None,          # unweighted, must reproduce PR #13 full29 bytes/scores
    "w1_component": "component",   # W1 main
    "w1_splitgroup": "splitgroup", # sensitivity: existing splitGroup key, not for selection
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    out = args.out
    out.mkdir(parents=True, exist_ok=False)
    (out / "models").mkdir()
    snap = load_snapshot()
    spec_path = args.workspace / SPEC_REL
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    data, features, paths = snap.load_data(args.workspace, spec)
    if len(features) != 29:
        raise SystemExit("expected 29 features")

    # bundle consistency: components and outer folds equal PR #13 row_metadata
    meta = pd.read_csv(BUNDLE / "scores/row_metadata.csv", keep_default_na=False)
    if not ((meta.row_id.to_numpy() == data.row_id.to_numpy()).all()
            and (meta.component.to_numpy() == data.component.to_numpy()).all()
            and (meta.outer_fold.to_numpy() == data.outer_fold.to_numpy()).all()):
        raise SystemExit("component/outer differ from PR #13 row_metadata")

    model_index = pd.read_csv(BUNDLE / "model_index.csv")
    scores, splits, training, weight_rows, weight_cmp = [], [], [], [], []
    for split, seed in SPLITS.items():
        bundle_split = pd.read_csv(BUNDLE / f"splits/{split}.csv")
        for fold in range(3):
            outer = data[data.outer_fold == fold]
            fit, cal = snap.inner_split(data[data.outer_fold != fold], seed + fold)
            # same fit/calibration rows as PR #13
            ref = bundle_split[(bundle_split.model == "full29") & (bundle_split.fold == fold)]
            for stage, part in [("fit", fit), ("calibration", cal), ("outer", outer)]:
                if set(ref[ref.stage == stage].row_id) != set(part.row_id):
                    raise SystemExit(f"{split} fold{fold} {stage} rows differ from PR #13")
                splits.append(pd.DataFrame({"split": split, "seed": seed, "fold": fold, "stage": stage,
                                            "row_id": part.row_id.to_numpy()}))
            wc, ws = weights_component(fit), weights_splitgroup(fit, snap)
            mal = fit.label.to_numpy() == 1
            weight_cmp.append({"split": split, "fold": fold, "fit_rows": len(fit), "fit_malicious": int(mal.sum()),
                "component_groups": int(fit.loc[mal, "component"].nunique()),
                "splitgroup_keys": int(len({sg if snap.shared_campaign(sg) else f"s{r}" for sg, r in zip(fit.loc[mal, "splitGroup"], fit.loc[mal, "row_id"])})),
                "malicious_weight_sum_component": float(wc[mal].sum()), "malicious_weight_sum_splitgroup": float(ws[mal].sum()),
                "normal_weight_all_one": bool((wc[~mal] == 1).all() and (ws[~mal] == 1).all()),
                "rows_weight_differs_gt1e-9": int((np.abs(wc - ws) > 1e-9).sum()),
                "max_abs_weight_diff": float(np.abs(wc - ws).max()),
                "min_w_component": float(wc[mal].min()), "max_w_component": float(wc[mal].max()),
                "min_w_splitgroup": float(ws[mal].min()), "max_w_splitgroup": float(ws[mal].max())})
            weight_rows.append(pd.DataFrame({"split": split, "fold": fold, "row_id": fit.row_id.to_numpy(),
                "label": fit.label.to_numpy(), "component": fit.component.to_numpy(), "splitGroup": fit.splitGroup.to_numpy(),
                "w_component": wc, "w_splitgroup": ws}))
            matrices = [snap.feature_matrix(p, features, "M_full") for p in (fit, cal, outer)]
            for variant, kind in VARIANTS.items():
                weight = None if kind is None else (wc if kind == "component" else ws)
                ds = lgb.Dataset(matrices[0], label=fit.label.to_numpy(), weight=weight,
                                 categorical_feature=["updateType"], feature_name=features)
                model = lgb.train(spec["lightgbm"], ds, num_boost_round=spec["rounds"])
                path = out / "models" / f"{variant}_{split}_fold{fold}.txt"
                model.save_model(str(path))
                row = {"variant": variant, "split": split, "seed": seed, "fold": fold,
                       "trained_rounds": model.current_iteration(), "model_sha256": sha(path),
                       "fit_rows": len(fit), "fit_malicious": int(mal.sum())}
                if variant == "full29_repro":
                    ref_sha = model_index[(model_index.feature_set == "full29") & (model_index.split == split)
                                          & (model_index.outer_fold == fold)].model_sha256.item()
                    row["pr13_model_sha256_match"] = row["model_sha256"] == ref_sha
                training.append(row)
                for stage, part, x in [("calibration", cal, matrices[1]), ("outer", outer, matrices[2])]:
                    s = model.predict(x, num_threads=2)
                    scores.append(pd.DataFrame({"variant": variant, "split": split, "seed": seed, "fold": fold,
                                                "stage": stage, "row_id": part.row_id.to_numpy(), "score": s}))
                print(f"done {variant} {split} fold{fold} rounds={row['trained_rounds']}", flush=True)
    pd.concat(scores).to_csv(out / "scores.csv", index=False, lineterminator="\n")
    pd.concat(splits).to_csv(out / "splits.csv", index=False, lineterminator="\n")
    pd.concat(weight_rows).to_csv(out / "fit_weights.csv", index=False, lineterminator="\n")
    pd.DataFrame(weight_cmp).to_csv(out / "weight_comparison.csv", index=False, lineterminator="\n")
    pd.DataFrame(training).to_csv(out / "training.csv", index=False, lineterminator="\n")
    data[["row_id", "package", "old_version", "new_version", "label", "class", "campaign", "component",
          "outer_fold", "type"]].to_csv(out / "row_metadata.csv", index=False, lineterminator="\n")
    manifest = {"experiment_id": "D06-W1", "data_version": "D06",
                "data_commit": "be87ab4cff66fff1980c4a71be8032b6b47225ba",
                "inputs": {k: {"path": str(v.relative_to(args.workspace)), "sha256": sha(v)} for k, v in paths.items()},
                "snapshot": str(SNAPSHOT.relative_to(HERE.parent)), "snapshot_sha256": SNAPSHOT_SHA256,
                "script_sha256": sha(__file__), "lightgbm_params": spec["lightgbm"], "rounds": spec["rounds"],
                "packages": {"lightgbm": lgb.__version__, "pandas": pd.__version__, "numpy": np.__version__},
                "read_test": False, "features": features}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
