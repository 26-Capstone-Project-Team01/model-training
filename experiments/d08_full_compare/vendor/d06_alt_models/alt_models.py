"""D06 Train: (1) feature-group combination search with LightGBM on existing 35 features, chosen on inner calibration only;
(2) Logistic Regression / Random Forest / MLP on full35. PR #13 splits and calibration policy unchanged; Test never read;
package code never executed.

Data, component/outer folds, inner split (seed+fold), PR #13 alignment checks and X1 encoding are taken unchanged from
../d06_full35_compare/run_full35.py (imported by path; it hash-checks the PR #13 snapshot).

Stage groupsearch (selection uses calibration rows only, never outer labels):
  base7 always included; optional groups obfNew(7), obfChange(7), obfChangedCode(8 incl. obfChangedFileCount), x1Hook(4), x1Calls(2)
  -> 32 combinations x 2 splits x 3 folds, LightGBM with PR #13 params/rounds. Criterion = mean calibration PR-AUC over the 6
  (split, fold) cells; tie -> fewer features. Already trained sets are recognised and their outer scores are not re-made:
  only the selected set gets outer scores, and only if it is not base7/full29/full35/base7_x1/full32 (existing runs).
Stage altmodels: LR, RF, MLP on full35 columns with hyperparameters fixed here (no tuning on any outer data):
  preprocessing fitted on the fit rows only: updateType one-hot (major/minor/patch), numeric NaN -> fit median + missing indicator
  for columns with any NaN in fit, LR/MLP additionally sign(x)*log1p(|x|) then StandardScaler. RF uses the imputed matrix.
  LR: C=1.0, lbfgs, max_iter=5000. RF: 500 trees, min_samples_leaf=2, max_features="sqrt", n_jobs=--jobs, random_state=seed+fold.
  MLP: hidden (64, 32), alpha=1e-3, adam, max_iter=500, early_stopping=False, random_state=seed+fold.
Scores (calibration + outer) are written in the same layout as d06_x3_models so evaluate.py applies the PR #13 calibration.

Usage: python -I -B alt_models.py --workspace <ws> --stage {groupsearch,altmodels} --out <new dir> [--jobs N] [--limit-cells N]
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import itertools
import json
import platform
import sys
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler

HERE = Path(__file__).resolve().parent
RUNNER = HERE.parent / "d06_full35_compare/run_full35.py"
EXISTING = {"base7", "full29", "full35", "base7_x1", "full32"}  # trained earlier; never retrained here


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def groups(features29, x1):
    obf = features29[7:]
    return {
        "obfNew": [c for c in obf if c.endswith("New")],
        "obfChange": [c for c in obf if c.endswith("Change")],
        "obfChangedCode": [c for c in obf if c.endswith("ChangedCode")] + ["obfChangedFileCount"],
        "x1Hook": x1[:4],
        "x1Calls": x1[4:],
    }


def name_of(chosen, G):
    if not chosen:
        return "base7"
    if set(chosen) == set(G):
        return "full35"
    if set(chosen) == {"obfNew", "obfChange", "obfChangedCode"}:
        return "full29"
    if set(chosen) == {"x1Hook", "x1Calls"}:
        return "base7_x1"
    return "gs_" + "+".join(chosen)


class Prep:
    """Fit-row-only preprocessing for sklearn models."""

    def __init__(self, scale):
        self.scale = scale

    def fit(self, x):
        self.cols = [c for c in x.columns if c != "updateType"]
        num = x[self.cols].astype(float)
        self.med = num.median()
        self.ind = [c for c in self.cols if num[c].isna().any()]
        if self.scale:
            self.sc = StandardScaler().fit(self._num(x))
        return self

    def _num(self, x):
        num = x[self.cols].astype(float)
        parts = [num.fillna(self.med)]
        if self.ind:
            parts.append(num[self.ind].isna().astype(float).add_suffix("__missing"))
        ut = x["updateType"].astype(str)
        parts.append(pd.DataFrame({f"updateType={k}": (ut == k).astype(float) for k in ["major", "minor", "patch"]}, index=x.index))
        m = pd.concat(parts, axis=1)
        if self.scale:
            m[self.cols] = np.sign(m[self.cols]) * np.log1p(np.abs(m[self.cols]))
        return m

    def transform(self, x):
        m = self._num(x)
        return self.sc.transform(m) if self.scale else m.to_numpy()


def make_model(kind, seed, jobs):
    if kind == "lr":
        return LogisticRegression(C=1.0, solver="lbfgs", max_iter=5000), True
    if kind == "rf":
        return RandomForestClassifier(n_estimators=500, min_samples_leaf=2, max_features="sqrt", n_jobs=jobs, random_state=seed), False
    if kind == "mlp":
        return MLPClassifier(hidden_layer_sizes=(64, 32), alpha=1e-3, solver="adam", max_iter=500, early_stopping=False, random_state=seed), True
    raise ValueError(kind)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", type=Path, required=True)
    ap.add_argument("--stage", choices=["groupsearch", "altmodels"], required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--jobs", type=int, default=2)
    ap.add_argument("--limit-cells", type=int, default=0, help="smoke test only: first N (split, fold) cells")
    a = ap.parse_args()
    r = load(RUNNER, "run_full35")
    versions = {"lightgbm": lgb.__version__, "pandas": pd.__version__, "numpy": np.__version__, "sklearn": sklearn.__version__}
    r.require(versions == r.PINNED, f"library versions differ: {versions}")
    out = a.out
    out.mkdir(parents=True, exist_ok=False)
    snap = r.load_snapshot()
    spec = json.loads((a.workspace / r.SPEC_REL).read_text(encoding="utf-8"))
    data, features29, paths = snap.load_data(a.workspace, spec)
    r.check_bundle_alignment(data)
    data = r.attach_x1(data)
    base7 = features29[:7]
    G = groups(features29, r.X1_ALL)
    assert sorted(sum(G.values(), [])) == sorted(features29[7:] + r.X1_ALL)
    full35 = features29 + r.X1_ALL
    cells = []
    for split, seed in r.SPLITS.items():
        bundle_split = pd.read_csv(r.BUNDLE / f"splits/{split}.csv")
        for fold in range(3):
            outer = data[data.outer_fold == fold]
            fit, cal = snap.inner_split(data[data.outer_fold != fold], seed + fold)
            ref = bundle_split[(bundle_split.model == "full29") & (bundle_split.fold == fold)]
            for stage, part in [("fit", fit), ("calibration", cal), ("outer", outer)]:
                r.require(set(ref[ref.stage == stage].row_id) == set(part.row_id), f"{split} fold{fold} {stage} differs from PR #13")
            cells.append((split, seed, fold, fit, cal, outer))
    if a.limit_cells:
        cells = cells[:a.limit_cells]
    scores, log = [], []

    def lgb_scores(cols, fit, parts):
        mats = [snap.feature_matrix(p, cols, "M_full") for p in [fit] + parts]
        ds = lgb.Dataset(mats[0], label=fit.label.to_numpy(), categorical_feature=["updateType"], feature_name=cols)
        model = lgb.train(spec["lightgbm"], ds, num_boost_round=spec["rounds"])
        return [model.predict(m, num_threads=a.jobs) for m in mats[1:]]

    if a.stage == "groupsearch":
        combos = [list(c) for k in range(len(G) + 1) for c in itertools.combinations(G, k)]
        for chosen in combos:
            cols = base7 + [f for g in chosen for f in G[g]]
            pr = []
            for split, seed, fold, fit, cal, outer in cells:
                (s_cal,) = lgb_scores(cols, fit, [cal])
                pr.append(average_precision_score(cal.label, s_cal))
                log.append({"combo": name_of(chosen, G), "groups": "+".join(chosen), "n_features": len(cols), "split": split, "fold": fold,
                            "cal_pr_auc": pr[-1], "cal_malicious": int(cal.label.sum()), "cal_rows": len(cal)})
            print(f"{name_of(chosen, G):55s} n={len(cols):2d} calPR={np.mean(pr):.4f}", flush=True)
        L = pd.DataFrame(log)
        L.to_csv(out / "groupsearch_calibration.csv", index=False, lineterminator="\n")
        S = L.groupby(["combo", "groups", "n_features"]).cal_pr_auc.agg(["mean", "std", "min"]).reset_index().sort_values(["mean", "n_features"], ascending=[False, True])
        S.to_csv(out / "groupsearch_ranking.csv", index=False, lineterminator="\n")
        best = S.iloc[0]
        sel = {"selected": best.combo, "groups": best.groups, "cal_pr_auc_mean": float(best["mean"]), "already_trained": best.combo in EXISTING}
        if not sel["already_trained"]:
            cols = base7 + [f for g in (best.groups.split("+") if best.groups else []) for f in G[g]]
            for split, seed, fold, fit, cal, outer in cells:
                s_cal, s_out = lgb_scores(cols, fit, [cal, outer])
                for stage, part, s in [("calibration", cal, s_cal), ("outer", outer, s_out)]:
                    scores.append(pd.DataFrame({"variant": best.combo, "split": split, "seed": seed, "fold": fold, "stage": stage,
                                                "row_id": part.row_id.to_numpy(), "score": s}))
        (out / "selection.json").write_text(json.dumps(sel, indent=1) + "\n")
        print("selected", sel, flush=True)
    else:
        for kind in ["lr", "rf", "mlp"]:
            for split, seed, fold, fit, cal, outer in cells:
                mats = [snap.feature_matrix(p, full35, "M_full") for p in (fit, cal, outer)]
                model, scale = make_model(kind, seed + fold, a.jobs)
                prep = Prep(scale).fit(mats[0])
                model.fit(prep.transform(mats[0]), fit.label.to_numpy())
                conv = getattr(model, "n_iter_", None)
                log.append({"variant": f"full35_{kind}", "split": split, "fold": fold, "n_inputs": prep.transform(mats[0]).shape[1],
                            "n_iter": int(np.max(conv)) if conv is not None else None})
                for stage, part, m in [("calibration", cal, mats[1]), ("outer", outer, mats[2])]:
                    s = model.predict_proba(prep.transform(m))[:, 1]
                    r.require(np.isfinite(s).all(), "invalid predictions")
                    scores.append(pd.DataFrame({"variant": f"full35_{kind}", "split": split, "seed": seed, "fold": fold, "stage": stage,
                                                "row_id": part.row_id.to_numpy(), "score": s}))
                print(f"done full35_{kind} {split} fold{fold}", flush=True)
        pd.DataFrame(log).to_csv(out / "training.csv", index=False, lineterminator="\n")
    if scores:
        pd.concat(scores).to_csv(out / "scores.csv", index=False, lineterminator="\n")
    man = {"stage": a.stage, "inputs": {k: sha(v) for k, v in paths.items()}, "runner_sha256": sha(RUNNER), "script_sha256": sha(__file__),
           "lightgbm_params": spec["lightgbm"], "rounds": spec["rounds"], "packages": versions, "python": platform.python_version(),
           "argv": sys.argv, "read_test": False, "limit_cells": a.limit_cells,
           "outputs": {p.name: sha(p) for p in sorted(out.glob("*")) if p.is_file()}}
    (out / "manifest.json").write_text(json.dumps(man, indent=1) + "\n")


if __name__ == "__main__":
    main()
