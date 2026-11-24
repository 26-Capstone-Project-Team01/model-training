"""D06 multi-group validation (MGV) + limited LightGBM hyperparameter search for the narrowed candidate set.
Train only; Test is never read; no package code execution; no new features or algorithms.

Candidates: full35, gs24, full28_noObfNew (LightGBM), B3 (full35 + LR + MLP blend, same rule as ../d06_alt_models/blend.py),
C5 routing (rank scale; JS change none & new dependency & no install script added -> gs24, else full35; same as ../d06_gs24_followup).

Partitions (component-disjoint, PR #13 components; inner fit/calibration = snapshot inner_split(train, seed)):
  pr13        : PR #13 outer folds, inner seeds 20261109 / 20261110 (= existing protocol; default config must reproduce saved full35)
  rgk3_s{k}   : k = 1..5, randomized greedy component 3-fold: malicious components shuffled (seed k) and put in the fold with the
                fewest malicious rows; normal components shuffled and put in the fold with the fewest rows of their class
  loco_{comp} : leave-one-large-component-out for malicious components with >= 18 rows (6): eval = that component + the normal
                components of PR #13 outer fold 0; train = everything else
Hyperparameters (limited, fixed grid, 12 configs): num_leaves {15, 31, 63} x min_data_in_leaf {20, 50} x rounds {100, 200};
all other PR #13 params unchanged. Default = (31, 20, 200) = PR #13. Selection per partition family and feature set by mean
calibration PR-AUC over that family's cells (never outer labels).
Operating targets: calibration FPR 1, 2, 3, 4, 5% (PR #13 calibrate, ML). Goal check (reported, not optimised on outer):
recall >= 0.90 and actual outer FPR <= 0.05.

Usage: python -I -B mgv_hpo.py --workspace <ws> --out <new dir> [--dry-run]   (dry run: 1 cell per family, default config only)
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import itertools
import json
import sys
import time
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score

HERE = Path(__file__).resolve().parent
EXP = HERE.parent
TARGETS = [0.01, 0.02, 0.03, 0.04, 0.05]
GRID = [{"num_leaves": nl, "min_data_in_leaf": md, "rounds": r} for nl, md, r in itertools.product([15, 31, 63], [20, 50], [100, 200])]
DEFAULT = {"num_leaves": 31, "min_data_in_leaf": 20, "rounds": 200}


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


def cfg_name(c):
    return f"nl{c['num_leaves']}_md{c['min_data_in_leaf']}_r{c['rounds']}"


def rgk3(data, snap, seed):
    counts = snap.component_counts(data)
    rng = np.random.default_rng(seed)
    assign, mal_load, cls_load = {}, np.zeros(3), np.zeros((3, counts.shape[1]))
    mal = list(counts.index[counts.malicious > 0])
    for g in rng.permutation(sorted(mal)):
        f = int(np.argmin(mal_load + rng.random(3) * 1e-6))
        assign[g] = f
        mal_load[f] += counts.loc[g, "malicious"]
        cls_load[f] += counts.loc[g].to_numpy()
    for g in rng.permutation(sorted(counts.index[counts.malicious == 0])):
        k = int(np.argmax(counts.loc[g].to_numpy()))
        f = int(np.argmin(cls_load[:, k] + rng.random(3) * 1e-6))
        assign[g] = f
        cls_load[f] += counts.loc[g].to_numpy()
    return data.component.map(assign).astype(int)


def cells(data, snap):
    """Yield (family, cell, seed, train_frame, eval_frame)."""
    for split, seed in {"split1": 20261109, "split2": 20261110}.items():
        for fold in range(3):
            yield "pr13", f"{split}_f{fold}", seed + fold, data[data.outer_fold != fold], data[data.outer_fold == fold]
    for k in range(1, 6):
        fa = rgk3(data, snap, 1000 + k)
        for fold in range(3):
            yield "rgk3", f"s{k}_f{fold}", 20261109 + 100 * k + fold, data[fa != fold], data[fa == fold]
    mal = data[data.label == 1].groupby("component").size()
    normal_eval = (data.label == 0) & (data.outer_fold == 0)
    for comp in sorted(mal[mal >= 18].index):
        ev = (data.component == comp) | normal_eval
        yield "loco", comp, 20261109 + 7, data[~ev & ~((data.label == 0) & (data.outer_fold == 0))], data[ev]


def rank_vs(normals, s):
    n = np.sort(normals)
    lo, hi = np.searchsorted(n, s, "left"), np.searchsorted(n, s, "right")
    return (lo + 0.5 * (hi - lo)) / len(n)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    out = a.out
    out.mkdir(parents=True, exist_ok=False)
    r = load(EXP / "d06_full35_compare/run_full35.py", "run_full35")
    alt = load(EXP / "d06_alt_models/alt_models.py", "alt_models")
    bl = load(EXP / "d06_alt_models/blend.py", "blend_alt")
    snap = r.load_snapshot()
    spec = json.loads((a.workspace / r.SPEC_REL).read_text(encoding="utf-8"))
    data, feat29, _ = snap.load_data(a.workspace, spec)
    r.check_bundle_alignment(data)
    data = r.attach_x1(data)
    G = alt.groups(feat29, r.X1_ALL)
    full35 = feat29 + r.X1_ALL
    FS = {"full35": full35, "gs24": feat29[:7] + G["obfChange"] + G["obfChangedCode"] + G["x1Calls"],
          "full28_noObfNew": [f for f in full35 if f not in G["obfNew"]]}
    grid = [DEFAULT] if a.dry_run else GRID
    rows, scores, seen = [], [], set()
    t0 = time.time()
    for fam, cell, seed, train, ev in cells(data, snap):
        if a.dry_run and fam in seen:
            continue
        seen.add(fam)
        snap.check_disjoint(train, ev)
        fit, cal = snap.inner_split(train, seed)
        cs, es = {}, {}
        for fs, cols in FS.items():
            mats = [snap.feature_matrix(p, cols, "M_full") for p in (fit, cal, ev)]
            for cfg in grid:
                params = dict(spec["lightgbm"], num_leaves=cfg["num_leaves"], min_data_in_leaf=cfg["min_data_in_leaf"])
                m = lgb.train(params, lgb.Dataset(mats[0], label=fit.label.to_numpy(), categorical_feature=["updateType"], feature_name=cols),
                              num_boost_round=cfg["rounds"])
                key = f"{fs}|{cfg_name(cfg)}"
                cs[key], es[key] = m.predict(mats[1], num_threads=1), m.predict(mats[2], num_threads=1)
        for kind in ["lr", "mlp"]:
            mats = [snap.feature_matrix(p, full35, "M_full") for p in (fit, cal, ev)]
            model, scale = alt.make_model(kind, seed, 1)
            prep = alt.Prep(scale).fit(mats[0])
            model.fit(prep.transform(mats[0]), fit.label.to_numpy())
            cs[f"full35_{kind}"], es[f"full35_{kind}"] = model.predict_proba(prep.transform(mats[1]))[:, 1], model.predict_proba(prep.transform(mats[2]))[:, 1]
        for key in cs:
            scores.append(pd.DataFrame({"family": fam, "cell": cell, "model": key, "stage": "calibration", "row_id": cal.row_id.to_numpy(), "score": cs[key]}))
            scores.append(pd.DataFrame({"family": fam, "cell": cell, "model": key, "stage": "eval", "row_id": ev.row_id.to_numpy(), "score": es[key]}))
        rows.append({"family": fam, "cell": cell, "seed": seed, "fit": len(fit), "cal": len(cal), "eval": len(ev), "eval_malicious": int(ev.label.sum()),
                     "cal_malicious": int(cal.label.sum()), "elapsed_s": round(time.time() - t0, 1)})
        print(f"{fam} {cell} done {time.time() - t0:.0f}s", flush=True)
    S = pd.concat(scores)
    S.to_csv(out / "scores.csv", index=False, lineterminator="\n")
    pd.DataFrame(rows).to_csv(out / "cells.csv", index=False, lineterminator="\n")
    # guard: pr13 default full35 == saved full35 (only cells with seeds equal to the saved protocol)
    saved = pd.read_csv(EXP / "d06_full35_compare/run/scores.csv")
    saved = saved[saved.variant == "full35"]
    chk = []
    for cell in S[(S.family == "pr13")].cell.unique():
        split, f = cell.split("_f")
        x = S[(S.family == "pr13") & (S.cell == cell) & (S.model == f"full35|{cfg_name(DEFAULT)}")]
        y = saved[(saved.split == split) & (saved.fold == int(f))]
        m = x.assign(stage=x.stage.replace({"eval": "outer"})).merge(y, on=["stage", "row_id"], suffixes=("", "_saved"))
        chk.append(bool(len(m) == len(y) and np.allclose(m.score, m.score_saved, rtol=0, atol=1e-15)))
    (out / "manifest.json").write_text(json.dumps({"dry_run": a.dry_run, "grid": grid, "pr13_default_full35_reproduces_saved": chk,
        "script_sha256": sha(__file__), "outputs": {p.name: sha(p) for p in sorted(out.glob("*.csv"))}}, indent=1) + "\n")
    print("guard", chk)


if __name__ == "__main__":
    main()
