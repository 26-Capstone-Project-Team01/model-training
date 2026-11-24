"""D06 Test follow-up development experiment (uses the already-evaluated Test; NOT a new pre-registered test).

1) W1 component weight (exp/d06-w1-component-weight run_w1.py weights_component) on full29 and full35,
   same fit/calibration split, seeds and LightGBM params as ../d06_test_eval (4 new models only).
2) Reuse saved models/scores of ../d06_test_eval/run for base7, base7_w, full29, full35, A1..A3.
3) Saved D06-E06/E09 models: Test scores (0.5 + ranking only; they have no calibration set).
4) Tree-prefix diagnostic (inference only): k in 6,7,10,20,50,100,200 trees of every 200-round model;
   thresholds from calibration only at each k. No k is selected from Test.

Usage: python -I -B followup_eval.py --workspace <ws> --groups <be87ab4c malicious_pair_groups.csv> --out <new dir>
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import platform
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

HERE = Path(__file__).resolve().parent
EVAL = HERE.parent / "d06_test_eval"
spec_ = importlib.util.spec_from_file_location("run_test_eval", EVAL / "run_test_eval.py")
R = importlib.util.module_from_spec(spec_)
spec_.loader.exec_module(R)  # helpers/constants only (main() is not called)

TARGETS = [0.01, 0.03, 0.05]
PREFIX = [6, 7, 10, 20, 50, 100, 200]
STORED = ["base7", "base7_w", "full29", "full35", "A1", "A2", "A3"]
NEW = {"full29_w1": "full29", "full35_w1": "full35"}


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def weights_component(fit):
    """W1 (run_w1.py, e8c5847): malicious weight 1/sqrt(n), n = malicious fit rows in the same component;
    normalized so malicious weights sum to the malicious fit count; normal/hard benign = 1."""
    w = np.ones(len(fit))
    mal = fit.label.to_numpy() == 1
    keys = fit.loc[mal, "component"]
    raw = 1 / np.sqrt(keys.map(keys.value_counts()).to_numpy())
    w[mal] = raw * mal.sum() / raw.sum()
    return w


def prepare(ws, groups_path):
    snap = R.load_snapshot()
    spec = json.loads((ws / R.SPEC_REL).read_text(encoding="utf-8"))
    data, feat29, paths = snap.load_data(ws, spec)
    tk, tx = R.encode_x1(R.TRAIN_FULL35)
    R.require((tk[R.KEY].to_numpy() == data[R.KEY].astype(str).to_numpy()).all(), "train keys")
    for c in R.X1:
        data[c] = tx[c].to_numpy()
    tst = pd.read_csv(R.TEST_FULL35, float_precision="round_trip")
    _, sx = R.encode_x1(R.TEST_FULL35)
    test = tst.drop(columns=R.X1).copy()
    for c in R.X1:
        test[c] = sx[c].to_numpy()
    st = pd.read_csv(R.TEST_STATUS, keep_default_na=False, dtype=str)
    test["class"], test["campaign"] = st["class"].to_numpy(), st["splitGroup"].to_numpy()
    test["test_row"] = np.arange(len(test))
    test["in674"] = ~test[R.KEY].astype(str).apply(tuple, axis=1).isin(R.VANT3)
    feats = {"base7": spec["features"]["M_base"], "base7_w": spec["features"]["M_base"], "full29": feat29, "full35": feat29 + R.X1}
    feats |= {k: feats[v] for k, v in NEW.items()}
    return snap, spec, data, test, feats, paths


def evaluate(test, cal_lab, cal_s, test_s, models, tag):
    """Thresholds from calibration only; metrics on Test-674 / Test-677."""
    thr_rows, met_rows = [], []
    for m in models:
        thr = {}
        for t in TARGETS:
            r = SNAP.calibrate(cal_s[m], cal_lab, np.zeros(len(cal_lab), bool), "ML", t)
            thr[t] = r["threshold"]
            thr_rows.append(tag | {"model": m, "target": t, "threshold": r["threshold"], "cal_fp": r["calibration_fp"], "cal_normals": r["calibration_normal"],
                                   "cal_fpr": r["calibration_fp"] / r["calibration_normal"]})
        thr["0.5"] = 0.5
        for tset, mask in [("Test-674", test.in674.to_numpy()), ("Test-677", np.ones(len(test), bool))]:
            tf, sc = test[mask], test_s[m][mask]
            base = tag | {"test_set": tset, "model": m, "ROC_AUC": roc_auc_score(tf.label, sc), "PR_AUC": average_precision_score(tf.label, sc)}
            for op in TARGETS + ["0.5"]:
                met_rows.append(base | {"op": "0.5" if op == "0.5" else f"calFPR{int(op * 100)}%", "threshold": thr[op], **R.metrics(tf, sc, thr[op])})
    return thr_rows, met_rows


def main():
    global SNAP
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", type=Path, required=True)
    ap.add_argument("--groups", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    versions = {"lightgbm": lgb.__version__, "pandas": pd.__version__, "numpy": np.__version__, "sklearn": R.sklearn.__version__}
    R.require(versions == R.PINNED, f"versions {versions}")
    out = args.out
    out.mkdir(parents=True, exist_ok=False)
    (out / "models").mkdir()
    SNAP, spec, data, test, feats, paths = prepare(args.workspace, args.groups)
    stored_scores = pd.read_csv(EVAL / "run/scores.csv")
    stored_splits = pd.read_csv(EVAL / "run/splits.csv")
    train_rows, thr_all, met_all, pre_thr, pre_met, score_rows = [], [], [], [], [], []
    for sname, seed in R.SEEDS.items():
        fit, cal = SNAP.inner_split(data, seed)
        ref = stored_splits[stored_splits.seed == sname]
        for stg, part in [("fit", fit), ("calibration", cal)]:
            R.require(set(ref[ref.stage == stg].row_id) == set(part.row_id), f"{sname} {stg} differs from d06_test_eval")
        cal_lab = cal.label.to_numpy()
        cal_s, test_s, boosters = {}, {}, {}
        # stored scores (base7, base7_w, full29, full35, A1..A3)
        for m in STORED:
            sc = stored_scores[(stored_scores.seed == sname) & (stored_scores.model == m)]
            c = sc[sc.stage == "calibration"].set_index("row_id").score
            t = sc[sc.stage == "test"].set_index("test_row").score
            cal_s[m], test_s[m] = c.loc[cal.row_id].to_numpy(), t.loc[test.test_row].to_numpy()
        for m in ["base7", "base7_w", "full29", "full35"]:
            boosters[m] = lgb.Booster(model_file=str(EVAL / "run/models" / f"{m}_{sname}.txt"))
        # new W1 models
        for m, basef in NEW.items():
            cols = feats[m]
            xf, xc, xt = (SNAP.feature_matrix(p, cols, "M_full") for p in (fit, cal, test))
            w = weights_component(fit)
            b = lgb.train(spec["lightgbm"], lgb.Dataset(xf, label=fit.label.to_numpy(), weight=w, categorical_feature=["updateType"], feature_name=cols),
                          num_boost_round=spec["rounds"])
            path = out / "models" / f"{m}_{sname}.txt"
            b.save_model(str(path))
            boosters[m] = b
            cal_s[m], test_s[m] = b.predict(xc, num_threads=2), b.predict(xt, num_threads=2)
            mal = fit.label.to_numpy() == 1
            train_rows.append({"seed": sname, "model": m, "feature_order": " ".join(cols), "weight": "W1 component 1/sqrt(n)", "trained_rounds": b.current_iteration(),
                               "model_sha256": sha(path), "fit_rows": len(fit), "fit_malicious": int(mal.sum()), "components_malicious": int(fit.loc[mal, "component"].nunique()),
                               "w_min": float(w[mal].min()), "w_max": float(w[mal].max()), "w_sum_malicious": float(w[mal].sum())})
            print(f"trained {m} {sname} rounds={b.current_iteration()}", flush=True)
            for stg, part, s in [("calibration", cal, cal_s[m]), ("test", test, test_s[m])]:
                score_rows.append(pd.DataFrame({"seed": sname, "model": m, "stage": stg, "row_id": part.row_id.to_numpy() if stg == "calibration" else -1,
                                                "test_row": part.test_row.to_numpy() if stg == "test" else -1, "score": s}))
        # sanity: stored boosters reproduce stored scores
        for m in ["base7", "base7_w", "full29", "full35"]:
            p = boosters[m].predict(SNAP.feature_matrix(test, feats[m], "M_full"), num_threads=2)
            R.require(np.abs(p - test_s[m]).max() < 1e-12, f"stored model {m} {sname} does not reproduce stored scores")
        models = STORED + list(NEW)
        tr, mr = evaluate(test, cal_lab, cal_s, test_s, models, {"seed": sname})
        thr_all += tr
        met_all += mr
        # tree prefix diagnostic
        for k in PREFIX:
            pc, pt = {}, {}
            for m in ["base7", "base7_w", "full29", "full35"] + list(NEW):
                cols = feats[m]
                pc[m] = boosters[m].predict(SNAP.feature_matrix(cal, cols, "M_full"), num_iteration=k, num_threads=2)
                pt[m] = boosters[m].predict(SNAP.feature_matrix(test, cols, "M_full"), num_iteration=k, num_threads=2)
            for a, wgt in R.BLEND.items():
                pc[a] = (1 - wgt) * pc["full29"] + wgt * pc["full35"]
                pt[a] = (1 - wgt) * pt["full29"] + wgt * pt["full35"]
            mlist = list(pc)
            tr, mr = evaluate(test, cal_lab, pc, pt, mlist, {"seed": sname, "trees": k})
            for m in mlist:  # calibration-side ranking too
                tr.append({"seed": sname, "trees": k, "model": m, "target": "cal_rank", "cal_ROC_AUC": roc_auc_score(cal_lab, pc[m]), "cal_PR_AUC": average_precision_score(cal_lab, pc[m])})
            pre_thr += tr
            pre_met += mr
    # E06/E09 saved models on Test (0.5 + ranking)
    tdf = pd.read_csv(R.TEST_FULL35).drop(columns=R.X1)
    X = tdf.drop(columns=R.KEY + ["label"])
    X["updateType"] = X["updateType"].astype("category")
    e_rows, e_scores = [], []
    for name, (rel, _) in R.E0609.items():
        b = lgb.Booster(model_file=str(R.REPO / rel))
        p = b.predict(X[b.feature_name()])
        e_scores.append(pd.DataFrame({"model": name, "test_row": test.test_row.to_numpy(), "score": p}))
        for tset, mask in [("Test-674", test.in674.to_numpy()), ("Test-677", np.ones(len(test), bool))]:
            tf, sc = test[mask], p[mask]
            e_rows.append({"model": name, "test_set": tset, "op": "0.5", "threshold": 0.5, "ROC_AUC": roc_auc_score(tf.label, sc),
                           "PR_AUC": average_precision_score(tf.label, sc), **R.metrics(tf, sc, 0.5)})
    pd.DataFrame(train_rows).to_csv(out / "training_w1.csv", index=False, lineterminator="\n")
    pd.concat(score_rows).to_csv(out / "scores_w1.csv", index=False, lineterminator="\n")
    pd.DataFrame(thr_all).to_csv(out / "thresholds.csv", index=False, lineterminator="\n")
    pd.DataFrame(met_all).to_csv(out / "metrics.csv", index=False, lineterminator="\n")
    pd.DataFrame(pre_thr).to_csv(out / "prefix_thresholds_calrank.csv", index=False, lineterminator="\n")
    pd.DataFrame(pre_met).to_csv(out / "prefix_metrics.csv", index=False, lineterminator="\n")
    pd.DataFrame(e_rows).to_csv(out / "e06_e09_test.csv", index=False, lineterminator="\n")
    pd.concat(e_scores).to_csv(out / "e06_e09_test_scores.csv", index=False, lineterminator="\n")
    manifest = {"experiment_id": "D06-TEST-FOLLOWUP", "nature": "post-hoc development experiment on the already-evaluated D06 Test (not pre-registered)",
                "base": "d06_test_eval (d3c0c0d)", "script_sha256": sha(__file__), "run_test_eval_sha256": sha(EVAL / "run_test_eval.py"),
                "inputs": {k: {"path": str(v.relative_to(args.workspace)), "sha256": sha(v)} for k, v in paths.items()} |
                          {"stored_scores": sha(EVAL / "run/scores.csv"), "stored_splits": sha(EVAL / "run/splits.csv"), "groups": sha(args.groups)},
                "new_models": NEW, "weight": "W1 component", "prefix_trees": PREFIX, "lightgbm_params": spec["lightgbm"], "rounds": spec["rounds"],
                "packages": versions, "python": platform.python_version(), "outputs": {p.name: sha(p) for p in sorted(out.rglob("*")) if p.is_file()}}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
