"""D08 G2f 60-run (Train-internal, no Test). M1, M2, M3, M4, M2-r, M4-r x 5 folds x 2 calibration seeds.

Reuses ../run_m1m4.py (imported, unchanged) and the sha-checked PR #13 snapshot.
Differences from the 40-run:
  * experiment-level group remap (config/merge_G2f.json) before PR #13 components() + greedy 5-fold;
  * 6 clipper pairs (config/dev_exclusion_clipper6.csv) removed from the development data (Train/Test files untouched);
  * M2-r / M4-r: malicious weight sum rescaled to the fold's M1 fit malicious count (normal weight 1);
  * whitespace bands (fit-normal p5/p95 of obfWhitespaceRatioChangedCode per seed x fold) saved for evaluation.
Usage: python -I -B run_g2f.py --snapshot <PR #13 executed_script_snapshot.py> --out <new dir> [--plan-only] [--smoke]
"""
from __future__ import annotations
import argparse, hashlib, importlib.util, json, platform, sys, time
from pathlib import Path
import numpy as np, pandas as pd, lightgbm as lgb, sklearn
from sklearn.metrics import average_precision_score

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import run_m1m4 as R  # noqa: E402  (main() not executed)

CFG = HERE / "config"
MODELS = ["M1", "M2", "M3", "M4", "M2-r", "M4-r"]
WS = "obfWhitespaceRatioChangedCode"


def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--snapshot", type=Path, required=True); ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--plan-only", action="store_true"); ap.add_argument("--smoke", action="store_true")
    a = ap.parse_args()
    assert sha(a.snapshot) == R.SNAPSHOT_SHA256
    spec = importlib.util.spec_from_file_location("snap", a.snapshot); snap = importlib.util.module_from_spec(spec); spec.loader.exec_module(snap)
    out = a.out; out.mkdir(parents=True, exist_ok=False)
    if not a.plan_only: (out / "models").mkdir()
    T, F29 = R.load_inputs()
    F28 = [f for f in F29 if f != "updateInterval"]; assert len(F28) == 28
    # --- development-data exclusion (6 clipper pairs) ---
    ex = pd.read_csv(CFG / "dev_exclusion_clipper6.csv", dtype=str, keep_default_na=False)
    exk = set(map(tuple, ex[R.KEY].values)); assert len(exk) == 6
    is_ex = T[R.KEY].apply(tuple, axis=1).isin(exk); assert is_ex.sum() == 6 and (T[is_ex].label == 1).all()
    T = T[~is_ex].copy()
    # --- G2f remap ---
    cfg = json.load(open(CFG / "merge_G2f.json"))
    T["splitGroup_orig"] = T.splitGroup; T["splitGroup"] = T.splitGroup.replace(cfg["group_merge"])
    for o in cfg["row_override"]:
        if (o["package"], o["old_version"], o["new_version"]) in exk: continue
        m = (T.package == o["package"]) & (T.old_version == o["old_version"]) & (T.new_version == o["new_version"])
        assert m.sum() == 1 and (T[m].label == 1).all(), o; T.loc[m, "splitGroup"] = o["splitGroup"]
    T["v28"] = T[F28].agg("|".join, axis=1); T["P"] = T.apply(R.payload_key, axis=1); T["_v"] = T.new_version.map(R.vkey)
    X = T.copy()
    for c in F28:
        if c != "updateType": X[c] = pd.to_numeric(X[c].replace({"True": "1", "False": "0", "": np.nan}))
    cf = T[["package", "label", "splitGroup", "largestChangedJsSha1", "changedJsSetSha1", "class"]].copy()
    cf.loc[cf.label == 0, ["splitGroup", "largestChangedJsSha1", "changedJsSetSha1"]] = ""
    T["component"] = snap.components(cf); X["component"] = T.component
    T["fold"] = R.greedy_folds(T.assign(splitGroup=cf.splitGroup), snap); X["fold"] = T.fold
    T[R.KEY + ["row_id", "class", "era", "splitGroup_orig", "splitGroup", "component", "fold", "P"]].to_csv(out / "fold_assignment.csv", index=False, lineterminator="\n")
    folds = [0] if a.smoke else range(5); seeds = R.CAL_SEEDS[:1] if a.smoke else R.CAL_SEEDS
    counts, cal_rows, m3_rows, wt_rows, train_log, thr_rows, met_rows, score_rows, imp_rows, ws_rows = [], [], [], [], [], [], [], [], [], []
    t0 = time.time()
    for seed in seeds:
        for f in folds:
            val, rest = X[X.fold == f], X[X.fold != f]
            chk = lambda d: d.assign(splitGroup=d.splitGroup.where(d.label == 1, ""), largestChangedJsSha1=d.largestChangedJsSha1.where(d.label == 1, ""), changedJsSetSha1=d.changedJsSetSha1.where(d.label == 1, ""))
            snap.check_disjoint(chk(val), chk(rest))
            is_cal = R.normal_only_calibration(rest, seed + f); cal, fit = rest[is_cal], rest[~is_cal]
            assert (cal.label == 0).all() and not set(cal.component) & set(fit.component)
            m1 = fit[fit.era == "D06"]; m3, n_add = R.m3_select(fit); w4 = R.m4_weights(fit)
            n1, n2 = int(m1.label.sum()), int(fit.label.sum()); mal = fit.label == 1
            w2r = pd.Series(1.0, index=fit.index); w2r[mal] = n1 / n2
            w4r = w4.copy(); w4r[mal] = w4[mal] * n1 / w4[mal].sum()
            fn = fit[fit.label == 0][WS].dropna()
            ws_rows.append({"cal_seed": seed, "fold": f, "p5": float(fn.quantile(.05)), "p95": float(fn.quantile(.95)), "n_fit_normal_nonmissing": len(fn)})
            cnt = {"cal_seed": seed, "fold": f}
            for nm, d in [("val", val), ("cal", cal), ("fit", fit)]:
                for c in ["malicious", "benign", "hard_benign"]: cnt[f"{nm}_{c}"] = int((d["class"] == c).sum())
            cnt |= {"M1_fit_mal": n1, "M1_fit_normal": int((m1.label == 0).sum()), "M2_fit_mal": n2, "M3_fit_mal": int(m3.label.sum()),
                    "M4_mal_w": round(float(w4[mal].sum()), 3), "M2r_mal_w": round(float(w2r[mal].sum()), 3), "M4r_mal_w": round(float(w4r[mal].sum()), 3),
                    "M2r_mal_row_weight": round(n1 / n2, 5), "val_campaigns": ";".join(f"{k}:{v}" for k, v in val[val.label == 1].splitGroup.value_counts().items())}
            counts.append(cnt)
            if a.plan_only: continue
            cal_rows.append(cal[R.KEY + ["row_id", "class"]].assign(cal_seed=seed, fold=f))
            m3_rows.append(m3[m3.era == "new"][R.KEY + ["row_id", "P", "changedJsSetSha1"]].assign(cal_seed=seed, fold=f))
            wt_rows.append(fit[R.KEY + ["row_id", "P", "label"]].assign(w_M4=w4.to_numpy(), w_M2r=w2r.to_numpy(), w_M4r=w4r.to_numpy(), cal_seed=seed, fold=f))
            sets = {"M1": (m1, None), "M2": (fit, None), "M3": (m3, None), "M4": (fit, w4), "M2-r": (fit, w2r), "M4-r": (fit, w4r)}
            for name in MODELS:
                d, w = sets[name]
                xm = snap.feature_matrix(d, F28, "M_full")
                booster = lgb.train(R.LGB_PARAMS, lgb.Dataset(xm, label=d.label.to_numpy(), weight=None if w is None else w.to_numpy(), categorical_feature=["updateType"], feature_name=F28), num_boost_round=R.ROUNDS)
                path = out / "models" / f"{name}_seed{seed}_fold{f}.txt"; booster.save_model(str(path))
                s_cal = booster.predict(snap.feature_matrix(cal, F28, "M_full"), num_threads=2)
                s_val = booster.predict(snap.feature_matrix(val, F28, "M_full"), num_threads=2)
                train_log.append({"cal_seed": seed, "fold": f, "model": name, "fit_rows": len(d), "fit_malicious": int(d.label.sum()), "fit_normal": int((d.label == 0).sum()),
                                  "malicious_weight_sum": float(w[d.label == 1].sum()) if w is not None else float(d.label.sum()),
                                  "normal_weight_sum": float(w[d.label == 0].sum()) if w is not None else float((d.label == 0).sum()),
                                  "m3_changedJsSet_addback": n_add if name == "M3" else "", "trees": booster.num_trees(), "model_sha256": sha(path), "elapsed_s": round(time.time() - t0, 1)})
                for fe, g, sc in zip(F28, booster.feature_importance("gain"), booster.feature_importance("split")):
                    imp_rows.append({"cal_seed": seed, "fold": f, "model": name, "feature": fe, "gain": float(g), "split": int(sc)})
                score_rows.append(pd.DataFrame({"cal_seed": seed, "fold": f, "model": name, "stage": "calibration", "row_id": cal.row_id.to_numpy(), "score": s_cal}))
                score_rows.append(pd.DataFrame({"cal_seed": seed, "fold": f, "model": name, "stage": "validation", "row_id": val.row_id.to_numpy(), "score": s_val}))
                pr = average_precision_score(val.label, s_val)
                for t in R.TARGETS:
                    c = snap.calibrate(s_cal, cal.label.to_numpy(), np.zeros(len(cal), bool), "ML", t)
                    thr_rows.append({"cal_seed": seed, "fold": f, "model": name, "target_fpr": t, "threshold": c["threshold"], "boundary": c.get("boundary"), "cal_normal": c["calibration_normal"],
                                     "budget": c["budget"], "cal_fp": c["calibration_fp"], "cal_ties_at_boundary": c["ties"], "cal_achieved_fpr": c["calibration_fp"] / c["calibration_normal"]})
                    met_rows.append({"cal_seed": seed, "fold": f, "model": name, "target_fpr": t, "threshold": c["threshold"], "PR_AUC_fold": pr, **R.metrics(val, s_val, c["threshold"], set())})
                print(f"seed {seed} fold {f} {name} trees={booster.num_trees()} {time.time() - t0:.0f}s", flush=True)
    pd.DataFrame(counts).to_csv(out / "fold_counts.csv", index=False, lineterminator="\n")
    pd.DataFrame(ws_rows).to_csv(out / "ws_bands.csv", index=False, lineterminator="\n")
    if not a.plan_only:
        for nm, rows in [("calibration_assignment", cal_rows), ("m3_selected_new_pairs", m3_rows), ("pair_weights", wt_rows), ("scores", score_rows)]:
            pd.concat(rows).to_csv(out / f"{nm}.csv", index=False, lineterminator="\n")
        for nm, rows in [("training_log", train_log), ("thresholds", thr_rows), ("metrics_fold", met_rows), ("feature_importance", imp_rows)]:
            pd.DataFrame(rows).to_csv(out / f"{nm}.csv", index=False, lineterminator="\n")
    env = {"python": platform.python_version(), "lightgbm": lgb.__version__, "pandas": pd.__version__, "numpy": np.__version__, "sklearn": sklearn.__version__}
    (out / "config.json").write_text(json.dumps({"data_commit": "2c48bd83d23ceb16ba7f6c3989d7fb623dcdd554", "inputs_sha256": {k: v[0] for k, v in R.EXPECTED.items()},
        "snapshot_sha256": R.SNAPSHOT_SHA256, "script_sha256": sha(__file__), "run_m1m4_sha256": sha(R.__file__),
        "merge_G2f_sha256": sha(CFG / "merge_G2f.json"), "dev_exclusion_sha256": sha(CFG / "dev_exclusion_clipper6.csv"), "excluded_pairs": sorted(map(list, exk)),
        "features_no_interval28": F28, "lightgbm_params": R.LGB_PARAMS, "rounds": R.ROUNDS, "cal_seeds": list(seeds), "folds": list(folds), "targets": R.TARGETS, "models": MODELS,
        "m2r": "M2 rows; malicious weight = M1_fit_malicious / M2_fit_malicious (uniform); normal 1", "m4r": "M4 weights x (M1_fit_malicious / sum M4 malicious weights); normal 1",
        "ws_bands": "per seed x fold: fit-normal p5/p95 of obfWhitespaceRatioChangedCode; missing = own band",
        "plan_only": a.plan_only, "smoke": a.smoke, "test_used": False, "environment": env}, indent=1) + "\n")
    print("done", round(time.time() - t0, 1))


if __name__ == "__main__":
    main()
