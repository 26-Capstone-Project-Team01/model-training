"""PHASE 1 (no Test access): final training of M1, M2, M3, M4, M2-r, M4-r x 2 calibration seeds on D08 Train
minus the 6 clipper pairs, G2f grouping, normal-only final calibration (25% of Train normals, rng seed = cal_seed).
Thresholds at target FPR 1% / 5% are fixed here from calibration scores (PR #13 calibrate, ML) and locked by sha256.
This script takes no Test path and never reads Test data.
Usage: python -I -B final_train.py --snapshot <PR #13 executed_script_snapshot.py> --out phase1
"""
from __future__ import annotations
import argparse, hashlib, importlib.util, json, platform, sys, time
from pathlib import Path
import numpy as np, pandas as pd, lightgbm as lgb, sklearn

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import run_m1m4 as R  # noqa: E402  (main() not executed)
CFG = HERE.parent / "g2f" / "config"
MODELS = ["M1", "M2", "M3", "M4", "M2-r", "M4-r"]
WS = "obfWhitespaceRatioChangedCode"


def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def prepare(snap):
    """Development data shared by phase 1 and phase 2: Train minus 6 clipper pairs, G2f groups, P, v28, components."""
    T, F29 = R.load_inputs()
    F28 = [f for f in F29 if f != "updateInterval"]; assert len(F28) == 28
    ex = pd.read_csv(CFG / "dev_exclusion_clipper6.csv", dtype=str, keep_default_na=False)
    exk = set(map(tuple, ex[R.KEY].values)); assert len(exk) == 6
    is_ex = T[R.KEY].apply(tuple, axis=1).isin(exk); assert is_ex.sum() == 6 and (T[is_ex].label == 1).all()
    T = T[~is_ex].copy()
    cfg = json.load(open(CFG / "merge_G2f.json"))
    T["splitGroup_orig"] = T.splitGroup; T["splitGroup"] = T.splitGroup.replace(cfg["group_merge"])
    for o in cfg["row_override"]:
        if (o["package"], o["old_version"], o["new_version"]) in exk: continue
        m = (T.package == o["package"]) & (T.old_version == o["old_version"]) & (T.new_version == o["new_version"])
        assert m.sum() == 1; T.loc[m, "splitGroup"] = o["splitGroup"]
    T["v28"] = T[F28].agg("|".join, axis=1); T["P"] = T.apply(R.payload_key, axis=1); T["_v"] = T.new_version.map(R.vkey)
    X = T.copy()
    for c in F28:
        if c != "updateType": X[c] = pd.to_numeric(X[c].replace({"True": "1", "False": "0", "": np.nan}))
    cf = T[["package", "label", "splitGroup", "largestChangedJsSha1", "changedJsSetSha1", "class"]].copy()
    cf.loc[cf.label == 0, ["splitGroup", "largestChangedJsSha1", "changedJsSetSha1"]] = ""
    X["component"] = snap.components(cf)
    return X, F28, exk


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--snapshot", type=Path, required=True); ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    assert sha(a.snapshot) == R.SNAPSHOT_SHA256
    spec = importlib.util.spec_from_file_location("snap", a.snapshot); snap = importlib.util.module_from_spec(spec); spec.loader.exec_module(snap)
    out = a.out; out.mkdir(parents=True, exist_ok=False); (out / "models").mkdir()
    X, F28, exk = prepare(snap)
    X[R.KEY + ["row_id", "class", "era", "splitGroup_orig", "splitGroup", "component", "P"]].to_csv(out / "dev_rows.csv", index=False, lineterminator="\n")
    cal_rows, log, thr, cal_scores, wsb, counts = [], [], [], [], [], []
    t0 = time.time()
    for seed in R.CAL_SEEDS:
        is_cal = R.normal_only_calibration(X, seed); cal, fit = X[is_cal], X[~is_cal]
        assert (cal.label == 0).all() and not set(cal.component) & set(fit.component)
        cal_rows.append(cal[R.KEY + ["row_id", "class"]].assign(cal_seed=seed))
        m1 = fit[fit.era == "D06"]; m3, n_add = R.m3_select(fit); w4 = R.m4_weights(fit)
        n1, n2 = int(m1.label.sum()), int(fit.label.sum()); mal = fit.label == 1
        w2r = pd.Series(1.0, index=fit.index); w2r[mal] = n1 / n2
        w4r = w4.copy(); w4r[mal] = w4[mal] * n1 / w4[mal].sum()
        fn = fit[fit.label == 0][WS].dropna(); wsb.append({"cal_seed": seed, "p5": float(fn.quantile(.05)), "p95": float(fn.quantile(.95))})
        sets = {"M1": (m1, None), "M2": (fit, None), "M3": (m3, None), "M4": (fit, w4), "M2-r": (fit, w2r), "M4-r": (fit, w4r)}
        for name in MODELS:
            d, w = sets[name]
            booster = lgb.train(R.LGB_PARAMS, lgb.Dataset(snap.feature_matrix(d, F28, "M_full"), label=d.label.to_numpy(), weight=None if w is None else w.to_numpy(),
                                categorical_feature=["updateType"], feature_name=F28), num_boost_round=R.ROUNDS)
            path = out / "models" / f"{name}_seed{seed}.txt"; booster.save_model(str(path))
            s_cal = booster.predict(snap.feature_matrix(cal, F28, "M_full"), num_threads=2)
            cal_scores.append(pd.DataFrame({"cal_seed": seed, "model": name, "row_id": cal.row_id.to_numpy(), "class": cal["class"].to_numpy(), "score": s_cal}))
            row = {"cal_seed": seed, "model": name, "fit_rows": len(d), "fit_malicious": int(d.label.sum()), "fit_benign": int((d["class"] == "benign").sum()),
                   "fit_hard_benign": int((d["class"] == "hard_benign").sum()), "malicious_weight_sum": float(w[d.label == 1].sum()) if w is not None else float(d.label.sum()),
                   "normal_weight_sum": float(w[d.label == 0].sum()) if w is not None else float((d.label == 0).sum()),
                   "m3_changedJsSet_addback": n_add if name == "M3" else "", "cal_benign": int((cal["class"] == "benign").sum()), "cal_hard_benign": int((cal["class"] == "hard_benign").sum()),
                   "trees": booster.num_trees(), "model_sha256": sha(path)}
            log.append(row)
            for t in R.TARGETS:
                c = snap.calibrate(s_cal, cal.label.to_numpy(), np.zeros(len(cal), bool), "ML", t)
                thr.append({"cal_seed": seed, "model": name, "target_fpr": t, "threshold": float(c["threshold"]), "boundary": c.get("boundary"), "cal_normal": c["calibration_normal"],
                            "budget": c["budget"], "cal_fp": c["calibration_fp"], "cal_ties_at_boundary": c["ties"], "cal_achieved_fpr": c["calibration_fp"] / c["calibration_normal"],
                            "model_sha256": row["model_sha256"]})
            print(f"seed {seed} {name} fit={len(d)} mal={int(d.label.sum())} {time.time() - t0:.0f}s", flush=True)
    pd.concat(cal_rows).to_csv(out / "final_calibration_assignment.csv", index=False, lineterminator="\n")
    pd.concat(cal_scores).to_csv(out / "calibration_scores.csv", index=False, lineterminator="\n")
    pd.DataFrame(log).to_csv(out / "training_log.csv", index=False, lineterminator="\n")
    pd.DataFrame(thr).to_csv(out / "thresholds.csv", index=False, lineterminator="\n")
    pd.DataFrame(wsb).to_csv(out / "ws_bands.csv", index=False, lineterminator="\n")
    env = {"python": platform.python_version(), "lightgbm": lgb.__version__, "pandas": pd.__version__, "numpy": np.__version__, "sklearn": sklearn.__version__}
    frozen = {"phase": 1, "test_read": False, "data_commit": "2c48bd83d23ceb16ba7f6c3989d7fb623dcdd554", "inputs_sha256": {k: v[0] for k, v in R.EXPECTED.items()},
              "snapshot_sha256": R.SNAPSHOT_SHA256, "script_sha256": sha(__file__), "run_m1m4_sha256": sha(R.__file__),
              "merge_G2f_sha256": sha(CFG / "merge_G2f.json"), "dev_exclusion_sha256": sha(CFG / "dev_exclusion_clipper6.csv"), "excluded_pairs": sorted(map(list, exk)),
              "features_no_interval28": F28, "lightgbm_params": R.LGB_PARAMS, "rounds": R.ROUNDS, "cal_seeds": R.CAL_SEEDS, "calibration": "normal-only components, 25% of Train normals, rng seed = cal_seed",
              "threshold_rule": "PR #13 calibrate ML: budget=floor(n*t), threshold=nextafter(boundary,+inf), score>=threshold", "models": MODELS,
              "thresholds": pd.DataFrame(thr)[["cal_seed", "model", "target_fpr", "threshold", "model_sha256"]].to_dict("records"),
              "calibration_assignment_sha256": sha(out / "final_calibration_assignment.csv"), "environment": env}
    (out / "frozen_thresholds.json").write_text(json.dumps(frozen, indent=1) + "\n")
    (out / "frozen_thresholds.sha256").write_text(sha(out / "frozen_thresholds.json") + "  frozen_thresholds.json\n")
    print("locked", sha(out / "frozen_thresholds.json"), round(time.time() - t0, 1))


if __name__ == "__main__":
    main()
