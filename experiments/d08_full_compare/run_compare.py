"""D08 full model comparison, STAGE A (Test never read): G2f 5-fold CV + final training + threshold lock.

Data: D08 Train minus 6 clipper pairs, G2f groups, PR #13 components / greedy 5-fold, normal-only calibration
(CV: rng seed = cal_seed + fold, 25% of rest; final: rng seed = cal_seed, 25% of Train) -- identical to the G2f 60-run and final 12 models.
Feature sets (definitions and column order as in the D06 code, unchanged):
  no_interval28, full29, full35, full28_noObfNew, gs24, base7_x1, full28_x3_d, full35_x3_d (LightGBM, PR #13 params, 200 rounds)
  B3 = blend of full35 LightGBM + LR + MLP (d06_alt_models Prep/make_model, blend candidates/combine);
  C5 = route by calibration-normal rank: gs24 if (obfChangedFileCount==0 & newDependencyAdded & !installScriptAdded) else full35.
Training-data conditions: D06 (fit rows of D06 era), D08 (all fit rows); for full35 / full28_noObfNew / gs24 also M4 (payload 1/sqrt(n_P)) and
M2-r (malicious weight sum = D06-condition malicious count). C5 exists for every condition where both full35 and gs24 exist; B3 for D06 / D08.
B3 selection (protocol adaptation, calibration has no malicious under G2f): CV fold f uses the OOF PR-AUC of the other 4 folds (same seed);
final model uses the OOF PR-AUC of all 5 folds (same seed). Train labels only.
Usage: python -I -B run_compare.py --snapshot <PR13> --m1m4 <run_m1m4.py> --final-train <final_g2f/final_train.py> --alt <vendor alt_models.py>
          --features <features_x1x3d_d08.csv> --guard-g2f <g2f/run> --guard-final <final_g2f/phase1> --out <new dir>
"""
from __future__ import annotations
import argparse, hashlib, importlib.util, json, pickle, platform, sys, time
from pathlib import Path
import numpy as np, pandas as pd, lightgbm as lgb, sklearn
from sklearn.metrics import average_precision_score

X1 = ["installHookNewProgramCount", "installHookArgsChanged", "installHookRefFileChanged", "installHookNewExternalExecCount", "addedProcExecCallCount", "addedNetworkCallCount"]
X3 = ["installHookTargetCount", "installHookTargetMaxBytes", "obfHookHexIdentRatio", "obfHookHexNumberRatio", "obfHookBracketAccessRatio", "obfHookEscapeDensity",
      "obfHookShortIdentRatio", "obfHookMeanIdentLength", "obfHookWhitespaceRatio", "installHookTargetProcExecCallCount", "installHookTargetNetworkCallCount",
      "addedNetworkCallPer1kAddedTokens", "addedProcExecCallPer1kAddedTokens"]
D = ["dependencyRangeChangedCount", "dependencyChangedRatio"]
TARGETS = [0.01, 0.03, 0.05]
GRID = [round(x, 1) for x in np.arange(0, 1.01, 0.1)]


def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path); m = importlib.util.module_from_spec(spec); sys.modules[name] = m; spec.loader.exec_module(m); return m


# ---- d06_alt_models/blend.py (copied: logit, combine, candidates) and d06_gs24_followup/combine_eval.py (rank_vs, mtype rule)
def logit(p):
    p = np.clip(p, 1e-6, 1 - 1e-6); return np.log(p / (1 - p))


def combine(frame, models, weights, scale):
    if scale == "prob": return sum(w * frame[m].to_numpy() for m, w in zip(models, weights))
    z = sum(w * logit(frame[m].to_numpy()) for m, w in zip(models, weights)); return 1 / (1 + np.exp(-z))


def candidates(n):
    if n == 2: return [(round(1 - w, 1), w) for w in GRID]
    return [(a, b, round(1 - a - b, 1)) for a in GRID for b in GRID if a + b <= 1.0 + 1e-9]


def rank_vs(normals, s):
    n = np.sort(normals); lo, hi = np.searchsorted(n, s, "left"), np.searchsorted(n, s, "right"); return (lo + 0.5 * (hi - lo)) / len(n)


def mtype(frame):
    return ((frame.obfChangedFileCount.fillna(0).to_numpy() == 0) & frame.newDependencyAdded.astype(bool).to_numpy() & ~frame.installScriptAdded.astype(bool).to_numpy())


def feature_sets(F29):
    base7, obf = F29[:7], F29[7:]
    obf_new = [c for c in obf if c.endswith("New")]
    G = {"obfChange": [c for c in obf if c.endswith("Change")], "obfChangedCode": [c for c in obf if c.endswith("ChangedCode")] + ["obfChangedFileCount"], "x1Calls": X1[4:]}
    full35 = F29 + X1
    S = {"no_interval28": [f for f in F29 if f != "updateInterval"], "full29": F29, "full35": full35, "full28_noObfNew": [f for f in full35 if f not in obf_new],
         "gs24": base7 + G["obfChange"] + G["obfChangedCode"] + G["x1Calls"], "base7_x1": base7 + X1,
         "full35_x3_d": full35 + X3 + D, "full28_x3_d": [f for f in full35 if f not in obf_new] + X3 + D}
    sizes = {k: len(v) for k, v in S.items()}
    assert sizes == {"no_interval28": 28, "full29": 29, "full35": 35, "full28_noObfNew": 28, "gs24": 24, "base7_x1": 13, "full35_x3_d": 50, "full28_x3_d": 43}, sizes
    return S


CONDS = {"no_interval28": ["D06", "D08", "M4", "M2-r"], "full29": ["D06", "D08"], "full35": ["D06", "D08", "M4", "M2-r"], "full28_noObfNew": ["D06", "D08", "M4", "M2-r"],
         "gs24": ["D06", "D08", "M4", "M2-r"], "base7_x1": ["D06", "D08"], "full35_x3_d": ["D06", "D08"], "full28_x3_d": ["D06", "D08"]}
SK = {"lr": ["D06", "D08"], "mlp": ["D06", "D08"]}  # sklearn models on full35 columns (B3 parts)


def cond_data(fit, cond, R):
    mal = fit.label == 1
    if cond == "D06": return fit[fit.era == "D06"], None
    if cond == "D08": return fit, None
    n1 = int(((fit.era == "D06") & mal).sum())
    if cond == "M4": return fit, R.m4_weights(fit)
    if cond == "M2-r":
        w = pd.Series(1.0, index=fit.index); w[mal] = n1 / int(mal.sum()); return fit, w
    raise ValueError(cond)


def main():
    ap = argparse.ArgumentParser()
    for k in ["snapshot", "m1m4", "final-train", "alt", "features", "guard-g2f", "guard-final", "out"]: ap.add_argument(f"--{k}", type=Path, required=True)
    ap.add_argument("--smoke", action="store_true")
    a = ap.parse_args()
    R = load(a.m1m4, "run_m1m4"); assert sha(a.snapshot) == R.SNAPSHOT_SHA256
    snap = load(a.snapshot, "snap"); FT = load(a.final_train, "final_train"); ALT = load(a.alt, "alt_models")
    out = a.out; out.mkdir(parents=True, exist_ok=False); (out / "models").mkdir()
    X, F28, exk = FT.prepare(snap)
    X["updateInterval"] = pd.to_numeric(X.updateInterval.replace("", np.nan))
    F29 = R.load_inputs()[1]; S = feature_sets(F29)
    feat = pd.read_csv(a.features, dtype={"old_version": str, "new_version": str}, keep_default_na=True)
    feat = feat[feat.split == "train"]
    X = X.merge(feat[R.KEY + X1 + X3 + D + ["extract_status"]], on=R.KEY, how="left", validate="one_to_one")
    assert X.extract_status.notna().all() and len(X) == 5338
    # G2f folds (identical rule to g2f/run_g2f.py) + guard
    cf = X[["package", "label", "splitGroup", "largestChangedJsSha1", "changedJsSetSha1", "class"]].copy()
    cf.loc[cf.label == 0, ["splitGroup", "largestChangedJsSha1", "changedJsSetSha1"]] = ""
    X["fold"] = R.greedy_folds(X.assign(splitGroup=cf.splitGroup), snap)
    old_fa = pd.read_csv(a.guard_g2f / "fold_assignment.csv")
    assert (X.set_index("row_id").fold.loc[old_fa.row_id].to_numpy() == old_fa.fold.to_numpy()).all(), "fold guard"
    X["mtype"] = mtype(X)
    X[R.KEY + ["row_id", "class", "era", "splitGroup", "component", "fold", "P", "mtype", "extract_status"]].to_csv(out / "dev_rows.csv", index=False, lineterminator="\n")
    seeds = R.CAL_SEEDS[:1] if a.smoke else R.CAL_SEEDS; folds = [0] if a.smoke else list(range(5))
    scores, log, thr = [], [], []
    t0 = time.time()

    def fit_all(fit, cal, ev, tag, seed, f):
        """Train every (feature set, condition) + LR/MLP on fit; score cal (+ ev). Returns dict name -> (cal scores, ev scores)."""
        res = {}
        for fs, conds in CONDS.items():
            cols = S[fs]
            for cond in conds:
                d, w = cond_data(fit, cond, R)
                bst = lgb.train(R.LGB_PARAMS, lgb.Dataset(snap.feature_matrix(d, cols, "M_full"), label=d.label.to_numpy(), weight=None if w is None else w.to_numpy(),
                                categorical_feature=["updateType"], feature_name=cols), num_boost_round=R.ROUNDS)
                name = f"{fs}|{cond}"
                if tag == "final": bst.save_model(str(out / "models" / f"{fs}__{cond}__seed{seed}.txt"))
                res[name] = tuple(bst.predict(snap.feature_matrix(p, cols, "M_full"), num_threads=2) if len(p) else np.array([]) for p in (cal, ev))
                log.append({"stage": tag, "cal_seed": seed, "fold": f, "model": name, "fit_rows": len(d), "fit_malicious": int(d.label.sum()),
                            "fit_normal": int((d.label == 0).sum()), "malicious_weight_sum": float(w[d.label == 1].sum()) if w is not None else float(d.label.sum())})
        for kind, conds in SK.items():
            for cond in conds:
                d, _ = cond_data(fit, cond, R)
                xf = snap.feature_matrix(d, S["full35"], "M_full")
                model, scale = ALT.make_model(kind, seed + (f if tag == "cv" else 0), 1)
                prep = ALT.Prep(scale).fit(xf); model.fit(prep.transform(xf), d.label.to_numpy())
                name = f"full35_{kind}|{cond}"
                if tag == "final": pickle.dump((prep, model), open(out / "models" / f"full35_{kind}__{cond}__seed{seed}.pkl", "wb"))
                res[name] = tuple(model.predict_proba(prep.transform(snap.feature_matrix(p, S["full35"], "M_full")))[:, 1] if len(p) else np.array([]) for p in (cal, ev))
                log.append({"stage": tag, "cal_seed": seed, "fold": f, "model": name, "fit_rows": len(d), "fit_malicious": int(d.label.sum()), "fit_normal": int((d.label == 0).sum())})
        # C5 routing (rank vs calibration normals of this cell)
        for cond in ["D06", "D08", "M4", "M2-r"]:
            a35, ags = res[f"full35|{cond}"], res[f"gs24|{cond}"]
            out_ = []
            for part, idx in ((cal, 0), (ev, 1)):
                if not len(part): out_.append(np.array([])); continue
                r35, rgs = rank_vs(a35[0], a35[idx]), rank_vs(ags[0], ags[idx])
                out_.append(np.where(part.mtype.to_numpy(), rgs, r35))
            res[f"C5|{cond}"] = tuple(out_)
        return res

    cv_raw = {}
    for seed in seeds:
        for f in folds:
            val, rest = X[X.fold == f], X[X.fold != f]
            is_cal = R.normal_only_calibration(rest, seed + f); cal, fit = rest[is_cal], rest[~is_cal]
            res = fit_all(fit, cal, val, "cv", seed, f); cv_raw[(seed, f)] = (cal, val, res)
            print(f"cv seed {seed} fold {f} {time.time() - t0:.0f}s", flush=True)
    # B3 (nested selection on other folds' OOF PR-AUC)
    def b3_select(seed, use_folds, cond):
        rows = []
        for f in use_folds:
            cal, val, res = cv_raw[(seed, f)]
            rows.append(pd.DataFrame({"label": val.label.to_numpy(), "full35": res[f"full35|{cond}"][1], "full35_lr": res[f"full35_lr|{cond}"][1], "full35_mlp": res[f"full35_mlp|{cond}"][1]}))
        oof = pd.concat(rows)
        best = None
        for scale in ["prob", "logit"]:
            for wt in candidates(3):
                pr = average_precision_score(oof.label, combine(oof, ["full35", "full35_lr", "full35_mlp"], wt, scale))
                key = (pr, wt[0], scale == "prob")
                if best is None or key > best[0]: best = (key, scale, wt)
        return {"scale": best[1], "weights": [float(x) for x in best[2]], "oof_pr_auc": float(best[0][0])}
    b3_sel = []
    for (seed, f), (cal, val, res) in cv_raw.items():
        for cond in SK["lr"]:
            others = [g for g in folds if g != f] or [f]
            sel = b3_select(seed, others, cond); b3_sel.append({"stage": "cv", "cal_seed": seed, "fold": f, "cond": cond, **sel})
            fr = {k: pd.DataFrame({m: res[f"{m}|{cond}"][i] for m in ["full35", "full35_lr", "full35_mlp"]}) for k, i in (("cal", 0), ("val", 1))}
            res[f"B3|{cond}"] = (combine(fr["cal"], ["full35", "full35_lr", "full35_mlp"], sel["weights"], sel["scale"]), combine(fr["val"], ["full35", "full35_lr", "full35_mlp"], sel["weights"], sel["scale"]))
        for name, (sc, sv) in res.items():
            scores.append(pd.DataFrame({"stage": "calibration", "cal_seed": seed, "fold": f, "model": name, "row_id": cal.row_id.to_numpy(), "score": sc}))
            scores.append(pd.DataFrame({"stage": "validation", "cal_seed": seed, "fold": f, "model": name, "row_id": val.row_id.to_numpy(), "score": sv}))
            for t in TARGETS:
                c = snap.calibrate(sc, cal.label.to_numpy(), np.zeros(len(cal), bool), "ML", t)
                thr.append({"stage": "cv", "cal_seed": seed, "fold": f, "model": name, "target_fpr": t, "threshold": float(c["threshold"]), "cal_fp": c["calibration_fp"], "cal_normal": c["calibration_normal"]})
    # final models
    final_sel = {}
    for seed in seeds:
        is_cal = R.normal_only_calibration(X, seed); cal, fit = X[is_cal], X[~is_cal]
        cal[R.KEY + ["row_id", "class"]].assign(cal_seed=seed).to_csv(out / f"final_calibration_seed{seed}.csv", index=False, lineterminator="\n")
        res = fit_all(fit, cal, X.iloc[:0], "final", seed, -1)
        for cond in SK["lr"]:
            sel = b3_select(seed, folds, cond); b3_sel.append({"stage": "final", "cal_seed": seed, "fold": -1, "cond": cond, **sel}); final_sel[f"{seed}|{cond}"] = sel
            fr = pd.DataFrame({m: res[f"{m}|{cond}"][0] for m in ["full35", "full35_lr", "full35_mlp"]})
            res[f"B3|{cond}"] = (combine(fr, ["full35", "full35_lr", "full35_mlp"], sel["weights"], sel["scale"]), np.array([]))
        for name, (sc, _) in res.items():
            scores.append(pd.DataFrame({"stage": "final_calibration", "cal_seed": seed, "fold": -1, "model": name, "row_id": cal.row_id.to_numpy(), "score": sc}))
            for t in TARGETS:
                c = snap.calibrate(sc, cal.label.to_numpy(), np.zeros(len(cal), bool), "ML", t)
                thr.append({"stage": "final", "cal_seed": seed, "fold": -1, "model": name, "target_fpr": t, "threshold": float(c["threshold"]), "cal_fp": c["calibration_fp"], "cal_normal": c["calibration_normal"]})
        print(f"final seed {seed} {time.time() - t0:.0f}s", flush=True)
    SC = pd.concat(scores); SC.to_csv(out / "scores_dev.csv", index=False, lineterminator="\n")
    TH = pd.DataFrame(thr); TH.to_csv(out / "thresholds.csv", index=False, lineterminator="\n")
    pd.DataFrame(log).to_csv(out / "training_log.csv", index=False, lineterminator="\n"); pd.DataFrame(b3_sel).to_csv(out / "b3_selection.csv", index=False, lineterminator="\n")
    # guards: no_interval28 conditions == earlier G2f 60-run (CV) and final 12 models (bitwise scores)
    guards = {}
    SC = pd.read_csv(out / "scores_dev.csv")  # compare after the same CSV round trip as the reference files
    if not a.smoke:
        g = pd.read_csv(a.guard_g2f / "scores.csv"); mp = {"D06": "M1", "D08": "M2", "M4": "M4", "M2-r": "M2-r"}
        for cond, m in mp.items():
            new = SC[(SC.stage.isin(["calibration", "validation"])) & (SC.model == f"no_interval28|{cond}")].sort_values(["cal_seed", "fold", "stage", "row_id"])
            ref = g[g.model == m].sort_values(["cal_seed", "fold", "stage", "row_id"])
            guards[f"cv_no_interval28_{cond}=={m}"] = bool(len(new) == len(ref) and np.array_equal(new.score.to_numpy(), ref.score.to_numpy()))
            fin = pd.read_csv(a.guard_final / "calibration_scores.csv"); fin = fin[fin.model == m].sort_values(["cal_seed", "row_id"])
            nf = SC[(SC.stage == "final_calibration") & (SC.model == f"no_interval28|{cond}")].sort_values(["cal_seed", "row_id"])
            guards[f"final_no_interval28_{cond}=={m}"] = bool(np.array_equal(nf.score.to_numpy(), fin.score.to_numpy()))
        assert all(guards.values()), guards
    lock = {"stage": "A", "test_read": False, "feature_sets": S, "conditions": CONDS, "sklearn_models": SK, "b3_final_selection": final_sel, "guards": guards,
            "thresholds_final": TH[TH.stage == "final"].to_dict("records"), "model_sha256": {p.name: sha(p) for p in sorted((out / "models").iterdir())},
            "inputs_sha256": {"features": sha(a.features), "run_m1m4": sha(a.m1m4), "final_train": sha(a.final_train), "alt_models": sha(a.alt), "snapshot": sha(a.snapshot), "script": sha(__file__)},
            "lightgbm_params": R.LGB_PARAMS, "rounds": R.ROUNDS, "cal_seeds": seeds, "targets": TARGETS,
            "environment": {"python": platform.python_version(), "lightgbm": lgb.__version__, "sklearn": sklearn.__version__, "pandas": pd.__version__, "numpy": np.__version__}}
    (out / "lock.json").write_text(json.dumps(lock, indent=1, default=str) + "\n"); (out / "lock.sha256").write_text(sha(out / "lock.json") + "  lock.json\n")
    print("locked", sha(out / "lock.json"), guards, round(time.time() - t0, 1))


if __name__ == "__main__":
    main()
