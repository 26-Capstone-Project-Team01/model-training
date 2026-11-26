"""D08 full model comparison, STAGE B: Validation (G2f CV OOF) metrics and one-shot D08 Test evaluation with the stage-A lock.
D08 Test was already evaluated for M1-M4-r, so every Test number here is a DEVELOPMENT evaluation (not an independent estimate).
Thresholds come only from stage A (calibration); nothing is re-estimated on Test labels.
Usage: python -I -B eval_compare.py --snapshot <PR13> --m1m4 <run_m1m4.py> --final-train <final_train.py> --run <stage A dir>
          --features <features_x1x3d_d08.csv> --test <D08 test.csv> --out <new dir>
"""
from __future__ import annotations
import argparse, hashlib, importlib.util, json, pickle, sys, time
from pathlib import Path
import numpy as np, pandas as pd, lightgbm as lgb
from sklearn.metrics import average_precision_score, roc_auc_score

TEST_SHA256 = "21a7c19ea5b5128f69ee4d253db138726bac3c74eeb92d52f87dde94219e45ea"
GENERIC = "individuals_case"


def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path); m = importlib.util.module_from_spec(spec); sys.modules[name] = m; spec.loader.exec_module(m); return m


def wilson(k, n, z=1.96):
    if n == 0: return (np.nan, np.nan)
    p = k / n; d = 1 + z * z / n; c = (p + z * z / (2 * n)) / d; h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0, c - h), min(1, c + h)


def metrics(frame, score, thr):
    """frame: class, splitGroup, P; returns dict + campaign rows."""
    sel = score >= thr; y = (frame["class"] == "malicious").to_numpy(); ben = (frame["class"] == "benign").to_numpy(); hb = (frame["class"] == "hard_benign").to_numpy()
    tp, fp, fn, tn = int((sel & y).sum()), int((sel & ~y).sum()), int((~sel & y).sum()), int((~sel & ~y).sum())
    rec = tp / y.sum() if y.sum() else np.nan; prec = tp / sel.sum() if sel.sum() else np.nan
    mal = frame[y].assign(sel=sel[y])
    per = mal.groupby("splitGroup").sel.agg(["sum", "size"]); per["recall"] = per["sum"] / per["size"]
    real = per.drop(index=GENERIC, errors="ignore")
    payc = mal[mal.splitGroup != GENERIC].groupby(["splitGroup", "P"]).sel.mean().groupby("splitGroup").mean()
    two = y.sum() > 0 and (~y).sum() > 0
    m = {"TP": tp, "FP": fp, "FN": fn, "TN": tn, "recall": rec, "precision": prec, "f1": 2 * rec * prec / (rec + prec) if (tp and rec + prec) else 0.0,
         "fpr_all_normal": fp / (~y).sum() if (~y).sum() else np.nan, "fpr_benign": (sel & ben).sum() / ben.sum() if ben.sum() else np.nan,
         "fpr_hard_benign": (sel & hb).sum() / hb.sum() if hb.sum() else np.nan, "hard_FP": int((sel & hb).sum()),
         "macro_campaign_recall": real.recall.mean() if len(real) else np.nan, "K": len(real), "macro_payload_within_campaign": payc.mean() if len(payc) else np.nan,
         "macro_payload_all": mal.groupby("P").sel.mean().mean() if len(mal) else np.nan,
         "PR_AUC": average_precision_score(y, score) if two else np.nan, "ROC_AUC": roc_auc_score(y, score) if two else np.nan}
    camp = [{"splitGroup": g, "n": int(r["size"]), "detected": int(r["sum"]), "recall": r.recall, "wilson_lo": wilson(int(r["sum"]), int(r["size"]))[0],
             "wilson_hi": wilson(int(r["sum"]), int(r["size"]))[1]} for g, r in per.iterrows()]
    return m, camp


def mtype(frame):
    return ((frame.obfChangedFileCount.fillna(0).to_numpy() == 0) & frame.newDependencyAdded.astype(bool).to_numpy() & ~frame.installScriptAdded.astype(bool).to_numpy())


def rank_vs(normals, s):
    n = np.sort(normals); lo, hi = np.searchsorted(n, s, "left"), np.searchsorted(n, s, "right"); return (lo + 0.5 * (hi - lo)) / len(n)


def combine(frame, models, weights, scale):
    if scale == "prob": return sum(w * frame[m].to_numpy() for m, w in zip(models, weights))
    z = sum(w * np.log(np.clip(frame[m].to_numpy(), 1e-6, 1 - 1e-6) / (1 - np.clip(frame[m].to_numpy(), 1e-6, 1 - 1e-6))) for m, w in zip(models, weights))
    return 1 / (1 + np.exp(-z))


def main():
    ap = argparse.ArgumentParser()
    for k in ["snapshot", "m1m4", "final-train", "run", "features", "test", "out"]: ap.add_argument(f"--{k}", type=Path, required=True)
    a = ap.parse_args()
    R = load(a.m1m4, "run_m1m4"); assert sha(a.snapshot) == R.SNAPSHOT_SHA256
    snap = load(a.snapshot, "snap"); FT = load(a.final_train, "final_train")
    lock_sha = (a.run / "lock.sha256").read_text().split()[0]; assert sha(a.run / "lock.json") == lock_sha, "stage A lock mismatch"
    lock = json.loads((a.run / "lock.json").read_text()); assert lock["test_read"] is False
    for n, h in lock["model_sha256"].items(): assert sha(a.run / "models" / n) == h, n
    assert lock["inputs_sha256"]["features"] == sha(a.features)
    out = a.out; out.mkdir(parents=True, exist_ok=False); t0 = time.time()
    S = lock["feature_sets"]; TH = pd.read_csv(a.run / "thresholds.csv")
    dev = pd.read_csv(a.run / "dev_rows.csv", keep_default_na=False)
    # ---------------- Validation (G2f CV OOF, CV thresholds)
    SC = pd.read_csv(a.run / "scores_dev.csv")
    V = SC[SC.stage == "validation"].merge(dev[["row_id", "class", "splitGroup", "P"]], on="row_id")
    vrows, vcamp = [], []
    for (m, sd), g in V.groupby(["model", "cal_seed"]):
        for t in lock["targets"]:
            th = TH[(TH.stage == "cv") & (TH.model == m) & (TH.cal_seed == sd) & (TH.target_fpr == t)].set_index("fold").threshold
            sel_thr = g.fold.map(th).to_numpy()
            # pooled OOF with per-fold thresholds: metrics() needs one threshold -> pass score - thr against 0
            mm, cc = metrics(g, g.score.to_numpy() - sel_thr, 0.0)
            mm["PR_AUC"] = average_precision_score(g["class"] == "malicious", g.score); mm["ROC_AUC"] = roc_auc_score(g["class"] == "malicious", g.score)
            vrows.append({"set": "validation_G2f_CV", "model": m, "cal_seed": sd, "target_fpr": t, **mm})
            vcamp += [{"set": "validation_G2f_CV", "model": m, "cal_seed": sd, "target_fpr": t, **c} for c in cc]
    # ---------------- Test (one shot)
    assert sha(a.test) == TEST_SHA256
    te = pd.read_csv(a.test, dtype=str, keep_default_na=False); assert len(te) == 684
    sa = pd.read_csv(R.INP / "split_assignment.csv", dtype=str, keep_default_na=False); gr = pd.read_csv(R.INP / "malicious_pair_groups.csv", dtype=str, keep_default_na=False)
    te = te.merge(sa[R.KEY + ["class", "splitGroup", "split"]], on=R.KEY, how="left", validate="one_to_one"); assert (te.split == "test").all()
    te = te.merge(gr[R.KEY + ["largestChangedJsSha1", "changedJsSetSha1", "addedDependencies", "addedInstallHooks"]], on=R.KEY, how="left").fillna("")
    te["label"] = te.label.astype(int); te["P"] = te.apply(R.payload_key, axis=1)
    feat = pd.read_csv(a.features, dtype={"old_version": str, "new_version": str}); feat = feat[feat.split == "test"].drop(columns="split")
    allcols = sorted({c for v in S.values() for c in v})
    Xt = te.copy()
    for c in allcols:
        if c in Xt.columns and c != "updateType": Xt[c] = pd.to_numeric(Xt[c].replace({"True": "1", "False": "0", "": np.nan}))
    xcols = [c for c in feat.columns if c not in R.KEY + ["source", "extract_status", "error_stage"]]
    Xt = Xt.merge(feat[R.KEY + xcols + ["source", "extract_status"]], on=R.KEY, how="left", validate="one_to_one")
    Xt["subset"] = np.where(Xt.source == "d06_saved", "test674", "new10")
    assert (Xt.subset == "test674").sum() == 674 and (Xt.subset == "new10").sum() == 10
    Xt["mtype"] = mtype(Xt)
    # disjointness (PR #13 check on jointly computed components)
    Xd, _, exk = FT.prepare(snap)
    both = pd.concat([Xd.assign(_side="dev"), Xt.assign(_side="test")], ignore_index=True)
    cf = both[["package", "label", "splitGroup", "largestChangedJsSha1", "changedJsSetSha1", "class"]].copy(); cf.loc[cf.label == 0, ["splitGroup", "largestChangedJsSha1", "changedJsSetSha1"]] = ""
    both["component"] = snap.components(cf)
    chk = lambda d: d.assign(splitGroup=d.splitGroup.where(d.label == 1, ""), largestChangedJsSha1=d.largestChangedJsSha1.where(d.label == 1, ""), changedJsSetSha1=d.changedJsSetSha1.where(d.label == 1, ""))
    snap.check_disjoint(chk(both[both._side == "dev"]), chk(both[both._side == "test"]))
    FS = SC[SC.stage == "final_calibration"]
    test_scores, trows, tcamp = [], [], []
    for sd in lock["cal_seeds"]:
        sc = {}
        for fs, conds in lock["conditions"].items():
            for cond in conds:
                b = lgb.Booster(model_file=str(a.run / "models" / f"{fs}__{cond}__seed{sd}.txt"))
                sc[f"{fs}|{cond}"] = b.predict(snap.feature_matrix(Xt, S[fs], "M_full"), num_threads=2)
        for kind, conds in lock["sklearn_models"].items():
            for cond in conds:
                prep, model = pickle.load(open(a.run / "models" / f"full35_{kind}__{cond}__seed{sd}.pkl", "rb"))
                sc[f"full35_{kind}|{cond}"] = model.predict_proba(prep.transform(snap.feature_matrix(Xt, S["full35"], "M_full")))[:, 1]
        for cond in ["D06", "D08", "M4", "M2-r"]:
            cal35 = FS[(FS.cal_seed == sd) & (FS.model == f"full35|{cond}")].score.to_numpy(); calgs = FS[(FS.cal_seed == sd) & (FS.model == f"gs24|{cond}")].score.to_numpy()
            sc[f"C5|{cond}"] = np.where(Xt.mtype.to_numpy(), rank_vs(calgs, sc[f"gs24|{cond}"]), rank_vs(cal35, sc[f"full35|{cond}"]))
        for cond in lock["sklearn_models"]["lr"]:
            sel = lock["b3_final_selection"][f"{sd}|{cond}"]
            fr = pd.DataFrame({m: sc[f"{m}|{cond}"] for m in ["full35", "full35_lr", "full35_mlp"]})
            sc[f"B3|{cond}"] = combine(fr, ["full35", "full35_lr", "full35_mlp"], sel["weights"], sel["scale"])
        for m, s in sc.items():
            test_scores.append(pd.DataFrame({"cal_seed": sd, "model": m, **{k: Xt[k] for k in R.KEY}, "class": Xt["class"], "splitGroup": Xt.splitGroup, "subset": Xt.subset, "P": Xt.P, "score": s}))
            for t in lock["targets"]:
                thr = TH[(TH.stage == "final") & (TH.model == m) & (TH.cal_seed == sd) & (TH.target_fpr == t)].threshold.iloc[0]
                for subset, mask in (("test684", np.ones(len(Xt), bool)), ("test674", (Xt.subset == "test674").to_numpy()), ("new10", (Xt.subset == "new10").to_numpy())):
                    mm, cc = metrics(Xt[mask], s[mask], thr)
                    trows.append({"set": subset, "model": m, "cal_seed": sd, "target_fpr": t, "threshold": thr, **mm, "exceeds_target": bool(mm["fpr_all_normal"] > t + 1e-12) if subset != "new10" else None})
                    tcamp += [{"set": subset, "model": m, "cal_seed": sd, "target_fpr": t, **c} for c in cc]
    ALL = pd.concat([pd.DataFrame(vrows), pd.DataFrame(trows)], ignore_index=True)
    ALL[["feature_set", "condition"]] = ALL.model.str.split("|", expand=True)
    ALL.to_csv(out / "metrics_by_seed.csv", index=False, lineterminator="\n")
    num = [c for c in ALL.columns if c not in ("set", "model", "feature_set", "condition", "cal_seed", "target_fpr", "exceeds_target", "threshold")]
    agg = ALL.groupby(["set", "feature_set", "condition", "target_fpr"])[num].agg(["mean", "std"]); agg.columns = [f"{x}_{y}" for x, y in agg.columns]
    agg.reset_index().to_csv(out / "metrics_mean_std.csv", index=False, lineterminator="\n")
    pd.concat([pd.DataFrame(vcamp), pd.DataFrame(tcamp)]).to_csv(out / "campaign_recall.csv", index=False, lineterminator="\n")
    pd.concat(test_scores).to_csv(out / "test_scores.csv", index=False, lineterminator="\n")
    (out / "eval_log.json").write_text(json.dumps({"stage_A_lock_sha256": lock_sha, "test_sha256": TEST_SHA256, "test_is_development_evaluation": True,
        "thresholds_reestimated": False, "disjoint_check": "PR #13 check_disjoint passed", "script_sha256": sha(__file__), "elapsed_s": round(time.time() - t0, 1)}, indent=1) + "\n")
    print("done", round(time.time() - t0, 1))


if __name__ == "__main__":
    main()
