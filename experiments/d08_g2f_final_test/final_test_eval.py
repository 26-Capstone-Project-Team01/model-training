"""PHASE 2: one-shot D08 Test evaluation with thresholds frozen in phase 1 (no threshold re-estimation, no Test-label tuning).
Verifies the phase-1 lock (frozen_thresholds.json sha256) and every model sha256 before reading Test.
Usage: python -I -B final_test_eval.py --snapshot <PR #13 snapshot> --phase1 phase1 --test inputs_test/test.csv --out phase2
"""
from __future__ import annotations
import argparse, hashlib, importlib.util, json, sys, time
from pathlib import Path
import numpy as np, pandas as pd, lightgbm as lgb
from sklearn.metrics import average_precision_score, roc_auc_score

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent)); sys.path.insert(0, str(HERE))
import run_m1m4 as R  # noqa: E402
import final_train as FT  # noqa: E402
TEST_SHA256 = "21a7c19ea5b5128f69ee4d253db138726bac3c74eeb92d52f87dde94219e45ea"; TEST_ROWS = 684
GENERIC = "individuals_case"; WS = "obfWhitespaceRatioChangedCode"


def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def wilson(k, n, z=1.96):
    if n == 0: return (np.nan, np.nan)
    p = k / n; d = 1 + z * z / n; c = (p + z * z / (2 * n)) / d; h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0, c - h), min(1, c + h)


def main():
    ap = argparse.ArgumentParser()
    for k in ["snapshot", "phase1", "test", "out"]: ap.add_argument(f"--{k}", type=Path, required=True)
    a = ap.parse_args()
    assert sha(a.snapshot) == R.SNAPSHOT_SHA256
    lock = (a.phase1 / "frozen_thresholds.sha256").read_text().split()[0]
    assert sha(a.phase1 / "frozen_thresholds.json") == lock, "phase-1 lock mismatch"
    frozen = json.loads((a.phase1 / "frozen_thresholds.json").read_text())
    assert frozen["test_read"] is False
    TH = pd.DataFrame(frozen["thresholds"])
    for r in TH.drop_duplicates(["cal_seed", "model"]).itertuples():
        assert sha(a.phase1 / "models" / f"{r.model}_seed{r.cal_seed}.txt") == r.model_sha256, f"model hash mismatch {r.model} {r.cal_seed}"
    spec = importlib.util.spec_from_file_location("snap", a.snapshot); snap = importlib.util.module_from_spec(spec); spec.loader.exec_module(snap)
    out = a.out; out.mkdir(parents=True, exist_ok=False)
    t0 = time.time()
    # ---- Test frame ----
    assert sha(a.test) == TEST_SHA256
    te = pd.read_csv(a.test, dtype=str, keep_default_na=False); assert len(te) == TEST_ROWS
    sa = pd.read_csv(R.INP / "split_assignment.csv", dtype=str, keep_default_na=False)
    gr = pd.read_csv(R.INP / "malicious_pair_groups.csv", dtype=str, keep_default_na=False)
    te = te.merge(sa[R.KEY + ["class", "splitGroup", "split"]], on=R.KEY, how="left", validate="one_to_one")
    assert (te.split == "test").all()
    te = te.merge(gr[R.KEY + ["largestChangedJsSha1", "changedJsSetSha1", "addedDependencies", "addedInstallHooks"]], on=R.KEY, how="left").fillna("")
    te["label"] = te.label.astype(int); assert ((te.label == 1) == (te["class"] == "malicious")).all()
    te["P"] = te.apply(R.payload_key, axis=1)
    F28 = frozen["features_no_interval28"]
    Xt = te.copy()
    for c in F28:
        if c != "updateType": Xt[c] = pd.to_numeric(Xt[c].replace({"True": "1", "False": "0", "": np.nan}))
    # ---- Train(dev) <-> Test disjointness (PR #13 check on jointly computed components) ----
    Xd, _, exk = FT.prepare(snap)
    assert not set(map(tuple, te[R.KEY].values)) & exk
    both = pd.concat([Xd.assign(_side="dev"), Xt.assign(_side="test")], ignore_index=True)
    cf = both[["package", "label", "splitGroup", "largestChangedJsSha1", "changedJsSetSha1", "class"]].copy()
    cf.loc[cf.label == 0, ["splitGroup", "largestChangedJsSha1", "changedJsSetSha1"]] = ""
    both["component"] = snap.components(cf)
    chk = lambda d: d.assign(splitGroup=d.splitGroup.where(d.label == 1, ""), largestChangedJsSha1=d.largestChangedJsSha1.where(d.label == 1, ""), changedJsSetSha1=d.changedJsSetSha1.where(d.label == 1, ""))
    snap.check_disjoint(chk(both[both._side == "dev"]), chk(both[both._side == "test"]))
    # ---- score ----
    xm = snap.feature_matrix(Xt, F28, "M_full")
    rows, camp, scores = [], [], []
    for (seed, model), g in TH.groupby(["cal_seed", "model"]):
        booster = lgb.Booster(model_file=str(a.phase1 / "models" / f"{model}_seed{seed}.txt"))
        s = booster.predict(xm, num_threads=2)
        scores.append(pd.DataFrame({"cal_seed": seed, "model": model, **{k: te[k] for k in R.KEY}, "class": te["class"], "splitGroup": te.splitGroup, "P": te.P, "score": s}))
        y = te.label.to_numpy() == 1; ben = (te["class"] == "benign").to_numpy(); hb = (te["class"] == "hard_benign").to_numpy()
        prauc, rocauc = average_precision_score(y, s), roc_auc_score(y, s)
        for r in g.itertuples():
            sel = s >= r.threshold
            tp, fp, fn, tn = int((sel & y).sum()), int((sel & ~y).sum()), int((~sel & y).sum()), int((~sel & ~y).sum())
            rec = tp / y.sum(); prec = tp / sel.sum() if sel.sum() else np.nan
            mal = te[y].assign(sel=sel[y])
            per = mal.groupby("splitGroup").sel.agg(["sum", "size"]); per["recall"] = per["sum"] / per["size"]
            real = per.drop(index=GENERIC, errors="ignore")
            pay = mal.groupby("P").sel.mean(); payc = mal[mal.splitGroup != GENERIC].groupby(["splitGroup", "P"]).sel.mean().groupby("splitGroup").mean()
            fpr = fp / (~y).sum()
            rows.append({"cal_seed": seed, "model": model, "target_fpr": r.target_fpr, "threshold": r.threshold, "TP": tp, "FP": fp, "FN": fn, "TN": tn,
                         "recall": rec, "precision": prec, "f1": 2 * rec * prec / (rec + prec) if sel.sum() and rec + prec else 0.0,
                         "fpr_all_normal": fpr, "fpr_minus_target": fpr - r.target_fpr, "exceeds_target": bool(fpr > r.target_fpr + 1e-12),
                         "fpr_benign": (sel & ben).sum() / ben.sum(), "fpr_hard_benign": (sel & hb).sum() / hb.sum(), "benign_FP": int((sel & ben).sum()), "hard_FP": int((sel & hb).sum()),
                         "macro_campaign_recall": real.recall.mean(), "K": len(real), "macro_payload_all": pay.mean(), "n_payloads": len(pay), "macro_payload_within_campaign": payc.mean(),
                         "individuals_recall": per.recall.get(GENERIC, np.nan), "PR_AUC": prauc, "ROC_AUC": rocauc})
            for grp, p in per.iterrows():
                lo, hi = wilson(int(p["sum"]), int(p["size"]))
                camp.append({"cal_seed": seed, "model": model, "target_fpr": r.target_fpr, "splitGroup": grp, "n": int(p["size"]), "detected": int(p["sum"]), "recall": p.recall, "wilson_lo": lo, "wilson_hi": hi})
    Rr = pd.DataFrame(rows); Rr.to_csv(out / "test_metrics_by_seed.csv", index=False, lineterminator="\n")
    num = [c for c in Rr.columns if c not in ("cal_seed", "model", "target_fpr", "exceeds_target")]
    agg = Rr.groupby(["model", "target_fpr"])[num].agg(["mean", "std"]); agg.columns = [f"{a}_{b}" for a, b in agg.columns]
    agg["exceeds_target_any_seed"] = Rr.groupby(["model", "target_fpr"]).exceeds_target.any(); agg.reset_index().to_csv(out / "test_metrics_mean_std.csv", index=False, lineterminator="\n")
    pd.DataFrame(camp).to_csv(out / "test_campaign_recall.csv", index=False, lineterminator="\n")
    pd.concat(scores).to_csv(out / "test_scores.csv", index=False, lineterminator="\n")
    (out / "test_run_log.json").write_text(json.dumps({"phase1_lock_sha256": lock, "test_sha256": TEST_SHA256, "test_rows": TEST_ROWS, "script_sha256": sha(__file__),
        "disjoint_check": "PR #13 check_disjoint(dev, test) passed on jointly computed components", "thresholds_reestimated": False, "elapsed_s": round(time.time() - t0, 1)}, indent=1) + "\n")
    print("done", round(time.time() - t0, 1))


if __name__ == "__main__":
    main()
