"""D06 Test-674 development evaluation as pre-registered (PREREGISTRATION.md, commit 75efbe1). Not a final generalization claim.

Reuses unchanged (imported by path): ../d06_test_eval/run_test_eval.py (snapshot load, X1 encoding, Test frame constants),
../d06_alt_models/alt_models.py (Prep, make_model, groups), ../d06_alt_models/blend.py (combine, candidates).
full35 Test scores are reused from ../d06_test_eval/run/scores.csv; full35 is also retrained here only as a reproduction guard.
Usage: python -I -B run_dev_eval.py --workspace <ws> --out <new dir>
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
from sklearn.metrics import average_precision_score

HERE = Path(__file__).resolve().parent
EXP = HERE.parent
TE = EXP / "d06_test_eval"
ALT = EXP / "d06_alt_models"
X4DIR = EXP / "d06_x4_rel_update"
X4 = ["x4RelUpdateIntervalRatio", "x4HistoryGapCount"]
MASTRA = "mastra-easy-day-js_2026-06"
TARGETS = [0.01, 0.03, 0.05]


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


def attach_x4(frame, path, key):
    raw = pd.read_csv(path, dtype=str, keep_default_na=False)
    raw = raw[key + X4].copy()
    for c in X4:
        raw[c] = pd.to_numeric(raw[c].replace("", np.nan), errors="raise").astype(float)
    m = frame[key].astype(str).merge(raw, on=key, how="left", validate="one_to_one")
    for c in X4:
        frame[c] = m[c].to_numpy()
    return frame


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    te = load(TE / "run_test_eval.py", "run_test_eval")
    alt = load(ALT / "alt_models.py", "alt_models")
    bl = load(ALT / "blend.py", "blend_alt")
    versions = {"lightgbm": lgb.__version__, "pandas": pd.__version__, "numpy": np.__version__, "sklearn": sklearn.__version__}
    te.require(versions == te.PINNED, f"library versions differ: {versions}")
    out = a.out
    out.mkdir(parents=True, exist_ok=False)
    (out / "models").mkdir()
    snap = te.load_snapshot()
    spec = json.loads((a.workspace / te.SPEC_REL).read_text(encoding="utf-8"))
    data, feat29, paths = snap.load_data(a.workspace, spec)
    base7 = spec["features"]["M_base"]
    tk, tx = te.encode_x1(te.TRAIN_FULL35)
    te.require((tk[te.KEY].to_numpy() == data[te.KEY].astype(str).to_numpy()).all(), "train X1 keys")
    for c in te.X1:
        data[c] = tx[c].to_numpy()
    tx4 = pd.read_csv(X4DIR / "run/d06_x4.csv", dtype=str, keep_default_na=False)
    te.require((tx4[te.KEY].to_numpy() == data[te.KEY].astype(str).to_numpy()).all() and (tx4.label.astype(int).to_numpy() == data.label.to_numpy()).all(), "train X4 keys")
    for c in X4:
        data[c] = pd.to_numeric(tx4[c].replace("", np.nan)).astype(float).to_numpy()
    feat35 = feat29 + te.X1
    G = alt.groups(feat29, te.X1)
    FEATS = {"full35": feat35, "base7_x1": base7 + te.X1, "gs24": base7 + G["obfChange"] + G["obfChangedCode"] + G["x1Calls"],
             "full35_x4": feat35 + X4, "full34_x4": [f for f in feat35 if f != "updateInterval"] + X4}
    te.require(len(FEATS["gs24"]) == 24, "gs24 size")
    # Test frame (same construction as run_test_eval)
    tst_raw = pd.read_csv(te.TEST_FULL35, float_precision="round_trip")
    sk, sx = te.encode_x1(te.TEST_FULL35)
    test = tst_raw.drop(columns=te.X1).copy()
    for c in te.X1:
        test[c] = sx[c].to_numpy()
    st = pd.read_csv(te.TEST_STATUS, keep_default_na=False, dtype=str)
    te.require((st[te.KEY].to_numpy() == test[te.KEY].astype(str).to_numpy()).all(), "test order")
    test["class"], test["campaign"], test["test_row"] = st["class"].to_numpy(), st.splitGroup.to_numpy(), np.arange(len(test))
    test["in674"] = ~test[te.KEY].astype(str).apply(tuple, axis=1).isin(te.VANT3)
    test = attach_x4(test, X4DIR / "test_diag/test674_x4.csv", te.KEY)
    te.require(test[test.in674][X4[1]].notna().sum() == 674 and test[~test.in674][X4[1]].isna().all(), "test X4 coverage")
    saved = pd.read_csv(TE / "run/scores.csv")
    saved_splits = pd.read_csv(TE / "run/splits.csv")
    rows_s, rows_thr, rows_met, rows_camp, sel_info, guard = [], [], [], [], {}, {}
    for sname, seed in te.SEEDS.items():
        fit, cal = snap.inner_split(data, seed)
        for stage, part in [("fit", fit), ("calibration", cal)]:
            ref = saved_splits[(saved_splits.seed == sname) & (saved_splits.stage == stage)]
            te.require(set(ref.row_id) == set(part.row_id), f"{sname} {stage} differs from d06_test_eval")
        cal_s, test_s = {}, {}
        for m, cols in FEATS.items():
            xf, xc, xt = (snap.feature_matrix(p, cols, "M_full") for p in (fit, cal, test))
            booster = lgb.train(spec["lightgbm"], lgb.Dataset(xf, label=fit.label.to_numpy(), categorical_feature=["updateType"], feature_name=cols),
                                num_boost_round=spec["rounds"])
            if m != "full35":
                booster.save_model(str(out / "models" / f"{m}_{sname}.txt"))
            cal_s[m], test_s[m] = booster.predict(xc, num_threads=2), booster.predict(xt, num_threads=2)
        # full35 guard: retrain == saved (after CSV round trip), then use the saved scores
        tmp = out / "_guard.csv"
        pd.DataFrame({"c": np.concatenate([cal_s["full35"], test_s["full35"]])}).to_csv(tmp, index=False)
        rt = pd.read_csv(tmp).c.to_numpy()
        tmp.unlink()
        sv = saved[(saved.seed == sname) & (saved.model == "full35")]
        sc_cal = sv[sv.stage == "calibration"].set_index("row_id").score.loc[cal.row_id].to_numpy()
        sc_test = sv[sv.stage == "test"].set_index("test_row").score.loc[test.test_row].to_numpy()
        te.require((rt == np.concatenate([sc_cal, sc_test])).all(), "full35 guard failed")
        guard[sname] = "full35 retrain == saved d06_test_eval scores"
        cal_s["full35"], test_s["full35"] = sc_cal, sc_test
        for kind in ["lr", "rf", "mlp"]:
            xf, xc, xt = (snap.feature_matrix(p, feat35, "M_full") for p in (fit, cal, test))
            model, scale = alt.make_model(kind, seed, 1)
            prep = alt.Prep(scale).fit(xf)
            model.fit(prep.transform(xf), fit.label.to_numpy())
            cal_s[f"full35_{kind}"], test_s[f"full35_{kind}"] = model.predict_proba(prep.transform(xc))[:, 1], model.predict_proba(prep.transform(xt))[:, 1]
        # blends: weights from calibration only (same candidates and rule as Train development)
        base_pr = {b: average_precision_score(cal.label, cal_s[b]) for b in ["full35_x4", "full34_x4"]}
        blends = {"B1": ["full35", "full35_lr"], "B2": ["full35", "full35_mlp"], "B3": ["full35", "full35_lr", "full35_mlp"],
                  "B3x_full35_x4": ["full35_x4", "full35_lr", "full35_mlp"], "B3x_full34_x4": ["full34_x4", "full35_lr", "full35_mlp"]}
        cf = pd.DataFrame(cal_s)
        tf_ = pd.DataFrame(test_s)
        for name, models in blends.items():
            best = None
            for scale in ["prob", "logit"]:
                for wt in bl.candidates(len(models)):
                    pr = average_precision_score(cal.label, bl.combine(cf, models, wt, scale))
                    key = (pr, wt[0], scale == "prob")
                    if best is None or key > best[0]:
                        best = (key, scale, wt)
            cal_s[name], test_s[name] = bl.combine(cf, models, best[2], best[1]), bl.combine(tf_, models, best[2], best[1])
            sel_info[f"{name}|{sname}"] = {"models": models, "scale": best[1], "weights": [abs(x) for x in best[2]], "cal_pr_auc": best[0][0]}
        sel_info[f"x4_blend_representative|{sname}"] = "B3x_" + max(base_pr, key=lambda b: (base_pr[b], b == "full35_x4"))
        sel_info[f"x4_base_cal_pr_auc|{sname}"] = base_pr
        mask = test.in674.to_numpy()
        tfm = test[mask]
        mal = tfm.label.to_numpy() == 1
        mas = (tfm.campaign == MASTRA).to_numpy()
        hb = (tfm["class"] == "hard_benign").to_numpy()
        for m in cal_s:
            rows_s.append(pd.DataFrame({"seed": sname, "model": m, "stage": "calibration", "row_id": cal.row_id.to_numpy(), "test_row": -1, "score": cal_s[m]}))
            rows_s.append(pd.DataFrame({"seed": sname, "model": m, "stage": "test", "row_id": -1, "test_row": test.test_row.to_numpy(), "score": test_s[m]}))
            sc = np.asarray(test_s[m])[mask]
            pr_all = average_precision_score(mal, sc)
            for t in TARGETS:
                r = snap.calibrate(np.asarray(cal_s[m]), cal.label.to_numpy(), np.zeros(len(cal), bool), "ML", t)
                thr = r["threshold"]
                rows_thr.append({"seed": sname, "model": m, "target": t, "threshold": thr, "cal_fpr": r["calibration_fp"] / r["calibration_normal"]})
                sel = sc >= thr
                rows_met.append({"seed": sname, "model": m, "target_fpr": t, "TP": int((sel & mal).sum()), "malicious": int(mal.sum()),
                                 "recall": (sel & mal).sum() / mal.sum(), "mastra_TP": int((sel & mas).sum()), "mastra_n": int(mas.sum()),
                                 "mastra_recall": (sel & mas).sum() / mas.sum(), "non_mastra_recall": (sel & mal & ~mas).sum() / (mal & ~mas).sum(),
                                 "FP": int((sel & ~mal).sum()), "fpr": (sel & ~mal).sum() / (~mal).sum(), "hard_FP": int((sel & hb).sum()),
                                 "hard_fpr": (sel & hb).sum() / hb.sum(), "cal_fpr": r["calibration_fp"] / r["calibration_normal"], "PR_AUC": pr_all,
                                 "PR_AUC_mastra_vs_normals": average_precision_score(mas[mas | ~mal], sc[mas | ~mal])})
                for camp, idx in pd.Series(np.arange(len(tfm))[mal]).groupby(tfm.campaign.to_numpy()[mal]):
                    rows_camp.append({"seed": sname, "model": m, "target_fpr": t, "campaign": camp, "n": len(idx), "TP": int(sel[idx.to_numpy()].sum())})
        print(f"done {sname}", flush=True)
    pd.concat(rows_s).to_csv(out / "scores.csv", index=False, lineterminator="\n")
    pd.DataFrame(rows_thr).to_csv(out / "thresholds.csv", index=False, lineterminator="\n")
    pd.DataFrame(rows_met).to_csv(out / "metrics_test674.csv", index=False, lineterminator="\n")
    pd.DataFrame(rows_camp).to_csv(out / "campaign_recall_test674.csv", index=False, lineterminator="\n")
    man = {"nature": "DEVELOPMENT evaluation on Test-674 (repeatedly analysed); not a final generalization claim", "preregistration_commit": "75efbe1",
           "guard": guard, "blend_selection": sel_info, "features": FEATS, "script_sha256": sha(__file__),
           "reused": {"run_test_eval": sha(TE / "run_test_eval.py"), "alt_models": sha(ALT / "alt_models.py"), "blend": sha(ALT / "blend.py"),
                      "saved_test_scores": sha(TE / "run/scores.csv"), "train_x4": sha(X4DIR / "run/d06_x4.csv"), "test_x4": sha(X4DIR / "test_diag/test674_x4.csv")},
           "inputs": {k: sha(v) for k, v in paths.items()}, "packages": versions, "python": platform.python_version(), "argv": sys.argv,
           "outputs": {p.name: sha(p) for p in sorted(out.glob("*.csv"))}}
    (out / "manifest.json").write_text(json.dumps(man, indent=1, default=str) + "\n")


if __name__ == "__main__":
    main()
