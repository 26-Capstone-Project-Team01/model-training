"""Hard benign false-positive analysis and change-type-wise performance (saved models/scores only; no training).

Design evidence = D06 Train outer folds (PR #13 splits), thresholds = ../d06_x1_fair_compare/calibration_attainment.csv (target 5%).
Diagnostic only = D06 Test-674 (../d06_test_eval, ../d06_es_followup), thresholds from their calibration.
Routing rules evaluated here are fixed before evaluation and only on Train outer (design check), never chosen on Test.

Usage: python -I -B hb_typewise.py --out <new dir>
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
EXP = HERE.parent
sys.path.insert(0, str(EXP / "d06_x1_cause_analysis"))
import common as c  # noqa: E402

spec = importlib.util.spec_from_file_location("snap", c.B / "provenance/phase2_run1_base7_full29/executed_script_snapshot.py")
snap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snap)
TEST = EXP / "d06_test_eval"
ES = EXP / "d06_es_followup"
BLEND = {"A1": 0.1, "A2": 0.2, "A3": 0.3}
TRAIN_MODELS = ["base7", "full29", "full35", "A1", "A2", "A3"]
TEST_MODELS = ["base7", "full29", "full35", "full35_es", "A1", "A2", "A3"]
KEYF = ["installScriptPresent", "installScriptAdded", "scriptEntryAdded", "newDependencyAdded", "newDependencyCount", "updateInterval", "obfChangedFileCount",
        "obfHexIdentRatioNew", "obfWhitespaceRatioChangedCode", "obfBracketAccessRatioChangedCode", "obfEscapeDensityChangedCode", "obfMeanIdentLengthChangedCode",
        "installHookNewProgramCount", "installHookRefFileChanged", "addedProcExecCallCount", "addedNetworkCallCount"]
ROUTES = {  # fixed before evaluation
    "route_noJS_base7": lambda d: d.obfChangedFileCount.fillna(0).to_numpy() == 0,
    "route_noJS_newDep_noHook_base7": lambda d: (d.obfChangedFileCount.fillna(0).to_numpy() == 0) & d.newDependencyAdded.astype(bool).to_numpy()
                                                & ~d.installScriptAdded.astype(bool).to_numpy(),
}


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def strata(d):
    js = d.obfChangedFileCount.fillna(0) > 0
    nd = d.newDependencyAdded.astype(bool)
    hk = d.installScriptAdded.astype(bool)
    return {"JS_changed": js, "no_JS_change": ~js, "newDep": nd, "no_newDep": ~nd, "installScriptAdded": hk, "no_installScriptAdded": ~hk,
            "noJS&newDep&noHook": ~js & nd & ~hk}


def stratum_table(frame, sel, tag):
    rows = []
    for name, mask in strata(frame).items():
        m = mask.to_numpy()
        for cls in ["malicious", "benign", "hard_benign"]:
            cm = m & (frame["class"].to_numpy() == cls)
            rows.append(tag | {"stratum": name, "class": cls, "n": int(cm.sum()), "selected": int((sel & cm).sum()),
                               "rate": float((sel & cm).sum() / cm.sum()) if cm.sum() else np.nan})
    return rows


def profile(d, name):
    r = {"group": name, "n": len(d)}
    for f in KEYF:
        v = d[f].astype(float)
        r[f"{f}>0"] = round(float((v > 0).mean()), 3)
        r[f"{f}_med"] = round(float(v.median()), 4) if v.notna().any() else np.nan
        r[f"{f}_NaN"] = int(v.isna().sum())
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True)
    out = ap.parse_args().out
    out.mkdir(parents=True, exist_ok=False)
    df = c.frame()
    # ---------------- Train outer (design) ----------------
    s13 = pd.read_csv(c.B / "scores/saved_scores.csv")[["model", "seed", "fold", "stage", "row_id", "score"]].rename(columns={"model": "variant"})
    s35 = pd.read_csv(c.C / "run/scores.csv")
    s35 = s35[s35.variant == "full35"][["variant", "seed", "fold", "stage", "row_id", "score"]]
    K = ["seed", "fold", "stage", "row_id"]
    w = pd.concat([s13, s35]).pivot_table(index=K, columns="variant", values="score").reset_index()
    for k, a in BLEND.items():
        w[k] = (1 - a) * w.full29 + a * w.full35
    w["split"] = w.seed.map(c.SEED)
    CI = pd.read_csv(EXP / "d06_x1_fair_compare/calibration_attainment.csv", float_precision="round_trip")
    thr = CI[CI.target == 0.05].set_index(["variant", "split", "fold"]).threshold
    cal = w[w.stage == "calibration"].merge(df, on="row_id")
    o = w[w.stage == "outer"].merge(df, on="row_id")
    for m in TRAIN_MODELS:
        o[f"sel_{m}"] = o[m].to_numpy() >= np.array([thr[(m, s, f)] for s, f in zip(o.split, o.fold)])
    # check vs fair_comparison
    FC = pd.read_csv(EXP / "d06_x1_fair_compare/fair_comparison.csv")
    for m in TRAIN_MODELS:
        for s, g in o.groupby("split"):
            r = FC[(FC.op == "calFPR5%") & (FC.variant == m) & (FC.split == s)].iloc[0]
            assert int((g[f"sel_{m}"] & (g.label == 1)).sum()) == r.TP and int((g[f"sel_{m}"] & (g.label == 0)).sum()) == r.FP, (m, s)
    # routing (Train outer design check): composite score, thresholds from calibration composite
    route_rows = []
    for rname, rule in ROUTES.items():
        for part in (cal, o):
            part[rname] = np.where(rule(part), part["base7"], part["full35"])
        for s in ["split1", "split2"]:
            for f in range(3):
                cg = cal[(cal.split == s) & (cal.fold == f)]
                t = snap.calibrate(cg[rname].to_numpy(), cg.label.to_numpy(), np.zeros(len(cg), bool), "ML", 0.05)["threshold"]
                msk = (o.split == s) & (o.fold == f)
                o.loc[msk, f"sel_{rname}"] = o.loc[msk, rname] >= t
        o[f"sel_{rname}"] = o[f"sel_{rname}"].astype(bool)
        for s, g in o.groupby("split"):
            mal = g.label == 1
            route_rows.append({"route": rname, "split": s, "TP": int((g[f"sel_{rname}"] & mal).sum()), "FP": int((g[f"sel_{rname}"] & ~mal).sum()),
                               "hard_FP": int((g[f"sel_{rname}"] & (g["class"] == "hard_benign")).sum()), "routed_rows": int(rule(g).sum()),
                               "routed_malicious": int((rule(g) & mal).sum())})
    for m in ["base7", "full35"]:
        for s, g in o.groupby("split"):
            mal = g.label == 1
            route_rows.append({"route": f"{m} (reference)", "split": s, "TP": int((g[f"sel_{m}"] & mal).sum()), "FP": int((g[f"sel_{m}"] & ~mal).sum()),
                               "hard_FP": int((g[f"sel_{m}"] & (g["class"] == "hard_benign")).sum())})
    pd.DataFrame(route_rows).to_csv(out / "train_routing_design_check.csv", index=False, lineterminator="\n")
    # strata performance (Train)
    st = []
    for m in TRAIN_MODELS + list(ROUTES):
        for s, g in o.groupby("split"):
            st += stratum_table(g, g[f"sel_{m}"].to_numpy(), {"data": "train_outer", "model": m, "split": s})
    # HB FP sets (Train)
    hb = o[o["class"] == "hard_benign"].copy()
    hb["n_models_fp"] = hb[[f"sel_{m}" for m in TRAIN_MODELS]].sum(axis=1)
    hbw = hb.pivot_table(index=["row_id", "package", "old_version", "new_version"], columns="split", values="n_models_fp").reset_index()
    sets = hb.groupby("split").apply(lambda g: {m: set(g.row_id[g[f"sel_{m}"]]) for m in TRAIN_MODELS})
    overlap = []
    for s in sets.index:
        S = sets[s]
        allm = set.intersection(*S.values())
        for m in TRAIN_MODELS:
            others = set.union(*[S[x] for x in TRAIN_MODELS if x != m])
            overlap.append({"data": "train_outer", "split": s, "model": m, "hard_FP": len(S[m]), "common_all_models": len(allm), "only_this_model": len(S[m] - others)})
    # TreeSHAP for HB FP vs HB TN (Train): base7, full29, full35 fold models
    mi = pd.read_csv(c.B / "model_index.csv")
    tr35 = pd.read_csv(c.C / "run/training.csv")
    shap_rows = []
    for (s, f), g in o.groupby(["split", "fold"]):
        for m in ["base7", "full29", "full35"]:
            if m == "full35":
                r = tr35[(tr35.variant == "full35") & (tr35.split == s) & (tr35.fold == f)].iloc[0]
                path, cols = c.C / "run/models" / f"full35_{s}_fold{f}.txt", r.feature_order.split()
            else:
                r = mi[(mi.feature_set == m) & (mi.split == s) & (mi.outer_fold == f)].iloc[0]
                path, cols = c.B / r.bundle_model_path, r.feature_order.split()
            b = lgb.Booster(model_file=str(path))
            grp = g[g["class"].isin(["hard_benign", "malicious"])]
            ctb = pd.DataFrame(b.predict(c.matrix(grp, cols), pred_contrib=True), columns=cols + ["bias"], index=grp.index)
            lab = np.where(grp["class"] == "malicious", np.where(grp[f"sel_{m}"], "malicious_TP", "malicious_FN"),
                           np.where(grp[f"sel_{m}"], "hard_FP", "hard_TN"))
            for L in np.unique(lab):
                mean = ctb[lab == L].sum()
                for feat, v in mean.items():
                    shap_rows.append({"data": "train_outer", "split": s, "fold": f, "model": m, "group": L, "n": int((lab == L).sum()), "feature": feat, "sum_contrib": float(v)})
    SH = pd.DataFrame(shap_rows)
    SH = SH.groupby(["data", "split", "model", "group", "feature"]).agg(n=("n", "sum"), sum_contrib=("sum_contrib", "sum")).reset_index()
    SH["mean_contrib"] = SH.sum_contrib / SH.n
    SH.to_csv(out / "train_treeshap_hb_vs_malicious.csv", index=False, lineterminator="\n")
    # profiles (Train)
    prof = []
    for s, g in o.groupby("split"):
        h = g[g["class"] == "hard_benign"]
        fp_any = h[[f"sel_{m}" for m in ["full29", "full35", "A2"]]].any(axis=1)
        prof += [profile(h[fp_any], f"{s} hard_FP(full29|full35|A2)") | {"split": s}, profile(h[~fp_any], f"{s} hard_TN") | {"split": s},
                 profile(g[g.label == 1], f"{s} malicious") | {"split": s}, profile(g[g["class"] == "benign"], f"{s} benign") | {"split": s}]
    pd.DataFrame(prof).to_csv(out / "train_feature_profiles.csv", index=False, lineterminator="\n")
    hb_cases = hb[["split", "fold", "row_id", "package", "old_version", "new_version", "n_models_fp"] + [f"sel_{m}" for m in TRAIN_MODELS] + TRAIN_MODELS + KEYF]
    hb_cases[hb_cases.n_models_fp > 0].sort_values(["n_models_fp", "split"], ascending=[False, True]).to_csv(out / "train_hard_fp_cases.csv", index=False, lineterminator="\n")

    # ---------------- Test (diagnostic only) ----------------
    tst = pd.read_csv(TEST / "analysis/d06_test_full35.csv", float_precision="round_trip")
    raw = pd.read_csv(TEST / "analysis/d06_test_full35.csv", dtype=str, keep_default_na=False)
    for col in c.X1:
        tst[col] = raw[col].map({"True": 1.0, "False": 0.0, "": np.nan}).astype(float) if col in ("installHookArgsChanged", c.REF) else pd.to_numeric(raw[col].replace("", np.nan))
    stt = pd.read_csv(TEST / "analysis/d06_test_x1_status.csv", keep_default_na=False, dtype=str)
    tst["class"], tst["campaign"], tst["test_row"] = stt["class"].to_numpy(), stt.splitGroup.to_numpy(), np.arange(len(tst))
    tst["in674"] = ~stt.excluded_in_test674.map({"True": True, "False": False}).to_numpy()
    ts = pd.concat([pd.read_csv(TEST / "run/scores.csv"), pd.read_csv(ES / "run/scores_es.csv")])
    ts = ts[ts.stage == "test"].pivot_table(index=["seed", "test_row"], columns="model", values="score").reset_index().merge(tst, on="test_row")
    ts = ts[ts.in674]
    tt = pd.concat([pd.read_csv(TEST / "run/thresholds.csv", float_precision="round_trip"), pd.read_csv(ES / "run/thresholds.csv", float_precision="round_trip")])
    tt = tt[tt.target == 0.05].drop_duplicates(["seed", "model"]).set_index(["seed", "model"]).threshold
    for m in TEST_MODELS:
        ts[f"sel_{m}"] = ts[m].to_numpy() >= np.array([tt[(s, m)] for s in ts.seed])
    for m in TEST_MODELS:
        for s, g in ts.groupby("seed"):
            st += stratum_table(g, g[f"sel_{m}"].to_numpy(), {"data": "test674_diagnostic", "model": m, "split": s})
    th = ts[ts["class"] == "hard_benign"].copy()
    th["n_models_fp"] = th[[f"sel_{m}" for m in TEST_MODELS]].sum(axis=1)
    for s, g in th.groupby("seed"):
        S = {m: set(g.test_row[g[f"sel_{m}"]]) for m in TEST_MODELS}
        allm = set.intersection(*S.values())
        for m in TEST_MODELS:
            others = set.union(*[S[x] for x in TEST_MODELS if x != m])
            overlap.append({"data": "test674_diagnostic", "split": s, "model": m, "hard_FP": len(S[m]), "common_all_models": len(allm), "only_this_model": len(S[m] - others)})
    th[th.n_models_fp > 0][["seed", "test_row", "package", "old_version", "new_version", "n_models_fp"] + [f"sel_{m}" for m in TEST_MODELS] + KEYF] \
        .sort_values("n_models_fp", ascending=False).to_csv(out / "test_hard_fp_cases.csv", index=False, lineterminator="\n")
    pd.DataFrame(st).to_csv(out / "strata_performance.csv", index=False, lineterminator="\n")
    pd.DataFrame(overlap).to_csv(out / "hard_fp_overlap.csv", index=False, lineterminator="\n")
    man = {"nature": "saved models/scores only; Train outer = design evidence, Test-674 = diagnostic only", "script_sha256": sha(__file__),
           "inputs": {"saved_scores": sha(c.B / "scores/saved_scores.csv"), "full35_scores": sha(c.C / "run/scores.csv"),
                      "fair_calibration": sha(EXP / "d06_x1_fair_compare/calibration_attainment.csv"), "test_scores": sha(TEST / "run/scores.csv"),
                      "es_scores": sha(ES / "run/scores_es.csv")},
           "routes_fixed_before_evaluation": list(ROUTES), "outputs": {p.name: sha(p) for p in sorted(out.glob("*")) if p.is_file()}}
    (out / "manifest.json").write_text(json.dumps(man, indent=1) + "\n")


if __name__ == "__main__":
    main()
