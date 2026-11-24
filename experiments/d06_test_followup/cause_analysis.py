"""Cause analysis for the D06 Test drop (post-hoc development analysis on the already-evaluated Test).
Inference / saved scores only: no training, no new features, no threshold changes.

Usage: python -I -B cause_analysis.py --workspace <ws> --groups <be87ab4c malicious_pair_groups.csv> --out <dir>
"""
from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
spec_ = importlib.util.spec_from_file_location("followup_eval", HERE / "followup_eval.py")
F = importlib.util.module_from_spec(spec_)
spec_.loader.exec_module(F)
R = F.R
FOCUS = {"mastra-easy-day-js_2026-06": "mastra", "canisterworm_2026-03": "canisterworm"}
BINARY = {"installScriptPresent", "installScriptAdded", "scriptEntryAdded", "newDependencyAdded", "installHookRefFileChanged"}
KEYF = ["installScriptPresent", "installScriptAdded", "scriptEntryAdded", "newDependencyAdded", "newDependencyCount", "updateType", "updateInterval",
        "obfChangedFileCount", "obfHexIdentRatioNew", "obfWhitespaceRatioChangedCode", "installHookRefFileChanged", "addedProcExecCallCount", "addedNetworkCallCount"]


def profile(df, name):
    d = {"group": name, "n": len(df)}
    for c in KEYF:
        v = df[c]
        if c == "updateType":
            d |= {f"updateType_{k}": round(float((v == k).mean()), 3) for k in ["major", "minor", "patch"]}
        elif c in BINARY:
            d[f"{c}=1"] = round(float((v.astype(float) == 1).mean()), 3)
        else:
            d[f"{c} med"] = round(float(v.median()), 4) if v.notna().any() else np.nan
            d[f"{c}>0"] = round(float((v > 0).mean()), 3)
        d[f"{c} NaN"] = int(v.isna().sum())
    d["no_hook&newDep"] = round(float((~df.installScriptAdded.astype(bool) & ~df.scriptEntryAdded.astype(bool) & df.newDependencyAdded.astype(bool)).mean()), 3)
    d["no_changed_js(obfChangedFileCount==0)"] = round(float((df.obfChangedFileCount == 0).mean()), 3)
    return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", type=Path, required=True)
    ap.add_argument("--groups", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    snap, spec, data, test, feats, _ = F.prepare(args.workspace, args.groups)
    test["grp"] = test.campaign.map(FOCUS).fillna(pd.Series(np.where(test.label == 1, "other_test_malicious", "test_" + test["class"]), index=test.index))
    splits = pd.read_csv(F.EVAL / "run/splits.csv")
    # E06/E09 training rows (train_model.py: splits/train_val_split_assignment.csv split == train)
    tv = pd.read_csv(R.REPO / "splits/train_val_split_assignment.csv", keep_default_na=False)
    e_train = data.merge(tv[R.KEY + ["split"]], on=R.KEY, how="left")
    R.require(e_train.split.notna().all(), "train_val assignment join")
    sets = {"E06/E09 train (2212)": e_train[e_train.split == "train"]}
    for s in R.SEEDS:
        ids = splits[(splits.seed == s) & (splits.stage == "fit")].row_id
        sets[f"fit {s}"] = data[data.row_id.isin(ids)]
    # 1) composition
    comp = []
    for name, d in sets.items():
        mal = d[d.label == 1]
        b_like = mal[~mal.installScriptAdded.astype(bool) & ~mal.scriptEntryAdded.astype(bool) & mal.newDependencyAdded.astype(bool)]
        neg = d[d.label == 0]
        nd_neg = neg[~neg.installScriptAdded.astype(bool) & ~neg.scriptEntryAdded.astype(bool) & neg.newDependencyAdded.astype(bool)]
        row = {"set": name, "rows": len(d), "malicious": len(mal), "benign": int((d["class"] == "benign").sum()), "hard_benign": int((d["class"] == "hard_benign").sum()),
               "mal_no_hook_newDep": len(b_like), "mal_no_hook_newDep_campaigns": "; ".join(f"{k}:{v}" for k, v in b_like.campaign.value_counts().head(5).items()),
               "neg_no_hook_newDep": len(nd_neg), "P(mal|no_hook&newDep)": round(len(b_like) / max(len(b_like) + len(nd_neg), 1), 3),
               "mal_with_hook": int((mal.installScriptAdded.astype(bool) | mal.scriptEntryAdded.astype(bool)).sum())}
        row |= {f"camp:{k}": v for k, v in mal.campaign.value_counts().head(8).items()}
        comp.append(row)
    pd.DataFrame(comp).to_csv(out / "training_composition.csv", index=False, lineterminator="\n")
    # 2) feature profiles
    prof = [profile(data[data.label == 1], "train_malicious"), profile(data[data["class"] == "benign"], "train_benign"),
            profile(data[data["class"] == "hard_benign"], "train_hard_benign")]
    for name, d in sets.items():
        prof.append(profile(d[d.label == 1], f"{name} malicious"))
    for g, d in test.groupby("grp"):
        prof.append(profile(d, f"test:{g}"))
    pd.DataFrame(prof).to_csv(out / "feature_profiles.csv", index=False, lineterminator="\n")
    # 3) scores by campaign/group and 5% thresholds (stored + W1 + E06/E09)
    sc = pd.concat([pd.read_csv(F.EVAL / "run/scores.csv"), pd.read_csv(HERE / "run/scores_w1.csv")])
    sc = sc[sc.stage == "test"].merge(test[["test_row", "grp", "in674", "package", "new_version"]], on="test_row")
    e = pd.read_csv(HERE / "run/e06_e09_test_scores.csv").merge(test[["test_row", "grp", "in674", "package", "new_version"]], on="test_row").assign(seed="saved")
    allsc = pd.concat([sc, e], ignore_index=True)
    allsc = allsc[allsc.in674]
    thr = pd.read_csv(HERE / "run/thresholds.csv")
    t5 = thr[thr.target == 0.05].set_index(["seed", "model"]).threshold
    dist = allsc.groupby(["seed", "model", "grp"]).score.describe(percentiles=[.1, .5, .9])[["count", "10%", "50%", "90%", "max"]].reset_index()
    dist["thr_calFPR5%"] = [t5.get((s, m), 0.5 if s == "saved" else np.nan) for s, m in zip(dist.seed, dist.model)]
    dist["share_ge_thr"] = [float((allsc[(allsc.seed == s) & (allsc.model == m) & (allsc.grp == g)].score >= t).mean()) if not np.isnan(t) else np.nan
                            for s, m, g, t in zip(dist.seed, dist.model, dist.grp, dist["thr_calFPR5%"])]
    dist.to_csv(out / "score_by_group_test674.csv", index=False, lineterminator="\n")
    # 4) same-pair score comparison for mastra / canisterworm
    piv = allsc[allsc.grp.isin(["mastra", "canisterworm"])].assign(col=lambda d: d.model + "|" + d.seed.astype(str)) \
        .pivot_table(index=["grp", "test_row", "package", "new_version"], columns="col", values="score").reset_index()
    piv.to_csv(out / "focus_pair_scores.csv", index=False, lineterminator="\n")
    # 5) importance and TreeSHAP on focus groups
    imp, shap = [], []
    boosters = {}
    for s in R.SEEDS:
        for m in ["base7", "base7_w", "full29", "full35"]:
            boosters[(m, s)] = (lgb.Booster(model_file=str(F.EVAL / "run/models" / f"{m}_{s}.txt")), feats[m])
        for m in F.NEW:
            boosters[(m, s)] = (lgb.Booster(model_file=str(HERE / "run/models" / f"{m}_{s}.txt")), feats[m])
    tdf = pd.read_csv(R.TEST_FULL35).drop(columns=R.X1)
    Xe = tdf.drop(columns=R.KEY + ["label"])
    Xe["updateType"] = Xe["updateType"].astype("category")
    for name, (rel, _) in R.E0609.items():
        b = lgb.Booster(model_file=str(R.REPO / rel))
        boosters[(name, "saved")] = (b, b.feature_name())
    for (m, s), (b, cols) in boosters.items():
        g = b.feature_importance(importance_type="gain")
        imp += [{"model": m, "seed": s, "feature": f, "gain_share": float(v / g.sum())} for f, v in zip(cols, g)]
        X = Xe[cols] if s == "saved" else snap.feature_matrix(test, cols, "M_full")
        contrib = b.predict(X, pred_contrib=True)
        cdf = pd.DataFrame(contrib, columns=list(cols) + ["bias"])
        for grp in ["mastra", "canisterworm", "test_benign", "test_hard_benign"]:
            mask = (test.grp == grp).to_numpy() & test.in674.to_numpy()
            mean = cdf[mask].mean()
            shap += [{"model": m, "seed": s, "group": grp, "feature": f, "mean_contrib_logodds": float(v)} for f, v in mean.items()]
    pd.DataFrame(imp).to_csv(out / "feature_importance.csv", index=False, lineterminator="\n")
    pd.DataFrame(shap).to_csv(out / "treeshap_focus_groups.csv", index=False, lineterminator="\n")
    print("written", out)


if __name__ == "__main__":
    main()
