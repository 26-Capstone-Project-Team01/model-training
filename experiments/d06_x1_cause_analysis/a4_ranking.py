import sys, importlib.util, types; sys.path.insert(0, ".")
import common as c, numpy as np, pandas as pd
from sklearn.metrics import roc_auc_score, average_precision_score
pd.set_option("display.width", 250); pd.set_option("display.max_rows", 400)
OUT = c.HERE / "out"
df = c.frame(); s = c.scores()
spc = importlib.util.spec_from_file_location("snap", c.B / "provenance/phase2_run1_base7_full29/executed_script_snapshot.py")
snap = importlib.util.module_from_spec(spc); spc.loader.exec_module(snap)
s = s.merge(df[["row_id", "label", "class", "campaign"]], on="row_id")
o, cal = s[s.stage == "outer"], s[s.stage == "calibration"]
rows = []
for (v, spl, fo), g in o.groupby(["variant", "split", "fold"]):
    y = g.label.values; sc = g.score.values
    r = {"variant": v, "split": spl, "fold": fo, "roc_auc": roc_auc_score(y, sc), "pr_auc": average_precision_score(y, sc)}
    hb = g[g["class"] != "benign"]; r["roc_auc_vs_hard"] = roc_auc_score(hb.label, hb.score)
    ex = g[g.campaign != "shai-hulud-original_2025-09"]
    r["roc_auc_excl_shai"] = roc_auc_score(ex.label, ex.score) if ex.label.nunique() == 2 else np.nan
    r["pr_auc_excl_shai"] = average_precision_score(ex.label, ex.score) if ex.label.nunique() == 2 else np.nan
    # existing PR #13 phase2 operating points: calibration normal FP budget (snapshot calibrate, ML policy)
    cg = cal[(cal.variant == v) & (cal.split == spl) & (cal.fold == fo)]
    for tgt in [0.01, 0.05]:
        res = snap.calibrate(cg.score.values, cg.label.values, np.zeros(len(cg), bool), "ML", tgt)
        pred = sc >= res["threshold"]
        r[f"cal{int(tgt*100)}_thr"] = res["threshold"]; r[f"cal{int(tgt*100)}_tp"] = int((pred & (y == 1)).sum()); r[f"cal{int(tgt*100)}_fp"] = int((pred & (y == 0)).sum())
    # diagnostic only: oracle recall at outer FPR <= 1% (threshold chosen on outer; NOT a policy)
    neg = np.sort(sc[y == 0])[::-1]; k = int(np.floor(0.01 * len(neg)))
    thr = np.nextafter(neg[k], np.inf); r["diag_recall_at_outer_fpr1"] = float((sc[y == 1] >= thr).mean())
    rows.append(r)
t = pd.DataFrame(rows); t.to_csv(OUT / "ranking_metrics_by_fold.csv", index=False)
for col in ["roc_auc", "pr_auc", "roc_auc_vs_hard", "roc_auc_excl_shai", "pr_auc_excl_shai", "diag_recall_at_outer_fpr1"]:
    print(f"== {col}"); print(t.pivot_table(index="variant", columns=["split", "fold"], values=col).reindex(c.VARS).round(4).to_string())
for tgt in ["cal1", "cal5"]:
    p = t.groupby(["variant", "split"])[[f"{tgt}_tp", f"{tgt}_fp"]].sum().unstack("split").reindex(c.VARS)
    print(f"== {tgt} (calibration FPR budget, PR #13 phase2 policy) pooled TP/FP"); print(p.to_string())
# rank change of malicious within fold (percentile, 1 = top), full35 vs full29
rk = o.copy(); rk["pct"] = rk.groupby(["variant", "split", "fold"]).score.rank(ascending=False, pct=True, method="average")
pv = rk[rk.label == 1].pivot_table(index=["split", "fold", "row_id", "campaign"], columns="variant", values="pct").reset_index()
pv["d35"] = pv.full35 - pv.full29
pv["c"] = pv.campaign.map(c.FOCUS).fillna("other")
print("== malicious in-fold rank percentile (lower=better): median full29 -> full35, and share of rows worse by >5pp")
print(pv.groupby(["c", "split"]).apply(lambda g: pd.Series({"n": len(g), "med29": g.full29.median(), "med35": g.full35.median(), "worse>5pp": (g.d35 > .05).mean(), "better>5pp": (g.d35 < -.05).mean()})).round(3).to_string())
pv.to_csv(OUT / "malicious_rank_change.csv", index=False)
# score distribution by class
q = o[o.variant.isin(["full29", "full35"])].groupby(["variant", "split", "class"]).score.describe(percentiles=[.5, .9, .99])[["count", "50%", "90%", "99%", "max"]]
print("== score distribution"); print(q.round(4).to_string())
