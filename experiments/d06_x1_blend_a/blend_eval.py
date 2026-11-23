"""Usage: python -I -B blend_eval.py  (writes the four CSVs next to this file)

A: pre-registered score blending of saved full29 (PR #13) and full35 scores. No training, no Test 677.
Weights fixed before evaluation: A1 0.9/0.1, A2 0.8/0.2, A3 0.7/0.3 (probability-space linear blend).
Operating point = PR #13 phase2 policy: calibration normal FP budget floor(n*0.01), snapshot calibrate(), applied to outer."""
import sys, importlib.util
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "d06_x1_cause_analysis"))  # shared loaders (common.py)
import common as c, numpy as np, pandas as pd
from sklearn.metrics import roc_auc_score, average_precision_score
pd.set_option("display.width", 250); pd.set_option("display.max_rows", 400)
spc = importlib.util.spec_from_file_location("snap", c.B / "provenance/phase2_run1_base7_full29/executed_script_snapshot.py")
snap = importlib.util.module_from_spec(spc); spc.loader.exec_module(snap)
W = {"A1": 0.1, "A2": 0.2, "A3": 0.3}   # weight of full35
df = c.frame(); s = c.scores()
K = ["split", "seed", "fold", "stage", "row_id"]
a = s[s.variant == "full29"][K + ["score"]].rename(columns={"score": "full29"})
b = s[s.variant == "full35"][K + ["score"]].rename(columns={"score": "full35"})
m = a.merge(b, on=K, how="outer", validate="one_to_one", indicator=True)
assert (m._merge == "both").all() and len(m) == len(a) == len(b), "1:1 pairing failed"
m = m.drop(columns="_merge")
for k, w in W.items(): m[k] = (1 - w) * m.full29 + w * m.full35
m = m.merge(df[["row_id", "package", "old_version", "new_version", "label", "class", "campaign", "component", "type"]], on="row_id", validate="many_to_one")
# key check: each (split, fold, row_id) appears once per stage
assert not m.duplicated(["split", "fold", "stage", "row_id"]).any()
print("paired rows:", len(m), m.groupby(["split", "stage"]).size().to_dict())
V = ["full29", "full35", "A1", "A2", "A3"]
o, cal = m[m.stage == "outer"], m[m.stage == "calibration"]
mini40 = set(df[(df.campaign == "mini-shai-hulud_2026-05") & (df.type == "B") & (df[c.NET] == 9)].row_id)
SHAI = "shai-hulud-original_2025-09"
# operating point per variant x split x fold
thr = {}
for v in V:
    for (spl, fo), g in cal.groupby(["split", "fold"]):
        r = snap.calibrate(g[v].values, g.label.values, np.zeros(len(g), bool), "ML", 0.01)
        thr[(v, spl, fo)] = r["threshold"]
o = o.copy()
for v in V:
    o[f"sel_{v}_cal1"] = [s_ >= thr[(v, sp_, f_)] for s_, sp_, f_ in zip(o[v], o.split, o.fold)]
    o[f"sel_{v}_0.05"] = o[v] >= 0.05; o[f"sel_{v}_0.5"] = o[v] >= 0.5
def metrics(g, col):
    sel, mal = g[col].values, g.label.values == 1
    tp, fp = int((sel & mal).sum()), int((sel & ~mal).sum())
    mm = g[mal]; per = pd.Series(sel[mal], index=mm.index).groupby(mm.campaign).mean()
    return {"tp": tp, "fn": int(mal.sum()) - tp, "fp": fp, "recall": tp / mal.sum(), "hard_fp": int((sel & (g["class"] == "hard_benign").values).sum()),
            "benign_fp": int((sel & (g["class"] == "benign").values).sum()), "precision": tp / max(sel.sum(), 1), "candidates": int(sel.sum()),
            "campaign_macro": per.mean()}
rows = []
for op in ["cal1", "0.05", "0.5"]:
    for v in V:
        for spl, g in o.groupby("split"):
            col = f"sel_{v}_{op}"
            r = {"op": op, "variant": v, "split": spl, **metrics(g, col)}
            ex = g[g.campaign != SHAI]; r["tp_excl_shai"] = int((ex[col] & (ex.label == 1)).sum()); r["fp_excl"] = None
            base, x35 = g[f"sel_full29_{op}"], g[f"sel_full35_{op}"]; mal = g.label == 1
            lost35 = mal & base & ~x35; gain35 = mal & ~base & x35
            r["recovered_of_lost35"] = f"{int((lost35 & g[col]).sum())}/{int(lost35.sum())}"
            r["kept_of_gain35"] = f"{int((gain35 & g[col]).sum())}/{int(gain35.sum())}"
            r["new_vs_full29"] = int((mal & ~base & g[col]).sum()); r["lost_vs_full29"] = int((mal & base & ~g[col]).sum())
            r["fp_added_vs_full29"] = int((~mal & ~base & g[col]).sum()); r["fp_removed_vs_full29"] = int((~mal & base & ~g[col]).sum())
            r["mini40_tp"] = int((g[col] & g.row_id.isin(mini40)).sum())
            for cc, nm in [("autotel-node-env-resolver_2026-06", "autotel"), ("miasma_2026-06", "miasma"), ("chaindrop_2026-08", "chaindrop"), (SHAI, "shai")]:
                r[f"{nm}_tp"] = int((g[col] & (g.campaign == cc)).sum())
            rows.append(r)
R = pd.DataFrame(rows).drop(columns="fp_excl"); R.to_csv(HERE / "blend_summary.csv", index=False)
cols1 = ["op", "variant", "split", "tp", "fn", "fp", "recall", "hard_fp", "benign_fp", "precision", "candidates", "campaign_macro", "tp_excl_shai"]
cols2 = ["op", "variant", "split", "new_vs_full29", "lost_vs_full29", "recovered_of_lost35", "kept_of_gain35", "fp_added_vs_full29", "fp_removed_vs_full29",
         "mini40_tp", "autotel_tp", "miasma_tp", "chaindrop_tp", "shai_tp"]
for op in ["cal1", "0.05", "0.5"]:
    print(f"\n===== operating point {op}"); x = R[R.op == op]
    print(x[cols1].round(4).to_string(index=False)); print(x[cols2].to_string(index=False))
# per fold stability (cal1): TP/FP delta vs full29
f = []
for v in V:
    for (spl, fo), g in o.groupby(["split", "fold"]):
        col, mal = f"sel_{v}_cal1", g.label == 1
        f.append({"variant": v, "split": spl, "fold": fo, "thr": thr[(v, spl, fo)], "tp": int((g[col] & mal).sum()), "fp": int((g[col] & ~mal).sum())})
F = pd.DataFrame(f); F.to_csv(HERE / "blend_fold_cal1.csv", index=False)
print("\n===== cal1 per fold TP / FP"); print(F.pivot_table(index="variant", columns=["split", "fold"], values=["tp", "fp"]).reindex(V).to_string())
print(F.pivot_table(index="variant", columns=["split", "fold"], values="thr").reindex(V).map(lambda x: f"{x:.3g}").to_string())
# ranking (diagnostic)
rk = []
for v in V:
    for (spl, fo), g in o.groupby(["split", "fold"]):
        ex = g[g.campaign != SHAI]
        rk.append({"variant": v, "split": spl, "fold": fo, "roc": roc_auc_score(g.label, g[v]), "pr": average_precision_score(g.label, g[v]),
                   "roc_vs_hard": roc_auc_score(g[g["class"] != "benign"].label, g[g["class"] != "benign"][v]),
                   "pr_excl_shai": average_precision_score(ex.label, ex[v])})
RK = pd.DataFrame(rk); RK.to_csv(HERE / "blend_ranking.csv", index=False)
for col in ["roc", "pr", "roc_vs_hard", "pr_excl_shai"]:
    print(f"== {col} (diagnostic)"); print(RK.pivot_table(index="variant", columns=["split", "fold"], values=col).reindex(V).round(4).to_string())
# mini40 & campaign score medians, rank percentile
o["dummy"] = 0
for v in V: o[f"pct_{v}"] = o.groupby(["split", "fold"])[v].rank(ascending=False, pct=True)
grp = {"mini40": o.row_id.isin(mini40), "autotel": o.campaign == "autotel-node-env-resolver_2026-06", "miasma": o.campaign == "miasma_2026-06",
       "chaindrop": o.campaign == "chaindrop_2026-08", "shai": o.campaign == SHAI, "hard_benign": o["class"] == "hard_benign"}
out = []
for nm, msk in grp.items():
    for spl in ["split1", "split2"]:
        g = o[msk & (o.split == spl)]
        out.append({"group": nm, "split": spl, **{f"med_{v}": round(g[v].median(), 4) for v in V}, **{f"rankpct_{v}": round(g[f"pct_{v}"].median(), 3) for v in ["full29", "full35", "A2"]}})
print("\n== group median scores / median in-fold rank percentile"); print(pd.DataFrame(out).to_string(index=False))
o.to_csv(HERE / "blend_outer_rows.csv", index=False)
