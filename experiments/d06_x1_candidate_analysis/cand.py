"""Candidate analysis on exp/d06-x1-fair-compare (55ced8c). Saved scores + saved calibration thresholds only. No training, no Test.

Usage: python -I -B experiments/d06_x1_candidate_analysis/cand.py  (writes 9 CSVs next to this file)
Scores are read with the pandas default float parser (same as fair.py); thresholds with float_precision="round_trip".
See README.md section 4."""
import sys; from pathlib import Path
HERE = Path(__file__).resolve().parent
R = HERE.parent; sys.path.insert(0, str(R / "d06_x1_cause_analysis"))  # experiments/ (repo-relative)
import common as c, numpy as np, pandas as pd
pd.set_option("display.width", 250); pd.set_option("display.max_rows", 500); pd.set_option("display.max_columns", 40)
OUT = HERE
df = c.frame()
s13 = pd.read_csv(R / "d06_feature_comparison_18/scores/saved_scores.csv")[["model", "seed", "fold", "stage", "row_id", "score"]].rename(columns={"model": "variant"})
s35 = pd.read_csv(R / "d06_full35_compare/run/scores.csv"); s35 = s35[s35.variant == "full35"][["variant", "seed", "fold", "stage", "row_id", "score"]]
K = ["seed", "fold", "stage", "row_id"]
w = pd.concat([s13, s35]).pivot_table(index=K, columns="variant", values="score").reset_index()
for k, a in {"A1": .1, "A2": .2, "A3": .3}.items(): w[k] = (1 - a) * w.full29 + a * w.full35
w["split"] = w.seed.map(c.SEED)
o = w[w.stage == "outer"].merge(df[["row_id", "package", "new_version", "label", "class", "campaign", "component", "type"]], on="row_id")
CI = pd.read_csv(R / "d06_x1_fair_compare/calibration_attainment.csv", float_precision="round_trip")
V = ["base7", "full29", "no_interval28", "full35", "A1", "A2", "A3"]; TG = [0.01, 0.03, 0.05]; OPN = {0.01: "calFPR1%", 0.03: "calFPR3%", 0.05: "calFPR5%"}
for v in V:
    for t in TG:
        th = CI[(CI.variant == v) & (CI.target == t)].set_index(["split", "fold"]).threshold
        o[f"sel_{v}_{t}"] = o[v].values >= np.array([th.loc[(s, f)] for s, f in zip(o.split, o.fold)])
# ---- consistency with fair_comparison.csv
FC = pd.read_csv(R / "d06_x1_fair_compare/fair_comparison.csv"); bad = 0
for v in V:
    for t in TG:
        for spl, g in o.groupby("split"):
            sel, mal = g[f"sel_{v}_{t}"], g.label == 1
            r = FC[(FC.op == OPN[t]) & (FC.variant == v) & (FC.split == spl)].iloc[0]
            bad += int((sel & mal).sum() != r.TP or (sel & ~mal).sum() != r.FP)
print("consistency with fair_comparison.csv: mismatches =", bad)
# scores parsed exactly as fair.py (default parser); thresholds read round_trip
# ---- 2a. gained / lost vs full29
rows, cases = [], []
for t in TG:
    for v in ["full35", "A1", "A2", "A3"]:
        for spl, g in o.groupby("split"):
            a, b, mal = g[f"sel_full29_{t}"], g[f"sel_{v}_{t}"], g.label == 1
            ben, hard = g["class"] == "benign", g["class"] == "hard_benign"
            gain, lost = mal & b & ~a, mal & a & ~b
            top = g[gain].campaign.value_counts()
            rows.append({"op": OPN[t], "variant": v, "split": spl, "TP_full29": int((a & mal).sum()), "TP_v": int((b & mal).sum()),
                         "gained": int(gain.sum()), "lost": int(lost.sum()), "net": int(gain.sum() - lost.sum()),
                         "gained_top_campaign": f"{top.index[0][:28]}:{top.iloc[0]}" if len(top) else "", "gained_top_share": round(top.iloc[0] / top.sum(), 2) if len(top) else np.nan,
                         "benignFP_full29": int((a & ben).sum()), "benignFP_v": int((b & ben).sum()), "hardFP_full29": int((a & hard).sum()), "hardFP_v": int((b & hard).sum()),
                         "fp_added": int((~mal & b & ~a).sum()), "fp_removed": int((~mal & a & ~b).sum())})
            for kind, m in [("gained", gain), ("lost", lost)]:
                sub = g[m]
                cases.append(sub.assign(op=OPN[t], variant=v, change=kind, score_v=sub[v])[["op", "variant", "change", "split", "fold", "row_id", "package", "new_version", "campaign", "type", "full29", "full35", "score_v"]])
G = pd.DataFrame(rows); G.to_csv(OUT / "gain_loss_vs_full29.csv", index=False)
pd.concat(cases, ignore_index=True).to_csv(OUT / "gain_loss_cases.csv", index=False)
print("\n== 2a gained/lost vs full29"); print(G.to_string(index=False))
# ---- 2b. campaign table
cr = []
for t in TG:
    for spl, g in o[o.label == 1].groupby("split"):
        for camp, h in g.groupby("campaign"):
            d = {"op": OPN[t], "split": spl, "campaign": camp, "n": len(h), "fold": ",".join(map(str, sorted(h.fold.unique())))}
            for v in ["full29", "full35", "A1", "A2", "A3"]: d[f"TP_{v}"] = int(h[f"sel_{v}_{t}"].sum())
            cr.append(d)
CR = pd.DataFrame(cr)
for v in ["full35", "A1", "A2", "A3"]: CR[f"d_{v}"] = CR[f"TP_{v}"] - CR.TP_full29
CR.to_csv(OUT / "campaign_tp_by_op.csv", index=False)
for t in TG:
    x = CR[(CR.op == OPN[t]) & (CR[["d_full35", "d_A1", "d_A2", "d_A3"]] != 0).any(axis=1)]
    print(f"\n== 2b campaigns with change, {OPN[t]}"); print(x.drop(columns="op").to_string(index=False))
# concentration: share of net gain from shai-hulud-original
SH = "shai-hulud-original_2025-09"
con = CR.groupby(["op", "split"]).apply(lambda x: pd.Series({**{f"net_{v}": int(x[f"d_{v}"].sum()) for v in ["full35", "A1", "A2", "A3"]},
                                                             **{f"net_{v}_exShai": int(x[x.campaign != SH][f"d_{v}"].sum()) for v in ["full35", "A1", "A2", "A3"]}}))
print("\n== 2c net TP change total vs excluding shai-hulud-original"); print(con.to_string())
con.to_csv(OUT / "net_gain_concentration.csv")
# campaign recall change counts (n>=5)
cc = []
for (op, spl), x in CR[CR.n >= 5].groupby(["op", "split"]):
    for v in ["full35", "A1", "A2", "A3"]:
        cc.append({"op": op, "split": spl, "variant": v, "campaigns": len(x), "up": int((x[f"d_{v}"] > 0).sum()), "down": int((x[f"d_{v}"] < 0).sum()), "same": int((x[f"d_{v}"] == 0).sum())})
CC = pd.DataFrame(cc); CC.to_csv(OUT / "campaign_direction_counts.csv", index=False)
print("\n== 2d campaigns (n>=5) recall up/down vs full29"); print(CC.pivot_table(index=["op", "variant"], columns="split", values=["up", "down", "same"]).to_string())
# ---- 3. threshold stability
ts = CI.groupby(["variant", "target"]).threshold.agg(["min", "max", "mean", "std"]).reset_index()
ts["max_over_min"] = ts["max"] / ts["min"]; ts.to_csv(OUT / "threshold_stats.csv", index=False)
print("\n== 3a threshold stats over 6 split-folds"); print(ts.to_string(index=False, float_format=lambda x: f"{x:.3g}"))
pf = []
for v in V:
    for t in TG:
        for (spl, fo), g in o.groupby(["split", "fold"]):
            sel, mal = g[f"sel_{v}_{t}"], g.label == 1
            ci = CI[(CI.variant == v) & (CI.target == t) & (CI.split == spl) & (CI.fold == fo)].iloc[0]
            pf.append({"variant": v, "target": t, "split": spl, "fold": fo, "threshold": ci.threshold, "cal_fpr": ci.achieved_cal_fpr,
                       "outer_fpr": (sel & ~mal).sum() / (~mal).sum(), "outer_fp": int((sel & ~mal).sum()), "outer_hard_fp": int((sel & (g["class"] == "hard_benign")).sum()),
                       "tp": int((sel & mal).sum()), "mal": int(mal.sum()), "recall": (sel & mal).sum() / mal.sum()})
PF = pd.DataFrame(pf); PF["fpr_gap"] = PF.outer_fpr - PF.cal_fpr; PF.to_csv(OUT / "per_fold_operating.csv", index=False)
for t in TG:
    x = PF[PF.target == t]
    print(f"\n== 3b per fold, target {t}: recall / outer FPR% (cal FPR {x.cal_fpr.min():.4f}~{x.cal_fpr.max():.4f})")
    p = x.assign(cell=lambda d: d.recall.map("{:.3f}".format) + " / " + (d.outer_fpr * 100).map("{:.2f}".format)).pivot_table(index="variant", columns=["split", "fold"], values="cell", aggfunc="first").reindex(V)
    print(p.to_string())
gap = PF.groupby(["variant", "target"]).fpr_gap.agg(["mean", "min", "max"]).reset_index(); gap.to_csv(OUT / "fpr_gap_stats.csv", index=False)
print("\n== 3c outer FPR - calibration FPR (pp)"); print(gap.assign(**{k: gap[k] * 100 for k in ["mean", "min", "max"]}).round(2).to_string(index=False))
o.to_csv(OUT / "outer_rows_with_selections.csv", index=False)
