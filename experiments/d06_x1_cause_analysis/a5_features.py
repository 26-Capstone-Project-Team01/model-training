import sys; sys.path.insert(0, ".")
import common as c, numpy as np, pandas as pd
pd.set_option("display.width", 250); pd.set_option("display.max_rows", 400)
OUT = c.HERE / "out"
df = c.frame(); s = c.scores(); sp = c.splits()
o = s[s.stage == "outer"].pivot_table(index=["split", "fold", "row_id"], columns="variant", values="score").reset_index()
o = o.merge(df[["row_id", "label", "class", "campaign", "package", "type", c.REF, c.PROC, c.NET, "installScriptAdded"]], on="row_id")
o["c"] = o.campaign.map(c.FOCUS).fillna(pd.Series(np.where(o.label == 1, o.campaign.str[:18], o["class"]), index=o.index))
rows = []
for v, feat in [("full29_ref", c.REF), ("full29_proc", c.PROC), ("full29_net", c.NET)]:
    for t in [0.05, 0.5]:
        a, b = o.full29 >= t, o[v] >= t
        for kind, m in [("gained", (o.label == 1) & b & ~a), ("lost", (o.label == 1) & ~b & a), ("fp_added", (o.label == 0) & b & ~a), ("fp_removed", (o.label == 0) & ~b & a)]:
            g = o[m]
            for (spl, fo, cc), gg in g.groupby(["split", "fold", "c"]):
                rows.append({"variant": v, "threshold": t, "change": kind, "split": spl, "fold": fo, "group": cc, "n": len(gg),
                             "feat_values": dict(gg[feat].fillna(-1).value_counts().sort_index().items()),
                             "examples": ", ".join(gg.package.head(3))})
ch = pd.DataFrame(rows); ch.to_csv(OUT / "single_feature_changes.csv", index=False)
print(ch[(ch.threshold == 0.05) & (ch.n >= 3)].sort_values(["variant", "change", "n"], ascending=[True, True, False]).to_string(index=False))
# training-fit relation feature value -> label, per split/fold
def binv(feat, v):
    if feat == c.REF: return v.map({1.0: "1", 0.0: "0"}).fillna("NaN")
    return pd.cut(v, [-1, 0, 1, 3, 5, 8, 11, 14, 17, 1000], labels=["0", "1", "2-3", "4-5", "6-8", "9-11", "12-14", "15-17", ">17"]).astype(str)
tab = []
for spl in ["split1", "split2"]:
    for fo in range(3):
        fit = df.loc[sp[(sp.split == spl) & (sp.fold == fo) & (sp.stage == "fit")].row_id.values]
        for feat in [c.REF, c.PROC, c.NET]:
            b = binv(feat, fit[feat])
            for val, g in fit.groupby(b):
                mal = g[g.label == 1]
                tab.append({"split": spl, "fold": fo, "feature": feat, "bin": val, "n": len(g), "malicious": int(g.label.sum()),
                            "p_mal": round(float(g.label.mean()), 3),
                            "top_campaign": (mal.campaign.value_counts().index[0][:20] if len(mal) else ""),
                            "top_campaign_share": (round(float(mal.campaign.value_counts().iloc[0] / len(mal)), 2) if len(mal) else np.nan)})
tab = pd.DataFrame(tab); tab.to_csv(OUT / "fit_feature_label_relation.csv", index=False)
print(tab[tab.feature == c.PROC].pivot_table(index="bin", columns=["split", "fold"], values="p_mal").to_string())
print(tab[(tab.feature == c.PROC) & (tab.bin != "0")].groupby(["split", "fold"]).apply(lambda g: f"mal {g.malicious.sum()}/{g.n.sum()}, top={g.sort_values('malicious').iloc[-1].top_campaign}").to_string())
print(tab[tab.feature == c.NET].pivot_table(index="bin", columns=["split", "fold"], values="p_mal").to_string())
print(tab[tab.feature == c.REF].pivot_table(index="bin", columns=["split", "fold"], values=["p_mal", "n"]).to_string())
# X1-positive malicious concentration (fit vs outer)
conc = []
for spl in ["split1", "split2"]:
    for fo in range(3):
        for stage in ["fit", "outer"]:
            part = df.loc[sp[(sp.split == spl) & (sp.fold == fo) & (sp.stage == stage)].row_id.values]
            mal = part[part.label == 1]
            for feat in [c.REF, c.PROC, c.NET]:
                pos = mal[mal[feat] > 0]
                vc = pos.campaign.value_counts()
                conc.append({"split": spl, "fold": fo, "stage": stage, "feature": feat, "mal_pos": len(pos), "mal_n": len(mal),
                             "campaigns_with_pos": len(vc), "top": vc.index[0][:22] if len(vc) else "", "top_share": round(float(vc.iloc[0] / len(pos)), 2) if len(vc) else np.nan,
                             "normal_pos_rate": round(float((part[part.label == 0][feat] > 0).mean()), 3)})
conc = pd.DataFrame(conc); conc.to_csv(OUT / "x1_positive_concentration.csv", index=False)
print(conc.to_string(index=False))
# campaign-level breadth on all 928: X1 positive in how many campaigns (>=5 pairs), excluding generic buckets
mal = df[(df.label == 1) & ~df.campaign.str.match(r"^(individual-compromise|individuals_case)")]
for feat in [c.REF, c.PROC, c.NET]:
    r = mal.groupby("campaign")[feat].apply(lambda v: (v > 0).mean())
    n = mal.groupby("campaign").size()
    print(feat, "campaigns(n>=5) with >=50% positive:", int(((r >= .5) & (n >= 5)).sum()), "/", int((n >= 5).sum()),
          "| list:", [k[:18] for k in r[(r >= .5) & (n >= 5)].index])
