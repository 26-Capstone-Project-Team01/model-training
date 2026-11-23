import sys; sys.path.insert(0, ".")
import common as c, numpy as np, pandas as pd
pd.set_option("display.width", 250); pd.set_option("display.max_rows", 400); pd.set_option("display.max_columns", 40)
OUT = c.HERE / "out"; OUT.mkdir(exist_ok=True)
df = c.frame(); s = c.scores(); sp = c.splits()
o = s[s.stage == "outer"].merge(df[["row_id", "label", "class", "campaign", "short", "type", "package"]], on="row_id")
# 1. per campaign x variant x split: TP at 0.05/0.5, median score (outer fold of that campaign)
rows = []
for (v, spl, camp), g in o[o.label == 1].groupby(["variant", "split", "campaign"]):
    rows.append({"variant": v, "split": spl, "campaign": camp, "n": len(g), "fold": ",".join(map(str, sorted(g.fold.unique()))),
                 "tp05": int((g.score >= .05).sum()), "tp50": int((g.score >= .5).sum()), "median": g.score.median()})
camp = pd.DataFrame(rows); camp.to_csv(OUT / "campaign_tp_by_variant.csv", index=False)
foc = camp[camp.campaign.isin(c.FOCUS)].assign(c=lambda x: x.campaign.map(c.FOCUS))
print(foc.pivot_table(index=["c", "fold", "n", "split"], columns="variant", values=["tp05", "tp50"]).reindex(columns=c.VARS, level=1).to_string())
print(foc.pivot_table(index=["c", "split"], columns="variant", values="median").reindex(columns=c.VARS).round(3).to_string())
# 2. X1 distribution per focus campaign (+ classes)
def x1prof(g):
    d = {"n": len(g)}
    for f in c.X1:
        v = g[f]; d[f[:18] + ">0"] = round(float((v > 0).mean()), 2); d[f[:18] + " NaN"] = int(v.isna().sum())
        if f in (c.PROC, c.NET, "installHookNewProgramCount"): d[f[:14] + " vals"] = dict(v.value_counts().sort_index().head(6).items())
    return pd.Series(d)
grp = df.assign(g=np.where(df.label == 1, df.short.replace("", "other_mal"), df["class"]))
print(grp.groupby("g").apply(x1prof).T.to_string())
# 3. key 29 features
key = ["installScriptPresent", "installScriptAdded", "scriptEntryAdded", "newDependencyAdded", "newDependencyCount", "updateInterval",
       "obfChangedFileCount", "obfWhitespaceRatioChangedCode", "obfHexIdentRatioNew", "obfBracketAccessRatioChangedCode", "obfEscapeDensityChangedCode"]
summ = grp.groupby("g")[key].agg(lambda v: round(float(v.astype(float).median()), 4) if v.dtype != bool else round(float(v.mean()), 2))
summ["updateType"] = grp.groupby("g").updateType.agg(lambda v: v.value_counts().to_dict())
print(summ.T.to_string())
# 4. fit composition per split/fold: malicious campaigns
f = sp[sp.stage == "fit"].merge(df[["row_id", "label", "campaign", "class"]], on="row_id")
comp = f[f.label == 1].groupby(["split", "fold", "campaign"]).size().rename("n").reset_index()
comp.to_csv(OUT / "fit_malicious_campaigns.csv", index=False)
for (a, b), g in comp.groupby(["split", "fold"]):
    g = g.sort_values("n", ascending=False)
    print(a, b, "fit mal", g.n.sum(), "|", ", ".join(f"{c.FOCUS.get(x, x[:14])}:{n}" for x, n in zip(g.campaign.head(6), g.n.head(6))), f"(+{len(g)-6} more)" if len(g) > 6 else "")
