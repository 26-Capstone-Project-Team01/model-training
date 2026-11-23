import sys; sys.path.insert(0, ".")
import common as c, numpy as np, pandas as pd, lightgbm as lgb
pd.set_option("display.width", 250); pd.set_option("display.max_rows", 400)
OUT = c.HERE / "out"
df = c.frame(); sp = c.splits()

def fitrows(split, fold, stage="fit"):
    ids = sp[(sp.split == split) & (sp.fold == fold) & (sp.stage == stage)].row_id
    return df.loc[ids.values]

def splits_on(variant, split, fold, feat):
    p, cols = c.model_path(variant, split, fold)
    t = lgb.Booster(model_file=str(p)).trees_to_dataframe()
    t = t[t.split_feature.notna()]
    by = t.groupby("split_feature").agg(n=("split_gain", "size"), gain=("split_gain", "sum"))
    by["share"] = by.gain / by.gain.sum()
    f = t[t.split_feature == feat]
    root = t[t.node_depth == 1].split_feature.value_counts().head(4).to_dict()
    return by.sort_values("gain", ascending=False), f, root

# --- mini40 / Proc: split2 fold1
fit = fitrows("split2", 1)
print("split2 fold1 fit:", len(fit), "malicious", int(fit.label.sum()))
g = fit.assign(grp=np.where(fit.label == 1, fit.campaign.map(c.FOCUS).fillna(fit.campaign.str[:16]), fit["class"]))
print("Proc distribution in fit by group:"); print(pd.crosstab(g.grp, g[c.PROC].fillna(-1).clip(upper=9)).to_string())
print("\nP(malicious | Proc) in fit:"); print(fit.groupby(fit[c.PROC] > 0).label.agg(["size", "sum", "mean"]).to_string())
hex_hi = fit.obfHexIdentRatioNew > 0.3
print("\nfit rows obfHexIdentRatioNew>0.3, by Proc>0 x group:"); print(pd.crosstab(g[hex_hi].grp, fit[hex_hi][c.PROC] > 0).to_string())
nohook = ~fit.installScriptAdded.astype(bool) & ~fit.scriptEntryAdded.astype(bool)
print("\nfit no-hook rows (installScriptAdded=F & scriptEntryAdded=F): label by Proc>0, Net>0"); print(pd.crosstab([g[nohook].grp], [fit[nohook][c.PROC] > 0]).to_string())
for v in ["full29", "full29_proc", "full35"]:
    by, f, root = splits_on(v, "split2", 1, c.PROC)
    print(f"\n[{v} split2 fold1] top gain features:", by.head(6)[["n", "share"]].round(3).to_dict("index"))
    print("  root splits:", root)
    if len(f):
        print("  Proc splits:", len(f), "thresholds:", f.threshold.round(2).value_counts().to_dict(), "depth:", f.node_depth.value_counts().sort_index().to_dict(),
              "gain share:", round(float(f.split_gain.sum() / by.gain.sum()), 3))
by29, _, _ = splits_on("full29", "split2", 1, c.PROC); byp, _, _ = splits_on("full29_proc", "split2", 1, c.PROC)
cmpd = pd.DataFrame({"full29_share": by29.share, "proc_share": byp.share, "full29_n": by29.n, "proc_n": byp.n}).fillna(0)
cmpd["d_share"] = cmpd.proc_share - cmpd.full29_share
print("\nsplit2 fold1 gain share change full29 -> +Proc (top 8 |d|):"); print(cmpd.reindex(cmpd.d_share.abs().sort_values(ascending=False).index).head(8).round(3).to_string())
cmpd.to_csv(OUT / "gain_share_split2_fold1_full29_vs_proc.csv")

# outer of split2 fold1: normal/hard benign Proc
outer = fitrows("split2", 1, "outer")
print("\nsplit2 fold1 OUTER: Proc>0 by class:", outer.groupby("class")[c.PROC].apply(lambda v: f"{int((v>0).sum())}/{len(v)}").to_dict())
cal = fitrows("split2", 1, "calibration")
print("split2 fold1 CAL: Proc>0 by class:", cal.groupby("class")[c.PROC].apply(lambda v: f"{int((v>0).sum())}/{len(v)}").to_dict())

# --- chaindrop: split1 fold1 Net
fit = fitrows("split1", 1); g = fit.assign(grp=np.where(fit.label == 1, fit.campaign.map(c.FOCUS).fillna(fit.campaign.str[:16]), fit["class"]))
print("\nsplit1 fold1 fit Net distribution:"); print(pd.crosstab(g.grp, pd.cut(fit[c.NET], [-1, 0, 1, 5, 11, 14, 17, 300])).to_string())
_, f, _ = splits_on("full29_net", "split1", 1, c.NET)
print("  +Net split1 fold1 Net thresholds:", f.threshold.round(2).value_counts().head(6).to_dict())
# --- autotel/miasma & shai-orig: fold2 fits
for spl in ["split1", "split2"]:
    fit = fitrows(spl, 2); g = fit.assign(grp=np.where(fit.label == 1, fit.campaign.map(c.FOCUS).fillna(fit.campaign.str[:16]), fit["class"]))
    t = g.groupby("grp").agg(n=("label", "size"), net_pos=(c.NET, lambda v: round(float((v > 0).mean()), 2)),
                             proc_pos=(c.PROC, lambda v: round(float((v > 0).mean()), 2)), ref_pos=(c.REF, lambda v: round(float((v > 0).mean()), 2)),
                             ws_cc_pos=("obfWhitespaceRatioChangedCode", lambda v: round(float((v > 0).mean()), 2)))
    print(f"\n{spl} fold2 fit (outer = shai-orig, autotel, miasma):"); print(t.to_string())
    mal = fit[fit.label == 1]
    print("  fit malicious with Net=0:", int((mal[c.NET] == 0).sum()), "of", len(mal), "| benign+hard with Net=0:", int((fit[fit.label == 0][c.NET] == 0).sum()), "of", int((fit.label == 0).sum()))
    print("  fit malicious with ALL X1 = 0:", int((mal[[c.REF, c.PROC, c.NET]].fillna(0) == 0).all(axis=1).sum()))
    _, f, _ = splits_on("full29_net", spl, 2, c.NET); print("  +Net Net thresholds:", f.threshold.round(2).value_counts().head(5).to_dict())
