import sys; sys.path.insert(0, ".")
import common as c, numpy as np, pandas as pd, lightgbm as lgb
pd.set_option("display.width", 250); pd.set_option("display.max_rows", 400)
OUT = c.HERE / "out"
df = c.frame(); s = c.scores(); sp = c.splits()
mini40 = df[(df.campaign == "mini-shai-hulud_2026-05") & (df.type == "B") & (df[c.NET] == 9)]
print("mini B-type with Net=9:", len(mini40), "| all @tanstack:", mini40.package.str.startswith("@tanstack/").all())
# per-campaign Net/Proc values for sha1-hulud
sha = df[df.campaign == "sha1-hulud-second-coming_2025-11"]
print("sha1-hulud Proc:", sha[c.PROC].value_counts().sort_index().to_dict(), "Net:", sha[c.NET].value_counts().sort_index().to_dict(), "Ref:", sha[c.REF].value_counts().to_dict())

def contrib(variant, split, fold, rows):
    p, cols = c.model_path(variant, split, fold)
    b = lgb.Booster(model_file=str(p))
    x = c.matrix(df.loc[rows.index], cols)
    ctb = pd.DataFrame(b.predict(x, pred_contrib=True, num_threads=2), columns=cols + ["bias"], index=rows.index)
    return ctb, b.predict(x, num_threads=2)

def report(name, rows, split, fold, variants=("full29", "full29_proc", "full32", "full35", "full29_net", "full29_ref"), top=8):
    print(f"\n===== {name}: n={len(rows)} {split} fold{fold}")
    allc = {}
    for v in variants:
        ctb, pr = contrib(v, split, fold, rows)
        allc[v] = ctb.mean()
        print(f"{v:12s} score median {np.median(pr):.3f} [min {pr.min():.3f}, max {pr.max():.3f}]  raw logit mean {ctb.sum(axis=1).mean():+.2f}")
    t = pd.DataFrame(allc).fillna(np.nan)
    t["d_proc"] = t.get("full29_proc") - t["full29"] if "full29_proc" in t else np.nan
    t["d_full35"] = t["full35"] - t["full29"]
    order = t.drop(index="bias").abs().max(axis=1).sort_values(ascending=False).index[:top]
    print("mean TreeSHAP contribution (log-odds):"); print(t.loc[list(order) + ["bias"]].round(2).to_string())
    t.to_csv(OUT / f"shap_{name}_{split}_fold{fold}.csv")

report("mini40", mini40, "split2", 1)
report("mini40", mini40, "split1", 1)
shai = df[df.campaign == "shai-hulud-original_2025-09"]
for spl in ["split1", "split2"]:
    report("shai_orig", shai, spl, 2)
for camp, nm in [("autotel-node-env-resolver_2026-06", "autotel"), ("miasma_2026-06", "miasma")]:
    report(nm, df[df.campaign == camp], "split2", 2)
report("chaindrop", df[df.campaign == "chaindrop_2026-08"], "split1", 1)

# example rows for mini40 split2 fold1
ctb29, p29 = contrib("full29", "split2", 1, mini40); ctbp, pp = contrib("full29_proc", "split2", 1, mini40)
ex = mini40[["package", "new_version", "installScriptAdded", "scriptEntryAdded", "newDependencyAdded", "newDependencyCount", c.REF, c.PROC, c.NET,
             "obfBracketAccessRatioChangedCode", "obfHexIdentRatioNew", "updateType"]].copy()
ex["full29"] = p29; ex["+proc"] = pp
for v in ["full32", "full35", "full29_net", "full29_ref"]:
    ex[v] = contrib(v, "split2", 1, mini40)[1]
ex["shap_proc(+proc)"] = ctbp[c.PROC].values
ex.to_csv(OUT / "mini40_split2_fold1_rows.csv", index=False)
print(ex.head(6).round(3).to_string()); print(ex[["full29", "+proc", "full32", "full35", "full29_net", "full29_ref"]].describe().loc[["min", "50%", "max"]].round(3).to_string())
print("mini40 distinct 29-feature profiles:", mini40[[x for x in df.columns if x.startswith("obf")] + ["installScriptAdded", "newDependencyAdded", "updateType"]].round(4).drop_duplicates().shape[0])
