"""M3 selection / M4 weighting candidates: expected counts, effective sample size, group shares (descriptive; full Train and per 5-fold fit part). Read-only."""
import sys, json, re, math
import numpy as np, pandas as pd
IN, FOLDS, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
KEY = ["package", "old_version", "new_version"]
rd = lambda n: pd.read_csv(f"{IN}/{n}", dtype=str, keep_default_na=False)
tr, gr = rd("d08_train.csv"), rd("d08_groups.csv")
fa = pd.read_csv(FOLDS, dtype=str, keep_default_na=False)
T = tr.merge(fa, on=KEY).merge(gr[KEY + ["largestChangedJsSha1", "addedDependencies", "addedInstallHooks"]], on=KEY, how="left").fillna("")
F28 = [c for c in tr.columns if c not in KEY + ["label", "updateInterval"]]
T["v28"] = T[F28].agg("|".join, axis=1)
T["ui"] = pd.to_numeric(T.updateInterval)
def payload(r):
    if r["class"] != "malicious": return ""
    if r.largestChangedJsSha1: return r.largestChangedJsSha1
    sig = r.addedInstallHooks + "|" + r.addedDependencies
    return "nojs:" + sig if sig != "|" else "nojs-empty:" + r.package
T["P"] = T.apply(payload, axis=1)
def vkey(v):
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", v); return tuple(map(int, m.groups())) if m else (9e9,)

def m3(fit, cap="sqrt"):
    """D06 rows all kept. New malicious rows: (1) one row per (package, old_version) = the lowest new_version;
    (2) per payload P, keep new rows up to cap minus D06 rows of P already in fit (>= 1 if P not in fit D06), preferring 28-vectors not yet present."""
    d06 = fit[fit.era == "D06"]; new = fit[(fit.era == "new") & (fit["class"] == "malicious")]
    s1 = new.assign(_v=new.new_version.map(vkey)).sort_values("_v").drop_duplicates(["package", "old_version"])
    keep = []
    for p, g in s1.groupby("P"):
        n_d06 = int((d06.P == p).sum()); n_all = n_d06 + len(g)
        c = len(g) if cap is None else (math.ceil(math.sqrt(n_all)) if cap == "sqrt" else cap)
        room = len(g) if cap is None else max(c - n_d06, 0 if n_d06 else 1)
        seen = set(d06[d06.P == p].v28); picked = []
        for idx, r in g.iterrows():
            if len(picked) >= room: break
            if r.v28 not in seen: picked.append(idx); seen.add(r.v28)
        for idx in g.index:
            if len(picked) >= room: break
            if idx not in picked: picked.append(idx)
        keep += picked
    return pd.concat([d06, fit.loc[keep], fit[(fit.era == "new") & (fit["class"] != "malicious")]])

def m4(fit, mode="sqrt_payload", norm="keep_class_total"):
    w = pd.Series(1.0, index=fit.index); mal = fit["class"] == "malicious"
    n_p = fit[mal].groupby("P").P.transform("size")
    if mode in ("sqrt_payload", "sqrt_payload_x_baseline"):
        w[mal] = 1 / np.sqrt(n_p)
    if mode == "sqrt_payload_x_baseline":
        m_po = fit[mal].groupby(["package", "old_version"]).package.transform("size")
        w[mal] = w[mal] / np.sqrt(m_po)
    if norm == "keep_class_total":
        w[mal] *= mal.sum() / w[mal].sum()
    elif norm == "balance_to_normal":
        w[mal] *= (~mal).sum() / w[mal].sum()
    elif norm == "d06_ratio":  # malicious : normal weight = D06 Train ratio 928 : 1839
        w[mal] *= (~mal).sum() * 928 / 1839 / w[mal].sum()
    return w

def describe(df, w=None):
    mal = df["class"] == "malicious"
    w = pd.Series(1.0, index=df.index) if w is None else w
    wm = w[mal]
    share = (wm.groupby(df.loc[mal, "splitGroup"]).sum() / wm.sum()).sort_values(ascending=False)
    return {"rows": len(df), "mal_rows": int(mal.sum()), "normal_rows": int((~mal).sum()), "mal_weight_sum": round(float(wm.sum()), 1), "normal_weight_sum": round(float(w[~mal].sum()), 1),
            "mal_share_of_weight": round(float(wm.sum() / w.sum()), 3), "mal_kish_neff": round(float(wm.sum() ** 2 / (wm ** 2).sum()), 1),
            "top_group_weight_share": f"{share.index[0]}:{share.iloc[0]:.3f}", "top3_weight_share": round(float(share.iloc[:3].sum()), 3),
            "effective_groups": round(float(1 / (share ** 2).sum()), 2), "unique_P": int(df[mal].P.nunique()), "unique_v28_mal": int(df[mal].v28.nunique())}

R = {"full_train": {}}
full = T
R["full_train"]["M1_D06_only"] = describe(full[full.era == "D06"])
R["full_train"]["M2_all"] = describe(full)
for cap in [None, "sqrt", 20, 5]:
    R["full_train"][f"M3_baseline_dedupe_cap_{cap}"] = describe(m3(full, cap))
for mode in ["sqrt_payload", "sqrt_payload_x_baseline"]:
    for norm in ["keep_class_total", "balance_to_normal", "d06_ratio"]:
        R["full_train"][f"M4_{mode}_{norm}"] = describe(full, m4(full, mode, norm))
# per 5-fold fit (outer only; inner normal-only calibration not removed here, so counts are upper bounds)
per = []
for f in range(5):
    fit = T[T.fold5 != str(f)]
    for name, d, w in [("M1", fit[fit.era == "D06"], None), ("M2", fit, None), ("M3_sqrt", m3(fit, "sqrt"), None), ("M3_cap20", m3(fit, 20), None),
                       ("M4_sqrt_payload_keep", fit, m4(fit, "sqrt_payload", "keep_class_total")), ("M4_sqrt_payload_balance", fit, m4(fit, "sqrt_payload", "balance_to_normal"))]:
        per.append({"fold": f, "variant": name, **describe(d, w)})
pd.DataFrame(per).to_csv(f"{OUT}/m3m4_per_fold.csv", index=False)
json.dump(R, open(f"{OUT}/m3m4_full.json", "w"), indent=1)
print(pd.DataFrame(R["full_train"]).T.to_string())
print(pd.DataFrame(per)[["fold", "variant", "mal_rows", "normal_rows", "mal_share_of_weight", "mal_kish_neff", "top_group_weight_share", "effective_groups", "unique_P"]].to_string(index=False))
