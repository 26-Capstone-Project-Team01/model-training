"""Read-only D08 dataset analysis (no model training / inference). Inputs: files copied from the D08 tag (2c48bd8), D06 (be87ab4c), D07-B (c5b4d32).
Test is used only for integrity / split / leakage checks. Writes CSV/JSON tables to <out>.
"""
import json, sys, math
from pathlib import Path
import numpy as np
import pandas as pd
from scipy import stats

IN = Path(sys.argv[1]); OUT = Path(sys.argv[2]); OUT.mkdir(parents=True, exist_ok=True)
KEY = ["package", "old_version", "new_version"]
def rd(n): return pd.read_csv(IN / n, keep_default_na=False, dtype=str)

tr, te = rd("d08_train.csv"), rd("d08_test.csv")
sa, bl, gr = rd("d08_split_assignment.csv"), rd("d08_baselines.csv"), rd("d08_groups.csv")
d06tr, d06te, d07te = rd("d06_train.csv"), rd("d06_test.csv"), rd("d07b_test.csv")
d06gr = rd("d06_groups.csv")
FEATS = [c for c in tr.columns if c not in KEY + ["label"]]
NUM = [f for f in FEATS if f != "updateType"]
BOOL = ["installScriptPresent", "installScriptAdded", "scriptEntryAdded", "newDependencyAdded"]
res = {}

def numeric(df):
    x = df.copy()
    for c in NUM:
        x[c] = pd.to_numeric(x[c].replace({"True": "1", "False": "0", "": np.nan}))
    x["label"] = x.label.astype(int)
    return x

def attach(df):
    m = df.merge(sa[KEY + ["class", "splitGroup", "split", "assignedBy"]], on=KEY, how="left", validate="one_to_one")
    m = m.merge(gr[KEY + ["campaign", "largestChangedJsSha1", "changedJsSetSha1", "changedJsFileCount", "addedDependencies", "addedInstallHooks"]], on=KEY, how="left")
    m = m.merge(bl[KEY + ["old_source", "level", "baseline_changed", "verified", "campaign"]].rename(columns={"campaign": "bl_campaign"}), on=KEY, how="left")
    return m

TR, TE = attach(numeric(tr)), attach(numeric(te))
TR["cls"] = TR["class"]; TE["cls"] = TE["class"]

# ---------------- A. basic validation
A = {}
A["rows"] = {"train": len(tr), "test": len(te)}
A["class_counts"] = {"train": TR.cls.value_counts().to_dict(), "test": TE.cls.value_counts().to_dict()}
A["label_vs_class_mismatch"] = {s: int(((d.label == 1) != (d.cls == "malicious")).sum()) for s, d in [("train", TR), ("test", TE)]}
A["label_values"] = {s: sorted(d.label.unique().tolist()) for s, d in [("train", tr), ("test", te)]}
A["dup_full_rows"] = {s: int(d.duplicated().sum()) for s, d in [("train", tr), ("test", te)]}
A["dup_keys"] = {s: int(d.duplicated(KEY).sum()) for s, d in [("train", tr), ("test", te)]}
A["dup_keys_ignoring_case"] = {s: int(d[KEY].apply(lambda c: c.str.lower()).duplicated().sum()) for s, d in [("train", tr), ("test", te)]}
A["same_package_old_eq_new"] = {s: int((d.old_version == d.new_version).sum()) for s, d in [("train", tr), ("test", te)]}
A["missing_cells_by_column_train"] = {c: int((tr[c] == "").sum()) for c in tr.columns if (tr[c] == "").any()}
A["missing_cells_by_column_test"] = {c: int((te[c] == "").sum()) for c in te.columns if (te[c] == "").any()}
A["assignment_missing"] = {s: int(d.cls.isna().sum()) for s, d in [("train", TR), ("test", TE)]}
A["split_assignment_consistency"] = {"train_rows_assigned_test": int((TR.split != "train").sum()), "test_rows_assigned_train": int((TE.split != "test").sum())}
# preservation vs D06 / D07-B
def preserved(old, new):
    k_old = old.set_index(KEY); k_new = new.set_index(KEY)
    common = k_old.index.intersection(k_new.index)
    same = (k_old.loc[common].sort_index() == k_new.loc[common][k_old.columns].sort_index()).all(axis=1)
    return {"old_rows": len(old), "present_in_new": len(common), "identical_values": int(same.sum()), "missing_from_new": len(old) - len(common)}
A["preserve_d06_train_in_d08_train"] = preserved(d06tr, tr)
A["preserve_d07b_test_in_d08_test"] = preserved(d07te, te)
A["d06_test_rows_in_d08_test"] = preserved(d06te, te)
A["d06_test_rows_in_d08_train"] = int(len(set(map(tuple, d06te[KEY].values)) & set(map(tuple, tr[KEY].values))))
new_tr = TR[~TR.set_index(KEY).index.isin(d06tr.set_index(KEY).index)]
A["new_train_rows_vs_d06"] = {"total": len(new_tr), "by_class": new_tr.cls.value_counts().to_dict(), "by_campaign": new_tr.campaign.value_counts().to_dict()}
new_te = TE[~TE.set_index(KEY).index.isin(d07te.set_index(KEY).index)]
A["new_test_rows_vs_d07b"] = new_te[KEY + ["campaign"]].values.tolist()
# leakage
def pv(df):
    s = set()
    for r in df[KEY].itertuples(index=False):
        s.add((r[0], r[1])); s.add((r[0], r[2]))
    return s
L = {}
L["key"] = len(set(map(tuple, tr[KEY].values)) & set(map(tuple, te[KEY].values)))
L["package"] = len(set(tr.package) & set(te.package))
L["package_version"] = len(pv(tr) & pv(te))
for h in ["largestChangedJsSha1", "changedJsSetSha1"]:
    L[h] = len({v for v in TR[h].dropna() if v} & {v for v in TE[h].dropna() if v})
sgt, sge = {v for v in TR.splitGroup.dropna() if v}, {v for v in TE.splitGroup.dropna() if v}
L["splitGroup"] = sorted(sgt & sge)
L["campaign"] = sorted({v for v in TR.campaign.dropna() if v} & {v for v in TE.campaign.dropna() if v})
fv = lambda d: d[FEATS].astype(str).agg("|".join, axis=1)
TR["fvec"], TE["fvec"] = fv(tr), fv(te)
both = set(TR.fvec) & set(TE.fvec)
L["identical_29_feature_vector_train_test"] = {"vectors": len(both), "test_rows": int(TE.fvec.isin(both).sum()), "test_rows_by_class": TE[TE.fvec.isin(both)].cls.value_counts().to_dict(),
                                              "label_conflicts": int(sum(TR[TR.fvec == v].label.iloc[0] != TE[TE.fvec == v].label.iloc[0] for v in both))}
# benign package that is malicious elsewhere
malpk_tr, malpk_te = set(TR[TR.cls == "malicious"].package), set(TE[TE.cls == "malicious"].package)
L["benign_train_pkg_in_malicious_test"] = len(set(TR[TR.cls != "malicious"].package) & malpk_te)
L["benign_test_pkg_in_malicious_train"] = len(set(TE[TE.cls != "malicious"].package) & malpk_tr)
L["benign_pkg_also_malicious_within_train"] = sorted(set(TR[TR.cls != "malicious"].package) & malpk_tr)
A["leakage"] = L
res["A"] = A

# ---------------- B. campaign / payload
B = {}
M = TR[TR.cls == "malicious"].copy()
B["train_malicious_by_splitGroup"] = M.splitGroup.value_counts().to_dict()
B["train_malicious_by_campaign"] = M.campaign.value_counts().to_dict()
B["test_malicious_by_splitGroup"] = TE[TE.cls == "malicious"].splitGroup.value_counts().to_dict()
sh = M.splitGroup.value_counts(normalize=True)
B["concentration"] = {"groups": int(M.splitGroup.nunique()), "top1_share": float(sh.iloc[0]), "top3_share": float(sh.iloc[:3].sum()), "top4_share": float(sh.iloc[:4].sum()),
                      "hhi": float((sh ** 2).sum()), "effective_groups": float(1 / (sh ** 2).sum())}
d06m = numeric(d06tr).merge(d06gr[KEY + ["splitGroup", "largestChangedJsSha1", "changedJsSetSha1"]], on=KEY, how="left")
d06m = d06m[d06m.label == 1]
sh6 = d06m.splitGroup.value_counts(normalize=True)
B["concentration_d06"] = {"groups": int(d06m.splitGroup.nunique()), "top1_share": float(sh6.iloc[0]), "top3_share": float(sh6.iloc[:3].sum()), "hhi": float((sh6 ** 2).sum()), "effective_groups": float(1 / (sh6 ** 2).sum())}
for name, d in [("d08", M), ("d06", d06m)]:
    ppk = d.package.value_counts()
    B[f"packages_{name}"] = {"unique_packages": int(d.package.nunique()), "pairs_per_package": {k: int(v) for k, v in ppk.describe().items() if k != "count"},
                              "packages_with_ge5_pairs": int((ppk >= 5).sum()), "top5": ppk.head(5).to_dict()}
    for h in ["largestChangedJsSha1", "changedJsSetSha1"]:
        v = d[h].replace("", np.nan)
        vc = v.value_counts()
        B[f"{h}_{name}"] = {"rows_with_hash": int(v.notna().sum()), "rows_empty": int(v.isna().sum()), "unique": int(v.nunique()), "top1_rows": int(vc.iloc[0]),
                            "top5_rows": int(vc.iloc[:5].sum()), "hashes_used_once": int((vc == 1).sum()),
                            "rows_in_hashes_with_ge10_rows": int(vc[vc >= 10].sum())}
# payload per group
pg = M.groupby("splitGroup").agg(pairs=("package", "size"), packages=("package", "nunique"), largest_hash_unique=("largestChangedJsSha1", lambda s: s.replace("", np.nan).nunique()),
                                 set_hash_unique=("changedJsSetSha1", lambda s: s.replace("", np.nan).nunique()), unique_feature_vectors=("fvec", "nunique")).sort_values("pairs", ascending=False)
pg["pairs_per_unique_vector"] = pg.pairs / pg.unique_feature_vectors
pg.to_csv(OUT / "B_group_diversity_train.csv")
# duplicate feature vectors
dv = {}
for c in ["malicious", "benign", "hard_benign"]:
    d = TR[TR.cls == c]
    dv[c] = {"rows": len(d), "unique_vectors": int(d.fvec.nunique()), "rows_in_repeated_vectors": int(d.fvec.duplicated(keep=False).sum()),
             "max_repeat": int(d.fvec.value_counts().iloc[0])}
xv = TR.groupby("fvec").cls.nunique()
dv["vectors_shared_across_classes"] = int((xv > 1).sum())
dv["rows_in_cross_class_vectors"] = int(TR.fvec.isin(xv[xv > 1].index).sum())
dv["cross_class_rows_by_class"] = TR[TR.fvec.isin(xv[xv > 1].index)].cls.value_counts().to_dict()
d6 = numeric(d06tr); d6["fvec"] = fv(d06tr)
dv["d06_malicious_unique_vectors"] = int(d6[d6.label == 1].fvec.nunique()); dv["d06_malicious_rows"] = int((d6.label == 1).sum())
B["duplicate_feature_vectors_train"] = dv
# diversity growth
newm = M[~M.set_index(KEY).index.isin(d06tr.set_index(KEY).index)]
B["diversity_growth"] = {"new_malicious_rows": len(newm), "new_unique_vectors": int(newm.fvec.nunique()),
                         "new_vectors_not_in_d06": int(len(set(newm.fvec) - set(d6[d6.label == 1].fvec))),
                         "new_largest_hash_unique": int(newm.largestChangedJsSha1.replace("", np.nan).nunique()),
                         "new_largest_hash_not_in_d06": int(len(set(newm.largestChangedJsSha1.replace("", np.nan).dropna()) - set(d06m.largestChangedJsSha1.replace("", np.nan).dropna()))),
                         "new_packages": int(newm.package.nunique()), "new_packages_not_in_d06": int(len(set(newm.package) - set(d06m.package))),
                         "new_rows_by_group": newm.splitGroup.value_counts().to_dict(), "new_groups": sorted(set(newm.splitGroup) - set(d06m.splitGroup))}
res["B"] = B

# ---------------- C. features
rows = []
for f in FEATS:
    for c in ["malicious", "benign", "hard_benign"]:
        s = TR[TR.cls == c][f]
        if f == "updateType":
            vc = s.value_counts(normalize=True)
            rows.append({"feature": f, "class": c, "dtype": "category", "n": len(s), "missing": int(s.isna().sum()), "nunique": int(s.nunique()),
                         "major": vc.get("major", 0), "minor": vc.get("minor", 0), "patch": vc.get("patch", 0)})
            continue
        q = s.quantile([0, .25, .5, .75, 1])
        iqr = q[.75] - q[.25]
        rows.append({"feature": f, "class": c, "dtype": "bool" if f in BOOL else "numeric", "n": len(s), "missing": int(s.isna().sum()), "nunique": int(s.nunique()),
                     "mean": s.mean(), "std": s.std(), "min": q[0], "q25": q[.25], "median": q[.5], "q75": q[.75], "max": q[1],
                     "share_zero": float((s == 0).mean()), "share_top_value": float(s.value_counts(normalize=True).iloc[0]) if s.notna().any() else np.nan,
                     "outlier_share_3iqr": float(((s < q[.25] - 3 * iqr) | (s > q[.75] + 3 * iqr)).mean()) if iqr > 0 else np.nan})
pd.DataFrame(rows).to_csv(OUT / "C_feature_stats_by_class_train.csv", index=False)
sep = []
for f in NUM:
    for a, b in [("malicious", "benign"), ("malicious", "hard_benign"), ("malicious", "all_benign")]:
        xa = TR[TR.cls == a][f]
        xb = TR[TR.cls != "malicious"][f] if b == "all_benign" else TR[TR.cls == b][f]
        y = np.r_[np.ones(xa.notna().sum()), np.zeros(xb.notna().sum())]
        v = np.r_[xa.dropna(), xb.dropna()]
        auc = stats.mannwhitneyu(xa.dropna(), xb.dropna()).statistic / (len(xa.dropna()) * len(xb.dropna())) if len(xa.dropna()) and len(xb.dropna()) else np.nan
        ks = stats.ks_2samp(xa.dropna(), xb.dropna()).statistic if len(xa.dropna()) and len(xb.dropna()) else np.nan
        sep.append({"feature": f, "vs": b, "auc_nonmissing": auc, "auc_strength": abs(auc - .5) * 2 if auc == auc else np.nan, "ks": ks,
                    "missing_rate_mal": float(xa.isna().mean()), "missing_rate_other": float(xb.isna().mean())})
ut = pd.crosstab(TR.cls, TR.updateType, normalize="index")
ut.to_csv(OUT / "C_updateType_by_class_train.csv")
S = pd.DataFrame(sep); S.to_csv(OUT / "C_feature_separation_train.csv", index=False)
corr = TR[NUM].corr(method="spearman")
corr.to_csv(OUT / "C_spearman_train.csv")
pairs = [(a, b, corr.loc[a, b]) for i, a in enumerate(NUM) for b in NUM[i + 1:] if abs(corr.loc[a, b]) >= .9]
pd.DataFrame(pairs, columns=["a", "b", "spearman"]).to_csv(OUT / "C_high_corr_pairs_train.csv", index=False)
# missing structure
miss = TR[NUM].isna()
res["C"] = {"missing_pattern_counts": miss.groupby(TR.cls).sum().loc[:, miss.any()].to_dict(),
            "rows_with_any_missing_by_class": miss.any(axis=1).groupby(TR.cls).mean().to_dict(),
            "changedcode_missing_equals_obfChangedFileCount0": bool((TR.obfHexIdentRatioChangedCode.isna() == (TR.obfChangedFileCount == 0)).all()),
            "high_corr_pairs_ge_0.9": len(pairs)}
# drift D06 -> D08 train (malicious only changes; benign identical)
dr = []
d6n = numeric(d06tr)
for f in NUM:
    a, b = d6n[d6n.label == 1][f].dropna(), TR[TR.cls == "malicious"][f].dropna()
    dr.append({"feature": f, "d06_mal_median": a.median(), "d08_mal_median": b.median(), "d06_mal_mean": a.mean(), "d08_mal_mean": b.mean(),
               "d06_mal_missing": float(d6n[d6n.label == 1][f].isna().mean()), "d08_mal_missing": float(TR[TR.cls == "malicious"][f].isna().mean()),
               "ks_d06_vs_d08_mal": stats.ks_2samp(a, b).statistic})
dd = pd.DataFrame(dr)
d6sep = []
for f in NUM:
    xa, xb = d6n[d6n.label == 1][f].dropna(), d6n[d6n.label == 0][f].dropna()
    d6sep.append({"feature": f, "d06_auc_mal_vs_allbenign": stats.mannwhitneyu(xa, xb).statistic / (len(xa) * len(xb))})
dd = dd.merge(pd.DataFrame(d6sep), on="feature").merge(S[S.vs == "all_benign"][["feature", "auc_nonmissing"]].rename(columns={"auc_nonmissing": "d08_auc_mal_vs_allbenign"}), on="feature")
dd.to_csv(OUT / "C_drift_d06_to_d08_malicious.csv", index=False)
res["C"]["updateType_d06_mal"] = d6n[d6n.label == 1].updateType.value_counts(normalize=True).to_dict()
res["C"]["updateType_d08_mal"] = TR[TR.cls == "malicious"].updateType.value_counts(normalize=True).to_dict()
res["C"]["malicious_share_train"] = {"d06": float((d6n.label == 1).mean()), "d08": float((TR.label == 1).mean())}

# ---------------- D. shortcut rules (Train only)
def rule_eval(name, sel, data, extra=None):
    m, b, h = data.cls == "malicious", data.cls == "benign", data.cls == "hard_benign"
    r = {"rule": name, "recall": float(sel[m].mean()), "benign_fpr": float(sel[b].mean()), "hard_benign_fpr": float(sel[h].mean()), "selected": int(sel.sum())}
    return r
rules = {
    "installScriptAdded": lambda d: d.installScriptAdded == 1,
    "installScriptPresent": lambda d: d.installScriptPresent == 1,
    "scriptEntryAdded": lambda d: d.scriptEntryAdded == 1,
    "installScriptAdded OR newDependencyAdded": lambda d: (d.installScriptAdded == 1) | (d.newDependencyAdded == 1),
    "updateInterval < 1 day": lambda d: d.updateInterval < 86400,
    "updateInterval < 7 days": lambda d: d.updateInterval < 7 * 86400,
    "updateInterval > 90 days": lambda d: d.updateInterval > 90 * 86400,
    "updateType == patch": lambda d: d.updateType == "patch",
    "updateType == major": lambda d: d.updateType == "major",
    "ChangedCode present (obfChangedFileCount > 0)": lambda d: d.obfChangedFileCount > 0,
    "obfChangedFileCount <= 2 and > 0": lambda d: (d.obfChangedFileCount > 0) & (d.obfChangedFileCount <= 2),
    "obfChangedFileCount == 1": lambda d: d.obfChangedFileCount == 1,
    "installScriptAdded AND obfChangedFileCount <= 2": lambda d: (d.installScriptAdded == 1) & (d.obfChangedFileCount <= 2),
    "installScriptAdded AND patch": lambda d: (d.installScriptAdded == 1) & (d.updateType == "patch"),
    "obfHexIdentRatioNew > 0": lambda d: d.obfHexIdentRatioNew > 0,
    "obfEscapeDensityChangedCode > 0.001": lambda d: d.obfEscapeDensityChangedCode > 0.001,
    "obfWhitespaceRatioChangedCode < 0.05": lambda d: d.obfWhitespaceRatioChangedCode < 0.05,
}
rr = []
d6a = attach(numeric(d06tr)) if False else None
d6n["cls"] = np.where(d6n.label == 1, "malicious", "x")
d6c = d6n.merge(pd.concat([rd("d06_train.csv")[KEY]]).assign(), on=KEY)
cls06 = rd("d06_baselines.csv")[KEY + ["class"]]
d6n = d6n.drop(columns="cls").merge(cls06.rename(columns={"class": "cls"}), on=KEY, how="left")
for name, fn in rules.items():
    r = rule_eval(name, fn(TR).fillna(False).astype(bool), TR)
    r6 = rule_eval(name, fn(d6n).fillna(False).astype(bool), d6n)
    r |= {"d06_recall": r6["recall"], "d06_benign_fpr": r6["benign_fpr"], "d06_hard_benign_fpr": r6["hard_benign_fpr"]}
    rr.append(r)
pd.DataFrame(rr).to_csv(OUT / "D_rules_train.csv", index=False)
# best single-threshold stump per feature (Train), both directions, objective = recall at benign FPR <= 5%
st = []
for f in NUM:
    x = TR[f].fillna(-1e18 if True else 0).to_numpy()
    m, b, h = (TR.cls == "malicious").to_numpy(), (TR.cls == "benign").to_numpy(), (TR.cls == "hard_benign").to_numpy()
    best = None
    for direction in (1, -1):
        xs = direction * x
        cand = np.unique(np.quantile(xs[~np.isinf(xs)], np.linspace(0, 1, 201)))
        for t in cand:
            sel = xs >= t
            fpr = sel[b].mean()
            if fpr <= 0.05:
                rec = sel[m].mean()
                if best is None or rec > best[0]:
                    best = (rec, fpr, sel[h].mean(), direction, t * direction)
    if best:
        st.append({"feature": f, "recall_at_benign_fpr_le_5pct": best[0], "benign_fpr": best[1], "hard_benign_fpr": best[2], "direction": ">=" if best[3] == 1 else "<=", "threshold": best[4]})
pd.DataFrame(st).sort_values("recall_at_benign_fpr_le_5pct", ascending=False).to_csv(OUT / "D_best_stump_train.csv", index=False)
# per-campaign recall of top shortcut rules
pc = []
for name in ["installScriptAdded", "installScriptAdded OR newDependencyAdded", "ChangedCode present (obfChangedFileCount > 0)", "updateInterval < 7 days"]:
    sel = rules[name](M).fillna(False).astype(bool)
    for g, s in sel.groupby(M.splitGroup):
        pc.append({"rule": name, "splitGroup": g, "n": len(s), "recall": float(s.mean())})
pd.DataFrame(pc).to_csv(OUT / "D_rules_by_group_train.csv", index=False)
# source of baseline vs features
TR["old_src"] = np.where(TR.old_source.str.startswith("archive:"), "archive", "registry")
res["D"] = {"old_source_by_class": pd.crosstab(TR.cls, TR.old_src).to_dict(), "level_by_class": pd.crosstab(TR.cls, TR.level).to_dict(),
            "baseline_changed_by_class": pd.crosstab(TR.cls, TR.baseline_changed).to_dict(),
            "updateInterval_median_days_by_class_and_level": {f"{a}|{b}": v for (a, b), v in (TR.groupby(["cls", "level"]).updateInterval.median() / 86400).round(2).items()}}
json.dump(res, open(OUT / "summary.json", "w"), indent=1, default=lambda o: o.item() if hasattr(o, "item") else str(o), ensure_ascii=False)
print("done")
