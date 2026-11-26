"""D06 (2,767) vs D08-new (2,577 malicious) information-value analysis. Read-only, no models."""
import sys, json
import numpy as np, pandas as pd
IN = sys.argv[1]; OUT = sys.argv[2]
KEY = ["package", "old_version", "new_version"]
rd = lambda n: pd.read_csv(f"{IN}/{n}", dtype=str, keep_default_na=False)
tr, sa, gr, d6 = rd("d08_train.csv"), rd("d08_split_assignment.csv"), rd("d08_groups.csv"), rd("d06_train.csv")
T = tr.merge(sa[KEY + ["class", "splitGroup"]], on=KEY).merge(gr[KEY + ["campaign", "largestChangedJsSha1", "changedJsSetSha1", "changedJsFileCount", "addedDependencies", "addedInstallHooks"]], on=KEY, how="left")
d6k = set(map(tuple, d6[KEY].values))
T["era"] = np.where(T[KEY].apply(tuple, axis=1).isin(d6k), "D06", "new")
F29 = [c for c in tr.columns if c not in KEY + ["label"]]
F28 = [f for f in F29 if f != "updateInterval"]
CC12 = [f for f in F29 if f.endswith("ChangedCode")] + ["obfChangedFileCount", "installScriptAdded", "scriptEntryAdded", "newDependencyAdded", "newDependencyCount"]
T["v28"] = T[F28].agg("|".join, axis=1)
T["v12"] = T[CC12].agg("|".join, axis=1)
M = T[T["class"] == "malicious"].copy()
N, D = M[M.era == "new"], M[M.era == "D06"]
R = {}
# --- verify ChatGPT numbers
R["new_malicious_rows"] = len(N)
po = N.groupby(["package", "old_version"]).size()
R["new_rows_sharing_package_old_within_new"] = int(po[po > 1].sum())
d6L, d6S = set(D.largestChangedJsSha1) - {""}, set(D.changedJsSetSha1) - {""}
R["new_rows_with_largest_hash_in_D06"] = int(N.largestChangedJsSha1.isin(d6L).sum())
nl = N[(N.largestChangedJsSha1 != "") & ~N.largestChangedJsSha1.isin(d6L)]
R["new_rows_with_new_largest_hash"] = len(nl); R["new_largest_hash_types"] = int(nl.largestChangedJsSha1.nunique())
ns = N[(N.changedJsSetSha1 != "") & ~N.changedJsSetSha1.isin(d6S)]
R["new_rows_with_new_set_hash"] = len(ns); R["new_set_hash_types"] = int(ns.changedJsSetSha1.nunique())
R["new_rows_without_changed_js"] = int((N.largestChangedJsSha1 == "").sum())
R["new_rows_no_js_by_obfChangedFileCount0"] = int((pd.to_numeric(N.obfChangedFileCount) == 0).sum())
R["check_sum_hash_rows"] = R["new_rows_with_largest_hash_in_D06"] + R["new_rows_with_new_largest_hash"] + R["new_rows_without_changed_js"]
# --- 28-vector novelty
d6v28 = set(T[T.era == "D06"].v28)  # all classes of D06
R["new_unique_v28"] = int(N.v28.nunique())
R["new_v28_not_in_D06_any_class"] = int(len(set(N.v28) - d6v28))
R["new_rows_whose_v28_in_D06"] = int(N.v28.isin(d6v28).sum())
R["new_rows_v28_repeated_within_new"] = int(N.v28.duplicated(keep=False).sum())
R["new_v12_unique"] = int(N.v12.nunique()); R["new_v12_not_in_D06_mal"] = int(len(set(N.v12) - set(D.v12)))
R["new_rows_v12_in_D06_mal"] = int(N.v12.isin(set(D.v12)).sum())
# --- diversity within payload (largest hash), new rows
N["payload"] = np.where(N.largestChangedJsSha1 != "", N.largestChangedJsSha1, "nojs:" + N.addedInstallHooks + "|" + N.addedDependencies)
pp = N.groupby("payload").agg(rows=("package", "size"), group=("splitGroup", "first"), packages=("package", "nunique"), baselines=("old_version", lambda s: s.index.size),
                              pkg_old=("package", lambda s: N.loc[s.index, ["package", "old_version"]].drop_duplicates().shape[0]),
                              v28=("v28", "nunique"), v12=("v12", "nunique"), in_D06=("largestChangedJsSha1", lambda s: bool(s.iloc[0] in d6L))).sort_values("rows", ascending=False)
pp.drop(columns="baselines").to_csv(f"{OUT}/new_payload_diversity.csv")
R["payload_clusters_new"] = len(pp); R["top_payload_clusters"] = pp.head(8).drop(columns="baselines").reset_index().to_dict("records")
# --- rows sharing package+baseline+payload+v28
k4 = N.groupby(["package", "old_version", "payload", "v28"]).size()
R["new_rows_sharing_pkg_old_payload_v28"] = int(k4[k4 > 1].sum())
k3 = N.groupby(["package", "old_version", "payload"]).size()
R["new_rows_sharing_pkg_old_payload"] = int(k3[k3 > 1].sum())
# --- similarity new vs D06 (standardised euclidean nearest neighbour on numeric 28, NaN -> -1 indicator)
def mat(df):
    x = df[F28].replace({"True": "1", "False": "0", "": np.nan}).copy()
    x["updateType"] = x.updateType.map({"major": 0, "minor": 1, "patch": 2})
    x = x.apply(pd.to_numeric)
    miss = x.isna().astype(float).add_suffix("_na")
    return pd.concat([x.fillna(0), miss], axis=1)
A = mat(M); mu, sd = A.mean(), A.std().replace(0, 1)
Z = ((A - mu) / sd).to_numpy()
zN, zD = Z[(M.era == "new").to_numpy()], Z[(M.era == "D06").to_numpy()]
nn = np.array([np.sqrt(((zD - r) ** 2).sum(1)).min() for r in zN])
nnD = np.array([np.sqrt(np.delete(((zD - r) ** 2).sum(1), i)).min() for i, r in enumerate(zD)])
R["nn_dist_new_to_D06"] = {"median": float(np.median(nn)), "p10": float(np.quantile(nn, .1)), "p90": float(np.quantile(nn, .9)), "share_exact0": float((nn == 0).mean())}
R["nn_dist_D06_to_D06_reference"] = {"median": float(np.median(nnD)), "p10": float(np.quantile(nnD, .1)), "p90": float(np.quantile(nnD, .9))}
N["nn_to_D06"] = nn
R["nn_by_group_median"] = N.groupby("splitGroup").nn_to_D06.median().round(3).to_dict()
# --- no-JS attacks
nj = N[N.largestChangedJsSha1 == ""]
R["new_nojs"] = {"rows": len(nj), "by_group": nj.splitGroup.value_counts().to_dict(), "hooks": nj.addedInstallHooks.value_counts().head(8).to_dict(),
                 "deps_nonempty": int((nj.addedDependencies != "").sum()), "unique_hook_dep_signatures": int((nj.addedInstallHooks + "|" + nj.addedDependencies).nunique()),
                 "unique_v28": int(nj.v28.nunique()), "mastra_type": int(((pd.to_numeric(nj.obfChangedFileCount) == 0) & (nj.newDependencyAdded == "True") & (nj.installScriptAdded == "False")).sum())}
dj = D[D.largestChangedJsSha1 == ""]
R["d06_nojs"] = {"rows": len(dj), "by_group": dj.splitGroup.value_counts().to_dict(), "unique_hook_dep_signatures": int((dj.addedInstallHooks + "|" + dj.addedDependencies).nunique())}
# --- value tiers (descriptive, full new set; selection itself must be done inside fit folds)
N["new_payload"] = ~N.payload.isin(set(D.largestChangedJsSha1) - {""}) & (N.largestChangedJsSha1 != "")
N["new_group"] = ~N.splitGroup.isin(set(D.splitGroup))
N["v12_new"] = ~N.v12.isin(set(D.v12))
N["first_in_pkg_old"] = ~N.sort_values("new_version").duplicated(["package", "old_version"]).reindex(N.index).fillna(False)
first = N.sort_values(["package", "old_version", "new_version"]).drop_duplicates(["package", "old_version"]).index
N["rep_pkg_old"] = N.index.isin(first)
tier = np.select([N.new_payload | N.new_group | (N.largestChangedJsSha1 == ""), N.v12_new], ["A_new_attack_signal", "B_new_changed_code_pattern"], "C_repeat_of_D06_payload")
N["tier"] = tier
R["tiers"] = pd.crosstab(N.tier, N.rep_pkg_old).to_dict()
R["tiers_by_group"] = pd.crosstab(N.splitGroup, N.tier).to_dict()
N[KEY + ["splitGroup", "payload", "tier", "rep_pkg_old", "nn_to_D06"]].to_csv(f"{OUT}/new_rows_tiers.csv", index=False)
json.dump(R, open(f"{OUT}/new_vs_d06.json", "w"), indent=1, default=str, ensure_ascii=False)
print(json.dumps(R, indent=1, default=str, ensure_ascii=False))
