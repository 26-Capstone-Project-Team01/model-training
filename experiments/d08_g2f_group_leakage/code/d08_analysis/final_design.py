"""Final M1-M4 design pre-check (no models, no Test). Read-only."""
import sys, json, re, importlib.util
import numpy as np, pandas as pd
IN, SNAP, FOLDS, OUT = sys.argv[1:5]
spec = importlib.util.spec_from_file_location("snap", SNAP); snap = importlib.util.module_from_spec(spec); spec.loader.exec_module(snap)
KEY = ["package", "old_version", "new_version"]
rd = lambda n: pd.read_csv(f"{IN}/{n}", dtype=str, keep_default_na=False)
tr, gr = rd("d08_train.csv"), rd("d08_groups.csv")
fa = pd.read_csv(FOLDS, dtype=str, keep_default_na=False)
T = tr.merge(fa, on=KEY).merge(gr[KEY + ["largestChangedJsSha1", "changedJsSetSha1", "addedDependencies", "addedInstallHooks"]], on=KEY, how="left").fillna("")
T["label"] = T.label.astype(int); T["fold5"] = T.fold5.astype(int)
F28 = [c for c in tr.columns if c not in KEY + ["label", "updateInterval"]]
assert len(F28) == 28
T["v28"] = T[F28].agg("|".join, axis=1)

def payload_key(r):
    """Malicious payload key. 1) largestChangedJsSha1; 2) no changed JS: 'nojs:<added install hooks>|<added deps>';
    3) no changed JS and no added hook/dependency: 'nojs-empty:<package>' (never one shared key for all empty rows)."""
    if r.label != 1: return ""
    if r.largestChangedJsSha1: return r.largestChangedJsSha1
    sig = r.addedInstallHooks + "|" + r.addedDependencies
    return "nojs:" + sig if sig != "|" else "nojs-empty:" + r.package
T["P"] = T.apply(payload_key, axis=1)
def vkey(v):
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", v); return tuple(map(int, m.groups())) if m else (10**9,)
T["_v"] = T.new_version.map(vkey)

def m3_revised(fit):
    """Keep all D06 rows. New malicious rows: one representative (lowest new_version) per (package, old_version, P, v28)."""
    new_mal = fit[(fit.era == "new") & (fit.label == 1)].sort_values(["package", "old_version", "P", "v28", "_v"])
    keep = new_mal.drop_duplicates(["package", "old_version", "P", "v28"])
    return pd.concat([fit[fit.era == "D06"], keep, fit[(fit.era == "new") & (fit.label == 0)]])
def m3_a(fit):
    new_mal = fit[(fit.era == "new") & (fit.label == 1)].sort_values("_v").drop_duplicates(["package", "old_version"])
    return pd.concat([fit[fit.era == "D06"], new_mal, fit[(fit.era == "new") & (fit.label == 0)]])
def m4_weights(fit):
    w = pd.Series(1.0, index=fit.index); mal = fit.label == 1
    n_p = fit[mal].groupby("P").P.transform("size")
    w[mal] = 1 / np.sqrt(n_p)
    w[mal] *= mal.sum() / w[mal].sum()
    return w

R = {}
# ---------- M3 on full Train (descriptive)
D6m, NEWm = T[(T.era == "D06") & (T.label == 1)], T[(T.era == "new") & (T.label == 1)]
d6P = set(D6m.P)
def m3_stats(sel, name):
    s_new = sel[(sel.era == "new") & (sel.label == 1)]
    newP = set(NEWm.P) - d6P
    out = {"variant": name, "new_kept": len(s_new), "new_removed": len(NEWm) - len(s_new), "removed_share": round(1 - len(s_new) / len(NEWm), 3),
           "malicious_total": int((sel.label == 1).sum()),
           "new_P_not_in_D06_total": len(newP), "new_P_not_in_D06_kept": len(newP & set(s_new.P)),
           "new_largest_hash_not_in_D06_total": len({p for p in newP if not p.startswith("nojs")}),
           "new_largest_hash_not_in_D06_kept": len({p for p in newP & set(s_new.P) if not p.startswith("nojs")}),
           "all_new_P_kept": f"{len(set(s_new.P))}/{NEWm.P.nunique()}",
           "new_v28_kept": f"{s_new.v28.nunique()}/{NEWm.v28.nunique()}",
           "new_v28_not_in_D06_kept": f"{len(set(s_new.v28) - set(T[T.era == 'D06'].v28))}/{len(set(NEWm.v28) - set(T[T.era == 'D06'].v28))}",
           "new_pkg_kept": f"{s_new.package.nunique()}/{NEWm.package.nunique()}",
           "nojs_new_kept": f"{(s_new.largestChangedJsSha1 == '').sum()}/{(NEWm.largestChangedJsSha1 == '').sum()}"}
    mal = sel[sel.label == 1]
    share = mal.splitGroup.value_counts(normalize=True)
    out |= {"top_group_share": f"{share.index[0]}:{share.iloc[0]:.3f}", "top3_share": round(float(share.iloc[:3].sum()), 3), "effective_groups": round(float(1 / (share ** 2).sum()), 2)}
    return out
R["m3_full_train"] = [m3_stats(T, "M2_all"), m3_stats(m3_a(T), "M3-a"), m3_stats(m3_revised(T), "M3-revised")]
# lost payloads in M3-a
lostA = (set(NEWm.P) - d6P) - set(m3_a(T).query("era=='new' and label==1").P)
R["m3a_lost_new_payloads"] = len(lostA)
R["m3a_lost_examples"] = NEWm[NEWm.P.isin(lostA)][KEY + ["splitGroup", "P"]].head(6).values.tolist()
# per-campaign kept/removed for M3-revised
rev = m3_revised(T)
cg = pd.DataFrame({"new_rows": NEWm.splitGroup.value_counts(), "M3a_kept": m3_a(T).query("era=='new' and label==1").splitGroup.value_counts(),
                   "M3rev_kept": rev.query("era=='new' and label==1").splitGroup.value_counts()}).fillna(0).astype(int)
cg["M3rev_removed"] = cg.new_rows - cg.M3rev_kept; cg["M3rev_keep_ratio"] = (cg.M3rev_kept / cg.new_rows).round(3)
cg.sort_values("new_rows", ascending=False).to_csv(f"{OUT}/m3_revised_by_group.csv")
R["m3_by_group"] = cg.sort_values("new_rows", ascending=False).reset_index().to_dict("records")

# ---------- normal-only calibration per fold
def normal_only_calibration(fit, seed, target=0.25):
    comp = fit.groupby("component").agg(mal=("label", "sum"), benign=("class", lambda s: (s == "benign").sum()), hb=("class", lambda s: (s == "hard_benign").sum()))
    cand = comp[comp.mal == 0]
    goal = np.array([comp.benign.sum(), comp.hb.sum()]) * target
    scale = np.maximum(goal, 1)
    cur, sel = np.zeros(2), []
    for g in np.random.default_rng(seed).permutation(sorted(cand.index)):
        nxt = cur + cand.loc[g, ["benign", "hb"]].to_numpy()
        if np.sum(((nxt - goal) / scale) ** 2) < np.sum(((cur - goal) / scale) ** 2):
            sel.append(g); cur = nxt
    return fit.component.isin(sel)
mixed = T.groupby("component").agg(mal=("label", "sum"), n=("label", "size"))
mixed = mixed[(mixed.mal > 0) & (mixed.n > mixed.mal)]
R["mixed_components"] = {"components": len(mixed), "normal_rows_in_them": int((mixed.n - mixed.mal).sum()),
                         "detail": T[T.component.isin(mixed.index) & (T.label == 0)][KEY + ["class", "component"]].values.tolist()}
rows, wstats = [], []
SEED = 20261109
for f in range(5):
    val = T[T.fold5 == f]; rest = T[T.fold5 != f]
    for frame_name, a, b in [("val vs rest", val, rest)]:
        snap.check_disjoint(a.assign(splitGroup=a.splitGroup.where(a.label == 1, "")), b.assign(splitGroup=b.splitGroup.where(b.label == 1, "")))
    is_cal = normal_only_calibration(rest, SEED + f)
    cal, fit = rest[is_cal], rest[~is_cal]
    assert (cal.label == 0).all() and not set(cal.component) & set(fit.component)
    m1 = fit[fit.era == "D06"]; m3 = m3_revised(fit); w = m4_weights(fit)
    wm = w[fit.label == 1]; share = (wm.groupby(fit.loc[fit.label == 1, "splitGroup"]).sum() / wm.sum()).sort_values(ascending=False)
    rows.append({"fold": f, "val_mal": int(val.label.sum()), "val_mal_D06": int(((val.era == "D06") & (val.label == 1)).sum()), "val_mal_new": int(((val.era == "new") & (val.label == 1)).sum()),
                 "val_benign": int((val["class"] == "benign").sum()), "val_hard_benign": int((val["class"] == "hard_benign").sum()),
                 "val_groups": ";".join(f"{k}:{v}" for k, v in val[val.label == 1].splitGroup.value_counts().head(4).items()),
                 "cal_benign": int((cal["class"] == "benign").sum()), "cal_hard_benign": int((cal["class"] == "hard_benign").sum()),
                 "cal_budget_1pct": int(np.floor(len(cal) * 0.01 + 1e-12)), "cal_budget_5pct": int(np.floor(len(cal) * 0.05 + 1e-12)),
                 "M1_fit": len(m1), "M1_fit_mal": int(m1.label.sum()),
                 "M2_fit": len(fit), "M2_fit_mal": int(fit.label.sum()),
                 "M3_fit": len(m3), "M3_fit_mal": int(m3.label.sum()),
                 "M4_fit": len(fit), "M4_mal_weight_sum": round(float(wm.sum()), 1), "fit_normal": int((fit.label == 0).sum())})
    wstats.append({"fold": f, "w_min": round(float(wm.min()), 4), "w_median": round(float(wm.median()), 4), "w_max": round(float(wm.max()), 4),
                   "kish_neff": round(float(wm.sum() ** 2 / (wm ** 2).sum()), 1), "top_group_weight_share": f"{share.index[0]}:{share.iloc[0]:.3f}",
                   "effective_groups_weighted": round(float(1 / (share ** 2).sum()), 2),
                   "top_group_row_share": f"{fit[fit.label == 1].splitGroup.value_counts(normalize=True).index[0]}:{fit[fit.label == 1].splitGroup.value_counts(normalize=True).iloc[0]:.3f}",
                   "nP": int(fit[fit.label == 1].P.nunique())})
    # identical validation/calibration rows for all models by construction: store ids
    val[KEY].assign(fold=f).to_csv(f"{OUT}/val_rows_fold{f}.csv", index=False)
    cal[KEY].assign(fold=f).to_csv(f"{OUT}/cal_rows_fold{f}.csv", index=False)
R["per_fold"] = rows; R["m4_weights"] = wstats
pd.DataFrame(rows).to_csv(f"{OUT}/final_fold_counts.csv", index=False)
pd.DataFrame(wstats).to_csv(f"{OUT}/final_m4_weights.csv", index=False)
json.dump(R, open(f"{OUT}/final_design.json", "w"), indent=1, default=str, ensure_ascii=False)
print(pd.DataFrame(R["m3_full_train"]).T.to_string())
print("M3-a lost new payloads:", R["m3a_lost_new_payloads"], R["m3a_lost_examples"])
print(cg.sort_values("new_rows", ascending=False).to_string())
print("mixed components", {k: v for k, v in R["mixed_components"].items() if k != "detail"}, R["mixed_components"]["detail"][:10])
print(pd.DataFrame(rows).T.to_string()); print(pd.DataFrame(wstats).to_string(index=False))
