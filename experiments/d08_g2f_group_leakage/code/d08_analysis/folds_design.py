"""Common component split design for D08 Train (read-only, no models). Reuses PR #13 snapshot components()/outer_folds()/inner_split()."""
import sys, json, importlib.util
import numpy as np, pandas as pd
IN, SNAP, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
spec = importlib.util.spec_from_file_location("snap", SNAP); snap = importlib.util.module_from_spec(spec); spec.loader.exec_module(snap)
KEY = ["package", "old_version", "new_version"]
rd = lambda n: pd.read_csv(f"{IN}/{n}", dtype=str, keep_default_na=False)
tr, sa, gr, d6 = rd("d08_train.csv"), rd("d08_split_assignment.csv"), rd("d08_groups.csv"), rd("d06_train.csv")
T = tr[KEY + ["label"]].merge(sa[KEY + ["class", "splitGroup"]], on=KEY).merge(gr[KEY + snap.HASHES], on=KEY, how="left").fillna("")
T["label"] = T.label.astype(int)
T.loc[T.label == 0, ["splitGroup"] + snap.HASHES] = ""
T["era"] = np.where(T[KEY].apply(tuple, axis=1).isin(set(map(tuple, d6[KEY].values))), "D06", "new")
T["component"] = snap.components(T)
cc = T.groupby("component").agg(rows=("label", "size"), mal=("label", "sum"), new=("era", lambda s: (s == "new").sum()), groups=("splitGroup", lambda s: ";".join(sorted({x for x in s if x}))[:120])).sort_values("rows", ascending=False)
cc.to_csv(f"{OUT}/components.csv")
R = {"components": int(len(cc)), "malicious_components": int((cc.mal > 0).sum()), "top_components": cc.head(8).reset_index().to_dict("records"),
     "largest_component_share_of_malicious": float(cc.mal.max() / T.label.sum())}
# PR #13 greedy 3-fold
T["fold3"] = snap.outer_folds(T)
def fold_table(col):
    t = T.groupby([col, "class"]).size().unstack(fill_value=0)
    t["D06_mal"] = T[(T.era == "D06") & (T.label == 1)].groupby(col).size()
    t["new_mal"] = T[(T.era == "new") & (T.label == 1)].groupby(col).size()
    t["mal_groups"] = T[T.label == 1].groupby(col).splitGroup.nunique()
    t["top_group"] = T[T.label == 1].groupby(col).splitGroup.agg(lambda s: f"{s.value_counts().index[0]}:{s.value_counts().iloc[0]}")
    return t.fillna(0)
R["pr13_greedy_3fold"] = fold_table("fold3").reset_index().to_dict("records")
# D06 rows: same fold as PR13 D06 outer folds? (only comparability, not required)
# 5-fold variant of the same greedy rule
def greedy(frame, k):
    counts = snap.component_counts(frame)
    assignment, loads = {}, np.zeros((k, 3), dtype=int)
    mal = counts.index[counts.malicious > 0]
    for g in sorted(mal, key=lambda g: (-int(counts.loc[g, "malicious"]), g)):
        f = min(range(k), key=lambda f: (loads[f, 0], f)); assignment[g] = f; loads[f] += counts.loc[g].to_numpy()
    normal = counts.index[counts.malicious == 0]; target = np.maximum(counts.sum().to_numpy()[1:] / k, 1)
    for g in sorted(normal, key=lambda g: (-int(counts.loc[g].sum()), g)):
        sizes = counts.loc[g].to_numpy(); f = min(range(k), key=lambda f: (float(np.sum((loads[f, 1:] + sizes[1:]) ** 2 / target)), f)); assignment[g] = f; loads[f] += sizes
    return frame.component.map(assignment).astype(int)
T["fold5"] = greedy(T, 5)
R["greedy_5fold"] = fold_table("fold5").reset_index().to_dict("records")
# inner split sizes per 3-fold (fit / calibration) and M1 fit size (D06 only)
inner = []
for f in range(3):
    rest = T[T.fold3 != f]
    for seed in (20261109, 20261110):
        fit, cal = snap.inner_split(rest, seed + f)
        inner.append({"fold": f, "seed": seed, "fit_rows": len(fit), "fit_mal": int(fit.label.sum()), "fit_D06_rows_for_M1": int((fit.era == "D06").sum()),
                      "fit_D06_mal": int(((fit.era == "D06") & (fit.label == 1)).sum()), "fit_new_mal": int(((fit.era == "new") & (fit.label == 1)).sum()),
                      "cal_rows": len(cal), "cal_mal": int(cal.label.sum()), "cal_normal": int((cal.label == 0).sum()),
                      "cal_top_group": cal[cal.label == 1].splitGroup.value_counts().head(1).to_dict(),
                      "eval_rows": int((T.fold3 == f).sum()), "eval_mal": int(T[T.fold3 == f].label.sum())})
R["inner_splits"] = inner
T[KEY + ["class", "era", "splitGroup", "component", "fold3", "fold5"]].to_csv(f"{OUT}/fold_assignment_design.csv", index=False)
json.dump(R, open(f"{OUT}/folds_design.json", "w"), indent=1, default=str)
print(json.dumps(R, indent=1, default=str)[:9000])
