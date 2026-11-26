"""Experimental group merge -> recompute components + greedy 5-fold + normal-only calibration counts (no training, no Test). Frozen inputs untouched."""
import sys, json, importlib.util
from pathlib import Path
import numpy as np, pandas as pd
sys.path.insert(0, "/home/user/d08_m1m4_experiment")
SNAP, MERGE, OUT = sys.argv[1:4]
import run_m1m4 as R  # imports only; main() not called
spec = importlib.util.spec_from_file_location("snap", SNAP); snap = importlib.util.module_from_spec(spec); spec.loader.exec_module(snap)
assert R.sha(SNAP) == R.SNAPSHOT_SHA256
T, F29 = R.load_inputs()
cfg = json.load(open(MERGE)); K = R.KEY
T["splitGroup_exp"] = T.splitGroup.replace(cfg.get("group_merge", {}))
for o in cfg.get("row_override", []):
    m = (T.package == o["package"]) & (T.old_version == o["old_version"]) & (T.new_version == o["new_version"])
    assert m.sum() == 1, o; T.loc[m, "splitGroup_exp"] = o["splitGroup"]
cf = T[["package", "label", "splitGroup_exp", "largestChangedJsSha1", "changedJsSetSha1", "class"]].rename(columns={"splitGroup_exp": "splitGroup"}).copy()
cf.loc[cf.label == 0, ["splitGroup", "largestChangedJsSha1", "changedJsSetSha1"]] = ""
T["component"] = snap.components(cf)
T["fold"] = R.greedy_folds(T.assign(splitGroup=cf.splitGroup), snap)
Path(OUT).mkdir(parents=True, exist_ok=True)
T[K + ["row_id", "class", "era", "splitGroup", "splitGroup_exp", "component", "fold"]].to_csv(f"{OUT}/fold_assignment_exp.csv", index=False)
old = pd.read_csv("/home/user/d08_m1m4_experiment/run/fold_assignment.csv", keep_default_na=False)
T["fold_old"] = T.row_id.map(old.set_index("row_id").fold)
rows = []
for f in range(5):
    v = T[T.fold == f]; rest = T[T.fold != f]
    for sd in (20261109, 20261110):
        cal = R.normal_only_calibration(rest, sd + f); fit = rest[~cal]
        rows.append({"fold": f, "cal_seed": sd, "val_mal": int(v.label.sum()), "val_mal_D06": int(((v.era == "D06") & (v.label == 1)).sum()),
                     "val_benign": int((v["class"] == "benign").sum()), "val_hb": int((v["class"] == "hard_benign").sum()),
                     "cal_n": int(cal.sum()), "fit_mal_M2": int(fit.label.sum()), "fit_mal_M1": int(((fit.era == "D06") & (fit.label == 1)).sum()),
                     "fit_normal": int((fit.label == 0).sum()), "fit_normal_M1": int(((fit.era == "D06") & (fit.label == 0)).sum()),
                     "val_groups": ";".join(f"{k}:{n}" for k, n in v[v.label == 1].splitGroup_exp.value_counts().items())})
C = pd.DataFrame(rows); C.to_csv(f"{OUT}/fold_counts_exp.csv", index=False)
moved = T[T.fold != T.fold_old]
print("rows moved fold:", len(moved), moved.groupby(["class", "fold_old", "fold"]).size().to_string())
pd.set_option("display.width", 250); pd.set_option("display.max_colwidth", 200)
print(C[C.cal_seed == 20261109].drop(columns="cal_seed").to_string(index=False))
