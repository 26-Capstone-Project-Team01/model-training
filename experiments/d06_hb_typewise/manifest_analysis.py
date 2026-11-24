"""Summaries from manifests/manifests_summary.csv (no network, no training).
- install-hook program families for hard_benign vs malicious (Train)
- candidate dependency features: existing-dependency range changes, changed-dependency ratio
Train only. Usage: python -I -B manifest_analysis.py --manifests manifests --hb out --out analysis
"""
from __future__ import annotations
import argparse, hashlib, json, re, sys
from pathlib import Path
import numpy as np, pandas as pd

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "d06_x1_cause_analysis"))
import common as c  # noqa: E402

sys.path.insert(0, str(HERE))
import hookfam  # noqa: E402

def main():
    ap = argparse.ArgumentParser()
    for n in ("--manifests", "--hb", "--out"):
        ap.add_argument(n, type=Path, required=True)
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=False)
    M = pd.read_csv(a.manifests / "manifests_summary.csv", keep_default_na=False, dtype=str)
    M["row_id"] = M.row_id.astype(int)
    M = M[M.manifest_ok == "True"].copy()
    df = c.frame()
    M = M.merge(df[["row_id", "installScriptAdded", "newDependencyAdded", "newDependencyCount", "obfChangedFileCount", "addedNetworkCallCount",
                    "addedProcExecCallCount", "installHookNewProgramCount", "installHookRefFileChanged"]], on="row_id")
    # hook categories were derived before malicious hook text was removed (sanitize_manifests.py)
    M["hook_has_url"] = M.hook_has_url == "True"
    M["hook_hides_output"] = M.hook_hides_output == "True"
    M["hook_tokens"] = pd.to_numeric(M.hook_tokens)
    M["new_hook_cmd"] = M.apply(hookfam.new_hook_cmd, axis=1)  # empty for malicious rows (text removed)
    hk = M[M.installScriptAdded.astype(bool)]
    fam = pd.crosstab([hk["class"]], hk.hook_family)
    fam.to_csv(a.out / "hook_family_by_class.csv", lineterminator="\n")
    hb_out = pd.read_csv(a.hb / "train_hard_fp_cases.csv", keep_default_na=False)
    fp_rows = set(hb_out[(hb_out[["sel_full29", "sel_full35", "sel_A2"]].astype(str) == "True").any(axis=1)].row_id.astype(int))
    hk = hk.assign(group=np.where(hk["class"] == "malicious", "malicious", np.where(hk.row_id.isin(fp_rows), "hard_FP", np.where(hk["class"] == "hard_benign", "hard_TN", "benign"))))
    g = hk.groupby("group").agg(n=("row_id", "size"), url=("hook_has_url", "mean"), hides=("hook_hides_output", "mean"), tokens_med=("hook_tokens", "median"))
    g = g.join(pd.crosstab(hk.group, hk.hook_family, normalize="index").round(3))
    g.to_csv(a.out / "hook_profile_by_group.csv", lineterminator="\n")
    hk[["row_id", "group", "campaign", "package", "old_version", "new_version", "hook_family", "new_hook_cmd"]].query("group!='malicious'") \
        .to_csv(a.out / "hook_commands_non_malicious.csv", index=False, lineterminator="\n")
    # malicious: per campaign family counts only (no command text dumped)
    pd.crosstab(hk[hk.group == "malicious"].campaign, hk[hk.group == "malicious"].hook_family).to_csv(a.out / "hook_family_malicious_by_campaign.csv", lineterminator="\n")

    # dependency candidates
    rows = []
    for r in M.itertuples(index=False):
        od, nd = {}, {}
        for f in ("dependencies", "optionalDependencies"):
            od.update(json.loads(getattr(r, f"old_{f}") or "{}"))
            nd.update(json.loads(getattr(r, f"new_{f}") or "{}"))
        common = set(od) & set(nd)
        changed = {d for d in common if str(od[d]) != str(nd[d])}
        added, removed = set(nd) - set(od), set(od) - set(nd)
        nonreg = [d for d in added if re.match(r"^(github:|gitlab:|bitbucket:|git\+|git:|https?:|ssh:|file:|link:)", str(nd[d])) or re.match(r"^[\w.-]+/[\w.-]+(#.*)?$", str(nd[d]))]
        rows.append({"row_id": r.row_id, "class": r[M.columns.get_loc("class")], "campaign": r.campaign,
                     "dep_total_new": len(nd), "dep_added": len(added), "dep_removed": len(removed), "dep_range_changed": len(changed),
                     "dep_changed_ratio": (len(changed) + len(added)) / len(nd) if nd else np.nan,
                     "dep_added_ratio": len(added) / len(nd) if nd else np.nan,
                     "dep_added_nonregistry_spec": len(nonreg),
                     "devdep_only_change": int(not added and not changed and getattr(r, "old_devDependencies") != getattr(r, "new_devDependencies"))})
    D = pd.DataFrame(rows)
    D.to_csv(a.out / "dependency_candidates.csv", index=False, lineterminator="\n")
    D["grp"] = np.where(D["class"] == "malicious", "malicious", np.where(D.row_id.isin(fp_rows), "hard_FP", D["class"]))
    summ = D.groupby("grp").agg(n=("row_id", "size"), dep_total_med=("dep_total_new", "median"), range_changed_gt0=("dep_range_changed", lambda s: (s > 0).mean()),
                                range_changed_med=("dep_range_changed", "median"), changed_ratio_med=("dep_changed_ratio", "median"),
                                added_ratio_med=("dep_added_ratio", "median"), added_ratio_eq1=("dep_added_ratio", lambda s: (s == 1).mean()),
                                no_deps_new=("dep_total_new", lambda s: (s == 0).mean()), nonregistry_added_gt0=("dep_added_nonregistry_spec", lambda s: (s > 0).mean()))
    summ.round(3).to_csv(a.out / "dependency_candidates_by_group.csv", lineterminator="\n")
    camp = D[D["class"] == "malicious"].groupby("campaign").agg(n=("row_id", "size"), range_changed_gt0=("dep_range_changed", lambda s: (s > 0).mean()),
                                                                 added_gt0=("dep_added", lambda s: (s > 0).mean()), nonreg=("dep_added_nonregistry_spec", lambda s: (s > 0).mean()))
    camp.round(3).to_csv(a.out / "dependency_candidates_malicious_by_campaign.csv", lineterminator="\n")
    (a.out / "manifest.json").write_text(json.dumps({"script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "inputs": {"manifests_summary": hashlib.sha256((a.manifests / "manifests_summary.csv").read_bytes()).hexdigest()},
        "note": "Train only, benign subset limited to rows with installScriptAdded or newDependencyAdded (manifests collected only for those)",
        "outputs": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(a.out.glob("*")) if p.is_file()}}, indent=1) + "\n")


if __name__ == "__main__":
    main()
