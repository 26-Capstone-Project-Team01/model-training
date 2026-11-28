"""G2g step 4: build merge_G2g.json from merge_G2f.json + the two code-relatedness families, and the per-pair change table.

Membership comes from family_membership.csv (written by decide_families.py from the scan evidence):
  columns package, old_version, new_version, family (skimmer | hidden_loader), basis
Rule:
  * group_merge: G2f entries + every G2f splitGroup whose rows are all in one family is renamed to the family group
    (js-metrics_2018 -> skimmer, react-native-aria-gluestack_2025-06 -> hidden-loader);
  * row_override: G2f entries (targets retargeted when they point at a merged group) + one entry per family member whose
    G2f group is individuals_case;
  * Train/Test split is never touched (Train rows only; Test rows checked to be absent).
Usage: python -I -B make_g2g.py --ws <d08_recovery> --members <family_membership.csv> --out <dir>
"""
from __future__ import annotations
import argparse, json
from pathlib import Path
import pandas as pd

KEY = ["package", "old_version", "new_version"]
NAMES = {"skimmer": "skimmer-family(js-metrics+apt-js+individuals)", "hidden_loader": "hidden-loader-family(react-native-aria+individuals)"}


def main():
    ap = argparse.ArgumentParser()
    for k in ("ws", "members", "out"): ap.add_argument(f"--{k}", type=Path, required=True)
    a = ap.parse_args(); a.out.mkdir(parents=True, exist_ok=True)
    g2f = json.load(open(a.ws / "g2f/config/merge_G2f.json"))
    fa = pd.read_csv(a.ws / "g2f/run/fold_assignment.csv", dtype=str, keep_default_na=False)
    sa = pd.read_csv(a.ws / "inputs/split_assignment.csv", dtype=str, keep_default_na=False)
    mem = pd.read_csv(a.members, dtype=str, keep_default_na=False)
    assert not mem.duplicated(KEY).any(), "a pair is in two families"
    m = mem.merge(fa[KEY + ["splitGroup_orig", "splitGroup", "fold", "era", "class"]], on=KEY, how="left", validate="one_to_one")
    assert m.splitGroup.ne("").all() and (m["class"] == "malicious").all(), "member not a Train malicious dev row"
    test_keys = set(map(tuple, sa[sa.split == "test"][KEY].values))
    assert not set(map(tuple, m[KEY].values)) & test_keys

    group_merge = dict(g2f["group_merge"]); merged_groups = {}
    for fam, d in m.groupby("family"):
        for grp in sorted(set(d.splitGroup) - {"individuals_case"}):
            all_rows = fa[fa.splitGroup == grp]
            if set(map(tuple, all_rows[KEY].values)) <= set(map(tuple, d[KEY].values)):
                merged_groups[grp] = NAMES[fam]
    # a G2f group that is the *target* of an earlier merge/override (e.g. js-metrics_2018, apt-js-skimmer) is merged by its G2f name;
    # group_merge works on the original splitGroup, so add the original names whose G2f value is a merged group
    for orig in sorted(set(fa.splitGroup_orig)):
        g = group_merge.get(orig, orig)
        if g in merged_groups and orig != "individuals_case": group_merge[orig] = merged_groups[g]
    row_override = []
    for o in g2f["row_override"]:
        o = dict(o); o["splitGroup"] = merged_groups.get(o["splitGroup"], o["splitGroup"]); row_override.append(o)
    have = {(o["package"], o["old_version"], o["new_version"]) for o in row_override}
    new_ind = m[(m.splitGroup == "individuals_case")].sort_values(KEY)
    for r in new_ind.itertuples(index=False):
        k = (r.package, r.old_version, r.new_version); assert k not in have
        row_override.append({"package": r.package, "old_version": r.old_version, "new_version": r.new_version, "splitGroup": NAMES[r.family]})
    cfg = {"group_merge": group_merge, "row_override": row_override}
    (a.out / "merge_G2g.json").write_text(json.dumps(cfg, indent=1, ensure_ascii=False) + "\n")
    summary = {"group_merge": len(group_merge), "group_merge_added": sorted(set(group_merge) - set(g2f["group_merge"])),
               "row_override": len(row_override), "row_override_G2f": len(g2f["row_override"]), "new_individuals_override": len(new_ind),
               "family_sizes": m.family.value_counts().to_dict(), "family_era": m.groupby(["family", "era"]).size().to_dict().__repr__(),
               "merged_G2f_groups": merged_groups}
    (a.out / "make_g2g_summary.json").write_text(json.dumps(summary, indent=1, ensure_ascii=False) + "\n")
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
