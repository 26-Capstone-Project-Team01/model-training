"""G2g step 5: compare G2f and G2g fold assignments (no training, no Test access beyond the split labels).

Writes pair_group_changes.csv (every Train dev row whose group or fold differs), fold_counts.csv, compare_summary.json.
Usage: python -I -B compare_g2f_g2g.py --ws <d08_recovery> --g2f <G2f fold_assignment.csv> --g2g <G2g fold_assignment.csv>
       --members <family_membership.csv> --out <dir>
"""
from __future__ import annotations
import argparse, json
from pathlib import Path
import pandas as pd

KEY = ["package", "old_version", "new_version"]


def counts(fa):
    c = fa.groupby(["fold", "class"]).size().unstack(fill_value=0)[["malicious", "benign", "hard_benign"]]
    return c


def main():
    ap = argparse.ArgumentParser()
    for k in ("ws", "g2f", "g2g", "members", "out"): ap.add_argument(f"--{k}", type=Path, required=True)
    a = ap.parse_args(); a.out.mkdir(parents=True, exist_ok=True)
    f = pd.read_csv(a.g2f, dtype=str, keep_default_na=False); g = pd.read_csv(a.g2g, dtype=str, keep_default_na=False)
    assert f[KEY + ["row_id", "class"]].equals(g[KEY + ["row_id", "class"]]), "row set / order differs"
    sa = pd.read_csv(a.ws / "inputs/split_assignment.csv", dtype=str, keep_default_na=False)
    tr = sa[sa.split == "train"]; te = sa[sa.split == "test"]
    keys = set(map(tuple, g[KEY].values))
    split_ok = keys <= set(map(tuple, tr[KEY].values)) and not keys & set(map(tuple, te[KEY].values))
    mem = pd.read_csv(a.members, dtype=str, keep_default_na=False)
    m = f[KEY + ["row_id", "class", "era", "splitGroup_orig", "splitGroup", "component", "fold"]].rename(
        columns={"splitGroup": "group_G2f", "component": "component_G2f", "fold": "fold_G2f"})
    m["group_G2g"] = g.splitGroup; m["component_G2g"] = g.component; m["fold_G2g"] = g.fold
    m = m.merge(mem[KEY + ["family"]], on=KEY, how="left").fillna({"family": ""})
    ch = m[(m.group_G2f != m.group_G2g) | (m.fold_G2f != m.fold_G2g)].copy()
    ch["change"] = ch.apply(lambda r: "+".join(x for x, c in (("group", r.group_G2f != r.group_G2g), ("fold", r.fold_G2f != r.fold_G2g)) if c), axis=1)
    ch.to_csv(a.out / "pair_group_changes.csv", index=False, lineterminator="\n")
    mv = ch[ch.fold_G2f != ch.fold_G2g]
    cf, cg = counts(f), counts(g)
    pd.concat({"G2f": cf, "G2g": cg}, axis=1).to_csv(a.out / "fold_counts.csv", lineterminator="\n")
    mal = lambda d: d[d["class"] == "malicious"]
    camp = lambda d: sorted(set(mal(d).splitGroup) - {"individuals_case"})
    fam_fold = {fam: m[m.family == fam].fold_G2g.value_counts().to_dict() for fam in ("skimmer", "hidden_loader")}
    moved_by = mv.groupby(["fold_G2f", "fold_G2g"]).size()
    s = {"train_test_assignment_unchanged": bool(split_ok), "rows": len(g),
         "group_changed_rows": int((ch.group_G2f != ch.group_G2g).sum()), "fold_moved_rows": len(mv),
         "fold_moves": {f"{i}->{j}": int(n) for (i, j), n in moved_by.items()},
         "fold_moves_by_class": mv["class"].value_counts().to_dict(),
         "fold_moves_family_rows": int((mv.family != "").sum()), "fold_moves_other_rows": int((mv.family == "").sum()),
         "components_moved": int(mv.component_G2g.nunique()),
         "fold_counts_G2f": {c: cf[c].tolist() for c in cf}, "fold_counts_G2g": {c: cg[c].tolist() for c in cg},
         "campaigns_excl_individuals_G2f": len(camp(f)), "campaigns_excl_individuals_G2g": len(camp(g)), "campaigns_G2g": camp(g),
         "family_fold_G2g": fam_fold, "individuals_case_rows_G2f": int((mal(f).splitGroup == "individuals_case").sum()),
         "individuals_case_rows_G2g": int((mal(g).splitGroup == "individuals_case").sum())}
    (a.out / "compare_summary.json").write_text(json.dumps(s, indent=1, ensure_ascii=False) + "\n")
    print(json.dumps(s, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
