"""G2g step 2: decide Skimmer / Hidden-loader family membership from the static-scan evidence (hashes and flags only).

Skimmer (seed = G2f groups js-metrics_2018 and apt-js-skimmer[from-individuals]):
  N3 = structural skeleton of each distinct added line (literals -> S/0, non-keyword identifiers -> i); lines whose N3 occurs
  in pairs of >= GENERIC_GROUPS distinct G2f groups outside the seeds and individuals_case are generic and dropped.
  score = max over seed pairs of shared N3 lines.  member <=> score >= SKIM_MIN, or the row already carries a seed label.
Hidden-loader (seed = G2f group react-native-aria-gluestack_2025-06):
  code hidden after a >= 100-char whitespace run in a changed/added text file of malicious_raw (scan_hidden_raw.py).
  member <=> a hidden segment carries a loader marker (version tag global['x']='<n>-..' or globalThis.x="<A>n-..",
  global['_V'], global['r']=require, the _$_xxxx string-shuffle array), or the row is a seed pair.
Outputs (no code text): family_membership.csv, evidence_skimmer.csv, evidence_hidden.csv, decide_summary.json
Usage: python -I -B decide_families.py --scan <scan dir> --hidden <hidden_raw dir> --out <dir>
"""
from __future__ import annotations
import argparse, json
from pathlib import Path
import pandas as pd

SKIM_SEED = {"js-metrics_2018", "apt-js-skimmer[from-individuals]"}
HID_SEED = {"react-native-aria-gluestack_2025-06"}
GENERIC_GROUPS = 3
SKIM_MIN = 20
MARKERS = ["version_tag", "version_tag_globalThis", "global_V", "global_r_require", "dollar_underscore_array"]
KEY = ["package", "old_version", "new_version"]


def skimmer(idx, lh):
    lh = lh[lh.n3_sha1 != ""].copy(); lh["grp"] = lh.row_id.map(idx.splitGroup_G2f)
    seeds = set(idx.index[idx.splitGroup_G2f.isin(SKIM_SEED)])
    res = {}
    for col in ("n3_sha1", "n2_sha1", "n1_sha1"):
        other = lh[~lh.row_id.isin(seeds) & (lh.grp != "individuals_case")]
        generic = set(other.groupby(col).grp.nunique().loc[lambda s: s >= GENERIC_GROUPS].index)
        L = lh[~lh[col].isin(generic)][["row_id", col]].drop_duplicates()
        j = L.merge(L[L.row_id.isin(seeds)].rename(columns={"row_id": "seed"}), on=col)
        j = j[j.row_id != j.seed].groupby(["row_id", "seed"]).size().rename("n").reset_index()
        best = j.sort_values(["n", "seed"], ascending=[False, True]).drop_duplicates("row_id").set_index("row_id")
        res[col[:2]] = best
    ev = idx[KEY + ["era", "splitGroup_G2f", "fold_G2f"]].copy()
    for k, b in res.items(): ev[f"shared_{k}_best"] = b.n.reindex(ev.index).fillna(0).astype(int)
    ev["best_seed_package_n3"] = res["n3"].seed.reindex(ev.index).map(idx.package).fillna("")
    ev["seed_label"] = ev.index.isin(seeds).astype(int)
    ev["strong_pattern"] = (ev.shared_n3_best >= SKIM_MIN).astype(int)
    ev["member"] = ((ev.strong_pattern == 1) | (ev.seed_label == 1)).astype(int)
    ev["basis"] = ev.apply(lambda r: ("seed label+" if r.seed_label else "") + (f"N3 {r.shared_n3_best} shared lines" if r.strong_pattern else "")
                           if r.member else "", axis=1).str.rstrip("+")
    ev.loc[(ev.member == 1) & (ev.strong_pattern == 0), "basis"] = "seed label only (G2f js-metrics_2018 dataset campaign); pattern below threshold"
    keep = (ev.member == 1) | (ev.shared_n3_best > 0)
    return ev[keep].sort_values(["member", "shared_n3_best"], ascending=False), sorted(ev.shared_n3_best[ev.member == 0].unique())[-3:]


def hidden(idx, hs):
    hs = hs.copy(); hs["marker"] = hs[MARKERS].max(axis=1)
    hseed = set(idx.index[idx.splitGroup_G2f.isin(HID_SEED)])
    g = hs.groupby("row_id")
    ev = idx.loc[sorted(set(hs.row_id)), KEY + ["era", "splitGroup_G2f", "fold_G2f"]].copy()
    ev["hidden_segments"] = g.size()
    for m in MARKERS: ev[m] = g[m].max()
    ev["max_ws_run"] = g.ws_run.max(); ev["in_added_file"] = g.file_added.max()
    ev["files"] = g.path.agg(lambda s: ";".join(sorted({p.split("/")[-1] for p in s}))[:120])
    ev["skeleton_clusters"] = g.skeleton_prefix_sha1.agg(lambda s: ";".join(sorted({x[:8] for x in s}))[:80])
    ev["hidden_text_hashes"] = g.hidden_sha1.agg(lambda s: ";".join(sorted({x[:8] for x in s}))[:80])
    ev["seed_label"] = ev.index.isin(hseed).astype(int)
    ev["member"] = ((g.marker.max() == 1) | ev.seed_label.astype(bool)).astype(int)
    ev["basis"] = ev.apply(lambda r: "+".join([m for m in MARKERS if r[m]] + (["seed label"] if r.seed_label else [])) if r.member else
                           "hidden whitespace only, no loader marker (vendored/bundled code)", axis=1)
    return ev.sort_values(["member", "splitGroup_G2f", "package", "new_version"], ascending=[False, True, True, True])


def main():
    ap = argparse.ArgumentParser()
    for k in ("scan", "hidden", "out"): ap.add_argument(f"--{k}", type=Path, required=True)
    a = ap.parse_args(); a.out.mkdir(parents=True, exist_ok=True)
    idx = pd.read_csv(a.scan / "pair_index.csv", keep_default_na=False).set_index("row_id")
    lh = pd.read_csv(a.scan / "line_hashes.csv.gz", keep_default_na=False)
    hs = pd.read_csv(a.hidden / "hidden_raw_segments.csv", keep_default_na=False)
    sk, next_scores = skimmer(idx, lh); hd = hidden(idx, hs)
    sk.to_csv(a.out / "evidence_skimmer.csv", index_label="row_id", lineterminator="\n")
    hd.to_csv(a.out / "evidence_hidden.csv", index_label="row_id", lineterminator="\n")
    mem = pd.concat([sk[sk.member == 1].assign(family="skimmer")[KEY + ["family", "basis"]],
                     hd[hd.member == 1].assign(family="hidden_loader")[KEY + ["family", "basis"]]])
    overlap = mem[mem.duplicated(KEY, keep=False)]
    mem.to_csv(a.out / "family_membership.csv", index=False, lineterminator="\n")
    def desc(df, fam):
        d = df[df.member == 1]
        return {"pairs": len(d), "by_era": d.era.value_counts().to_dict(), "by_G2f_group": d.splitGroup_G2f.value_counts().to_dict(),
                "by_G2f_fold": d.fold_G2f.astype(str).value_counts().sort_index().to_dict(),
                "individuals_case": int((d.splitGroup_G2f == "individuals_case").sum())}
    s = {"skimmer": desc(sk, "skimmer"), "skimmer_strong_pattern": {"pairs": int(sk.strong_pattern.sum()),
         "by_fold": sk[sk.strong_pattern == 1].fold_G2f.astype(str).value_counts().sort_index().to_dict(),
         "shared_n3_range": [int(sk[sk.strong_pattern == 1].shared_n3_best.min()), int(sk[sk.strong_pattern == 1].shared_n3_best.max())],
         "highest_non_member_scores": [int(x) for x in next_scores]},
         "hidden_loader": desc(hd, "hidden"), "hidden_non_members": hd[hd.member == 0][["package", "new_version", "splitGroup_G2f"]].values.tolist(),
         "overlap_between_families": overlap[KEY].values.tolist(), "params": {"GENERIC_GROUPS": GENERIC_GROUPS, "SKIM_MIN": SKIM_MIN, "MARKERS": MARKERS}}
    (a.out / "decide_summary.json").write_text(json.dumps(s, indent=1, ensure_ascii=False) + "\n")
    print(json.dumps(s, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
