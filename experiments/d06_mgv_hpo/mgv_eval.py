"""Evaluate mgv_hpo.py scores. Train only (no Test). Selections use calibration rows only.

Per family (pr13 split1, pr13 split2, rgk3 s1..s5, loco = one group per family/repeat):
  - HPO: per feature set, config with the best mean calibration PR-AUC over the group's cells (default kept on ties)
  - B3 : full35(selected config) + LR + MLP, scale prob|logit, 0.1 simplex grid, best mean calibration PR-AUC (same rule as blend.py)
  - C5 : routing on calibration-normal rank scale with full35 and gs24 (selected configs)
Thresholds per cell by PR #13 calibrate (ML) at target calibration FPR 1..5%. Reported for default and HPO-selected configs.
Usage: python -I -B mgv_eval.py --scores <mgv_hpo out> --out <new dir>
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score

HERE = Path(__file__).resolve().parent
EXP = HERE.parent
sys.path.insert(0, str(EXP / "d06_x1_cause_analysis"))
import common as c  # noqa: E402

TARGETS = [0.01, 0.02, 0.03, 0.04, 0.05]
DEFAULT = "nl31_md20_r200"


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


def rank_vs(normals, s):
    n = np.sort(normals)
    lo, hi = np.searchsorted(n, s, "left"), np.searchsorted(n, s, "right")
    return (lo + 0.5 * (hi - lo)) / len(n)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scores", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=False)
    bl = load(EXP / "d06_alt_models/blend.py", "blend_alt")
    snap = load(c.B / "provenance/phase2_run1_base7_full29/executed_script_snapshot.py", "snap")
    df = c.frame()
    S = pd.read_csv(a.scores / "scores.csv")
    S["group"] = np.where(S.family == "pr13", "pr13_" + S.cell.str.split("_").str[0],
                          np.where(S.family == "rgk3", "rgk3_" + S.cell.str.split("_").str[0], "loco"))
    W = S.pivot_table(index=["group", "cell", "stage", "row_id"], columns="model", values="score").reset_index()
    W = W.merge(df[["row_id", "label", "class", "campaign", "obfChangedFileCount", "newDependencyAdded", "installScriptAdded"]], on="row_id")
    W["mtype"] = (W.obfChangedFileCount.fillna(0) == 0) & W.newDependencyAdded.astype(bool) & ~W.installScriptAdded.astype(bool)
    cfgs = sorted({m.split("|")[1] for m in S.model.unique() if "|" in m})
    sel_log, rows = [], []
    for grp, g in W.groupby("group"):
        cal = g[g.stage == "calibration"]
        chosen = {}
        for fs in ["full35", "gs24", "full28_noObfNew"]:
            prs = {cf: float(np.mean([average_precision_score(h.label, h[f"{fs}|{cf}"]) for _, h in cal.groupby("cell")])) for cf in cfgs}
            best = max(prs, key=lambda k: (round(prs[k], 12), k == DEFAULT))
            chosen[fs] = best
            sel_log += [{"group": grp, "feature_set": fs, "config": k, "cal_pr_auc": v, "selected": k == best} for k, v in prs.items()]
        cand = {}
        for mode in ["default", "hpo"]:
            pick = {fs: (DEFAULT if mode == "default" else chosen[fs]) for fs in chosen}
            for fs in ["full35", "gs24", "full28_noObfNew"]:
                cand[f"{fs}|{mode}"] = g[f"{fs}|{pick[fs]}"].to_numpy()
            # B3 blend
            tmp = pd.DataFrame({"full35": g[f"full35|{pick['full35']}"].to_numpy(), "full35_lr": g.full35_lr.to_numpy(), "full35_mlp": g.full35_mlp.to_numpy()}, index=g.index)
            best = None
            for scale in ["prob", "logit"]:
                for wt in bl.candidates(3):
                    pr = float(np.mean([average_precision_score(h.label, bl.combine(tmp.loc[h.index], ["full35", "full35_lr", "full35_mlp"], wt, scale))
                                        for _, h in cal.groupby("cell")]))
                    key = (pr, wt[0], scale == "prob")
                    if best is None or key > best[0]:
                        best = (key, scale, wt)
            cand[f"B3|{mode}"] = np.asarray(bl.combine(tmp, ["full35", "full35_lr", "full35_mlp"], best[2], best[1]), dtype=float)
            sel_log.append({"group": grp, "feature_set": f"B3|{mode}", "config": f"{best[1]} {[abs(x) for x in best[2]]}", "cal_pr_auc": best[0][0], "selected": True})
            # C5 routing on rank scale, per cell
            c5 = np.zeros(len(g))
            for cell, h in g.groupby("cell"):
                idx = g.index.get_indexer(h.index)
                nrm = h[(h.stage == "calibration") & (h.label == 0)]
                r35 = rank_vs(nrm[f"full35|{pick['full35']}"].to_numpy(), h[f"full35|{pick['full35']}"].to_numpy())
                rgs = rank_vs(nrm[f"gs24|{pick['gs24']}"].to_numpy(), h[f"gs24|{pick['gs24']}"].to_numpy())
                c5[idx] = np.where(h.mtype, rgs, r35)
            cand[f"C5|{mode}"] = c5
        for name, sc in cand.items():
            g2 = g.assign(score=sc)
            for t in TARGETS:
                tp = fp = hfp = 0
                for cell, h in g2.groupby("cell"):
                    hc, he = h[h.stage == "calibration"], h[h.stage == "eval"]
                    thr = snap.calibrate(hc.score.to_numpy(), hc.label.to_numpy(), np.zeros(len(hc), bool), "ML", t)["threshold"]
                    sel = he.score.to_numpy() >= thr
                    m = he.label.to_numpy() == 1
                    tp += int((sel & m).sum()); fp += int((sel & ~m).sum()); hfp += int((sel & (he["class"] == "hard_benign").to_numpy()).sum())
                ev = g2[g2.stage == "eval"]
                nm, nn, nh = int((ev.label == 1).sum()), int((ev.label == 0).sum()), int((ev["class"] == "hard_benign").sum())
                pr = float(np.mean([average_precision_score(h.label, h.score) for _, h in ev.groupby("cell") if h.label.nunique() == 2]))
                rows.append({"group": grp, "model": name, "target_fpr": t, "TP": tp, "malicious": nm, "recall": tp / nm, "FP": fp, "fpr": fp / nn,
                             "hard_FP": hfp, "hard_fpr": hfp / nh if nh else np.nan, "PR_AUC": pr, "goal_met": tp / nm >= 0.90 and fp / nn <= 0.05})
    R = pd.DataFrame(rows)
    R.to_csv(a.out / "metrics.csv", index=False, lineterminator="\n")
    pd.DataFrame(sel_log).to_csv(a.out / "selection_calibration.csv", index=False, lineterminator="\n")
    summ = R[R.group != "loco"].groupby(["model", "target_fpr"]).agg(groups=("group", "nunique"), recall_min=("recall", "min"), recall_mean=("recall", "mean"),
                                                                       fpr_max=("fpr", "max"), fpr_mean=("fpr", "mean"), hard_fpr_mean=("hard_fpr", "mean"),
                                                                       goal_met_groups=("goal_met", "sum")).reset_index()
    summ.to_csv(a.out / "summary_non_loco.csv", index=False, lineterminator="\n")
    (a.out / "manifest.json").write_text(json.dumps({"script_sha256": sha(__file__), "scores_sha256": sha(a.scores / "scores.csv"),
        "outputs": {p.name: sha(p) for p in sorted(a.out.glob("*.csv"))}}, indent=1) + "\n")
    print(summ.round(3).to_string(index=False))


if __name__ == "__main__":
    main()
