"""DIAGNOSTIC (uses outer labels; not used to select any model, weight or threshold).

For each split and outer fold:
  same recall : the other model's threshold is set to the lowest score that reaches full35's outer TP at its calibrated
                5% threshold (exactly the same TP per fold when possible). Report FP, Hard benign FP, benign FP.
  same FPR    : each model's threshold is set so that outer FP = floor(x * normals) (x = 1%, 3%, 5%), as in
                d06_x1_fair_compare/diagnostic_matched_outer_fpr.csv. Report TP and Hard benign FP.
Also: at the calibrated 5% operating points (evaluate.py), malicious missed by full35 and caught by LR / MLP / blends,
and malicious caught by full35 and lost.
Usage: python -I -B matched.py --eval <evaluate.py out dir> --runs run_alt run_blend --out <new dir>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
EXP = HERE.parent
sys.path.insert(0, str(EXP / "d06_x1_cause_analysis"))
import common as c  # noqa: E402

K = ["seed", "fold", "stage", "row_id"]


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--eval", type=Path, required=True)
    ap.add_argument("--runs", type=Path, nargs="+", required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=False)
    s35 = pd.read_csv(c.C / "run/scores.csv")
    parts = [s35[s35.variant == "full35"][["variant"] + K + ["score"]]] + [pd.read_csv(r / "scores.csv")[["variant"] + K + ["score"]] for r in a.runs]
    w = pd.concat(parts).pivot_table(index=K, columns="variant", values="score").reset_index()
    meta = pd.read_csv(c.C / "run/row_metadata.csv", keep_default_na=False)[["row_id", "label", "class", "campaign", "type"]]
    w = w.merge(meta, on="row_id")
    w["split"] = w.seed.map(c.SEED)
    o = w[w.stage == "outer"].copy()
    V = [v for v in w.columns if v.startswith(("full35_", "B"))]
    thr = pd.read_csv(a.eval / "thresholds.csv", float_precision="round_trip")
    thr = thr[thr.target == 0.05].set_index(["variant", "split", "fold"]).threshold
    rows, fpr_rows = [], []
    for (sp, f), g in o.groupby(["split", "fold"]):
        mal, hb, ben = g.label.to_numpy() == 1, (g["class"] == "hard_benign").to_numpy(), (g["class"] == "benign").to_numpy()
        tp35 = int(((g.full35.to_numpy() >= thr[("full35", sp, f)]) & mal).sum())
        for v in ["full35"] + V:
            s = g[v].to_numpy()
            ms = np.sort(s[mal])[::-1]
            t = ms[tp35 - 1] if tp35 > 0 else np.inf
            sel = s >= t
            rows.append({"split": sp, "fold": f, "variant": v, "target_TP": tp35, "TP": int((sel & mal).sum()), "FP": int((sel & ~mal).sum()),
                         "hard_FP": int((sel & hb).sum()), "benign_FP": int((sel & ben).sum())})
            neg = np.sort(s[~mal])[::-1]
            for x in [0.01, 0.03, 0.05]:
                k = int(np.floor(x * len(neg)))
                t2 = np.nextafter(neg[k], np.inf)
                sel2 = s >= t2
                fpr_rows.append({"split": sp, "fold": f, "variant": v, "outer_fpr_budget": x, "TP": int((sel2 & mal).sum()), "FP": int((sel2 & ~mal).sum()),
                                 "hard_FP": int((sel2 & hb).sum())})
    R = pd.DataFrame(rows).groupby(["split", "variant"])[["target_TP", "TP", "FP", "hard_FP", "benign_FP"]].sum().reset_index()
    R.to_csv(a.out / "same_recall_as_full35_fpr5.csv", index=False, lineterminator="\n")
    F = pd.DataFrame(fpr_rows).groupby(["split", "variant", "outer_fpr_budget"])[["TP", "FP", "hard_FP"]].sum().reset_index()
    F.to_csv(a.out / "same_outer_fpr.csv", index=False, lineterminator="\n")
    # gains / losses at calibrated 5%
    for v in ["full35"] + V:
        o[f"sel_{v}"] = o[v].to_numpy() >= np.array([thr[(v, sp, f)] for sp, f in zip(o.split, o.fold)])
    gl = []
    m = o[o.label == 1]
    for sp, g in m.groupby("split"):
        miss = ~g.sel_full35
        gl.append({"split": sp, "variant": "full35", "malicious": len(g), "full35_missed": int(miss.sum())})
        for v in V:
            gl.append({"split": sp, "variant": v, "malicious": len(g), "full35_missed": int(miss.sum()),
                       "added_among_full35_missed": int((miss & g[f"sel_{v}"]).sum()), "lost_from_full35": int((~miss & ~g[f"sel_{v}"]).sum()),
                       "added_campaigns": ";".join(f"{k}:{n}" for k, n in g[miss & g[f"sel_{v}"]].campaign.value_counts().items()),
                       "lost_campaigns": ";".join(f"{k}:{n}" for k, n in g[~miss & ~g[f"sel_{v}"]].campaign.value_counts().items())})
        both = miss & g.sel_full35_lr & g.sel_full35_mlp
        either = miss & (g.sel_full35_lr | g.sel_full35_mlp)
        gl.append({"split": sp, "variant": "LR_or_MLP (union, reference)", "malicious": len(g), "full35_missed": int(miss.sum()),
                   "added_among_full35_missed": int(either.sum()), "added_by_both": int(both.sum())})
    pd.DataFrame(gl).to_csv(a.out / "gain_loss_vs_full35_fpr5.csv", index=False, lineterminator="\n")
    man = {"nature": "DIAGNOSTIC ONLY (outer labels used for matching); not used for selection", "script_sha256": sha(__file__),
           "inputs": {"thresholds": sha(a.eval / "thresholds.csv"), **{str(r): sha(r / "scores.csv") for r in a.runs}},
           "outputs": {p.name: sha(p) for p in sorted(a.out.glob("*.csv"))}}
    (a.out / "manifest.json").write_text(json.dumps(man, indent=1) + "\n")


if __name__ == "__main__":
    main()
