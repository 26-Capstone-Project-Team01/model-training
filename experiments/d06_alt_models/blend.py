"""Blending full35 (LightGBM, d06_full35_compare) with LR / MLP (run_alt) from saved scores only. No training. No Test.

Pre-specified candidates (fixed before any blend result was computed):
  scales : "prob"  = weighted mean of probabilities
           "logit" = weighted mean of logit(clip(p, 1e-6, 1-1e-6)), mapped back with the logistic function
  weights: two-model blends B1 full35+LR, B2 full35+MLP: w_other in {0.0, 0.1, ..., 0.9, 1.0}
           three-model blend B3 full35+LR+MLP: all (w_full35, w_lr, w_mlp) on the 0.1 simplex grid (66 points)
Selection: per split, the (scale, weights) with the highest mean calibration PR-AUC over the 3 folds. Ties -> larger
w_full35, then "prob". Outer labels are never used for selection. Thresholds are then set by evaluate.py with the
PR #13 calibration policy, as for every other variant.

Also writes a score-scale check (quantiles by class on calibration rows, Spearman/Pearson between models).
Usage: python -I -B blend.py --out <new dir>
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
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

K = ["seed", "fold", "stage", "row_id"]
GRID = [round(x, 1) for x in np.arange(0, 1.01, 0.1)]
BLENDS = {"B1_f35_lr": ["full35", "full35_lr"], "B2_f35_mlp": ["full35", "full35_mlp"], "B3_f35_lr_mlp": ["full35", "full35_lr", "full35_mlp"]}


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def logit(p):
    p = np.clip(p, 1e-6, 1 - 1e-6)
    return np.log(p / (1 - p))


def combine(frame, models, weights, scale):
    if scale == "prob":
        return sum(w * frame[m].to_numpy() for m, w in zip(models, weights))
    z = sum(w * logit(frame[m].to_numpy()) for m, w in zip(models, weights))
    return 1 / (1 + np.exp(-z))


def candidates(n):
    if n == 2:
        return [(round(1 - w, 1), w) for w in GRID]
    return [(a, b, round(1 - a - b, 1)) for a in GRID for b in GRID if a + b <= 1.0 + 1e-9]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True)
    out = ap.parse_args().out
    out.mkdir(parents=True, exist_ok=False)
    s35 = pd.read_csv(c.C / "run/scores.csv")
    s35 = s35[s35.variant == "full35"]
    alt = pd.read_csv(HERE / "run_alt/scores.csv")
    w = pd.concat([s35, alt])[["variant", "split"] + K + ["score"]].pivot_table(index=["split"] + K, columns="variant", values="score").reset_index()
    assert w[["full35", "full35_lr", "full35_mlp"]].notna().all().all()
    meta = pd.read_csv(c.C / "run/row_metadata.csv", keep_default_na=False)[["row_id", "label", "class"]]
    w = w.merge(meta, on="row_id")
    cal = w[w.stage == "calibration"]
    # scale check
    rows = []
    for m in ["full35", "full35_lr", "full35_mlp"]:
        for cls, g in cal.groupby("class"):
            q = g[m].quantile([.05, .25, .5, .75, .95])
            rows.append({"model": m, "class": cls, "n": len(g), **{f"q{int(k * 100)}": v for k, v in q.items()},
                         "share_lt_0.01": (g[m] < .01).mean(), "share_gt_0.99": (g[m] > .99).mean()})
    pd.DataFrame(rows).to_csv(out / "score_scale_calibration.csv", index=False, lineterminator="\n")
    corr = {f"{a}~{b}": {"spearman": float(cal[a].corr(cal[b], method="spearman")), "pearson": float(cal[a].corr(cal[b]))}
            for a, b in itertools.combinations(["full35", "full35_lr", "full35_mlp"], 2)}
    # selection on calibration
    sel_rows, chosen = [], {}
    for name, models in BLENDS.items():
        for split, g in cal.groupby("split"):
            best = None
            for scale in ["prob", "logit"]:
                for wt in candidates(len(models)):
                    pr = float(np.mean([average_precision_score(h.label, combine(h, models, wt, scale)) for _, h in g.groupby("fold")]))
                    sel_rows.append({"blend": name, "split": split, "scale": scale, "weights": " ".join(map(str, wt)), "cal_pr_auc": pr})
                    key = (pr, wt[0], scale == "prob")
                    if best is None or key > best[0]:
                        best = (key, scale, wt)
            chosen[(name, split)] = (best[1], best[2])
    S = pd.DataFrame(sel_rows)
    S.to_csv(out / "selection_calibration.csv", index=False, lineterminator="\n")
    scores = []
    for (name, split), (scale, wt) in chosen.items():
        g = w[w.split == split]
        scores.append(pd.DataFrame({"variant": name, "split": split, "seed": g.seed, "fold": g.fold, "stage": g.stage, "row_id": g.row_id,
                                    "score": combine(g, BLENDS[name], wt, scale)}))
    pd.concat(scores).to_csv(out / "scores.csv", index=False, lineterminator="\n")
    sel = {f"{n}|{s}": {"models": BLENDS[n], "scale": sc, "weights": list(wt),
                        "cal_pr_auc": float(S[(S.blend == n) & (S.split == s) & (S.scale == sc) & (S.weights == " ".join(map(str, wt)))].cal_pr_auc.iloc[0]),
                        "full35_only_cal_pr_auc": float(S[(S.blend == n) & (S.split == s) & (S.scale == "prob") & (S.weights == " ".join(map(str, candidates(len(BLENDS[n]))[0] if len(BLENDS[n]) == 2 else (1.0, 0.0, 0.0))))].cal_pr_auc.iloc[0])}
           for (n, s), (sc, wt) in chosen.items()}
    man = {"selected": sel, "correlation_calibration": corr, "script_sha256": sha(__file__),
           "inputs": {"full35_scores": sha(c.C / "run/scores.csv"), "alt_scores": sha(HERE / "run_alt/scores.csv")},
           "outputs": {p.name: sha(p) for p in sorted(out.glob("*.csv"))}}
    (out / "manifest.json").write_text(json.dumps(man, indent=1) + "\n")
    print(json.dumps(sel, indent=1))
    print(json.dumps(corr, indent=1))


if __name__ == "__main__":
    main()
