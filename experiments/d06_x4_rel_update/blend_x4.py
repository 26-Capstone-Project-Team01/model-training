"""Blend X4 LightGBM variants with the saved LR / MLP (full35 features, ../d06_alt_models/run_alt). No training. No Test.

Same pre-specified procedure as ../d06_alt_models/blend.py (its combine()/candidates() are imported unchanged):
scales prob|logit, 0.1 weight grid (2-model) / 0.1 simplex grid (3-model), selection per split by mean calibration PR-AUC
over 3 folds, ties -> larger base weight, then prob.
Base model choice ("improved model"), fixed before blending: the X4 variant (full35_x4 or full34_x4) with the higher mean
calibration PR-AUC over the 6 (split, fold) cells. Blends of BOTH X4 variants are written and reported; the calibration-chosen
one is marked primary. Outer labels are not used for any choice.
Usage: python -I -B blend_x4.py --models run_models --out <new dir>
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score

HERE = Path(__file__).resolve().parent
ALT = HERE.parent / "d06_alt_models"
K = ["seed", "fold", "stage", "row_id"]


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location("blend_alt", ALT / "blend.py")
    b = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(b)
    s = pd.concat([pd.read_csv(a.models / "scores.csv"), pd.read_csv(ALT / "run_alt/scores.csv")])
    w = s[["variant", "split"] + K + ["score"]].pivot_table(index=["split"] + K, columns="variant", values="score").reset_index()
    meta = pd.read_csv(b.c.C / "run/row_metadata.csv", keep_default_na=False)[["row_id", "label"]]
    w = w.merge(meta, on="row_id")
    cal = w[w.stage == "calibration"]
    base_pr = {v: float(np.mean([average_precision_score(h.label, h[v]) for _, h in cal.groupby(["split", "fold"])])) for v in ["full35_x4", "full34_x4"]}
    primary = max(base_pr, key=lambda v: (base_pr[v], v == "full35_x4"))
    sel_rows, scores, chosen = [], [], {}
    for base in ["full35_x4", "full34_x4"]:
        blends = {f"B1x_{base}_lr": [base, "full35_lr"], f"B2x_{base}_mlp": [base, "full35_mlp"], f"B3x_{base}_lr_mlp": [base, "full35_lr", "full35_mlp"]}
        for name, models in blends.items():
            for split, g in cal.groupby("split"):
                best = None
                for scale in ["prob", "logit"]:
                    for wt in b.candidates(len(models)):
                        pr = float(np.mean([average_precision_score(h.label, b.combine(h, models, wt, scale)) for _, h in g.groupby("fold")]))
                        sel_rows.append({"blend": name, "split": split, "scale": scale, "weights": " ".join(map(str, wt)), "cal_pr_auc": pr})
                        key = (pr, wt[0], scale == "prob")
                        if best is None or key > best[0]:
                            best = (key, scale, wt)
                chosen[f"{name}|{split}"] = {"models": models, "scale": best[1], "weights": [abs(x) for x in best[2]], "cal_pr_auc": best[0][0]}
                gg = w[w.split == split]
                scores.append(pd.DataFrame({"variant": name, "split": split, "seed": gg.seed, "fold": gg.fold, "stage": gg.stage, "row_id": gg.row_id,
                                            "score": b.combine(gg, models, best[2], best[1])}))
    pd.DataFrame(sel_rows).to_csv(a.out / "selection_calibration.csv", index=False, lineterminator="\n")
    pd.concat(scores).to_csv(a.out / "scores.csv", index=False, lineterminator="\n")
    man = {"base_calibration_pr_auc": base_pr, "primary_base": primary, "selected": chosen, "script_sha256": sha(__file__),
           "blend_py_sha256": sha(ALT / "blend.py"), "inputs": {"models": sha(a.models / "scores.csv"), "alt": sha(ALT / "run_alt/scores.csv")},
           "outputs": {p.name: sha(p) for p in sorted(a.out.glob("*.csv"))}}
    (a.out / "manifest.json").write_text(json.dumps(man, indent=1) + "\n")
    print(json.dumps({"base_calibration_pr_auc": base_pr, "primary_base": primary,
                      "selected": {k: (v["scale"], v["weights"], round(v["cal_pr_auc"], 4)) for k, v in chosen.items()}}, indent=1))


if __name__ == "__main__":
    main()
