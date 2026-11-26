"""Aggregate M1-M4 Train-internal validation results (no Test). Usage: python -I -B evaluate_m1m4.py --run run --out eval"""
import argparse, json
from pathlib import Path
import numpy as np, pandas as pd
from sklearn.metrics import average_precision_score

ap = argparse.ArgumentParser(); ap.add_argument("--run", type=Path, required=True); ap.add_argument("--out", type=Path, required=True)
a = ap.parse_args(); a.out.mkdir(parents=True, exist_ok=False)
fa = pd.read_csv(a.run / "fold_assignment.csv", dtype={"row_id": int}, keep_default_na=False)
S = pd.read_csv(a.run / "scores.csv"); TH = pd.read_csv(a.run / "thresholds.csv"); MF = pd.read_csv(a.run / "metrics_fold.csv")
GENERIC = "individuals_case"
V = S[S.stage == "validation"].merge(fa[["row_id", "class", "era", "splitGroup", "fold"]], on=["row_id", "fold"])
V["label"] = (V["class"] == "malicious").astype(int)
V = V.merge(TH[["cal_seed", "fold", "model", "target_fpr", "threshold"]], on=["cal_seed", "fold", "model"])
V["sel"] = V.score >= V.threshold
# calibration overlap between seeds
C = pd.read_csv(a.run / "calibration_assignment.csv")
ov = [{"fold": f, "overlap_rows": len(set(g[g.cal_seed == 20261109].row_id) & set(g[g.cal_seed == 20261110].row_id)), "rows": int((g.cal_seed == 20261109).sum())} for f, g in C.groupby("fold")]
pd.DataFrame(ov).to_csv(a.out / "calibration_seed_overlap.csv", index=False)
rows, camp = [], []
for (m, sd, t), g in V.groupby(["model", "cal_seed", "target_fpr"]):
    mal, ben, hb = g.label == 1, g["class"] == "benign", g["class"] == "hard_benign"
    tp, fp = int((g.sel & mal).sum()), int((g.sel & ~mal).sum())
    rec, prec = tp / mal.sum(), tp / max(g.sel.sum(), 1)
    per = g[mal].groupby("splitGroup").sel.agg(["mean", "size"])
    real = per.drop(index=GENERIC, errors="ignore")
    fm = MF[(MF.model == m) & (MF.cal_seed == sd) & (MF.target_fpr == t)]
    rows.append({"model": m, "cal_seed": sd, "target_fpr": t, "TP": tp, "FP": fp, "recall": rec, "precision": prec, "f1": 2 * rec * prec / (rec + prec) if rec + prec else 0,
                 "fpr_all_normal": fp / (~mal).sum(), "fpr_benign": (g.sel & ben).sum() / ben.sum(), "fpr_hard_benign": (g.sel & hb).sum() / hb.sum(),
                 "benign_FP": int((g.sel & ben).sum()), "hard_FP": int((g.sel & hb).sum()),
                 "macro_campaign_recall_real": real["mean"].mean(), "macro_campaign_recall_incl_individuals": per["mean"].mean(),
                 "individuals_case_recall": per["mean"].get(GENERIC, np.nan), "min_campaign_recall_real": real["mean"].min(),
                 "recall_D06_rows": g[mal & (g.era == "D06")].sel.mean(), "recall_new_rows": g[mal & (g.era == "new")].sel.mean(),
                 "PR_AUC_fold_mean": fm.PR_AUC_fold.mean(), "PR_AUC_fold_min": fm.PR_AUC_fold.min(),
                 "recall_fold_std": fm.recall.std(), "recall_fold_min": fm.recall.min(), "fpr_all_fold_std": fm.fpr_all_normal.std(), "fpr_all_fold_max": fm.fpr_all_normal.max(),
                 "hard_fpr_fold_max": fm.fpr_hard_benign.max()})
    for grp, r in per.iterrows():
        camp.append({"model": m, "cal_seed": sd, "target_fpr": t, "splitGroup": grp, "n": int(r["size"]), "recall": r["mean"]})
R = pd.DataFrame(rows); R.to_csv(a.out / "summary_by_model_seed.csv", index=False)
pd.DataFrame(camp).to_csv(a.out / "campaign_recall.csv", index=False)
# PR-AUC pooled per seed (OOF concatenation across folds; scores from different fold models -> reported as secondary)
pa = []
for (m, sd), g in S[S.stage == "validation"].merge(fa[["row_id", "class"]], on="row_id").groupby(["model", "cal_seed"]):
    pa.append({"model": m, "cal_seed": sd, "PR_AUC_pooled_oof": average_precision_score(g["class"] == "malicious", g.score)})
pd.DataFrame(pa).to_csv(a.out / "pr_auc_pooled.csv", index=False)
# seed variability
sv = R.groupby(["model", "target_fpr"]).agg(**{f"{c}_seed_diff": (c, lambda s: s.max() - s.min()) for c in ["recall", "fpr_benign", "fpr_hard_benign", "macro_campaign_recall_real"]}).reset_index()
sv.to_csv(a.out / "seed_variability.csv", index=False)
# fold-level table
MF.to_csv(a.out / "metrics_fold_copy.csv", index=False)
print(pd.DataFrame(ov).to_string(index=False))
pd.set_option("display.width", 280); pd.set_option("display.max_columns", 40)
print(R.round(4).to_string(index=False)); print(pd.DataFrame(pa).round(4).to_string(index=False)); print(sv.round(4).to_string(index=False))
