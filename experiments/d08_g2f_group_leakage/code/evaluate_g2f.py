"""Aggregate the G2f 60-run (Train-internal; no Test). Usage: python -I -B evaluate_g2f.py --run run --out eval"""
import argparse, itertools
from pathlib import Path
import numpy as np, pandas as pd
from sklearn.metrics import average_precision_score

ap = argparse.ArgumentParser(); ap.add_argument("--run", type=Path, required=True); ap.add_argument("--out", type=Path, required=True)
a = ap.parse_args(); a.out.mkdir(parents=True, exist_ok=False)
GENERIC = "individuals_case"; WS = "obfWhitespaceRatioChangedCode"
KEY = ["package", "old_version", "new_version"]
fa = pd.read_csv(a.run / "fold_assignment.csv", keep_default_na=False)
tr = pd.read_csv(Path(__file__).resolve().parent.parent / "inputs" / "train.csv", dtype=str, keep_default_na=False)
fa = fa.merge(tr[KEY + [WS]], on=KEY, how="left"); fa["ws"] = pd.to_numeric(fa[WS].replace("", np.nan))
S = pd.read_csv(a.run / "scores.csv"); TH = pd.read_csv(a.run / "thresholds.csv"); MF = pd.read_csv(a.run / "metrics_fold.csv"); B = pd.read_csv(a.run / "ws_bands.csv")
V = S[S.stage == "validation"].merge(fa[["row_id", "class", "era", "splitGroup", "fold", "ws"]], on=["row_id", "fold"])
V["label"] = (V["class"] == "malicious").astype(int)
V = V.merge(TH[["cal_seed", "fold", "model", "target_fpr", "threshold"]], on=["cal_seed", "fold", "model"]).merge(B, on=["cal_seed", "fold"])
V["sel"] = V.score >= V.threshold
V["ws_band"] = np.select([V.ws.isna(), V.ws < V.p5, V.ws > V.p95], ["missing", "low(<fit-normal p5)", "high(>p95)"], "normal(p5-p95)")


def wilson(k, n, z=1.96):
    if n == 0: return (np.nan, np.nan)
    p = k / n; d = 1 + z * z / n; c = (p + z * z / (2 * n)) / d; h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0, c - h), min(1, c + h))


rows, camp = [], []
for (m, sd, t), g in V.groupby(["model", "cal_seed", "target_fpr"]):
    mal = g.label == 1; ben = g["class"] == "benign"; hb = g["class"] == "hard_benign"
    tp, fp = int((g.sel & mal).sum()), int((g.sel & ~mal).sum())
    rec, prec = tp / mal.sum(), tp / max(g.sel.sum(), 1)
    per = g[mal].groupby("splitGroup").agg(k=("sel", "sum"), n=("sel", "size"), fold=("fold", "first"))
    per["recall"] = per.k / per.n
    real = per.drop(index=GENERIC, errors="ignore")
    fold_macro = real.groupby("fold").recall.mean()
    fm = MF[(MF.model == m) & (MF.cal_seed == sd) & (MF.target_fpr == t)]
    rows.append({"model": m, "cal_seed": sd, "target_fpr": t, "TP": tp, "FN": int(mal.sum()) - tp, "FP": fp, "benign_FP": int((g.sel & ben).sum()), "hard_FP": int((g.sel & hb).sum()),
                 "recall": rec, "precision": prec, "f1": 2 * rec * prec / (rec + prec) if rec + prec else 0,
                 "fpr_all_normal": fp / (~mal).sum(), "fpr_benign": (g.sel & ben).sum() / ben.sum(), "fpr_hard_benign": (g.sel & hb).sum() / hb.sum(),
                 "macro_campaign_recall": real.recall.mean(), "K": len(real), "macro_n_ge5": real[real.n >= 5].recall.mean(), "K_n_ge5": int((real.n >= 5).sum()),
                 "macro_incl_individuals": per.recall.mean(), "individuals_recall": per.recall.get(GENERIC, np.nan), "min_campaign_recall": real.recall.min(),
                 "macro_fold_stratified": fold_macro.mean(), "recall_D06_rows": g[mal & (g.era == "D06")].sel.mean(), "recall_new_rows": g[mal & (g.era == "new")].sel.mean(),
                 "PR_AUC_fold_mean": fm.PR_AUC_fold.mean(), "recall_fold_min": fm.recall.min(), "fpr_all_fold_max": fm.fpr_all_normal.max(), "hard_fpr_fold_max": fm.fpr_hard_benign.max()})
    for grp, r in per.iterrows():
        lo, hi = wilson(int(r.k), int(r.n))
        camp.append({"model": m, "cal_seed": sd, "target_fpr": t, "splitGroup": grp, "fold": int(r.fold), "n": int(r.n), "detected": int(r.k), "recall": r.recall,
                     "wilson_lo": lo, "wilson_hi": hi, "macro_weight": 0 if grp == GENERIC else 1 / len(real)})
R = pd.DataFrame(rows); R.to_csv(a.out / "summary_by_model_seed.csv", index=False)
C = pd.DataFrame(camp); C.to_csv(a.out / "campaign_recall.csv", index=False)
# macro decomposition by fold (sum of recall/K per fold)
Cr = C[C.splitGroup != GENERIC]
dec = Cr.assign(c=Cr.recall * Cr.macro_weight).groupby(["target_fpr", "model", "cal_seed", "fold"]).c.sum().unstack("fold")
dec["macro"] = dec.sum(axis=1); dec.reset_index().to_csv(a.out / "macro_fold_decomposition.csv", index=False)
# paired campaign comparisons (same seed/target/campaign)
pair = []
P = Cr.pivot_table(index=["cal_seed", "target_fpr", "splitGroup"], columns="model", values="recall")
for x, y in itertools.permutations(P.columns, 2):
    if x >= y: continue
    for (sd, t), g in P.groupby(level=[0, 1]):
        d = g[x] - g[y]
        pair.append({"cal_seed": sd, "target_fpr": t, "A": x, "B": y, "mean_diff_A_minus_B": d.mean(), "A_better": int((d > 1e-12).sum()), "B_better": int((d < -1e-12).sum()), "ties": int((d.abs() <= 1e-12).sum()),
                     "campaigns_A_better": ";".join(d[d > 1e-12].index.get_level_values(2)), "campaigns_B_better": ";".join(d[d < -1e-12].index.get_level_values(2))})
pd.DataFrame(pair).to_csv(a.out / "paired_campaign_comparison.csv", index=False)
# whitespace bands
wb = V.groupby(["target_fpr", "model", "cal_seed", "class", "ws_band"]).sel.agg(["mean", "size"]).reset_index().rename(columns={"mean": "flag_rate", "size": "n"})
wb.to_csv(a.out / "whitespace_band.csv", index=False)
# PR-AUC pooled OOF
pa = [{"model": m, "cal_seed": sd, "PR_AUC_pooled_oof": average_precision_score(g.label, g.score)} for (m, sd), g in V[V.target_fpr == 0.01].groupby(["model", "cal_seed"])]
pd.DataFrame(pa).to_csv(a.out / "pr_auc_pooled.csv", index=False)
sv = R.groupby(["model", "target_fpr"]).agg(**{f"{c}_seed_diff": (c, lambda s: s.max() - s.min()) for c in ["recall", "fpr_all_normal", "fpr_hard_benign", "macro_campaign_recall"]}).reset_index()
sv.to_csv(a.out / "seed_variability.csv", index=False)
MF.to_csv(a.out / "metrics_fold_copy.csv", index=False)
pd.set_option("display.width", 300); pd.set_option("display.max_columns", 40)
print(R[["model", "cal_seed", "target_fpr", "recall", "fpr_all_normal", "fpr_benign", "fpr_hard_benign", "hard_FP", "macro_campaign_recall", "macro_n_ge5", "min_campaign_recall", "PR_AUC_fold_mean"]].round(4).to_string(index=False))
