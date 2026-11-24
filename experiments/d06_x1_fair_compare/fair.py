"""Same-protocol comparison on D06 outer (PR #13 splits). Saved scores only; no training; no Test.
Thresholds from calibration only (PR #13 calibrate, ML policy) at target FPR 1/3/5%; 0.5 reference.

Usage (from anywhere): python -I -B experiments/d06_x1_fair_compare/fair.py
Writes the four CSVs next to this file. Inputs: see README.md section 10."""
import sys, importlib.util
from pathlib import Path
HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE.parent / "d06_x1_cause_analysis"))  # shared loaders (common.py)
import common as c, numpy as np, pandas as pd
from sklearn.metrics import roc_auc_score, average_precision_score
pd.set_option("display.width", 260); pd.set_option("display.max_rows", 400)
spc = importlib.util.spec_from_file_location("snap", c.B / "provenance/phase2_run1_base7_full29/executed_script_snapshot.py")
snap = importlib.util.module_from_spec(spc); spc.loader.exec_module(snap)
df = c.frame()
s13 = pd.read_csv(c.B / "scores/saved_scores.csv")[["model", "seed", "fold", "stage", "row_id", "score"]].rename(columns={"model": "variant"})
s35 = pd.read_csv(c.C / "run/scores.csv"); s35 = s35[s35.variant == "full35"][["variant", "seed", "fold", "stage", "row_id", "score"]]
S = pd.concat([s13, s35]); K = ["seed", "fold", "stage", "row_id"]
w = S.pivot_table(index=K, columns="variant", values="score").reset_index()
assert w[["base7", "full29", "no_interval28", "full35"]].notna().all().all() and not w.duplicated(K).any()
for k, a in {"A1": .1, "A2": .2, "A3": .3}.items(): w[k] = (1 - a) * w.full29 + a * w.full35
w = w.merge(df[["row_id", "label", "class", "campaign"]], on="row_id"); w["split"] = w.seed.map(c.SEED)
V = ["base7", "full29", "no_interval28", "full35", "A1", "A2", "A3"]
cal, o = w[w.stage == "calibration"], w[w.stage == "outer"]
# same rows check
assert o.groupby(["split", "fold"]).size().to_dict() == {("split1", 0): 945, ("split1", 1): 911, ("split1", 2): 911, ("split2", 0): 945, ("split2", 1): 911, ("split2", 2): 911}
thr, calinfo = {}, []
for v in V:
    for (spl, fo), g in cal.groupby(["split", "fold"]):
        for tgt in [0.01, 0.03, 0.05]:
            r = snap.calibrate(g[v].values, g.label.values, np.zeros(len(g), bool), "ML", tgt)
            thr[(v, spl, fo, tgt)] = r["threshold"]
            calinfo.append({"variant": v, "split": spl, "fold": fo, "target": tgt, "cal_normals": r["calibration_normal"], "budget": r["budget"],
                            "cal_fp": r["calibration_fp"], "achieved_cal_fpr": r["calibration_fp"] / r["calibration_normal"], "boundary_ties": r["ties"], "threshold": r["threshold"]})
CI = pd.DataFrame(calinfo); CI.to_csv(HERE / "calibration_attainment.csv", index=False)
rows = []
for op in [0.01, 0.03, 0.05, "0.5"]:
    for v in V:
        for spl, g in o.groupby("split"):
            t = np.array([0.5 if op == "0.5" else thr[(v, spl, f, op)] for f in g.fold])
            sel = g[v].values >= t; mal = g.label.values == 1; neg = ~mal
            tp, fp = int((sel & mal).sum()), int((sel & neg).sum()); rec = tp / mal.sum(); prec = tp / max(sel.sum(), 1)
            per = pd.Series(sel[mal], index=g.campaign.values[mal]).groupby(level=0).mean()
            rows.append({"op": f"calFPR{int(op*100)}%" if op != "0.5" else "0.5", "variant": v, "split": spl, "TP": tp, "FN": int(mal.sum()) - tp, "FP": fp,
                         "HardFP": int((sel & (g["class"] == "hard_benign").values).sum()), "Recall": rec, "Precision": prec,
                         "F1": 2 * rec * prec / (rec + prec) if rec + prec else 0, "outerFPR": fp / neg.sum(), "CampMacro": per.mean()})
R = pd.DataFrame(rows); R.to_csv(HERE / "fair_comparison.csv", index=False)
rk = []
for v in V:
    for spl, g in o.groupby("split"):
        pf = [(roc_auc_score(h.label, h[v]), average_precision_score(h.label, h[v])) for _, h in g.groupby("fold")]
        rk.append({"variant": v, "split": spl, "ROC_AUC_fold_mean": np.mean([a for a, _ in pf]), "PR_AUC_fold_mean": np.mean([b for _, b in pf])})
RK = pd.DataFrame(rk); RK.to_csv(HERE / "ranking.csv", index=False)
for op in R.op.unique():
    print(f"\n===== {op}"); print(R[R.op == op].drop(columns="op").round(4).to_string(index=False))
print("\n===== ranking (threshold-free, fold mean)"); print(RK.round(4).to_string(index=False))
print("\n===== calibration attainment (achieved cal FPR / budget / ties), mean over folds")
print(CI.groupby(["variant", "target"])[["cal_normals", "budget", "cal_fp", "achieved_cal_fpr", "boundary_ties"]].agg(["min", "max"]).round(4).to_string())
# reference only: E06/E09 OOF on CV01 split (different folds, no calibration, ES on eval fold)
p = pd.read_csv(REPO / "results/diagnostics/d06_diag01_pair_predictions.csv")
ref = []
for v, g in p.groupby("variant"):
    m = g.label == 1; sel = g.proba >= .5
    ref.append({"variant": v, "rows": len(g), "TP@0.5": int((sel & m).sum()), "FP@0.5": int((sel & ~m).sum()), "Recall@0.5": (sel & m).sum() / m.sum(),
                "PR_AUC_fold_mean": np.mean([average_precision_score(h.label, h.proba) for _, h in g.groupby("fold")]),
                "ROC_AUC_fold_mean": np.mean([roc_auc_score(h.label, h.proba) for _, h in g.groupby("fold")])})
print("\n===== REFERENCE ONLY: E06/E09 CV01 OOF (different split, no calibration, early stopping on eval fold)"); print(pd.DataFrame(ref).round(4).to_string(index=False))
cv = pd.read_csv(REPO / "splits/cv_3fold_assignment.csv"); print("cv01 cols", cv.columns.tolist()[:6])

# DIAGNOSTIC ONLY (uses outer labels; not a policy, not used for any choice): TP at matched outer FP budget per fold
dg = []
for x in [0.01, 0.03, 0.05]:
    for v in V:
        for spl, g in o.groupby("split"):
            tp = fp = 0
            for _, h in g.groupby("fold"):
                neg = np.sort(h[v].values[h.label.values == 0])[::-1]; k = int(np.floor(x * len(neg)))
                t = np.nextafter(neg[k], np.inf); sel = h[v].values >= t
                tp += int((sel & (h.label.values == 1)).sum()); fp += int((sel & (h.label.values == 0)).sum())
            dg.append({"outerFPR_budget": x, "variant": v, "split": spl, "TP": tp, "FP": fp})
D = pd.DataFrame(dg); D.to_csv(HERE / "diagnostic_matched_outer_fpr.csv", index=False)
print("\n===== DIAGNOSTIC: TP at matched OUTER FP budget (oracle thresholds)")
print(D.pivot_table(index="variant", columns=["outerFPR_budget", "split"], values="TP").reindex(V).to_string())
