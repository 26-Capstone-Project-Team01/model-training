"""DIAGNOSTIC ONLY: matched actual-FPR comparison from existing G2f 60-run validation scores.
Thresholds are chosen on validation normal labels (per fold, largest threshold with validation normal FP <= floor(n*t)),
so these numbers are NOT independent estimates and the thresholds must NOT be used operationally. No training, no Test."""
import sys
from pathlib import Path
import numpy as np, pandas as pd
RUN, OUT = Path(sys.argv[1]), Path(sys.argv[2]); OUT.mkdir(parents=True, exist_ok=False)
GENERIC = "individuals_case"; MODELS = ["M1", "M2-r", "M2", "M3", "M4", "M4-r"]; B = 2000
fa = pd.read_csv(RUN / "fold_assignment.csv", keep_default_na=False)
S = pd.read_csv(RUN / "scores.csv"); S = S[S.stage == "validation"].merge(fa[["row_id", "class", "splitGroup", "P", "fold"]], on=["row_id", "fold"])
S["mal"] = S["class"] == "malicious"
TH = pd.read_csv(RUN / "thresholds.csv")

def matched_thr(g, t):
    neg = np.sort(g.loc[~g.mal, "score"].to_numpy())[::-1]; k = int(np.floor(len(neg) * t + 1e-12))
    return np.nextafter(neg[k], np.inf) if k < len(neg) else -np.inf   # score >= thr; ties at the (k+1)-th normal stay negative

rows = []
for (m, sd, f), g in S.groupby(["model", "cal_seed", "fold"]):
    for t in (0.01, 0.05):
        rows.append({"model": m, "cal_seed": sd, "fold": f, "target": t, "mode": "matched_val_FPR(diagnostic)", "thr": matched_thr(g, t)})
        rows.append({"model": m, "cal_seed": sd, "fold": f, "target": t, "mode": "calibration(pre-set)", "thr": float(TH[(TH.model == m) & (TH.cal_seed == sd) & (TH.fold == f) & (TH.target_fpr == t)].threshold.iloc[0])})
T = pd.DataFrame(rows); T.to_csv(OUT / "thresholds_used.csv", index=False)
V = S.merge(T, on=["model", "cal_seed", "fold"]); V["sel"] = V.score >= V.thr
V.loc[V.mal, ["model", "cal_seed", "target", "mode", "row_id", "splitGroup", "P", "fold", "sel"]].to_csv(OUT / "malicious_decisions.csv.gz", index=False)

def summarize(g):
    mal = g[g.mal]; nor = g[~g.mal]; hb = g["class"] == "hard_benign"
    camp = mal[mal.splitGroup != GENERIC].groupby("splitGroup").sel.mean()
    pay = mal.groupby("P").sel.mean()
    pay_c = mal[mal.splitGroup != GENERIC].groupby(["splitGroup", "P"]).sel.mean().groupby("splitGroup").mean()
    return pd.Series({"recall": mal.sel.mean(), "fpr_all": nor.sel.mean(), "fpr_benign": g[g["class"] == "benign"].sel.mean(), "fpr_hard_benign": g[hb].sel.mean(),
                      "hard_FP": int(g[hb].sel.sum()), "macro_campaign": camp.mean(), "K": len(camp), "macro_campaign_n_ge5": camp[mal[mal.splitGroup != GENERIC].groupby("splitGroup").size() >= 5].mean(),
                      "macro_payload_all": pay.mean(), "n_payloads": len(pay), "macro_payload_within_campaign": pay_c.mean(), "individuals_recall": mal[mal.splitGroup == GENERIC].sel.mean()})
R = V.groupby(["mode", "target", "model", "cal_seed"]).apply(summarize).reset_index(); R.to_csv(OUT / "summary.csv", index=False)
C = V[V.mal].groupby(["mode", "target", "model", "cal_seed", "fold", "splitGroup"]).sel.agg(["mean", "size"]).reset_index().rename(columns={"mean": "recall", "size": "n"})
C.to_csv(OUT / "campaign_recall.csv", index=False)
# paired campaign bootstrap: M1 - M2-r macro difference (campaigns resampled), per mode/target/seed
rng = np.random.default_rng(20261126); bs = []
for (mo, t, sd), g in C[C.splitGroup != GENERIC].groupby(["mode", "target", "cal_seed"]):
    p = g.pivot_table(index="splitGroup", columns="model", values="recall")
    for a, b in [("M1", "M2-r")]:
        d = (p[a] - p[b]).to_numpy(); boot = np.array([d[rng.integers(0, len(d), len(d))].mean() for _ in range(B)])
        bs.append({"mode": mo, "target": t, "cal_seed": sd, "diff": f"{a}-{b}", "mean_diff": d.mean(), "ci95_lo": np.quantile(boot, .025), "ci95_hi": np.quantile(boot, .975),
                   "a_better": int((d > 1e-12).sum()), "b_better": int((d < -1e-12).sum()), "ties": int((np.abs(d) <= 1e-12).sum()), "K": len(d)})
pd.DataFrame(bs).to_csv(OUT / "paired_bootstrap_M1_vs_M2r.csv", index=False)
print("written", OUT)
