"""Train-outer evaluation of new variants vs reused base7 / full29 (PR #13 saved scores) and full35 (d06_full35_compare).

Thresholds: PR #13 calibrate (ML policy) on each fold's calibration scores at target FPR 1/3/5% (same as ../d06_x1_fair_compare).
Before evaluating, base7 / full29 / full35 TP·FP·HardFP are recomputed and must equal ../d06_x1_fair_compare/fair_comparison.csv.
No training, no Test, no threshold or model choice from outer labels.

Usage: python -I -B evaluate.py --runs run_x1 [run_x3d ...] --out <new dir>
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

spec = importlib.util.spec_from_file_location("snap", c.B / "provenance/phase2_run1_base7_full29/executed_script_snapshot.py")
snap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snap)
BASE = ["base7", "full29", "full35"]
TARGETS = [0.01, 0.03, 0.05]
K = ["seed", "fold", "stage", "row_id"]


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=Path, nargs="+", required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    out = a.out
    out.mkdir(parents=True, exist_ok=False)
    meta = pd.read_csv(c.C / "run/row_metadata.csv", keep_default_na=False)[["row_id", "package", "old_version", "new_version", "label", "class", "campaign", "type"]]
    s13 = pd.read_csv(c.B / "scores/saved_scores.csv")
    s13 = s13[s13.model.isin(["base7", "full29"])][["model"] + K + ["score"]].rename(columns={"model": "variant"})
    s35 = pd.read_csv(c.C / "run/scores.csv")
    parts = [s13[["variant"] + K + ["score"]], s35[s35.variant == "full35"][["variant"] + K + ["score"]]]
    new = []
    for run in a.runs:
        s = pd.read_csv(run / "scores.csv")
        new += sorted(s.variant.unique())
        parts.append(s[["variant"] + K + ["score"]])
    V = BASE + new
    w = pd.concat(parts).pivot_table(index=K, columns="variant", values="score").reset_index()
    assert w[V].notna().all().all() and not w.duplicated(K).any()
    w = w.merge(meta, on="row_id")
    w["split"] = w.seed.map(c.SEED)
    cal, o = w[w.stage == "calibration"], w[w.stage == "outer"].copy()
    thr, calrows = {}, []
    for v in V:
        for (sp, f), g in cal.groupby(["split", "fold"]):
            for t in TARGETS:
                r = snap.calibrate(g[v].to_numpy(), g.label.to_numpy(), np.zeros(len(g), bool), "ML", t)
                thr[(v, sp, f, t)] = r["threshold"]
                calrows.append({"variant": v, "split": sp, "fold": f, "target": t, "threshold": r["threshold"], "cal_fp": r["calibration_fp"],
                                "cal_normal": r["calibration_normal"], "budget": r["budget"], "ties": r["ties"]})
    pd.DataFrame(calrows).to_csv(out / "thresholds.csv", index=False, lineterminator="\n")
    for v in V:
        for t in TARGETS:
            o[f"sel_{v}_{t}"] = o[v].to_numpy() >= np.array([thr[(v, sp, f, t)] for sp, f in zip(o.split, o.fold)])
    mal, hb, ben = o.label == 1, o["class"] == "hard_benign", o["class"] == "benign"
    # --- headline metrics
    rows = []
    for v in V:
        for sp, g in o.groupby("split"):
            gm, gh, gb = g.label == 1, g["class"] == "hard_benign", g["class"] == "benign"
            pr = [average_precision_score(h.label, h[v]) for _, h in g.groupby("fold")]
            for t in TARGETS:
                sel = g[f"sel_{v}_{t}"]
                rows.append({"variant": v, "split": sp, "target_fpr": t, "TP": int((sel & gm).sum()), "malicious": int(gm.sum()),
                             "recall": (sel & gm).sum() / gm.sum(), "FP": int((sel & ~gm).sum()), "outer_fpr": (sel & ~gm).sum() / (~gm).sum(),
                             "hard_FP": int((sel & gh).sum()), "hard_fpr": (sel & gh).sum() / gh.sum(), "benign_FP": int((sel & gb).sum()),
                             "benign_fpr": (sel & gb).sum() / gb.sum(), "PR_AUC_fold_mean": float(np.mean(pr)),
                             "PR_AUC_pooled": float(average_precision_score(g.label, g[v])),
                             "campaign_macro_recall": float(g[gm].groupby("campaign")[f"sel_{v}_{t}"].mean().mean())})
    R = pd.DataFrame(rows)
    R.to_csv(out / "metrics.csv", index=False, lineterminator="\n")
    fc = pd.read_csv(EXP / "d06_x1_fair_compare/fair_comparison.csv")
    for v in BASE:
        for t in TARGETS:
            for sp in ["split1", "split2"]:
                x = R[(R.variant == v) & (R.split == sp) & (R.target_fpr == t)].iloc[0]
                y = fc[(fc.variant == v) & (fc.split == sp) & (fc.op == f"calFPR{int(t * 100)}%")].iloc[0]
                assert (x.TP, x.FP, x.hard_FP) == (y.TP, y.FP, y.HardFP), (v, sp, t)
    # --- campaign / attack type recall
    cr, tr = [], []
    for v in V:
        for t in TARGETS:
            for sp, g in o[mal].groupby("split"):
                for camp, h in g.groupby("campaign"):
                    cr.append({"variant": v, "split": sp, "target_fpr": t, "campaign": camp, "n": len(h), "TP": int(h[f"sel_{v}_{t}"].sum())})
                for typ, h in g.groupby("type"):
                    tr.append({"variant": v, "split": sp, "target_fpr": t, "type": typ, "n": len(h), "TP": int(h[f"sel_{v}_{t}"].sum()),
                               "recall": h[f"sel_{v}_{t}"].mean()})
    pd.DataFrame(cr).to_csv(out / "campaign_recall.csv", index=False, lineterminator="\n")
    pd.DataFrame(tr).to_csv(out / "type_recall.csv", index=False, lineterminator="\n")
    # --- changes vs full35 (row level)
    ch, cases = [], []
    for v in V:
        if v == "full35":
            continue
        for t in TARGETS:
            for sp, g in o.groupby("split"):
                a35, av = g[f"sel_full35_{t}"], g[f"sel_{v}_{t}"]
                gm = g.label == 1
                d = {"variant": v, "split": sp, "target_fpr": t,
                     "malicious_new_detected": int((av & ~a35 & gm).sum()), "malicious_lost": int((~av & a35 & gm).sum()),
                     "fp_removed": int((~av & a35 & ~gm).sum()), "fp_new": int((av & ~a35 & ~gm).sum()),
                     "hard_fp_removed": int((~av & a35 & (g["class"] == "hard_benign")).sum()),
                     "hard_fp_new": int((av & ~a35 & (g["class"] == "hard_benign")).sum())}
                ch.append(d)
                if t == 0.05:
                    for kind, m in [("malicious_new_detected", av & ~a35 & gm), ("malicious_lost", ~av & a35 & gm),
                                    ("fp_removed", ~av & a35 & ~gm), ("fp_new", av & ~a35 & ~gm)]:
                        for r in g[m].itertuples():
                            cases.append({"variant": v, "split": sp, "kind": kind, "row_id": r.row_id, "package": r.package, "old_version": r.old_version,
                                          "new_version": r.new_version, "class": g.loc[r.Index, "class"],
                                          "campaign": r.campaign, "type": r.type, "score_full35": g.loc[r.Index, "full35"], "score_variant": g.loc[r.Index, v]})
    pd.DataFrame(ch).to_csv(out / "change_vs_full35.csv", index=False, lineterminator="\n")
    pd.DataFrame(cases).to_csv(out / "change_vs_full35_cases_fpr5.csv", index=False, lineterminator="\n")
    man = {"nature": "Train outer only; saved scores; thresholds from calibration (PR #13 calibrate, ML)", "script_sha256": sha(__file__),
           "base_inputs": {"pr13_saved_scores": sha(c.B / "scores/saved_scores.csv"), "full35_scores": sha(c.C / "run/scores.csv")},
           "runs": {str(r): sha(r / "scores.csv") for r in a.runs}, "variants": V, "check": "base7/full29/full35 TP,FP,HardFP == fair_comparison.csv",
           "outputs": {p.name: sha(p) for p in sorted(out.glob("*.csv"))}}
    (out / "manifest.json").write_text(json.dumps(man, indent=1) + "\n")


if __name__ == "__main__":
    main()
