"""Final comparison of the narrowed candidates on Test-674 (DEVELOPMENT evaluation; Test-674 has been analysed repeatedly).
Saved scores only, no training, no new features.

Candidates (Test protocol: Train inner_split(seed) fit / calibration, seeds 20261109 / 20261110):
  full35, gs24, B3 (weights from that seed's calibration)   <- ../d06_test674_dev/run/scores.csv (full35 == ../d06_test_eval, guarded there)
  full28_noObfNew                                           <- ../d06_gs24_followup/run_ablation/scores.csv
  C5 routing (rank vs that seed's calibration normals; JS change none & new dependency & no install script added -> gs24)
Operating points:
  A. Train-chosen (independent of Test-674 labels): calibration target from the MGV rule (../d06_mgv_hpo README section 8):
     3% for full35, B3, C5, full28_noObfNew; 4% for gs24. Targets 1/3/5% are also reported.
  B. Test-chosen (NOT independent): per seed, the threshold on Test-674 scores with the highest recall subject to Test FPR <= 5%.
Usage: python -I -B final_compare.py --out <new dir>
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
MASTRA = "mastra-easy-day-js_2026-06"
VANT3 = {("vant", "4.9.11", "4.9.12"), ("vant", "4.9.11", "4.9.13"), ("vant", "4.9.11", "4.9.14")}
OP = {"full35": 0.03, "B3": 0.03, "C5": 0.03, "full28_noObfNew": 0.03, "gs24": 0.04}
TARGETS = [0.01, 0.03, 0.05]


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def rank_vs(normals, s):
    n = np.sort(normals)
    lo, hi = np.searchsorted(n, s, "left"), np.searchsorted(n, s, "right")
    return (lo + 0.5 * (hi - lo)) / len(n)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True)
    out = ap.parse_args().out
    out.mkdir(parents=True, exist_ok=False)
    dv = pd.read_csv(EXP / "d06_test674_dev/run/scores.csv")
    dv = dv[dv.model.isin(["full35", "gs24", "B3"])]
    ab = pd.read_csv(EXP / "d06_gs24_followup/run_ablation/scores.csv")
    ab = ab[(ab.protocol == "test") & (ab.variant == "full28_noObfNew")].rename(columns={"variant": "model", "split": "seedname"})
    ab = ab.assign(seed=ab.seedname)[["seed", "model", "stage", "row_id", "test_row", "score"]]
    S = pd.concat([dv, ab])
    S["rid"] = np.where(S.stage == "calibration", S.row_id, S.test_row)
    W = S.pivot_table(index=["seed", "stage", "rid"], columns="model", values="score").reset_index()
    df = c.frame()
    test = pd.read_csv(EXP / "d06_test_eval/analysis/d06_test_full35.csv", float_precision="round_trip")
    st = pd.read_csv(EXP / "d06_test_eval/analysis/d06_test_x1_status.csv", keep_default_na=False, dtype=str)
    tm = pd.DataFrame({"rid": np.arange(len(test)), "label": test.label, "class": st["class"], "campaign": st.splitGroup,
                       "nojs": test.obfChangedFileCount.fillna(0) == 0, "nd": test.newDependencyAdded.astype(bool), "isa": test.installScriptAdded.astype(bool),
                       "in674": ~test[["package", "old_version", "new_version"]].astype(str).apply(tuple, axis=1).isin(VANT3)})
    cm = pd.DataFrame({"rid": df.row_id, "label": df.label, "class": df["class"], "campaign": df.campaign, "nojs": df.obfChangedFileCount.fillna(0) == 0,
                       "nd": df.newDependencyAdded.astype(bool), "isa": df.installScriptAdded.astype(bool), "in674": True})
    W = pd.concat([W[W.stage == "calibration"].merge(cm, on="rid"), W[W.stage == "test"].merge(tm, on="rid")], ignore_index=True)
    assert W[["full35", "gs24", "B3", "full28_noObfNew"]].notna().all().all()
    for sd, g in W.groupby("seed"):
        nrm = g[(g.stage == "calibration") & (g.label == 0)]
        r35, rgs = rank_vs(nrm.full35.to_numpy(), g.full35.to_numpy()), rank_vs(nrm.gs24.to_numpy(), g.gs24.to_numpy())
        W.loc[g.index, "C5"] = np.where(g.nojs & g.nd & ~g.isa, rgs, r35)
    M = ["full35", "gs24", "full28_noObfNew", "B3", "C5"]
    rows = []
    for sd, g in W.groupby("seed"):
        cal, ev = g[g.stage == "calibration"], g[(g.stage == "test") & g.in674]
        mal, hb, mas = ev.label.to_numpy() == 1, (ev["class"] == "hard_benign").to_numpy(), (ev.campaign == MASTRA).to_numpy()

        def met(m, sel, kind, target, thr):
            return {"seed": sd, "model": m, "threshold_source": kind, "target": target, "threshold": thr, "recall": (sel & mal).sum() / mal.sum(),
                    "fpr": (sel & ~mal).sum() / (~mal).sum(), "hard_fpr": (sel & hb).sum() / hb.sum(), "mastra_recall": (sel & mas).sum() / mas.sum(),
                    "non_mastra_recall": (sel & mal & ~mas).sum() / (mal & ~mas).sum(), "TP": int((sel & mal).sum()), "FP": int((sel & ~mal).sum()),
                    "hard_FP": int((sel & hb).sum()), "mastra_TP": int((sel & mas).sum()), "PR_AUC": average_precision_score(mal, ev[m])}
        for m in M:
            for t in sorted(set(TARGETS + [OP[m]])):
                thr = snap.calibrate(cal[m].to_numpy(), cal.label.to_numpy(), np.zeros(len(cal), bool), "ML", t)["threshold"]
                rows.append(met(m, ev[m].to_numpy() >= thr, "train_calibration" + (" (MGV operating point)" if t == OP[m] else ""), t, thr))
            s = ev[m].to_numpy()
            neg = np.sort(s[~mal])[::-1]
            k = int(np.floor(0.05 * len(neg)))
            thr = np.nextafter(neg[k], np.inf)  # at most k normals at or above -> Test FPR <= 5%
            rows.append(met(m, s >= thr, "TEST-CHOSEN (not independent)", 0.05, thr))
    R = pd.DataFrame(rows)
    R.to_csv(out / "test674_final_compare.csv", index=False, lineterminator="\n")
    stab = R.groupby(["model", "threshold_source", "target"]).agg(recall_s09=("recall", "first"), recall_s10=("recall", "last"), fpr_s09=("fpr", "first"),
                                                                  fpr_s10=("fpr", "last"), hard_fpr_s09=("hard_fpr", "first"), hard_fpr_s10=("hard_fpr", "last"),
                                                                  mastra_s09=("mastra_recall", "first"), mastra_s10=("mastra_recall", "last"),
                                                                  nonmastra_s09=("non_mastra_recall", "first"), nonmastra_s10=("non_mastra_recall", "last")).reset_index()
    stab["recall_seed_gap"] = (stab.recall_s09 - stab.recall_s10).abs()
    stab.to_csv(out / "test674_stability.csv", index=False, lineterminator="\n")
    # check reused numbers against earlier evaluations (5% train-calibration)
    prev = pd.read_csv(EXP / "d06_gs24_followup/eval/metrics.csv")
    for m in ["full35", "gs24", "full28_noObfNew"]:
        for sd in ["seed20261109", "seed20261110"]:
            x = R[(R.model == m) & (R.seed == sd) & (R.target == 0.05) & (R.threshold_source == "train_calibration")].iloc[0]
            y = prev[(prev.protocol == "test") & (prev.model == m) & (prev.split == sd) & (prev.target_fpr == 0.05)].iloc[0]
            assert (x.TP, x.FP, x.mastra_TP) == (y.TP, y.FP, y.mastra_TP), (m, sd)
    (out / "manifest.json").write_text(json.dumps({"nature": "DEVELOPMENT evaluation on Test-674; TEST-CHOSEN rows are not independent", "operating_points": OP,
        "script_sha256": sha(__file__), "inputs": {"test674_dev_scores": sha(EXP / "d06_test674_dev/run/scores.csv"),
        "ablation_scores": sha(EXP / "d06_gs24_followup/run_ablation/scores.csv")}, "outputs": {p.name: sha(p) for p in sorted(out.glob("*.csv"))}}, indent=1) + "\n")


if __name__ == "__main__":
    main()
