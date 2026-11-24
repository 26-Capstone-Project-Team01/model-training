"""Final D06 comparison: full35, full28_noObfNew, gs24, C5 routing, B3, full35+X3+D, full28_noObfNew+X3+D.
Saved scores only. Thresholds: PR #13 calibrate (ML) on each cell's calibration scores at target FPR 1/3/5% (never Test labels).
Train outer = PR #13 2 splits x 3 folds (design evidence). Test-674 = DEVELOPMENT evaluation (repeatedly analysed; not independent).
C5 = rank (vs that cell's calibration normals) routing: JS change none & new dependency & no install script added -> gs24, else full35.
Usage: python -I -B compare_final.py --x3final run --out <new dir>
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
TARGETS = [0.01, 0.03, 0.05]
MASTRA = "mastra-easy-day-js_2026-06"
VANT3 = {("vant", "4.9.11", "4.9.12"), ("vant", "4.9.11", "4.9.13"), ("vant", "4.9.11", "4.9.14")}
M = ["full35", "full28_noObfNew", "gs24", "C5", "B3", "full35_x3_d", "full28_x3_d"]
K = ["split", "fold", "stage", "rid"]


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def rank_vs(normals, s):
    n = np.sort(normals)
    lo, hi = np.searchsorted(n, s, "left"), np.searchsorted(n, s, "right")
    return (lo + 0.5 * (hi - lo)) / len(n)


def outer_scores(x3f):
    def std(df, name, var_col="variant", keep=None):
        d = df if keep is None else df[df[var_col] == keep]
        return d.assign(model=name)[["model", "split", "fold", "stage", "row_id", "score"]].rename(columns={"row_id": "rid"})
    s35 = pd.read_csv(c.C / "run/scores.csv")
    gs = pd.read_csv(EXP / "d06_alt_models/run_gs/scores.csv")
    ab = pd.read_csv(EXP / "d06_gs24_followup/run_ablation/scores.csv")
    b3 = pd.read_csv(EXP / "d06_alt_models/run_blend/scores.csv")
    x3 = pd.read_csv(EXP / "d06_x3_models/run_x3d/scores.csv")
    nw = pd.read_csv(x3f / "scores.csv")
    parts = [std(s35, "full35", keep="full35"), std(gs, "gs24"), std(ab[ab.protocol == "train_outer"], "full28_noObfNew", keep="full28_noObfNew"),
             std(b3, "B3", keep="B3_f35_lr_mlp"), std(x3, "full35_x3_d", keep="full35_x3_d"),
             std(nw[nw.protocol == "train_outer"], "full28_x3_d", keep="full28_x3_d")]
    W = pd.concat(parts).pivot_table(index=K, columns="model", values="score").reset_index()
    df = c.frame()
    meta = pd.DataFrame({"rid": df.row_id, "label": df.label, "class": df["class"], "campaign": df.campaign,
                         "mtype": (df.obfChangedFileCount.fillna(0) == 0) & df.newDependencyAdded.astype(bool) & ~df.installScriptAdded.astype(bool), "in674": True})
    W = W.merge(meta, on="rid")
    W["stage"] = W.stage.replace({"outer": "eval"})
    return W.assign(protocol="train_outer")


def test_scores(x3f):
    dv = pd.read_csv(EXP / "d06_test674_dev/run/scores.csv")
    dv = dv[dv.model.isin(["full35", "gs24", "B3"])].rename(columns={"seed": "split"})
    ab = pd.read_csv(EXP / "d06_gs24_followup/run_ablation/scores.csv")
    ab = ab[(ab.protocol == "test") & (ab.variant == "full28_noObfNew")].rename(columns={"variant": "model"})
    nw = pd.read_csv(x3f / "scores.csv")
    nw = nw[nw.protocol == "test"].rename(columns={"variant": "model"})
    S = pd.concat([dv[["model", "split", "stage", "row_id", "test_row", "score"]], ab[["model", "split", "stage", "row_id", "test_row", "score"]],
                   nw[["model", "split", "stage", "row_id", "test_row", "score"]]])
    S["rid"] = np.where(S.stage == "calibration", S.row_id, S.test_row)
    S["fold"] = -1
    W = S.pivot_table(index=K, columns="model", values="score").reset_index()
    df = c.frame()
    cm = pd.DataFrame({"rid": df.row_id, "label": df.label, "class": df["class"], "campaign": df.campaign,
                       "mtype": (df.obfChangedFileCount.fillna(0) == 0) & df.newDependencyAdded.astype(bool) & ~df.installScriptAdded.astype(bool), "in674": True})
    t = pd.read_csv(EXP / "d06_test_eval/analysis/d06_test_full35.csv", float_precision="round_trip")
    st = pd.read_csv(EXP / "d06_test_eval/analysis/d06_test_x1_status.csv", keep_default_na=False, dtype=str)
    tm = pd.DataFrame({"rid": np.arange(len(t)), "label": t.label, "class": st["class"], "campaign": st.splitGroup,
                       "mtype": (t.obfChangedFileCount.fillna(0) == 0) & t.newDependencyAdded.astype(bool) & ~t.installScriptAdded.astype(bool),
                       "in674": ~t[["package", "old_version", "new_version"]].astype(str).apply(tuple, axis=1).isin(VANT3)})
    W = pd.concat([W[W.stage == "calibration"].merge(cm, on="rid"), W[W.stage == "test"].merge(tm, on="rid").assign(stage="eval")], ignore_index=True)
    return W.assign(protocol="test")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--x3final", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    out = a.out
    out.mkdir(parents=True, exist_ok=False)
    W = pd.concat([outer_scores(a.x3final), test_scores(a.x3final)], ignore_index=True)
    base = [m for m in M if m != "C5"]
    assert W[base].notna().all().all(), W[base].isna().sum()
    for (p, s, f), g in W.groupby(["protocol", "split", "fold"]):
        nrm = g[(g.stage == "calibration") & (g.label == 0)]
        r35, rgs = rank_vs(nrm.full35.to_numpy(), g.full35.to_numpy()), rank_vs(nrm.gs24.to_numpy(), g.gs24.to_numpy())
        W.loc[g.index, "C5"] = np.where(g.mtype, rgs, r35)
    thr = {}
    for (p, s, f), g in W[W.stage == "calibration"].groupby(["protocol", "split", "fold"]):
        for m in M:
            for t in TARGETS:
                thr[(p, s, f, m, t)] = snap.calibrate(g[m].to_numpy(), g.label.to_numpy(), np.zeros(len(g), bool), "ML", t)["threshold"]
    E = W[(W.stage == "eval") & W.in674].copy()
    for m in M:
        for t in TARGETS:
            E[f"sel|{m}|{t}"] = E[m].to_numpy() >= np.array([thr[(p, s, f, m, t)] for p, s, f in zip(E.protocol, E.split, E.fold)])
    rows, camp, gl = [], [], []
    for (p, s), g in E.groupby(["protocol", "split"]):
        mal, hb, mas = g.label.to_numpy() == 1, (g["class"] == "hard_benign").to_numpy(), (g.campaign == MASTRA).to_numpy()
        for m in M:
            pr = float(np.mean([average_precision_score(h.label, h[m]) for _, h in g.groupby("fold")]))
            for t in TARGETS:
                sel = g[f"sel|{m}|{t}"].to_numpy()
                r = {"protocol": p, "split": s, "model": m, "target_fpr": t, "TP": int((sel & mal).sum()), "recall": (sel & mal).sum() / mal.sum(),
                     "FP": int((sel & ~mal).sum()), "fpr": (sel & ~mal).sum() / (~mal).sum(), "hard_FP": int((sel & hb).sum()), "hard_fpr": (sel & hb).sum() / hb.sum(),
                     "PR_AUC": pr, "campaign_macro_recall": float(pd.Series(sel[mal]).groupby(g.campaign.to_numpy()[mal]).mean().mean())}
                if p == "test":
                    r |= {"mastra_TP": int((sel & mas).sum()), "mastra_recall": (sel & mas).sum() / mas.sum(), "non_mastra_recall": (sel & mal & ~mas).sum() / (mal & ~mas).sum()}
                rows.append(r)
                for k, idx in pd.Series(np.arange(len(g))[mal]).groupby(g.campaign.to_numpy()[mal]):
                    camp.append({"protocol": p, "split": s, "model": m, "target_fpr": t, "campaign": k, "n": len(idx), "TP": int(sel[idx.to_numpy()].sum())})
                if m != "full35":
                    rs = g[f"sel|full35|{t}"].to_numpy()
                    gl.append({"protocol": p, "split": s, "model": m, "target_fpr": t, "new_detected": int((sel & ~rs & mal).sum()), "lost": int((~sel & rs & mal).sum()),
                               "fp_new": int((sel & ~rs & ~mal).sum()), "fp_removed": int((~sel & rs & ~mal).sum()),
                               "hard_fp_new": int((sel & ~rs & hb).sum()), "hard_fp_removed": int((~sel & rs & hb).sum())})
    R = pd.DataFrame(rows)
    # checks against earlier evaluations
    fc = pd.read_csv(EXP / "d06_x1_fair_compare/fair_comparison.csv")
    for sp in ["split1", "split2"]:
        x = R[(R.protocol == "train_outer") & (R.split == sp) & (R.model == "full35") & (R.target_fpr == 0.05)].iloc[0]
        y = fc[(fc.variant == "full35") & (fc.split == sp) & (fc.op == "calFPR5%")].iloc[0]
        assert (x.TP, x.FP, x.hard_FP) == (y.TP, y.FP, y.HardFP)
    x3e = pd.read_csv(EXP / "d06_x3_models/eval_x3d/metrics.csv")
    for sp in ["split1", "split2"]:
        for t in TARGETS:
            x = R[(R.protocol == "train_outer") & (R.split == sp) & (R.model == "full35_x3_d") & (R.target_fpr == t)].iloc[0]
            y = x3e[(x3e.variant == "full35_x3_d") & (x3e.split == sp) & (x3e.target_fpr == t)].iloc[0]
            assert (x.TP, x.FP, x.hard_FP) == (y.TP, y.FP, y.hard_FP)
    gf = pd.read_csv(EXP / "d06_gs24_followup/eval/metrics.csv")
    for (pm, gm) in [("full35", "full35"), ("gs24", "gs24"), ("full28_noObfNew", "full28_noObfNew"), ("C5", "C5_route_mastraType")]:
        for prot in ["train_outer", "test"]:
            for sp in gf[gf.protocol == prot].split.unique():
                x = R[(R.protocol == prot) & (R.split == sp) & (R.model == pm) & (R.target_fpr == 0.05)].iloc[0]
                y = gf[(gf.protocol == prot) & (gf.split == sp) & (gf.model == gm) & (gf.target_fpr == 0.05)].iloc[0]
                assert (x.TP, x.FP, x.hard_FP) == (y.TP, y.FP, y.hard_FP), (pm, prot, sp)
    R.to_csv(out / "metrics.csv", index=False, lineterminator="\n")
    pd.DataFrame(camp).to_csv(out / "campaign_recall.csv", index=False, lineterminator="\n")
    pd.DataFrame(gl).to_csv(out / "change_vs_full35.csv", index=False, lineterminator="\n")
    st = R.pivot_table(index=["protocol", "model", "target_fpr"], columns="split", values=["recall", "fpr", "hard_fpr", "PR_AUC"]).reset_index()
    st.columns = ["_".join([x for x in col if x]) if isinstance(col, tuple) else col for col in st.columns]
    for mtr in ["recall", "fpr", "hard_fpr", "PR_AUC"]:
        cols = [col for col in st.columns if col.startswith(mtr + "_")]
        st[f"{mtr}_gap"] = st[cols].max(axis=1) - st[cols].min(axis=1)
    st.to_csv(out / "stability.csv", index=False, lineterminator="\n")
    (out / "manifest.json").write_text(json.dumps({"nature": "Train outer = design evidence; Test-674 = development evaluation (not independent)",
        "thresholds": "Train calibration only, PR #13 calibrate ML, targets 1/3/5%", "script_sha256": sha(__file__),
        "checks": "full35 outer == fair_comparison; full35_x3_d outer == d06_x3_models/eval_x3d; full35/gs24/full28/C5 5% == d06_gs24_followup/eval",
        "outputs": {p.name: sha(p) for p in sorted(out.glob("*.csv"))}}, indent=1) + "\n")


if __name__ == "__main__":
    main()
