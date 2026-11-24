"""full35 + gs24 combinations and evaluation, exactly as pre-registered (PREREGISTRATION.md 46ade76). Saved scores only.

Inputs (reused): Train outer full35 (../d06_full35_compare/run), gs24 (../d06_alt_models/run_gs); Test protocol full35
(../d06_test_eval/run), gs24 (../d06_test674_dev/run); new ablations (run_ablation). Weights / selections use calibration
rows only; thresholds by PR #13 calibrate (ML) on each cell's calibration scores. Test-674 is reported, never used to choose.
Usage: python -I -B combine_eval.py --ablation run_ablation --out <new dir>
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
GRID = [round(x, 1) for x in np.arange(0, 1.01, 0.1)]
MASTRA = "mastra-easy-day-js_2026-06"
VANT3 = {("vant", "4.9.11", "4.9.12"), ("vant", "4.9.11", "4.9.13"), ("vant", "4.9.11", "4.9.14")}
BASE = ["full35", "gs24", "full28_noObfNew", "full31_noHook"]


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def logit(p):
    p = np.clip(p, 1e-6, 1 - 1e-6)
    return np.log(p / (1 - p))


def rank_vs(normals, s):
    n = np.sort(normals)
    lo, hi = np.searchsorted(n, s, "left"), np.searchsorted(n, s, "right")
    return (lo + 0.5 * (hi - lo)) / len(n)


def attack_type(f):
    a = f.installScriptAdded.astype(bool) | f.scriptEntryAdded.astype(bool)
    return np.where(a, "A", np.where(f.newDependencyAdded.astype(bool), "B", "C"))


def frames(abl):
    """Long score table: protocol, split, fold, stage, rid, <models>, metadata."""
    df = c.frame()
    df["type"] = attack_type(df)
    s35 = pd.read_csv(c.C / "run/scores.csv")
    s35 = s35[s35.variant == "full35"]
    gs = pd.read_csv(EXP / "d06_alt_models/run_gs/scores.csv").assign(variant="gs24")
    ab = pd.read_csv(abl / "scores.csv")
    o = pd.concat([s35, gs, ab[ab.protocol == "train_outer"]])[["variant", "split", "fold", "stage", "row_id", "score"]]
    W1 = o.pivot_table(index=["split", "fold", "stage", "row_id"], columns="variant", values="score").reset_index()
    W1 = W1.merge(df[["row_id", "label", "class", "campaign", "type", "obfChangedFileCount", "newDependencyAdded", "installScriptAdded"]], on="row_id")
    W1 = W1.rename(columns={"row_id": "rid"}).assign(protocol="train_outer", stage=lambda d: d.stage.replace({"outer": "eval"}), in674=True)
    # Test protocol
    te_s = pd.read_csv(EXP / "d06_test_eval/run/scores.csv")
    dv = pd.read_csv(EXP / "d06_test674_dev/run/scores.csv")
    t = pd.concat([te_s[te_s.model == "full35"], dv[dv.model == "gs24"]]).rename(columns={"model": "variant", "seed": "split"})
    t = pd.concat([t, ab[ab.protocol == "test"].rename(columns={})[["variant", "split", "stage", "row_id", "test_row", "score"]]])
    t["rid"] = np.where(t.stage == "calibration", t.row_id, t.test_row)
    W2 = t.pivot_table(index=["split", "stage", "rid"], columns="variant", values="score").reset_index()
    test = pd.read_csv(EXP / "d06_test_eval/analysis/d06_test_full35.csv", float_precision="round_trip")
    st = pd.read_csv(EXP / "d06_test_eval/analysis/d06_test_x1_status.csv", keep_default_na=False, dtype=str)
    tm = pd.DataFrame({"rid": np.arange(len(test)), "label": test.label, "class": st["class"], "campaign": st.splitGroup, "type": attack_type(test),
                       "obfChangedFileCount": test.obfChangedFileCount, "newDependencyAdded": test.newDependencyAdded, "installScriptAdded": test.installScriptAdded,
                       "in674": ~test[["package", "old_version", "new_version"]].astype(str).apply(tuple, axis=1).isin(VANT3)})
    cm = df[["row_id", "label", "class", "campaign", "type", "obfChangedFileCount", "newDependencyAdded", "installScriptAdded"]].rename(columns={"row_id": "rid"}).assign(in674=True)
    W2 = pd.concat([W2[W2.stage == "calibration"].merge(cm, on="rid"), W2[W2.stage == "test"].merge(tm, on="rid").assign(stage="eval")])
    W2 = W2.assign(protocol="test", fold=-1)
    W = pd.concat([W1, W2], ignore_index=True)
    assert W[BASE].notna().all().all()
    W["nojs"] = W.obfChangedFileCount.fillna(0).to_numpy() == 0
    W["mtype"] = W.nojs & W.newDependencyAdded.astype(bool) & ~W.installScriptAdded.astype(bool)
    return W


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ablation", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    out = a.out
    out.mkdir(parents=True, exist_ok=False)
    W = frames(a.ablation)
    # rank scores per cell (calibration normals of that cell)
    for (p, s, f), g in W.groupby(["protocol", "split", "fold"]):
        normals = g[(g.stage == "calibration") & (g.label == 0)]
        for m in ["full35", "gs24"]:
            W.loc[g.index, f"r_{m}"] = rank_vs(normals[m].to_numpy(), g[m].to_numpy())
    combos, selection = {}, []
    sel_cols = []
    for (p, s), g in W.groupby(["protocol", "split"]):
        cal = g[g.stage == "calibration"]
        cells = list(cal.groupby("fold"))

        def score_fn(kind, w, d):
            if kind == "C1_prob":
                return (1 - w) * d.full35 + w * d.gs24
            if kind == "C2_logit":
                return 1 / (1 + np.exp(-((1 - w) * logit(d.full35.to_numpy()) + w * logit(d.gs24.to_numpy()))))
            if kind == "C3_rank":
                return (1 - w) * d.r_full35 + w * d.r_gs24
            if kind == "C6_typewise_rank":
                wj, wn = w
                ww = np.where(d.nojs, wn, wj)
                return (1 - ww) * d.r_full35 + ww * d.r_gs24
            raise ValueError(kind)

        for kind, cand in [("C1_prob", GRID), ("C2_logit", GRID), ("C3_rank", GRID), ("C6_typewise_rank", [(x, y) for x in GRID for y in GRID])]:
            best = None
            for w in cand:
                pr = float(np.mean([average_precision_score(h.label, score_fn(kind, w, h)) for _, h in cells]))
                selection.append({"protocol": p, "split": s, "combo": kind, "weight": str(w), "cal_pr_auc": pr})
                key = (pr, -(w if not isinstance(w, tuple) else sum(w)))
                if best is None or key > best[0]:
                    best = (key, w)
            W.loc[g.index, kind] = np.asarray(score_fn(kind, best[1], g), dtype=float)
            combos[f"{p}|{s}|{kind}"] = {"weight": best[1], "cal_pr_auc": best[0][0]}
        W.loc[g.index, "C4_route_noJS"] = np.where(g.nojs, g.r_gs24, g.r_full35)
        W.loc[g.index, "C5_route_mastraType"] = np.where(g.mtype, g.r_gs24, g.r_full35)
        W.loc[g.index, "C7_or_maxrank"] = np.maximum(g.r_full35, g.r_gs24)
        W.loc[g.index, "C8_and_minrank"] = np.minimum(g.r_full35, g.r_gs24)
    pd.DataFrame(selection).to_csv(out / "selection_calibration.csv", index=False, lineterminator="\n")
    M = BASE + ["C1_prob", "C2_logit", "C3_rank", "C4_route_noJS", "C5_route_mastraType", "C6_typewise_rank", "C7_or_maxrank", "C8_and_minrank"]
    # thresholds per cell
    thr = {}
    for (p, s, f), g in W[W.stage == "calibration"].groupby(["protocol", "split", "fold"]):
        for m in M:
            for t in TARGETS:
                thr[(p, s, f, m, t)] = snap.calibrate(g[m].to_numpy(), g.label.to_numpy(), np.zeros(len(g), bool), "ML", t)["threshold"]
    E = W[(W.stage == "eval") & W.in674].copy()
    for m in M:
        for t in TARGETS:
            E[f"sel|{m}|{t}"] = E[m].to_numpy() >= np.array([thr[(p, s, f, m, t)] for p, s, f in zip(E.protocol, E.split, E.fold)])
    rows, camp, typ, gl = [], [], [], []
    for (p, s), g in E.groupby(["protocol", "split"]):
        mal, hb = g.label.to_numpy() == 1, (g["class"] == "hard_benign").to_numpy()
        mas = (g.campaign == MASTRA).to_numpy()
        for m in M:
            pr = float(np.mean([average_precision_score(h.label, h[m]) for _, h in g.groupby("fold")]))
            for t in TARGETS:
                sel = g[f"sel|{m}|{t}"].to_numpy()
                r = {"protocol": p, "split": s, "model": m, "target_fpr": t, "TP": int((sel & mal).sum()), "malicious": int(mal.sum()), "recall": (sel & mal).sum() / mal.sum(),
                     "FP": int((sel & ~mal).sum()), "fpr": (sel & ~mal).sum() / (~mal).sum(), "hard_FP": int((sel & hb).sum()), "hard_fpr": (sel & hb).sum() / hb.sum(),
                     "PR_AUC": pr, "campaign_macro_recall": float(pd.Series(sel[mal]).groupby(g.campaign.to_numpy()[mal]).mean().mean())}
                if p == "test":
                    r |= {"mastra_TP": int((sel & mas).sum()), "mastra_recall": (sel & mas).sum() / mas.sum(), "non_mastra_recall": (sel & mal & ~mas).sum() / (mal & ~mas).sum()}
                rows.append(r)
                for k, idx in pd.Series(np.arange(len(g))[mal]).groupby(g.campaign.to_numpy()[mal]):
                    camp.append({"protocol": p, "split": s, "model": m, "target_fpr": t, "campaign": k, "n": len(idx), "TP": int(sel[idx.to_numpy()].sum())})
                for k, idx in pd.Series(np.arange(len(g))[mal]).groupby(g.type.to_numpy()[mal]):
                    typ.append({"protocol": p, "split": s, "model": m, "target_fpr": t, "type": k, "n": len(idx), "TP": int(sel[idx.to_numpy()].sum())})
                for ref in ["full35", "gs24"]:
                    if m == ref:
                        continue
                    rs = g[f"sel|{ref}|{t}"].to_numpy()
                    gl.append({"protocol": p, "split": s, "model": m, "vs": ref, "target_fpr": t, "new_detected": int((sel & ~rs & mal).sum()), "lost": int((~sel & rs & mal).sum()),
                               "fp_removed": int((~sel & rs & ~mal).sum()), "fp_new": int((sel & ~rs & ~mal).sum()),
                               "hard_fp_removed": int((~sel & rs & hb).sum()), "hard_fp_new": int((sel & ~rs & hb).sum())})
    for name, d in [("metrics.csv", rows), ("campaign_recall.csv", camp), ("type_recall.csv", typ), ("gain_loss.csv", gl)]:
        pd.DataFrame(d).to_csv(out / name, index=False, lineterminator="\n")
    # sanity: reused base models reproduce earlier evaluations at 5%
    R = pd.DataFrame(rows)
    fc = pd.read_csv(EXP / "d06_x1_fair_compare/fair_comparison.csv")
    for sp in ["split1", "split2"]:
        x = R[(R.protocol == "train_outer") & (R.split == sp) & (R.model == "full35") & (R.target_fpr == 0.05)].iloc[0]
        y = fc[(fc.variant == "full35") & (fc.split == sp) & (fc.op == "calFPR5%")].iloc[0]
        assert (x.TP, x.FP) == (y.TP, y.FP)
    dvm = pd.read_csv(EXP / "d06_test674_dev/run/metrics_test674.csv")
    for sd in ["seed20261109", "seed20261110"]:
        for m in ["full35", "gs24"]:
            x = R[(R.protocol == "test") & (R.split == sd) & (R.model == m) & (R.target_fpr == 0.05)].iloc[0]
            y = dvm[(dvm.seed == sd) & (dvm.model == m) & (dvm.target_fpr == 0.05)].iloc[0]
            assert (x.TP, x.FP, x.mastra_TP) == (y.TP, y.FP, y.mastra_TP), (sd, m)
    (out / "manifest.json").write_text(json.dumps({"preregistration_commit": "46ade76", "combo_selection": {k: {"weight": str(v["weight"]), "cal_pr_auc": v["cal_pr_auc"]} for k, v in combos.items()},
        "checks": "full35 train-outer 5% == fair_comparison; full35/gs24 test 5% == d06_test674_dev", "script_sha256": sha(__file__),
        "inputs": {"ablation": sha(a.ablation / "scores.csv"), "full35_outer": sha(c.C / "run/scores.csv"), "gs24_outer": sha(EXP / "d06_alt_models/run_gs/scores.csv"),
                   "full35_test": sha(EXP / "d06_test_eval/run/scores.csv"), "gs24_test": sha(EXP / "d06_test674_dev/run/scores.csv")},
        "outputs": {p.name: sha(p) for p in sorted(out.glob("*.csv"))}}, indent=1) + "\n")


if __name__ == "__main__":
    main()
