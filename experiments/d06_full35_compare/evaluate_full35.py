"""Saved-score evaluation for D06 full29 vs full35 (X1) variants.

The evaluation definitions (THRESHOLDS ... recall_table, check_against_pr13) are copied verbatim from
W1 evaluate_w1.py (model-training exp/d06-w1-component-weight e8c5847, file SHA-256
00a3532198e889621e2bc30757a2bc8459e6585e3a2945a86ff88561ea0ba454), which reproduces PR #13 phase7.
Before evaluating, PR #13 full29 tables are recomputed from saved scores and must match PR #13 exactly.

Baseline = PR #13 saved full29 scores (identical to the full29 repro retrain, see repro_verification.json).
No training/inference. Test 677 is never read. No threshold, feature set or model is selected from outer results.
"""
from __future__ import annotations

import argparse
import math
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
BUNDLE = HERE.parent / "d06_feature_comparison_18"
X1CSV = HERE.parent / "d06_x1_extraction/analysis/d06_full35.csv"
VARIANTS = ["full35", "full32", "full29_ref", "full29_proc", "full29_net"]
BASE = "full29_pr13"
DISPLAY = [0.01, 0.05, 0.1, 0.5]  # PR #13 display thresholds (pre-fixed), used for group/paired tables
X1 = ["installHookNewProgramCount", "installHookArgsChanged", "installHookRefFileChanged",
      "installHookNewExternalExecCount", "addedProcExecCallCount", "addedNetworkCallCount"]

# ---- copied verbatim from evaluate_w1.py (e8c5847) ----
THRESHOLDS = [0, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.2, 0.3, 0.5, 0.7, 0.9, 0.99, 1]
TOPS = [0.01, 0.05, 0.1, 0.2, 0.3, 0.5]
LOWS = [0.01, 0.05, 0.1]
RECALLS = [0.9, 0.95]
SEEDS = [20261109, 20261110]


def selection_metrics(rows, sel):
    mal = rows.label.to_numpy() == 1
    n_mal, n_norm = int(mal.sum()), int((~mal).sum())
    tp, fp = int((sel & mal).sum()), int((sel & ~mal).sum())
    r = {"rows": len(rows), "malicious_n": n_mal, "normal_n": n_norm, "review_candidates": int(sel.sum()),
         "tp": tp, "fp": fp, "fn": n_mal - tp, "tn": n_norm - fp,
         "recall": tp / n_mal if n_mal else np.nan, "fpr": fp / n_norm if n_norm else np.nan,
         "review_rate": sel.sum() / len(rows), "candidate_malicious_fraction": tp / sel.sum() if sel.sum() else np.nan,
         "selected_malicious": tp}
    for cls in ["benign", "hard_benign"]:
        m = rows["class"].to_numpy() == cls
        r[f"{cls}_n"], r[f"selected_{cls}"] = int(m.sum()), int((sel & m).sum())
    mrows = rows[mal]
    msel = pd.Series(sel[mal], index=mrows.index)
    for g in ["campaign", "component"]:
        per = msel.groupby(mrows[g]).mean()
        r[f"{g}_macro_recall"] = float(per.mean()) if len(per) else np.nan
        r[f"{g}_n"], r[f"{g}_any_selected"] = int(len(per)), int((msel.groupby(mrows[g]).sum() > 0).sum())
    return r


def thresholds_table(df, ids):
    out = []
    for keys, g in df.groupby(ids):
        meta = dict(zip(ids, keys))
        for fold in [0, 1, 2, -1]:
            rows = g if fold == -1 else g[g.fold == fold]
            for t in THRESHOLDS:
                out.append(dict(meta, fold=fold, threshold=t, **selection_metrics(rows, rows.score.to_numpy() >= t)))
    return pd.DataFrame(out)


def ranking_table(df, ids):
    out = []
    for keys, g in df.groupby(ids):
        meta = dict(zip(ids, keys))
        for f in TOPS:
            agg = {"k": 0, "strict_rows": 0, "tie_rows": 0, "tie_slots": 0, "malicious_min": 0, "malicious_max": 0, "tie_all_rows": 0, "tie_all_malicious": 0, "rows": 0, "malicious_n": 0}
            for fold in [0, 1, 2]:
                rows = g[g.fold == fold]
                s, mal = rows.score.to_numpy(), rows.label.to_numpy() == 1
                k = math.ceil(f * len(rows))
                b = np.sort(s)[::-1][k - 1]
                strict, tie = s > b, s == b
                slots = k - int(strict.sum())
                tm, tn = int((tie & mal).sum()), int((tie & ~mal).sum())
                sm = int((strict & mal).sum())
                r = {"k": k, "boundary_score": float(b), "strict_rows": int(strict.sum()), "tie_rows": int(tie.sum()),
                     "tie_slots": slots, "malicious_min": sm + max(0, slots - tn), "malicious_max": sm + min(slots, tm),
                     "tie_all_rows": int((s >= b).sum()), "tie_all_malicious": int(((s >= b) & mal).sum()),
                     "rows": len(rows), "malicious_n": int(mal.sum())}
                out.append(dict(meta, fold=fold, top_fraction=f, **r))
                for key in agg:
                    agg[key] += r[key]
            out.append(dict(meta, fold=-1, top_fraction=f, **agg))
    return pd.DataFrame(out)


def low_table(df, ids):
    out = []
    for keys, g in df.groupby(ids):
        meta = dict(zip(ids, keys))
        for fold in [0, 1, 2, -1]:
            rows = g if fold == -1 else g[g.fold == fold]
            mal = rows.label.to_numpy() == 1
            for c in LOWS:
                low = rows.score.to_numpy() <= c
                out.append(dict(meta, fold=fold, cutoff=c, rows=len(rows), malicious_n=int(mal.sum()),
                    low_rows=int(low.sum()), low_malicious=int((low & mal).sum()), low_normal=int((low & ~mal).sum()),
                    low_hard_benign=int((low & (rows["class"].to_numpy() == "hard_benign")).sum())))
    return pd.DataFrame(out)


def recall_table(cal, outer, ids):
    out = []
    for keys, g in outer.groupby(ids):
        meta = dict(zip(ids, keys))
        c_all = cal
        for k, v in meta.items():
            c_all = c_all[c_all[k] == v]
        pooled = []
        for fold in [0, 1, 2]:
            c = c_all[c_all.fold == fold]
            o = g[g.fold == fold]
            cm = np.sort(c[c.label == 1].score.to_numpy())[::-1]
            for target in RECALLS:
                if len(cm) == 0:
                    out.append(dict(meta, fold=fold, target_recall=target, status="unavailable"))
                    continue
                t = float(cm[math.ceil(target * len(cm)) - 1])
                sel = o.score.to_numpy() >= t
                pooled.append((target, o, sel))
                out.append(dict(meta, fold=fold, target_recall=target, status="ok", threshold=t, **selection_metrics(o, sel)))
        for target in RECALLS:
            parts = [(o, s) for tg, o, s in pooled if tg == target]
            if len(parts) == 3:
                rows = pd.concat([o for o, _ in parts])
                out.append(dict(meta, fold=-1, target_recall=target, status="ok",
                                **selection_metrics(rows, np.concatenate([s for _, s in parts]))))
    return pd.DataFrame(out)


def check_against_pr13(meta):
    s = pd.read_csv(BUNDLE / "scores/saved_scores.csv", keep_default_na=False)
    s = s[s.model == "full29"].drop(columns=["class", "campaign", "component", "label"]).merge(meta, on="row_id")
    outer, cal = s[s.stage == "outer"], s[s.stage == "calibration"]
    ev = BUNDLE / "evaluation"
    checks = {
        "thresholds": (thresholds_table(outer, ["seed"]), pd.read_csv(ev / "thresholds.csv"), ["seed", "fold", "threshold"]),
        "ranking": (ranking_table(outer, ["seed"]), pd.read_csv(ev / "ranking.csv"), ["seed", "fold", "top_fraction"]),
        "low_scores": (low_table(outer, ["seed"]), pd.read_csv(ev / "low_scores.csv"), ["seed", "fold", "cutoff"]),
        "recall_examples": (recall_table(cal, outer, ["seed"]), pd.read_csv(ev / "recall_examples.csv"), ["seed", "fold", "target_recall"]),
    }
    report = {}
    for name, (mine, ref, key) in checks.items():
        ref = ref[ref.model == "full29"]
        cols = [c for c in mine.columns if c in ref.columns and c not in key + ["model", "variant", "source_scenario"]]
        m = mine.merge(ref, on=key, suffixes=("_mine", "_ref"), validate="one_to_one")
        if len(m) != len(ref) or len(m) != len(mine):
            raise SystemExit(f"{name}: row count mismatch mine={len(mine)} ref={len(ref)} merged={len(m)}")
        bad = []
        for c in cols:
            a, b = m[f"{c}_mine"], m[f"{c}_ref"]
            if pd.api.types.is_numeric_dtype(a) and pd.api.types.is_numeric_dtype(b):
                ok = np.isclose(a.astype(float), b.astype(float), rtol=1e-12, atol=1e-12, equal_nan=True)
            else:
                ok = a.astype(str) == b.astype(str)
            if not ok.all():
                bad.append(c)
        if bad:
            raise SystemExit(f"{name}: columns differ from PR #13: {bad}")
        report[name] = {"rows": len(m), "columns_checked": len(cols)}
    return report


# ---- end of copied definitions ----


def group_recall(df, ids):
    """Recall per attack type proxy (A/B/C), campaign and component at display thresholds, pooled over folds."""
    out = []
    for keys, g in df.groupby(ids):
        meta = dict(zip(ids, keys))
        mal = g[g.label == 1]
        for t in DISPLAY:
            sel = mal.score >= t
            for axis in ["type", "campaign", "component"]:
                for name, idx in mal.groupby(axis).groups.items():
                    out.append(dict(meta, threshold=t, axis=axis, group=name, malicious_n=len(idx),
                                    tp=int(sel[idx].sum()), recall=float(sel[idx].mean())))
    return pd.DataFrame(out)


def fold_consistency(thr):
    """Per split x fold x threshold delta vs PR #13 full29 (outer rows of that fold only)."""
    t = thr[thr.fold >= 0]
    base = t[t.variant == BASE].set_index(["seed", "fold", "threshold"])
    rows = []
    for r in t[t.variant != BASE].itertuples():
        b = base.loc[(r.seed, r.fold, r.threshold)]
        rows.append({"variant": r.variant, "seed": r.seed, "fold": r.fold, "threshold": r.threshold,
                     "tp": r.tp, "tp_base": int(b.tp), "d_tp": int(r.tp - b.tp), "fp": r.fp, "fp_base": int(b.fp),
                     "d_fp": int(r.fp - b.fp), "d_hard_benign_fp": int(r.selected_hard_benign - b.selected_hard_benign),
                     "d_benign_fp": int(r.selected_benign - b.selected_benign),
                     "d_campaign_macro_recall": r.campaign_macro_recall - b.campaign_macro_recall})
    return pd.DataFrame(rows)


def paired_cases(outer, rowmeta, x1):
    """Row-level changes vs PR #13 full29 at display thresholds (same seed, same outer row)."""
    piv = outer.pivot_table(index=["seed", "fold", "row_id"], columns="variant", values="score").reset_index()
    piv = piv.merge(rowmeta, on="row_id").merge(x1, on="row_id")
    summary, cases = [], []
    for v in VARIANTS:
        for t in DISPLAY:
            a, b = piv[BASE] >= t, piv[v] >= t
            mal, hard = piv.label == 1, piv["class"] == "hard_benign"
            for seed, g in piv.groupby("seed"):
                m = piv.seed == seed
                summary.append({"variant": v, "seed": seed, "threshold": t,
                                "tp_gain": int((m & mal & b & ~a).sum()), "tp_lost": int((m & mal & ~b & a).sum()),
                                "fp_added": int((m & ~mal & b & ~a).sum()), "fp_removed": int((m & ~mal & ~b & a).sum()),
                                "hard_benign_fp_added": int((m & hard & b & ~a).sum()),
                                "hard_benign_fp_removed": int((m & hard & ~b & a).sum())})
            for kind, mask in [("malicious_gained", mal & b & ~a), ("malicious_lost", mal & ~b & a),
                               ("normal_fp_added", ~mal & b & ~a), ("normal_fp_removed", ~mal & ~b & a)]:
                sub = piv[mask]
                cases.append(sub.assign(variant=v, threshold=t, change=kind, score_base=sub[BASE], score_new=sub[v])
                             [["variant", "threshold", "change", "seed", "fold", "row_id", "package", "old_version",
                               "new_version", "class", "campaign", "component", "type", "score_base", "score_new"] + X1])
    return pd.DataFrame(summary), pd.concat(cases, ignore_index=True)


def importance_summary(imp):
    imp = imp.copy()
    imp["gain_share"] = imp.gain / imp.groupby(["variant", "split", "fold"]).gain.transform("sum")
    imp["rank"] = imp.groupby(["variant", "split", "fold"]).gain.rank(ascending=False, method="min").astype(int)
    imp["is_x1"] = imp.feature.isin(X1)
    return imp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", type=Path, required=True)
    args = ap.parse_args()
    meta = pd.read_csv(args.run / "row_metadata.csv", keep_default_na=False)
    m6 = meta[["row_id", "label", "class", "campaign", "component", "type"]]
    report = check_against_pr13(m6)
    print("PR #13 full29 reproduction of evaluation:", report, flush=True)

    base = pd.read_csv(BUNDLE / "scores/saved_scores.csv", keep_default_na=False)
    base = base[base.model == "full29"].drop(columns=["class", "campaign", "component", "label"]).merge(m6, on="row_id")
    base = base.assign(variant=BASE)[["variant", "seed", "fold", "stage", "row_id", "score"]]
    new = pd.read_csv(args.run / "scores.csv")
    if set(new.variant) != set(VARIANTS):
        raise SystemExit(f"unexpected variants {sorted(set(new.variant))}")
    new = new[["variant", "seed", "fold", "stage", "row_id", "score"]]
    allscores = pd.concat([base, new]).merge(m6, on="row_id")
    outer, cal = allscores[allscores.stage == "outer"], allscores[allscores.stage == "calibration"]
    ids = ["variant", "seed"]
    out = args.run / "evaluation"
    out.mkdir(exist_ok=False)
    thr = thresholds_table(outer, ids)
    thr["precision"] = thr.candidate_malicious_fraction
    tables = {"thresholds": thr, "ranking": ranking_table(outer, ids), "low_scores": low_table(outer, ids),
              "recall_examples": recall_table(cal, outer, ids), "group_recall": group_recall(outer, ids),
              "fold_consistency": fold_consistency(thr)}
    x1 = pd.read_csv(X1CSV, dtype=str, keep_default_na=False)[X1].assign(row_id=np.arange(len(meta)))
    summ, cases = paired_cases(outer, meta[["row_id", "package", "old_version", "new_version", "type"]].merge(m6.drop(columns=["type"]), on="row_id"), x1)
    tables["paired_vs_full29"] = summ
    tables["paired_cases"] = cases
    tables["feature_importance_summary"] = importance_summary(pd.read_csv(args.run / "feature_importance.csv"))
    for name, t in tables.items():
        t.to_csv(out / f"{name}.csv", index=False, lineterminator="\n")
    print("written", out)


if __name__ == "__main__":
    main()
