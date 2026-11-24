"""Early stopping follow-up (post-hoc development experiment on the already-evaluated D06 Test). See ES_PLAN.md.

Usage: python -I -B es_eval.py --workspace <ws> --groups <be87ab4c malicious_pair_groups.csv> --out <new dir>
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import platform
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

HERE = Path(__file__).resolve().parent
spec_ = importlib.util.spec_from_file_location("followup_eval", HERE.parent / "d06_test_followup" / "followup_eval.py")
F = importlib.util.module_from_spec(spec_)
spec_.loader.exec_module(F)
R = F.R
MODELS = ["base7", "full35"]
TARGETS = [0.01, 0.03, 0.05]


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", type=Path, required=True)
    ap.add_argument("--groups", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    versions = {"lightgbm": lgb.__version__, "pandas": pd.__version__, "numpy": np.__version__, "sklearn": R.sklearn.__version__}
    R.require(versions == R.PINNED, f"versions {versions}")
    out = args.out
    out.mkdir(parents=True, exist_ok=False)
    (out / "models").mkdir()
    snap, spec, data, test, feats, paths = F.prepare(args.workspace, args.groups)
    stored_scores = pd.read_csv(F.EVAL / "run/scores.csv")
    stored_splits = pd.read_csv(F.EVAL / "run/splits.csv")
    es_rows, split_rows, score_rows, thr_rows, met_rows, camp_rows = [], [], [], [], [], []
    for sname, seed in R.SEEDS.items():
        fit, cal = snap.inner_split(data, seed)
        ref = stored_splits[stored_splits.seed == sname]
        for stg, part in [("fit", fit), ("calibration", cal)]:
            R.require(set(ref[ref.stage == stg].row_id) == set(part.row_id), f"{sname} {stg} differs")
        sub, val = snap.inner_split(fit, seed)
        snap.check_disjoint(sub, val)
        R.require(len(sub) + len(val) == len(fit) and not set(sub.row_id) & set(val.row_id), "sub/val partition")
        for stg, part in [("sub_fit", sub), ("validation", val)]:
            split_rows.append(pd.DataFrame({"seed": sname, "stage": stg, "row_id": part.row_id.to_numpy(), "component": part.component.to_numpy(),
                                            "class": part["class"].to_numpy(), "campaign": part.campaign.to_numpy()}))
        cal_s, test_s = {}, {}
        for m in MODELS:
            cols = feats[m]
            xs, xv, xf, xc, xt = (snap.feature_matrix(p, cols, "M_full") for p in (sub, val, fit, cal, test))
            dsub = lgb.Dataset(xs, label=sub.label.to_numpy(), categorical_feature=["updateType"], feature_name=cols)
            dval = lgb.Dataset(xv, label=val.label.to_numpy(), categorical_feature=["updateType"], feature_name=cols, reference=dsub)
            hist = {}
            es_model = lgb.train(spec["lightgbm"], dsub, num_boost_round=spec["rounds"], valid_sets=[dval], valid_names=["val"],
                                 callbacks=[lgb.early_stopping(stopping_rounds=50, first_metric_only=True, verbose=False), lgb.record_evaluation(hist)])
            B = max(int(es_model.best_iteration), 1)
            ll = hist["val"]["binary_logloss"]
            final = lgb.train(spec["lightgbm"], lgb.Dataset(xf, label=fit.label.to_numpy(), categorical_feature=["updateType"], feature_name=cols), num_boost_round=B)
            path = out / "models" / f"{m}_es_{sname}.txt"
            final.save_model(str(path))
            name = f"{m}_es"
            cal_s[name], test_s[name] = final.predict(xc, num_threads=2), final.predict(xt, num_threads=2)
            es_rows.append({"seed": sname, "model": name, "feature_count": len(cols), "best_iteration": B, "rounds_run_on_subfit": len(ll),
                            "val_logloss_best": float(ll[B - 1]), "val_logloss_at_1": float(ll[0]), "val_logloss_last": float(ll[-1]),
                            "refit_rounds": final.current_iteration(), "model_sha256": sha(path),
                            "sub_fit_rows": len(sub), "sub_fit_malicious": int(sub.label.sum()), "val_rows": len(val), "val_malicious": int(val.label.sum()),
                            "val_malicious_campaigns": "; ".join(f"{k}:{v}" for k, v in val[val.label == 1].campaign.value_counts().head(6).items())})
            print(f"{name} {sname}: best_iteration={B}", flush=True)
        for m in MODELS:  # stored 200-round
            sc = stored_scores[(stored_scores.seed == sname) & (stored_scores.model == m)]
            cal_s[m] = sc[sc.stage == "calibration"].set_index("row_id").score.loc[cal.row_id].to_numpy()
            test_s[m] = sc[sc.stage == "test"].set_index("test_row").score.loc[test.test_row].to_numpy()
        for m in cal_s:
            for stg, part, s in [("calibration", cal, cal_s[m]), ("test", test, test_s[m])]:
                if m.endswith("_es"):
                    score_rows.append(pd.DataFrame({"seed": sname, "model": m, "stage": stg, "row_id": part.row_id.to_numpy() if stg == "calibration" else -1,
                                                    "test_row": part.test_row.to_numpy() if stg == "test" else -1, "score": s}))
        F.SNAP = snap
        tr, mr = F.evaluate(test, cal.label.to_numpy(), cal_s, test_s, list(cal_s), {"seed": sname})
        thr_rows += tr
        met_rows += mr
        thr = {(r["model"], r["target"]): r["threshold"] for r in tr}
        for m in cal_s:
            for tset, mask in [("Test-674", test.in674.to_numpy()), ("Test-677", np.ones(len(test), bool))]:
                tf, sc = test[mask], test_s[m][mask]
                mal = tf.label.to_numpy() == 1
                for op in TARGETS + ["0.5"]:
                    t = 0.5 if op == "0.5" else thr[(m, op)]
                    sel = sc >= t
                    for camp, idx in pd.Series(np.arange(len(tf))[mal]).groupby(tf.campaign.to_numpy()[mal]):
                        camp_rows.append({"seed": sname, "test_set": tset, "op": "0.5" if op == "0.5" else f"calFPR{int(op * 100)}%", "model": m,
                                          "campaign": camp, "n": len(idx), "TP": int(sel[idx.to_numpy()].sum()), "Recall": float(sel[idx.to_numpy()].mean())})
    pd.DataFrame(es_rows).to_csv(out / "early_stopping.csv", index=False, lineterminator="\n")
    pd.concat(split_rows).to_csv(out / "subfit_validation_split.csv", index=False, lineterminator="\n")
    pd.concat(score_rows).to_csv(out / "scores_es.csv", index=False, lineterminator="\n")
    pd.DataFrame(thr_rows).to_csv(out / "thresholds.csv", index=False, lineterminator="\n")
    pd.DataFrame(met_rows).to_csv(out / "metrics.csv", index=False, lineterminator="\n")
    pd.DataFrame(camp_rows).to_csv(out / "campaign_recall.csv", index=False, lineterminator="\n")
    manifest = {"experiment_id": "D06-TEST-ES-FOLLOWUP", "nature": "post-hoc development experiment on the already-evaluated D06 Test", "plan": "ES_PLAN.md",
                "plan_sha256": sha(HERE / "ES_PLAN.md"), "script_sha256": sha(__file__),
                "inputs": {k: {"path": str(v.relative_to(args.workspace)), "sha256": sha(v)} for k, v in paths.items()} |
                          {"stored_scores": sha(F.EVAL / "run/scores.csv"), "stored_splits": sha(F.EVAL / "run/splits.csv")},
                "early_stopping": {"monitor": "validation binary_logloss", "max_rounds": spec["rounds"], "stopping_rounds": 50, "first_metric_only": True},
                "lightgbm_params": spec["lightgbm"], "packages": versions, "python": platform.python_version(),
                "outputs": {p.name: sha(p) for p in sorted(out.rglob("*")) if p.is_file()}}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
