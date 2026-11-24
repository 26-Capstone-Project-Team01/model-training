"""D06 Test evaluation exactly as pre-registered (PREREGISTRATION.md, correction 1).

- Train 2,767 -> PR #13 components -> inner_split(seed) fit / calibration (seeds 20261109 primary, 20261110 secondary).
- Models trained on fit only: base7, base7_w (E09-style weight), full29, full35. PR #13 LightGBM params, 200 rounds, no early stopping.
- A1..A3 = (1-w)*full29 + w*full35, w = 0.1/0.2/0.3 (calibration and test).
- Thresholds from calibration only (PR #13 calibrate, ML policy) at target FPR 1/3/5%; 0.5 reference.
- Test-674 (primary) = Test-677 minus 3 vant pairs; Test-677 secondary.
- Reference only: saved D06-E06/E09 models on Test-677 at 0.5 (train_model.py feature preparation).
No Test-based choice of anything. Package code is never executed.

Usage: python -I -B run_test_eval.py --workspace <ws> --groups <be87ab4c malicious_pair_groups.csv> --out <new dir>
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import platform
import sys
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
import sklearn
from sklearn.metrics import average_precision_score, roc_auc_score

HERE = Path(__file__).resolve().parent
EXP = HERE.parent
REPO = EXP.parent
BUNDLE = EXP / "d06_feature_comparison_18"
SNAPSHOT = BUNDLE / "provenance/phase2_run1_base7_full29/executed_script_snapshot.py"
SNAPSHOT_SHA256 = "049bf00c0269ff9638caad8273f3dc49254ba91cec9da35ebd3c4db87cf62854"
SPEC_REL = "temp/detection-feasibility/phase2/evaluation_spec.json"
TRAIN_FULL35 = EXP / "d06_x1_extraction/analysis/d06_full35.csv"
TEST_FULL35 = HERE / "analysis/d06_test_full35.csv"
TEST_STATUS = HERE / "analysis/d06_test_x1_status.csv"
GROUPS_SHA256 = "b05c9dfd869dde5b9a488d830bebec998c9673a388e835ec1b52c253153d7a7b"
SEEDS = {"seed20261109": 20261109, "seed20261110": 20261110}
PRIMARY_SEED = "seed20261109"
PINNED = {"lightgbm": "4.7.0", "pandas": "3.0.6", "numpy": "2.5.3", "sklearn": "1.9.1"}
KEY = ["package", "old_version", "new_version"]
X1 = ["installHookNewProgramCount", "installHookArgsChanged", "installHookRefFileChanged",
      "installHookNewExternalExecCount", "addedProcExecCallCount", "addedNetworkCallCount"]
X1_BOOL = {"installHookArgsChanged", "installHookRefFileChanged"}
VANT3 = {("vant", "4.9.11", "4.9.12"), ("vant", "4.9.11", "4.9.13"), ("vant", "4.9.11", "4.9.14")}
BLEND = {"A1": 0.1, "A2": 0.2, "A3": 0.3}
TARGETS = [0.01, 0.03, 0.05]
TRAINED = ["base7", "base7_w", "full29", "full35"]
ALL = TRAINED + list(BLEND)
E0609 = {"E06": ("models/D06_E06_package_json_only.txt", {"recall": 0.6082949308755761, "precision": 0.8859060402684564, "f1": 0.7213114754098361, "pr_auc": 0.8687580548681246}),
         "E09": ("models/D06_E09_package_json_only_campaign_weight.txt", {"recall": 0.7096774193548387, "precision": 0.7979274611398963, "f1": 0.751219512195122, "pr_auc": 0.8143329429804234})}


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def require(c, m):
    if not c:
        raise SystemExit(m)


def load_snapshot():
    require(sha(SNAPSHOT) == SNAPSHOT_SHA256, "snapshot hash mismatch")
    spec = importlib.util.spec_from_file_location("run1_snapshot", SNAPSHOT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def encode_x1(path):
    raw = pd.read_csv(path, dtype=str, keep_default_na=False)
    out = {}
    for c in X1:
        s = raw[c]
        if c in X1_BOOL:
            require(set(s) <= {"True", "False", ""}, f"bad bool {c}")
            out[c] = s.map({"True": 1.0, "False": 0.0, "": np.nan}).astype(float).to_numpy()
        else:
            out[c] = pd.to_numeric(s.replace("", np.nan), errors="raise").astype(float).to_numpy()
    return raw[KEY + ["label"]], pd.DataFrame(out)


def weights_e09(fit, snap):
    """E09 / train_model.compute_sample_weights: key = shared splitGroup, generic bucket rows are singletons."""
    w = np.ones(len(fit))
    mal = fit.label.to_numpy() == 1
    keys = pd.Series([sg if snap.shared_campaign(sg) else f"singleton:{rid}"
                      for sg, rid in zip(fit.loc[mal, "splitGroup"], fit.loc[mal, "row_id"])], index=fit.index[mal])
    raw = 1 / np.sqrt(keys.map(keys.value_counts()).to_numpy())
    w[mal] = raw * mal.sum() / raw.sum()
    return w


def metrics(frame, scores, thr):
    sel = scores >= thr
    mal = frame.label.to_numpy() == 1
    cls = frame["class"].to_numpy()
    tp, fp = int((sel & mal).sum()), int((sel & ~mal).sum())
    rec = tp / mal.sum()
    prec = tp / sel.sum() if sel.sum() else float("nan")
    camp = frame.loc[mal, "campaign"].to_numpy()
    per = pd.Series(sel[mal]).groupby(camp).mean()
    return {"TP": tp, "FN": int(mal.sum()) - tp, "FP": fp, "benign_FP": int((sel & (cls == "benign")).sum()),
            "hard_FP": int((sel & (cls == "hard_benign")).sum()), "Recall": rec, "Precision": prec,
            "F1": 2 * rec * prec / (rec + prec) if sel.sum() and (rec + prec) else 0.0,
            "test_FPR": fp / (~mal).sum(), "CampMacro": float(per.mean()), "selected": int(sel.sum())}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", type=Path, required=True)
    ap.add_argument("--groups", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    versions = {"lightgbm": lgb.__version__, "pandas": pd.__version__, "numpy": np.__version__, "sklearn": sklearn.__version__}
    require(versions == PINNED, f"library versions differ: {versions}")
    require(sha(args.groups) == GROUPS_SHA256, "groups hash mismatch")
    out = args.out
    out.mkdir(parents=True, exist_ok=False)
    (out / "models").mkdir()
    snap = load_snapshot()
    spec = json.loads((args.workspace / SPEC_REL).read_text(encoding="utf-8"))
    data, feat29, paths = snap.load_data(args.workspace, spec)  # hash-checked train / groups / classes
    require(len(feat29) == 29, "expected 29 features")
    base7 = spec["features"]["M_base"]
    require(len(base7) == 7, "base7")

    # ---- attach Train X1 by row order (keys/labels checked)
    tk, tx = encode_x1(TRAIN_FULL35)
    require((tk[KEY].to_numpy() == data[KEY].astype(str).to_numpy()).all() and (tk.label.astype(int).to_numpy() == data.label.to_numpy()).all(), "train X1 keys/labels")
    for c in X1:
        data[c] = tx[c].to_numpy()
    feat35 = feat29 + X1
    FEATS = {"base7": base7, "base7_w": base7, "full29": feat29, "full35": feat35}

    # ---- Test frame
    tst_raw = pd.read_csv(TEST_FULL35, float_precision="round_trip")
    sk, sx = encode_x1(TEST_FULL35)
    test = tst_raw.drop(columns=X1).copy()
    for c in X1:
        test[c] = sx[c].to_numpy()
    st = pd.read_csv(TEST_STATUS, keep_default_na=False, dtype=str)
    require((st[KEY].to_numpy() == test[KEY].astype(str).to_numpy()).all(), "test status order")
    require((st.label.astype(int).to_numpy() == test.label.to_numpy()).all() and ((st.label == "1") == (st["class"] == "malicious")).all(), "test labels/class")
    test["class"] = st["class"].to_numpy()
    test["campaign"] = st["splitGroup"].to_numpy()
    test["test_row"] = np.arange(len(test))
    test["in674"] = ~test[KEY].astype(str).apply(tuple, axis=1).isin(VANT3)
    require(len(test) == 677 and int(test.in674.sum()) == 674, "test sizes")

    # ---- Train/Test leakage checks (package, payload hashes, real campaign)
    groups = pd.read_csv(args.groups, keep_default_na=False, dtype=str)
    tg = test[KEY].astype(str).merge(groups[KEY + ["splitGroup", "largestChangedJsSha1", "changedJsSetSha1"]], on=KEY, how="left").fillna("")
    leak = {"package": len(set(data.package) & set(test.package)),
            "key": len(set(map(tuple, data[KEY].astype(str).to_numpy())) & set(map(tuple, test[KEY].astype(str).to_numpy())))}
    for h in snap.HASHES:
        leak[h] = len({v for v in data[h] if v} & {v for v in tg[h] if v})
    leak["real_splitGroup"] = sorted({v for v in set(data.splitGroup) & set(tg.splitGroup) if snap.shared_campaign(v)})
    require(leak["package"] == 0 and leak["key"] == 0 and all(leak[h] == 0 for h in snap.HASHES) and not leak["real_splitGroup"], f"train/test leakage {leak}")

    rows_scores, rows_split, rows_train, rows_thr, rows_met, rows_rank, rows_camp, rows_gl, gl_cases = [], [], [], [], [], [], [], [], []
    for sname, seed in SEEDS.items():
        fit, cal = snap.inner_split(data, seed)
        snap.check_disjoint(fit, cal)
        require(len(fit) + len(cal) == len(data) and not set(fit.row_id) & set(cal.row_id), "fit/cal partition")
        for stage, part in [("fit", fit), ("calibration", cal)]:
            rows_split.append(pd.DataFrame({"seed": sname, "stage": stage, "row_id": part.row_id.to_numpy(), "component": part.component.to_numpy(),
                                            "class": part["class"].to_numpy(), "campaign": part.campaign.to_numpy()}))
        cal_s, test_s = {}, {}
        for m in TRAINED:
            cols = FEATS[m]
            xf, xc, xt = (snap.feature_matrix(p, cols, "M_full") for p in (fit, cal, test))
            w = weights_e09(fit, snap) if m == "base7_w" else None
            ds = lgb.Dataset(xf, label=fit.label.to_numpy(), weight=w, categorical_feature=["updateType"], feature_name=cols)
            booster = lgb.train(spec["lightgbm"], ds, num_boost_round=spec["rounds"])
            path = out / "models" / f"{m}_{sname}.txt"
            booster.save_model(str(path))
            cal_s[m] = booster.predict(xc, num_threads=2)
            test_s[m] = booster.predict(xt, num_threads=2)
            gain = booster.feature_importance(importance_type="gain")
            rows_train.append({"seed": sname, "model": m, "feature_count": len(cols), "feature_order": " ".join(cols), "sample_weight": "E09" if w is not None else "none",
                               "requested_rounds": spec["rounds"], "trained_rounds": booster.current_iteration(), "model_sha256": sha(path),
                               "fit_rows": len(fit), "fit_malicious": int(fit.label.sum()), "cal_rows": len(cal), "cal_malicious": int(cal.label.sum()),
                               "cal_normals": int((cal.label == 0).sum()), "top5_gain": "; ".join(f"{f}:{g / gain.sum():.3f}" for f, g in sorted(zip(cols, gain), key=lambda x: -x[1])[:5])})
            print(f"trained {m} {sname} rounds={booster.current_iteration()}", flush=True)
        for k, wgt in BLEND.items():
            cal_s[k] = (1 - wgt) * cal_s["full29"] + wgt * cal_s["full35"]
            test_s[k] = (1 - wgt) * test_s["full29"] + wgt * test_s["full35"]
        for m in ALL:
            rows_scores.append(pd.DataFrame({"seed": sname, "model": m, "stage": "calibration", "row_id": cal.row_id.to_numpy(), "test_row": -1, "score": cal_s[m]}))
            rows_scores.append(pd.DataFrame({"seed": sname, "model": m, "stage": "test", "row_id": -1, "test_row": test.test_row.to_numpy(), "score": test_s[m]}))
        # thresholds
        thr = {}
        for m in ALL:
            for t in TARGETS:
                r = snap.calibrate(cal_s[m], cal.label.to_numpy(), np.zeros(len(cal), bool), "ML", t)
                thr[(m, t)] = r["threshold"]
                rows_thr.append({"seed": sname, "model": m, "target": t, "threshold": r["threshold"], "cal_normals": r["calibration_normal"],
                                 "budget": r["budget"], "cal_fp": r["calibration_fp"], "cal_fpr": r["calibration_fp"] / r["calibration_normal"], "boundary_ties": r["ties"]})
            thr[(m, "0.5")] = 0.5
        # metrics on Test-674 / Test-677
        for tset, mask in [("Test-674", test.in674.to_numpy()), ("Test-677", np.ones(len(test), bool))]:
            tf = test[mask]
            for m in ALL:
                sc = test_s[m][mask]
                rows_rank.append({"seed": sname, "test_set": tset, "model": m, "ROC_AUC": roc_auc_score(tf.label, sc), "PR_AUC": average_precision_score(tf.label, sc)})
                for op in TARGETS + ["0.5"]:
                    mt = metrics(tf, sc, thr[(m, op)])
                    cal_fpr = np.nan if op == "0.5" else next(r["cal_fpr"] for r in rows_thr if r["seed"] == sname and r["model"] == m and r["target"] == op)
                    rows_met.append({"seed": sname, "test_set": tset, "op": "0.5" if op == "0.5" else f"calFPR{int(op * 100)}%", "model": m,
                                     "threshold": thr[(m, op)], **mt, "cal_FPR": cal_fpr, "test_minus_cal_FPR": mt["test_FPR"] - cal_fpr if op != "0.5" else np.nan})
                    selm = sc >= thr[(m, op)]
                    malm = tf.label.to_numpy() == 1
                    for camp, idx in pd.Series(np.arange(len(tf))[malm]).groupby(tf.campaign.to_numpy()[malm]):
                        rows_camp.append({"seed": sname, "test_set": tset, "op": "0.5" if op == "0.5" else f"calFPR{int(op * 100)}%", "model": m,
                                          "campaign": camp, "n": len(idx), "TP": int(selm[idx.to_numpy()].sum())})
                # gain/loss vs full29 (same op)
                if m != "full29":
                    for op in TARGETS + ["0.5"]:
                        a = test_s["full29"][mask] >= thr[("full29", op)]
                        b = sc >= thr[(m, op)]
                        malm = tf.label.to_numpy() == 1
                        opn = "0.5" if op == "0.5" else f"calFPR{int(op * 100)}%"
                        rows_gl.append({"seed": sname, "test_set": tset, "op": opn, "model": m, "gained": int((malm & b & ~a).sum()), "lost": int((malm & a & ~b).sum()),
                                        "fp_added": int((~malm & b & ~a).sum()), "fp_removed": int((~malm & a & ~b).sum()),
                                        "hard_fp_added": int(((tf["class"] == "hard_benign").to_numpy() & b & ~a).sum()),
                                        "hard_fp_removed": int(((tf["class"] == "hard_benign").to_numpy() & a & ~b).sum())})
                        if tset == "Test-674":
                            for kind, msk in [("gained", malm & b & ~a), ("lost", malm & a & ~b)]:
                                sub = tf[msk]
                                gl_cases.append(pd.DataFrame({"seed": sname, "op": opn, "model": m, "change": kind, "test_row": sub.test_row.to_numpy(),
                                                              "package": sub.package.to_numpy(), "new_version": sub.new_version.to_numpy(), "campaign": sub.campaign.to_numpy(),
                                                              "score_full29": test_s["full29"][mask][msk], "score_model": sc[msk]}))

    # ---- reference: saved E06/E09 on Test-677 at 0.5 (train_model.py preparation)
    tdf = pd.read_csv(TEST_FULL35).drop(columns=X1)
    X = tdf.drop(columns=KEY + ["label"])
    X["updateType"] = X["updateType"].astype("category")
    ref = {}
    for name, (rel, rec) in E0609.items():
        b = lgb.Booster(model_file=str(REPO / rel))
        p = b.predict(X[b.feature_name()])
        sel = p >= 0.5
        y = tdf.label.to_numpy() == 1
        tp = int((sel & y).sum())
        got = {"recall": tp / y.sum(), "precision": tp / sel.sum(), "f1": 2 * tp / (sel.sum() + y.sum()), "pr_auc": average_precision_score(y, p)}
        ref[name] = {"model_file": rel, "model_sha256": sha(REPO / rel), "trees": b.num_trees(), "features": b.feature_name(), "TP": tp, "FP": int((sel & ~y).sum()),
                     "reproduced": got, "recorded": rec, "max_abs_diff": max(abs(got[k] - rec[k]) for k in rec), "match_1e-9": all(abs(got[k] - rec[k]) < 1e-9 for k in rec)}

    pd.concat(rows_split).to_csv(out / "splits.csv", index=False, lineterminator="\n")
    pd.concat(rows_scores).to_csv(out / "scores.csv", index=False, lineterminator="\n")
    pd.DataFrame(rows_train).to_csv(out / "training.csv", index=False, lineterminator="\n")
    pd.DataFrame(rows_thr).to_csv(out / "thresholds.csv", index=False, lineterminator="\n")
    pd.DataFrame(rows_met).to_csv(out / "metrics.csv", index=False, lineterminator="\n")
    pd.DataFrame(rows_rank).to_csv(out / "ranking.csv", index=False, lineterminator="\n")
    pd.DataFrame(rows_camp).to_csv(out / "campaign_tp.csv", index=False, lineterminator="\n")
    pd.DataFrame(rows_gl).to_csv(out / "gain_loss_vs_full29.csv", index=False, lineterminator="\n")
    pd.concat(gl_cases, ignore_index=True).to_csv(out / "gain_loss_cases_test674.csv", index=False, lineterminator="\n")
    test[KEY + ["test_row", "label", "class", "campaign", "in674"]].to_csv(out / "test_rows.csv", index=False, lineterminator="\n")
    (out / "e06_e09_reproduction.json").write_text(json.dumps(ref, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    manifest = {"experiment_id": "D06-TEST-EVAL", "preregistration": "PREREGISTRATION.md", "preregistration_sha256": sha(HERE / "PREREGISTRATION.md"),
                "data_commit": "be87ab4cff66fff1980c4a71be8032b6b47225ba",
                "inputs": {k: {"path": str(v.relative_to(args.workspace)), "sha256": sha(v)} for k, v in paths.items()} |
                          {"train_full35": sha(TRAIN_FULL35), "test_full35": sha(TEST_FULL35), "test_status": sha(TEST_STATUS), "groups": GROUPS_SHA256},
                "snapshot_sha256": SNAPSHOT_SHA256, "script_sha256": sha(__file__), "lightgbm_params": spec["lightgbm"], "rounds": spec["rounds"],
                "seeds": SEEDS, "primary_seed": PRIMARY_SEED, "models": {m: FEATS[m] for m in TRAINED}, "blend": BLEND, "targets": TARGETS,
                "leakage_checks": leak, "packages": versions, "python": platform.python_version(), "read_test_for_selection": False,
                "outputs": {p.name: sha(p) for p in sorted(out.rglob("*")) if p.is_file()}}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print("E06/E09 reproduction:", {k: (v["match_1e-9"], round(v["max_abs_diff"], 12)) for k, v in ref.items()})


if __name__ == "__main__":
    main()
