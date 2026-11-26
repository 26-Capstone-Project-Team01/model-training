"""D08 M1-M4 Train-internal experiment (no Test). See README.md.

Reuses (imported by path, sha-checked) the PR #13 snapshot: components(), check_disjoint(), component_counts(), feature_matrix(), calibrate().
Usage: python -I -B run_m1m4.py --snapshot <executed_script_snapshot.py> --out <new dir> [--smoke]
"""
from __future__ import annotations
import argparse, hashlib, importlib.util, json, platform, re, sys, time
from pathlib import Path
import numpy as np, pandas as pd, lightgbm as lgb, sklearn
from sklearn.metrics import average_precision_score, precision_score

HERE = Path(__file__).resolve().parent
INP = HERE / "inputs"
KEY = ["package", "old_version", "new_version"]
EXPECTED = {"train.csv": ("9237bf7450761ae3e9bcfc716be8efb331875846aec368c0b44da2bb5ed9ae96", 5344),
            "split_assignment.csv": ("3599396cde88d7c5cb7da3fbf49074599115b035844edee01f4cbdf2667150d7", 6028),
            "malicious_pair_groups.csv": ("f181fa37068ee65d30033acb27fec7d2671dad4900a9a2292e5c6024a4f5fe6f", 3737),
            "baselines.csv": ("8b2507178f8914c797678e47e5f1e14f70af8a66efdc5bdae127ab6d2b738213", 6610),
            "d06_train.csv": ("22fbc8752fff5fff90e40b911f6bf7d187769b4566db957d65a37a16be7d2c23", 2767)}
SNAPSHOT_SHA256 = "049bf00c0269ff9638caad8273f3dc49254ba91cec9da35ebd3c4db87cf62854"
LGB_PARAMS = {"objective": "binary", "metric": "binary_logloss", "verbosity": -1, "num_threads": 2, "deterministic": True, "force_col_wise": True, "seed": 20261109}
ROUNDS = 200
CAL_SEEDS = [20261109, 20261110]
TARGETS = [0.01, 0.05]
MODELS = ["M1", "M2", "M3", "M4"]


def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def load_inputs():
    for n, (h, rows) in EXPECTED.items():
        assert sha(INP / n) == h, f"{n} sha256 differs"
        assert len(pd.read_csv(INP / n, dtype=str, keep_default_na=False)) == rows, f"{n} rows differ"
    rd = lambda n: pd.read_csv(INP / n, dtype=str, keep_default_na=False)
    tr, sa, gr, d6 = rd("train.csv"), rd("split_assignment.csv"), rd("malicious_pair_groups.csv"), rd("d06_train.csv")
    T = tr.merge(sa[KEY + ["class", "splitGroup", "split"]], on=KEY, how="left", validate="one_to_one")
    assert (T.split == "train").all() and T["class"].notna().all()
    T = T.merge(gr[KEY + ["largestChangedJsSha1", "changedJsSetSha1", "addedDependencies", "addedInstallHooks"]], on=KEY, how="left").fillna("")
    T["label"] = T.label.astype(int)
    assert ((T.label == 1) == (T["class"] == "malicious")).all()
    T["era"] = np.where(T[KEY].apply(tuple, axis=1).isin(set(map(tuple, d6[KEY].values))), "D06", "new")
    assert (T.era == "D06").sum() == 2767
    T["row_id"] = np.arange(len(T))
    return T, [c for c in tr.columns if c not in KEY + ["label"]]


def payload_key(r):
    if r.label != 1: return ""
    if r.largestChangedJsSha1: return r.largestChangedJsSha1
    sig = r.addedInstallHooks + "|" + r.addedDependencies
    return "nojs:" + sig if sig != "|" else "nojs-empty:" + r.package


def vkey(v):
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", v)
    return tuple(map(int, m.groups())) if m else (10 ** 9, 0, 0)


def greedy_folds(frame, snap, k=5):
    counts = snap.component_counts(frame)
    assignment, loads = {}, np.zeros((k, 3), dtype=int)
    for g in sorted(counts.index[counts.malicious > 0], key=lambda g: (-int(counts.loc[g, "malicious"]), g)):
        f = min(range(k), key=lambda f: (loads[f, 0], f)); assignment[g] = f; loads[f] += counts.loc[g].to_numpy()
    target = np.maximum(counts.sum().to_numpy()[1:] / k, 1)
    for g in sorted(counts.index[counts.malicious == 0], key=lambda g: (-int(counts.loc[g].sum()), g)):
        s = counts.loc[g].to_numpy(); f = min(range(k), key=lambda f: (float(np.sum((loads[f, 1:] + s[1:]) ** 2 / target)), f)); assignment[g] = f; loads[f] += s
    return frame.component.map(assignment).astype(int)


def normal_only_calibration(fit, seed, share=0.25):
    comp = fit.groupby("component").agg(mal=("label", "sum"), benign=("class", lambda s: (s == "benign").sum()), hb=("class", lambda s: (s == "hard_benign").sum()))
    cand = comp[comp.mal == 0]
    goal = np.array([comp.benign.sum(), comp.hb.sum()]) * share; scale = np.maximum(goal, 1)
    cur, sel = np.zeros(2), []
    for g in np.random.default_rng(seed).permutation(sorted(cand.index)):
        nxt = cur + cand.loc[g, ["benign", "hb"]].to_numpy()
        if np.sum(((nxt - goal) / scale) ** 2) < np.sum(((cur - goal) / scale) ** 2):
            sel.append(g); cur = nxt
    return fit.component.isin(sel)


def m3_select(fit):
    """D06 rows all; new malicious: one row (lowest new_version) per (package, old_version, P, v28);
    then add back the lowest-version row of any changedJsSetSha1 present among new malicious fit rows but absent from the kept rows."""
    new_mal = fit[(fit.era == "new") & (fit.label == 1)].sort_values(["package", "old_version", "P", "v28", "_v"])
    keep = new_mal.drop_duplicates(["package", "old_version", "P", "v28"])
    kept_sets = set(keep.changedJsSetSha1) | set(fit[(fit.era == "D06") & (fit.label == 1)].changedJsSetSha1)
    missing = new_mal[(new_mal.changedJsSetSha1 != "") & ~new_mal.changedJsSetSha1.isin(kept_sets)]
    addback = missing.sort_values("_v").drop_duplicates("changedJsSetSha1")
    sel = pd.concat([fit[fit.era == "D06"], keep, addback, fit[(fit.era == "new") & (fit.label == 0)]])
    assert not sel.row_id.duplicated().any()
    return sel, len(addback)


def m4_weights(fit):
    w = pd.Series(1.0, index=fit.index); mal = fit.label == 1
    w[mal] = 1 / np.sqrt(fit[mal].groupby("P").P.transform("size"))
    w[mal] *= mal.sum() / w[mal].sum()
    return w


def metrics(ev, score, thr, groups_generic):
    sel = score >= thr
    mal = ev.label.to_numpy() == 1; ben = (ev["class"] == "benign").to_numpy(); hb = (ev["class"] == "hard_benign").to_numpy()
    tp, fp = int((sel & mal).sum()), int((sel & ~mal).sum())
    rec = tp / mal.sum(); prec = tp / sel.sum() if sel.sum() else np.nan
    return {"TP": tp, "FN": int(mal.sum()) - tp, "FP": fp, "benign_FP": int((sel & ben).sum()), "hard_FP": int((sel & hb).sum()),
            "recall": rec, "precision": prec, "f1": 2 * rec * prec / (rec + prec) if sel.sum() and rec + prec else 0.0,
            "fpr_all_normal": fp / (~mal).sum(), "fpr_benign": (sel & ben).sum() / ben.sum(), "fpr_hard_benign": (sel & hb).sum() / hb.sum(),
            "recall_D06_rows": float(sel[mal & (ev.era == "D06").to_numpy()].mean()) if (mal & (ev.era == "D06").to_numpy()).any() else np.nan,
            "recall_new_rows": float(sel[mal & (ev.era == "new").to_numpy()].mean()) if (mal & (ev.era == "new").to_numpy()).any() else np.nan}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--snapshot", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--smoke", action="store_true")
    a = ap.parse_args()
    assert sha(a.snapshot) == SNAPSHOT_SHA256
    spec = importlib.util.spec_from_file_location("snap", a.snapshot); snap = importlib.util.module_from_spec(spec); spec.loader.exec_module(snap)
    out = a.out; out.mkdir(parents=True, exist_ok=False); (out / "models").mkdir()
    T, F29 = load_inputs()
    F28 = [f for f in F29 if f != "updateInterval"]; assert len(F28) == 28
    T["v28"] = T[F28].agg("|".join, axis=1); T["P"] = T.apply(payload_key, axis=1); T["_v"] = T.new_version.map(vkey)
    # numeric frame for model input (snapshot feature_matrix expects floats/bools)
    X = T.copy()
    for c in F28:
        if c != "updateType":
            X[c] = pd.to_numeric(X[c].replace({"True": "1", "False": "0", "": np.nan}))
    comp_frame = T[["package", "label", "splitGroup", "largestChangedJsSha1", "changedJsSetSha1", "class"]].copy()
    comp_frame.loc[comp_frame.label == 0, ["splitGroup", "largestChangedJsSha1", "changedJsSetSha1"]] = ""
    T["component"] = snap.components(comp_frame); X["component"] = T.component
    T["fold"] = greedy_folds(T.assign(splitGroup=comp_frame.splitGroup), snap); X["fold"] = T.fold
    T[KEY + ["row_id", "class", "era", "splitGroup", "component", "fold", "P"]].to_csv(out / "fold_assignment.csv", index=False, lineterminator="\n")
    generic = {g for g in T.splitGroup.unique() if g and not snap.shared_campaign(g)}
    folds = [0] if a.smoke else range(5)
    seeds = CAL_SEEDS[:1] if a.smoke else CAL_SEEDS
    cal_rows, m3_rows, m4_rows, train_log, thr_rows, met_rows, score_rows, imp_rows = [], [], [], [], [], [], [], []
    t0 = time.time()
    for seed in seeds:
        for f in folds:
            val, rest = X[X.fold == f], X[X.fold != f]
            chk = lambda d: d.assign(splitGroup=d.splitGroup.where(d.label == 1, ""), largestChangedJsSha1=d.largestChangedJsSha1.where(d.label == 1, ""), changedJsSetSha1=d.changedJsSetSha1.where(d.label == 1, ""))
            snap.check_disjoint(chk(val), chk(rest))
            is_cal = normal_only_calibration(rest, seed + f)
            cal, fit = rest[is_cal], rest[~is_cal]
            assert (cal.label == 0).all() and not set(cal.component) & set(fit.component)
            cal_rows.append(cal[KEY + ["row_id", "class"]].assign(cal_seed=seed, fold=f))
            m3, n_add = m3_select(fit)
            w4 = m4_weights(fit)
            m3_rows.append(m3[m3.era == "new"][KEY + ["row_id", "P", "changedJsSetSha1"]].assign(cal_seed=seed, fold=f))
            m4_rows.append(fit[KEY + ["row_id", "P"]].assign(weight=w4.to_numpy(), cal_seed=seed, fold=f))
            train_sets = {"M1": (fit[fit.era == "D06"], None), "M2": (fit, None), "M3": (m3, None), "M4": (fit, w4)}
            for name in MODELS:
                d, w = train_sets[name]
                xm = snap.feature_matrix(d, F28, "M_full")
                booster = lgb.train(LGB_PARAMS, lgb.Dataset(xm, label=d.label.to_numpy(), weight=None if w is None else w.to_numpy(), categorical_feature=["updateType"], feature_name=F28),
                                    num_boost_round=ROUNDS)
                path = out / "models" / f"{name}_seed{seed}_fold{f}.txt"; booster.save_model(str(path))
                s_cal = booster.predict(snap.feature_matrix(cal, F28, "M_full"), num_threads=2)
                s_val = booster.predict(snap.feature_matrix(val, F28, "M_full"), num_threads=2)
                train_log.append({"cal_seed": seed, "fold": f, "model": name, "fit_rows": len(d), "fit_malicious": int(d.label.sum()), "fit_normal": int((d.label == 0).sum()),
                                  "malicious_weight_sum": float(w[d.label == 1].sum()) if w is not None else float(d.label.sum()),
                                  "m3_changedJsSet_addback": n_add if name == "M3" else "", "cal_benign": int((cal["class"] == "benign").sum()), "cal_hard_benign": int((cal["class"] == "hard_benign").sum()),
                                  "val_rows": len(val), "val_malicious": int(val.label.sum()), "trees": booster.num_trees(), "current_iteration": booster.current_iteration(),
                                  "model_sha256": sha(path), "elapsed_s": round(time.time() - t0, 1)})
                for fe, g, sc in zip(F28, booster.feature_importance("gain"), booster.feature_importance("split")):
                    imp_rows.append({"cal_seed": seed, "fold": f, "model": name, "feature": fe, "gain": float(g), "split": int(sc)})
                score_rows.append(pd.DataFrame({"cal_seed": seed, "fold": f, "model": name, "stage": "calibration", "row_id": cal.row_id.to_numpy(), "score": s_cal}))
                score_rows.append(pd.DataFrame({"cal_seed": seed, "fold": f, "model": name, "stage": "validation", "row_id": val.row_id.to_numpy(), "score": s_val}))
                pr = average_precision_score(val.label, s_val)
                for t in TARGETS:
                    c = snap.calibrate(s_cal, cal.label.to_numpy(), np.zeros(len(cal), bool), "ML", t)
                    thr_rows.append({"cal_seed": seed, "fold": f, "model": name, "target_fpr": t, "threshold": c["threshold"], "boundary": c.get("boundary"),
                                     "cal_normal": c["calibration_normal"], "budget": c["budget"], "cal_fp": c["calibration_fp"], "cal_ties_at_boundary": c["ties"],
                                     "cal_achieved_fpr": c["calibration_fp"] / c["calibration_normal"]})
                    met_rows.append({"cal_seed": seed, "fold": f, "model": name, "target_fpr": t, "threshold": c["threshold"], "PR_AUC_fold": pr,
                                     **metrics(val, s_val, c["threshold"], generic)})
                print(f"seed {seed} fold {f} {name} trees={booster.num_trees()} {time.time() - t0:.0f}s", flush=True)
    pd.concat(cal_rows).to_csv(out / "calibration_assignment.csv", index=False, lineterminator="\n")
    pd.concat(m3_rows).to_csv(out / "m3_selected_new_pairs.csv", index=False, lineterminator="\n")
    pd.concat(m4_rows).to_csv(out / "m4_pair_weights.csv", index=False, lineterminator="\n")
    pd.DataFrame(train_log).to_csv(out / "training_log.csv", index=False, lineterminator="\n")
    pd.DataFrame(thr_rows).to_csv(out / "thresholds.csv", index=False, lineterminator="\n")
    pd.DataFrame(met_rows).to_csv(out / "metrics_fold.csv", index=False, lineterminator="\n")
    pd.concat(score_rows).to_csv(out / "scores.csv", index=False, lineterminator="\n")
    pd.DataFrame(imp_rows).to_csv(out / "feature_importance.csv", index=False, lineterminator="\n")
    env = {"python": platform.python_version(), "platform": platform.platform(), "lightgbm": lgb.__version__, "pandas": pd.__version__, "numpy": np.__version__, "sklearn": sklearn.__version__}
    (out / "config.json").write_text(json.dumps({"data_commit": "2c48bd83d23ceb16ba7f6c3989d7fb623dcdd554", "inputs_sha256": {k: v[0] for k, v in EXPECTED.items()},
        "snapshot_sha256": SNAPSHOT_SHA256, "script_sha256": sha(__file__), "features_no_interval28": F28, "lightgbm_params": LGB_PARAMS, "rounds": ROUNDS, "early_stopping": False,
        "outer": "PR #13 components(), greedy 5-fold (fixed, seed-free)", "calibration": "normal-only components, 25% of fit benign/hard_benign, rng seed = cal_seed + fold",
        "cal_seeds": list(seeds), "folds": list(folds), "targets": TARGETS, "threshold_rule": "PR #13 calibrate ML: budget=floor(n*t), threshold=nextafter(boundary,+inf), score>=threshold, ties at boundary negative",
        "m3": "D06 all + new malicious one per (package, old_version, P, v28) lowest new_version + add-back of missing changedJsSetSha1 (lowest version)",
        "m4": "malicious w=1/sqrt(n_P) within fit, normalised to fit malicious count; normal w=1",
        "payload_key": "largestChangedJsSha1 | 'nojs:'+addedInstallHooks+'|'+addedDependencies | 'nojs-empty:'+package",
        "environment": env, "smoke": a.smoke, "test_used": False}, indent=1) + "\n")
    print("done", time.time() - t0)


if __name__ == "__main__":
    main()
