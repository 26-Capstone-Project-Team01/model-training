"""Train only the new ablations (full28_noObfNew, full31_noHook) under both pre-registered protocols (PREREGISTRATION.md 46ade76).

Train-outer protocol: ../d06_full35_compare/run_full35.py helpers (PR #13 snapshot, alignment checks, attach_x1, inner_split(seed+fold)).
Test protocol: Train inner_split(seed) fit/calibration exactly as ../d06_test_eval (fit/cal rows checked against its splits.csv),
Test-677 frame built as in ../d06_test674_dev/run_dev_eval.py. LightGBM PR #13 params, 200 rounds. No package code execution.
Usage: python -I -B train_ablation.py --ws-outer <ws> --ws-test <ws> --out <new dir>
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
EXP = HERE.parent


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


def variants(feat29, x1):
    obf_new = [c for c in feat29[7:] if c.endswith("New")]
    hook = x1[:4]
    full35 = feat29 + x1
    v = {"full28_noObfNew": [f for f in full35 if f not in obf_new], "full31_noHook": [f for f in full35 if f not in hook]}
    assert len(obf_new) == 7 and len(v["full28_noObfNew"]) == 28 and len(v["full31_noHook"]) == 31
    return v


def train(spec, cols, fit):
    ds = lgb.Dataset(fit[0], label=fit[1], categorical_feature=["updateType"], feature_name=cols)
    return lgb.train(spec["lightgbm"], ds, num_boost_round=spec["rounds"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ws-outer", type=Path, required=True)
    ap.add_argument("--ws-test", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    out = a.out
    out.mkdir(parents=True, exist_ok=False)
    (out / "models").mkdir()
    rows, training = [], []
    # ---- Train-outer protocol
    r = load(EXP / "d06_full35_compare/run_full35.py", "run_full35")
    snap = r.load_snapshot()
    spec = json.loads((a.ws_outer / r.SPEC_REL).read_text(encoding="utf-8"))
    data, feat29, _ = snap.load_data(a.ws_outer, spec)
    r.check_bundle_alignment(data)
    data = r.attach_x1(data)
    V = variants(feat29, r.X1_ALL)
    for split, seed in r.SPLITS.items():
        bs = pd.read_csv(r.BUNDLE / f"splits/{split}.csv")
        for fold in range(3):
            outer = data[data.outer_fold == fold]
            fit, cal = snap.inner_split(data[data.outer_fold != fold], seed + fold)
            ref = bs[(bs.model == "full29") & (bs.fold == fold)]
            for stage, part in [("fit", fit), ("calibration", cal), ("outer", outer)]:
                r.require(set(ref[ref.stage == stage].row_id) == set(part.row_id), "outer split differs from PR #13")
            for name, cols in V.items():
                m = train(spec, cols, (snap.feature_matrix(fit, cols, "M_full"), fit.label.to_numpy()))
                p = out / "models" / f"outer_{name}_{split}_fold{fold}.txt"
                m.save_model(str(p))
                training.append({"protocol": "train_outer", "variant": name, "cell": f"{split}_fold{fold}", "model_sha256": sha(p), "features": " ".join(cols)})
                for stage, part in [("calibration", cal), ("outer", outer)]:
                    rows.append(pd.DataFrame({"protocol": "train_outer", "variant": name, "split": split, "seed": seed, "fold": fold, "stage": stage,
                                              "row_id": part.row_id.to_numpy(), "test_row": -1, "score": m.predict(snap.feature_matrix(part, cols, "M_full"), num_threads=2)}))
    # ---- Test protocol
    te = load(EXP / "d06_test_eval/run_test_eval.py", "run_test_eval")
    snap2 = te.load_snapshot()
    spec2 = json.loads((a.ws_test / te.SPEC_REL).read_text(encoding="utf-8"))
    data2, feat29b, _ = snap2.load_data(a.ws_test, spec2)
    tk, tx = te.encode_x1(te.TRAIN_FULL35)
    te.require((tk[te.KEY].to_numpy() == data2[te.KEY].astype(str).to_numpy()).all(), "train X1 keys")
    for c in te.X1:
        data2[c] = tx[c].to_numpy()
    tst = pd.read_csv(te.TEST_FULL35, float_precision="round_trip")
    sk, sx = te.encode_x1(te.TEST_FULL35)
    test = tst.drop(columns=te.X1).copy()
    for c in te.X1:
        test[c] = sx[c].to_numpy()
    test["test_row"] = np.arange(len(test))
    V2 = variants(feat29b, te.X1)
    saved_splits = pd.read_csv(EXP / "d06_test_eval/run/splits.csv")
    for sname, seed in te.SEEDS.items():
        fit, cal = snap2.inner_split(data2, seed)
        for stage, part in [("fit", fit), ("calibration", cal)]:
            ref = saved_splits[(saved_splits.seed == sname) & (saved_splits.stage == stage)]
            te.require(set(ref.row_id) == set(part.row_id), "test-protocol split differs")
        for name, cols in V2.items():
            m = train(spec2, cols, (snap2.feature_matrix(fit, cols, "M_full"), fit.label.to_numpy()))
            p = out / "models" / f"test_{name}_{sname}.txt"
            m.save_model(str(p))
            training.append({"protocol": "test", "variant": name, "cell": sname, "model_sha256": sha(p), "features": " ".join(cols)})
            rows.append(pd.DataFrame({"protocol": "test", "variant": name, "split": sname, "seed": seed, "fold": -1, "stage": "calibration",
                                      "row_id": cal.row_id.to_numpy(), "test_row": -1, "score": m.predict(snap2.feature_matrix(cal, cols, "M_full"), num_threads=2)}))
            rows.append(pd.DataFrame({"protocol": "test", "variant": name, "split": sname, "seed": seed, "fold": -1, "stage": "test",
                                      "row_id": -1, "test_row": test.test_row.to_numpy(), "score": m.predict(snap2.feature_matrix(test, cols, "M_full"), num_threads=2)}))
    pd.concat(rows).to_csv(out / "scores.csv", index=False, lineterminator="\n")
    pd.DataFrame(training).to_csv(out / "training.csv", index=False, lineterminator="\n")
    (out / "manifest.json").write_text(json.dumps({"preregistration_commit": "46ade76", "script_sha256": sha(__file__), "lightgbm_params": spec["lightgbm"],
        "rounds": spec["rounds"], "variants": V, "outputs": {p.name: sha(p) for p in sorted(out.glob("*.csv"))}}, indent=1) + "\n")
    print("trained", len(training))


if __name__ == "__main__":
    main()
