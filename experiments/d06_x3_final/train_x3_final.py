"""Last D06 improvement models: full35+X3+D (50) and full28_noObfNew+X3+D (43), PR #13 conditions unchanged.

Train-outer protocol (helpers of ../d06_full35_compare/run_full35.py): trains full28_x3_d only; full35_x3_d outer scores are
reused from ../d06_x3_models/run_x3d and guarded here by retraining fold 0 of split1 (bit-identical after CSV round trip).
Test protocol (Train inner_split(seed) fit / calibration as ../d06_test_eval, seeds 20261109 / 20261110): trains full35_x3_d
and full28_x3_d, scores calibration + Test-677; guard: full35 retrained here == ../d06_test_eval/run/scores.csv.
X3/D: Train ../d06_x3_extraction/analysis/d06_x3d.csv, Test ../d06_x3_extraction/test_analysis/d06_test_x3d.csv (keys/labels checked).
LightGBM PR #13 params, 200 rounds, no early stopping, no weights, NaN kept. No package code execution.
Usage: python -I -B train_x3_final.py --ws-outer <ws> --ws-test <ws> --out <new dir>
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
X3D_TRAIN = EXP / "d06_x3_extraction/analysis/d06_x3d.csv"
X3D_TEST = EXP / "d06_x3_extraction/test_analysis/d06_test_x3d.csv"
KEY = ["package", "old_version", "new_version"]


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


def attach(frame, path, cols):
    raw = pd.read_csv(path, dtype=str, keep_default_na=False)
    assert len(raw) == len(frame) and (raw[KEY].to_numpy() == frame[KEY].astype(str).to_numpy()).all()
    assert (raw.label.astype(int).to_numpy() == frame.label.astype(int).to_numpy()).all()
    for c in cols:
        v = pd.to_numeric(raw[c].replace("", np.nan), errors="raise").astype(float)
        assert not np.isinf(v).any()
        frame[c] = v.to_numpy()
    return frame


def roundtrip(values, out):
    p = out / "_rt.csv"
    pd.DataFrame({"v": values}).to_csv(p, index=False)
    r = pd.read_csv(p).v.to_numpy()
    p.unlink()
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ws-outer", type=Path, required=True)
    ap.add_argument("--ws-test", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    out = a.out
    out.mkdir(parents=True, exist_ok=False)
    (out / "models").mkdir()
    tv = load(EXP / "d06_x3_models/train_variants.py", "train_variants")
    X3D = tv.X3 + tv.D
    rows, training, guards = [], [], {}
    # ---------------- Train-outer
    r = load(EXP / "d06_full35_compare/run_full35.py", "run_full35")
    snap = r.load_snapshot()
    spec = json.loads((a.ws_outer / r.SPEC_REL).read_text(encoding="utf-8"))
    data, feat29, _ = snap.load_data(a.ws_outer, spec)
    r.check_bundle_alignment(data)
    data = attach(r.attach_x1(data), X3D_TRAIN, X3D)
    obf_new = [f for f in feat29[7:] if f.endswith("New")]
    full35 = feat29 + r.X1_ALL
    V = {"full35_x3_d": full35 + X3D, "full28_x3_d": [f for f in full35 if f not in obf_new] + X3D}
    assert len(V["full35_x3_d"]) == 50 and len(V["full28_x3_d"]) == 43
    saved_x3d = pd.read_csv(EXP / "d06_x3_models/run_x3d/scores.csv")
    for split, seed in r.SPLITS.items():
        bs = pd.read_csv(r.BUNDLE / f"splits/{split}.csv")
        for fold in range(3):
            outer = data[data.outer_fold == fold]
            fit, cal = snap.inner_split(data[data.outer_fold != fold], seed + fold)
            ref = bs[(bs.model == "full29") & (bs.fold == fold)]
            for stage, part in [("fit", fit), ("calibration", cal), ("outer", outer)]:
                assert set(ref[ref.stage == stage].row_id) == set(part.row_id)
            todo = ["full28_x3_d"] + (["full35_x3_d"] if (split, fold) == ("split1", 0) else [])
            for name in todo:
                cols = V[name]
                mats = [snap.feature_matrix(p, cols, "M_full") for p in (fit, cal, outer)]
                m = lgb.train(spec["lightgbm"], lgb.Dataset(mats[0], label=fit.label.to_numpy(), categorical_feature=["updateType"], feature_name=cols),
                              num_boost_round=spec["rounds"])
                sc_cal, sc_out = m.predict(mats[1], num_threads=2), m.predict(mats[2], num_threads=2)
                if name == "full35_x3_d":  # guard only; reused scores stay those of run_x3d
                    s = saved_x3d[(saved_x3d.variant == name) & (saved_x3d.split == split) & (saved_x3d.fold == fold)]
                    exp_ = np.concatenate([s[s.stage == "calibration"].set_index("row_id").score.loc[cal.row_id].to_numpy(),
                                           s[s.stage == "outer"].set_index("row_id").score.loc[outer.row_id].to_numpy()])
                    guards["train_outer_full35_x3_d_split1_fold0_equals_run_x3d"] = bool((roundtrip(np.concatenate([sc_cal, sc_out]), out) == exp_).all())
                    continue
                path = out / "models" / f"outer_{name}_{split}_fold{fold}.txt"
                m.save_model(str(path))
                training.append({"protocol": "train_outer", "variant": name, "cell": f"{split}_fold{fold}", "features": len(cols), "model_sha256": sha(path)})
                for stage, part, sc in [("calibration", cal, sc_cal), ("outer", outer, sc_out)]:
                    rows.append(pd.DataFrame({"protocol": "train_outer", "variant": name, "split": split, "seed": seed, "fold": fold, "stage": stage,
                                              "row_id": part.row_id.to_numpy(), "test_row": -1, "score": sc}))
    # ---------------- Test protocol
    te = load(EXP / "d06_test_eval/run_test_eval.py", "run_test_eval")
    snap2 = te.load_snapshot()
    spec2 = json.loads((a.ws_test / te.SPEC_REL).read_text(encoding="utf-8"))
    d2, f29b, _ = snap2.load_data(a.ws_test, spec2)
    assert f29b == feat29
    tk, tx = te.encode_x1(te.TRAIN_FULL35)
    for c in te.X1:
        d2[c] = tx[c].to_numpy()
    d2 = attach(d2, X3D_TRAIN, X3D)
    tst = pd.read_csv(te.TEST_FULL35, float_precision="round_trip")
    sk, sx = te.encode_x1(te.TEST_FULL35)
    test = tst.drop(columns=te.X1).copy()
    for c in te.X1:
        test[c] = sx[c].to_numpy()
    test = attach(test, X3D_TEST, X3D)
    test["test_row"] = np.arange(len(test))
    saved_te = pd.read_csv(EXP / "d06_test_eval/run/scores.csv")
    sp = pd.read_csv(EXP / "d06_test_eval/run/splits.csv")
    for sname, seed in te.SEEDS.items():
        fit, cal = snap2.inner_split(d2, seed)
        for stage, part in [("fit", fit), ("calibration", cal)]:
            assert set(sp[(sp.seed == sname) & (sp.stage == stage)].row_id) == set(part.row_id)
        for name, cols in {"full35": full35, **V}.items():
            mats = [snap2.feature_matrix(p, cols, "M_full") for p in (fit, cal, test)]
            m = lgb.train(spec2["lightgbm"], lgb.Dataset(mats[0], label=fit.label.to_numpy(), categorical_feature=["updateType"], feature_name=cols),
                          num_boost_round=spec2["rounds"])
            sc_cal, sc_te = m.predict(mats[1], num_threads=2), m.predict(mats[2], num_threads=2)
            if name == "full35":
                s = saved_te[(saved_te.seed == sname) & (saved_te.model == "full35")]
                exp_ = np.concatenate([s[s.stage == "calibration"].set_index("row_id").score.loc[cal.row_id].to_numpy(),
                                       s[s.stage == "test"].set_index("test_row").score.loc[test.test_row].to_numpy()])
                guards[f"test_protocol_full35_{sname}_equals_d06_test_eval"] = bool((roundtrip(np.concatenate([sc_cal, sc_te]), out) == exp_).all())
                continue
            path = out / "models" / f"test_{name}_{sname}.txt"
            m.save_model(str(path))
            training.append({"protocol": "test", "variant": name, "cell": sname, "features": len(cols), "model_sha256": sha(path)})
            rows.append(pd.DataFrame({"protocol": "test", "variant": name, "split": sname, "seed": seed, "fold": -1, "stage": "calibration",
                                      "row_id": cal.row_id.to_numpy(), "test_row": -1, "score": sc_cal}))
            rows.append(pd.DataFrame({"protocol": "test", "variant": name, "split": sname, "seed": seed, "fold": -1, "stage": "test",
                                      "row_id": -1, "test_row": test.test_row.to_numpy(), "score": sc_te}))
    assert all(guards.values()), guards
    pd.concat(rows).to_csv(out / "scores.csv", index=False, lineterminator="\n")
    pd.DataFrame(training).to_csv(out / "training.csv", index=False, lineterminator="\n")
    (out / "manifest.json").write_text(json.dumps({"guards": guards, "variants": V, "script_sha256": sha(__file__), "lightgbm_params": spec["lightgbm"],
        "rounds": spec["rounds"], "inputs": {"x3d_train": sha(X3D_TRAIN), "x3d_test": sha(X3D_TEST)},
        "outputs": {p.name: sha(p) for p in sorted(out.glob("*.csv"))}}, indent=1) + "\n")
    print(json.dumps(guards, indent=1))


if __name__ == "__main__":
    main()
