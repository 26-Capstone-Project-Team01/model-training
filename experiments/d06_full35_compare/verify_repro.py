"""Compare full29_repro (run_full35.py --stage repro) with PR #13 saved full29 models and scores.

Model text is compared after removing CR (PR #13 files were written on Windows with mixed CRLF).
Writes verification JSON to --out. Exit code 1 on any content/score mismatch above 1e-12.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
BUNDLE = HERE.parent / "d06_feature_comparison_18"


def h(b):
    return hashlib.sha256(b).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    mi = pd.read_csv(BUNDLE / "model_index.csv")
    tr = pd.read_csv(args.run / "training.csv")
    models, ok = [], True
    for r in tr.itertuples():
        ref = mi[(mi.feature_set == "full29") & (mi.split == r.split) & (mi.outer_fold == r.fold)].iloc[0]
        a = (BUNDLE / ref.bundle_model_path).read_bytes()
        b = (args.run / "models" / f"full29_repro_{r.split}_fold{r.fold}.txt").read_bytes()
        same = a.replace(b"\r", b"") == b.replace(b"\r", b"")
        ok &= same and int(ref.actual_rounds) == int(r.trained_rounds)
        models.append({"model": f"full29_{r.split}_fold{r.fold}", "pr13_model_sha256": ref.model_sha256,
                       "repro_model_sha256": r.model_sha256, "raw_bytes_equal": a == b,
                       "content_equal_after_removing_CR": same,
                       "pr13_actual_rounds": int(ref.actual_rounds), "repro_trained_rounds": int(r.trained_rounds)})
    s13 = pd.read_csv(BUNDLE / "scores/saved_scores.csv")
    s13 = s13[s13.model == "full29"][["seed", "fold", "stage", "row_id", "score"]]
    rep = pd.read_csv(args.run / "scores.csv")[["seed", "fold", "stage", "row_id", "score"]]
    m = s13.merge(rep, on=["seed", "fold", "stage", "row_id"], suffixes=("_pr13", "_repro"), validate="one_to_one")
    d = np.abs(m.score_pr13 - m.score_repro)
    ok &= len(m) == len(s13) == len(rep) and float(d.max()) <= 1e-12
    res = {"purpose": "full29 unweighted retrain with run_full35.py (PR #13 snapshot, pinned libraries) vs PR #13 saved full29",
           "models": models, "all_model_content_equal": all(x["content_equal_after_removing_CR"] for x in models),
           "scores": {"pr13_rows": len(s13), "repro_rows": len(rep), "matched_rows": len(m), "max_abs_diff": float(d.max()),
                      "exact_equal_fraction": float((d == 0).mean())},
           "run_manifest": json.loads((args.run / "manifest.json").read_text(encoding="utf-8")),
           "passed": bool(ok)}
    args.out.write_text(json.dumps(res, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({k: res[k] for k in ["all_model_content_equal", "scores", "passed"]}, indent=1))
    print([(x["model"], x["pr13_actual_rounds"], x["repro_trained_rounds"], x["raw_bytes_equal"]) for x in models])
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
