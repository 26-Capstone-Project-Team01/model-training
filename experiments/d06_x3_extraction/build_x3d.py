"""Assemble D06 Train X3/D columns in train.csv row order from extract_x3.py JSONL (no network, no training).

Output analysis/d06_x3d.csv: package, old_version, new_version, label, X3 13, D 2, x3diag 4 (diagnostic, not model input).
Failed pairs keep empty cells (NaN) and are listed in analysis/d06_x3d_status.csv with the reason (never filled with 0).
Usage: python -I -B build_x3d.py --train <train.csv> --jsonl <malicious.jsonl> <benign.jsonl> --out <new dir>
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import pandas as pd

X3 = ["installHookTargetCount", "installHookTargetMaxBytes", "obfHookHexIdentRatio", "obfHookHexNumberRatio",
      "obfHookBracketAccessRatio", "obfHookEscapeDensity", "obfHookShortIdentRatio", "obfHookMeanIdentLength",
      "obfHookWhitespaceRatio", "installHookTargetProcExecCallCount", "installHookTargetNetworkCallCount",
      "addedNetworkCallPer1kAddedTokens", "addedProcExecCallPer1kAddedTokens"]
D = ["dependencyRangeChangedCount", "dependencyChangedRatio"]
DIAG = ["x3diagChangedCodeAddedTokenCount", "x3diagChangedFileTokenCount", "x3diagHookTargetUnresolvedCount", "x3diagHookTargetNonJsCount"]
KEY = ["package", "old_version", "new_version"]


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", type=Path, required=True)
    ap.add_argument("--jsonl", type=Path, nargs="+", required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=False)
    train = pd.read_csv(a.train, dtype=str, keep_default_na=False)
    assert sha(a.train) == "22fbc8752fff5fff90e40b911f6bf7d187769b4566db957d65a37a16be7d2c23"
    rows = [json.loads(l) for p in a.jsonl for l in p.read_text().splitlines()]
    R = pd.DataFrame(rows)
    assert R.row_id.is_unique and len(R) == len(train) == 2767, "every Train pair must have exactly one result"
    R = R.set_index("row_id").sort_index()
    assert (R[KEY].to_numpy() == train[KEY].to_numpy()).all() and (R.label.astype(str).to_numpy() == train.label.to_numpy()).all()
    out = train[KEY + ["label"]].copy()
    for col in X3 + D + DIAG:
        v = R[col] if col in R else pd.Series(index=R.index, dtype=object)
        out[col] = v.where(R.status == "ok").map(lambda x: "" if x is None or x != x else repr(float(x)) if isinstance(x, float) else str(x)).to_numpy()
    out.to_csv(a.out / "d06_x3d.csv", index=False, lineterminator="\n")
    st = R[["package", "old_version", "new_version", "class", "status", "error_stage", "error", "old_check", "new_check", "seconds"]].reset_index()
    st.to_csv(a.out / "d06_x3d_status.csv", index=False, lineterminator="\n")
    man = {"train_sha256": sha(a.train), "jsonl": {p.name: sha(p) for p in a.jsonl}, "script_sha256": sha(__file__),
           "status": R.groupby(["class", "status"]).size().reset_index().values.tolist(), "model_columns": X3 + D, "diagnostic_columns": DIAG,
           "outputs": {p.name: sha(p) for p in sorted(a.out.glob("*.csv"))}}
    (a.out / "manifest.json").write_text(json.dumps(man, indent=1) + "\n")
    print(man["status"])


if __name__ == "__main__":
    main()
