"""Test-677 counterpart of build_x3d.py + verify_x3.py (both imported by path and reused unchanged; only the row file,
its pinned sha256 and the stored reference CSV differ). No network, no training.

Usage: python -I -B build_verify_x3_test.py --test <be87 test.csv> --jsonl <malicious.jsonl> <benign.jsonl> --out <new dir>
  -> <out>/d06_test_x3d.csv, d06_test_x3d_status.csv, manifest.json (build) and <out>/verify/ (verify_x3 against
     ../d06_test_eval/analysis/d06_test_full35.csv)
"""
from __future__ import annotations
import argparse, hashlib, importlib.util, json, sys
from pathlib import Path
import pandas as pd

HERE = Path(__file__).resolve().parent
TEST_SHA256 = "e8a70053ce639ebc79d7bc8d9402578d3ceaf24853ed31735b5f55c418b8bd73"
REF = HERE.parent / "d06_test_eval/analysis/d06_test_full35.csv"


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--test", type=Path, required=True)
    ap.add_argument("--jsonl", type=Path, nargs="+", required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    assert sha(a.test) == TEST_SHA256
    a.out.mkdir(parents=True, exist_ok=False)
    b = load("build_x3d")
    test = pd.read_csv(a.test, dtype=str, keep_default_na=False)
    R = pd.DataFrame([json.loads(l) for p in a.jsonl for l in p.read_text().splitlines()])
    assert R.row_id.is_unique and len(R) == len(test) == 677
    R = R.set_index("row_id").sort_index()
    assert (R[b.KEY].to_numpy() == test[b.KEY].to_numpy()).all() and (R.label.astype(str).to_numpy() == test.label.to_numpy()).all()
    out = test[b.KEY + ["label"]].copy()
    for col in b.X3 + b.D + b.DIAG:
        v = R[col] if col in R else pd.Series(index=R.index, dtype=object)
        out[col] = v.where(R.status == "ok").map(lambda x: "" if x is None or x != x else repr(float(x)) if isinstance(x, float) else str(x)).to_numpy()
    out.to_csv(a.out / "d06_test_x3d.csv", index=False, lineterminator="\n")
    R[["package", "old_version", "new_version", "class", "status", "error_stage", "error", "old_check", "new_check", "seconds"]].reset_index() \
        .to_csv(a.out / "d06_test_x3d_status.csv", index=False, lineterminator="\n")
    v = load("verify_x3")
    v.FULL35 = REF
    sys.argv = ["verify_x3.py", "--jsonl", *map(str, a.jsonl), "--out", str(a.out / "verify")]
    v.main()
    (a.out / "manifest.json").write_text(json.dumps({"test_sha256": TEST_SHA256, "reference": str(REF.relative_to(HERE.parent)), "reference_sha256": sha(REF),
        "jsonl": {p.name: sha(p) for p in a.jsonl}, "script_sha256": sha(__file__), "build_x3d_sha256": sha(HERE / "build_x3d.py"),
        "verify_x3_sha256": sha(HERE / "verify_x3.py"), "extract_x3_test_sha256": sha(HERE / "extract_x3_test.py"), "extract_x3_sha256": sha(HERE / "extract_x3.py"),
        "extractor": "depbee-analyzer feat/x3-hook-target-context e45cb4d", "options": "--reuse-x1-calls --file-cache (all rows)",
        "status": R.groupby(["class", "status"]).size().reset_index().values.tolist(),
        "outputs": {p.name: sha(p) for p in sorted(a.out.glob("*.csv"))}}, indent=1) + "\n")


if __name__ == "__main__":
    main()
