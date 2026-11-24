"""DIAGNOSTIC ONLY: X4 values for D06 Test-674 pairs (registry `time` maps), to see whether X4 could help the mastra
(dependency-addition) misses. No model is scored, nothing is selected or tuned from this. Registry JSON only.
Usage: python -I -B test_diag_x4.py --status ../d06_test_eval/analysis/d06_test_x1_status.csv --out <new dir>"""
from __future__ import annotations
import argparse, gzip, hashlib, json, sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import numpy as np, pandas as pd
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from x4 import x4_features  # noqa: E402
from extract_x4 import fetch  # noqa: E402


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--status", type=Path, required=True); ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args(); a.out.mkdir(parents=True, exist_ok=False)
    st = pd.read_csv(a.status, dtype=str, keep_default_na=False)
    st = st[st.excluded_in_test674 == "False"].reset_index(drop=True).rename(columns={"class": "class_"})
    with ThreadPoolExecutor(4) as pool:
        recs = list(pool.map(fetch, sorted(st.package.unique())))
    with gzip.open(a.out / "packuments.jsonl.gz", "wt", encoding="utf-8") as f:
        for r in recs:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    by = {r["name"]: r for r in recs}
    rows = []
    for r in st.itertuples(index=False):
        rec = by[r.package]
        f = x4_features(rec["time"], r.old_version, r.new_version) if rec["status"] == 200 else {"x4RelUpdateIntervalRatio": np.nan, "x4HistoryGapCount": np.nan, "status": f"registry_{rec['status']}"}
        rows.append({"package": r.package, "old_version": r.old_version, "new_version": r.new_version, "class": r.class_, "group": r.splitGroup if r.class_ == "malicious" else r.class_, **f})
    X = pd.DataFrame(rows)
    X.to_csv(a.out / "test674_x4.csv", index=False, lineterminator="\n")
    s = X.groupby("group").agg(n=("package", "size"), missing=("x4RelUpdateIntervalRatio", lambda v: v.isna().mean()),
                               p10=("x4RelUpdateIntervalRatio", lambda v: v.quantile(.1)), med=("x4RelUpdateIntervalRatio", "median"),
                               p90=("x4RelUpdateIntervalRatio", lambda v: v.quantile(.9)), gt10=("x4RelUpdateIntervalRatio", lambda v: (v > 10).mean()))
    s.round(3).to_csv(a.out / "test674_x4_by_group.csv", lineterminator="\n")
    (a.out / "manifest.json").write_text(json.dumps({"nature": "diagnostic only; no model scoring or selection", "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "status_input_sha256": hashlib.sha256(a.status.read_bytes()).hexdigest(), "pairs": len(X),
        "outputs": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(a.out.glob("*")) if p.is_file()}}, indent=1) + "\n")
    print(s.round(3).to_string()); print(X.status.value_counts().to_dict())


if __name__ == "__main__":
    main()
