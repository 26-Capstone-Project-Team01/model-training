"""Compute X4 for all D06 Train pairs (2,767) from registry packument `time` maps. Reads registry JSON only; no tarball,
no package code execution, no training, no Test.

Every package is fetched once; the `time` map, HTTP status and fetch time are stored (gzip JSONL) so the features can be
recomputed offline (`--from-log`). Registry state changes over time, so a new fetch can give different values.
Usage: python -I -B extract_x4.py --train <be87 train.csv> --out <new dir> [--threads 4]
       python -I -B extract_x4.py --train <be87 train.csv> --from-log <dir>/packuments.jsonl.gz --out <new dir>
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import pandas as pd

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from x4 import FEATURES, x4_features  # noqa: E402

TRAIN_SHA256 = "22fbc8752fff5fff90e40b911f6bf7d187769b4566db957d65a37a16be7d2c23"
KEY = ["package", "old_version", "new_version"]


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def fetch(name):
    import requests
    t0 = datetime.now(timezone.utc).isoformat()
    for attempt in range(3):
        try:
            r = requests.get("https://registry.npmjs.org/" + quote(name, safe="@"), timeout=120)
            if r.status_code == 200:
                return {"name": name, "fetched_at": t0, "status": 200, "time": r.json().get("time")}
            if r.status_code in (404, 410):
                return {"name": name, "fetched_at": t0, "status": r.status_code, "time": None}
            status = r.status_code
        except Exception as exc:
            status = f"error:{type(exc).__name__}"
        time.sleep(2 ** attempt)
    return {"name": name, "fetched_at": t0, "status": status, "time": None}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--from-log", type=Path)
    ap.add_argument("--threads", type=int, default=4)
    a = ap.parse_args()
    assert sha(a.train) == TRAIN_SHA256
    a.out.mkdir(parents=True, exist_ok=False)
    train = pd.read_csv(a.train, dtype=str, keep_default_na=False)
    names = sorted(train.package.unique())
    if a.from_log:
        recs = [json.loads(l) for l in gzip.open(a.from_log, "rt", encoding="utf-8")]
    else:
        with ThreadPoolExecutor(a.threads) as pool:
            recs = list(pool.map(fetch, names))
        with gzip.open(a.out / "packuments.jsonl.gz", "wt", encoding="utf-8") as f:
            for r in recs:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    by = {r["name"]: r for r in recs}
    assert set(by) == set(names)
    rows = []
    for i, r in enumerate(train.itertuples(index=False)):
        rec = by[r.package]
        if rec["status"] != 200:
            f = {"x4RelUpdateIntervalRatio": float("nan"), "x4HistoryGapCount": float("nan"), "status": f"registry_{rec['status']}"}
        else:
            f = x4_features(rec["time"], r.old_version, r.new_version)
        rows.append({"row_id": i, "package": r.package, "old_version": r.old_version, "new_version": r.new_version, "label": r.label, **f})
    X = pd.DataFrame(rows)
    X[["package", "old_version", "new_version", "label"] + list(FEATURES)].to_csv(a.out / "d06_x4.csv", index=False, lineterminator="\n")
    X.drop(columns=list(FEATURES)).to_csv(a.out / "d06_x4_status.csv", index=False, lineterminator="\n")
    man = {"definition": "x4.py", "x4_sha256": sha(HERE / "x4.py"), "script_sha256": sha(__file__), "train_sha256": TRAIN_SHA256,
           "packages": len(names), "registry_status": pd.Series([r["status"] for r in recs]).astype(str).value_counts().to_dict(),
           "pair_status": X.status.value_counts().to_dict(), "from_log": str(a.from_log) if a.from_log else None,
           "outputs": {p.name: sha(p) for p in sorted(a.out.glob("*")) if p.is_file()}}
    (a.out / "manifest.json").write_text(json.dumps(man, indent=1) + "\n")
    print(json.dumps({k: man[k] for k in ("registry_status", "pair_status")}, indent=1))


if __name__ == "__main__":
    main()
