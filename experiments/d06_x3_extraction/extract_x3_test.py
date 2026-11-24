"""D06 Test-677: X3 / D extraction with the Train extraction code reused unchanged (extract_x3.py imported by path:
extract_pair, source handling of extract_x1.py, --reuse-x1-calls and --file-cache speed-ups whose output identity was
verified in speedup_equivalence*/). Only the row list differs: be87ab4c derived/splits/test.csv (677 pairs, sha256 e8a70053…)
joined with derived/pairs/baselines.csv. row_id = Test row index (0..676). Package code is never executed.

usage: python -I -B extract_x3_test.py --analyzer-src <depbee-analyzer src @ e45cb4d> --test <test.csv> --baselines <baselines.csv>
         --archive-repo <sparse clone or worktree at be87ab4c> --cache-dir <dir> --out <results.jsonl> --part {malicious,benign} [--workers N]
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import shutil
import sys
import tempfile
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("extract_x3", HERE / "extract_x3.py")
ex = importlib.util.module_from_spec(_spec)
sys.modules["extract_x3"] = ex
_spec.loader.exec_module(ex)
TEST_SHA256 = "e8a70053ce639ebc79d7bc8d9402578d3ceaf24853ed31735b5f55c418b8bd73"
KEY = ex.KEY


def main() -> None:
    ap = argparse.ArgumentParser()
    for name in ("--analyzer-src", "--test", "--baselines", "--archive-repo", "--cache-dir", "--out", "--part"):
        ap.add_argument(name, required=True)
    ap.add_argument("--workers", type=int, default=4)
    args = ap.parse_args()
    if hashlib.sha256(Path(args.test).read_bytes()).hexdigest() != TEST_SHA256:
        raise SystemExit("test.csv is not the D06 Test-677 file")
    test = list(csv.DictReader(open(args.test, newline="", encoding="utf-8")))
    base = {tuple(r[k] for k in KEY): r for r in csv.DictReader(open(args.baselines, newline="", encoding="utf-8"))}
    rows = []
    for i, t in enumerate(test):
        b = base[tuple(t[k] for k in KEY)]
        rows.append({**{k: t[k] for k in KEY}, "row_id": i, "label": t["label"], "class": b["class"],
                     "old_source": b["old_source"], "new_source": b["new_source"]})
    if len(rows) != 677:
        raise SystemExit("expected 677 Test pairs")
    rows = [r for r in rows if (r["class"] == "malicious") == (args.part == "malicious")]
    out = Path(args.out)
    done = {json.loads(l)["row_id"] for l in out.read_text().splitlines()} if out.is_file() else set()
    todo = [r for r in rows if r["row_id"] not in done]
    print(f"{args.part}: selected {len(rows)}, done {len(done)}, todo {len(todo)}", flush=True)
    work_parent = Path(tempfile.mkdtemp(prefix=f"x3t_{args.part}_"))
    try:
        batches = [todo[i:i + ex.x1.BATCH] for i in range(0, len(todo), ex.x1.BATCH)] if args.part == "malicious" else [todo]
        with ProcessPoolExecutor(max_workers=args.workers) as pool, out.open("a") as sink:
            for i, batch in enumerate(batches):
                if args.part == "malicious":
                    ex.x1._sparse_batch(Path(args.archive_repo), batch)
                jobs = [(r, args.analyzer_src, args.archive_repo, args.cache_dir, str(work_parent), True, True) for r in batch]
                for res in pool.map(ex.extract_pair, jobs, chunksize=1):
                    sink.write(json.dumps(res, ensure_ascii=False) + "\n")
                    sink.flush()
                print(f"batch {i + 1}/{len(batches)} done", flush=True)
    finally:
        shutil.rmtree(work_parent, ignore_errors=True)


if __name__ == "__main__":
    main()
