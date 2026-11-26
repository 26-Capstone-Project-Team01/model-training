"""D08 X1/X3/D extraction for pairs not covered by the D06 extraction, plus a D06 re-extraction sample (parity check).

Reuses ../vendor/d06_x3_extraction/extract_x3.py and ../vendor/d06_x1_extraction/extract_x1.py VERBATIM (copied from model-training exp/d06-x3-test-final df491c1:
experiments/d06_x3_extraction/extract_x3.py, experiments/d06_x1_extraction/extract_x1.py). Only two things differ:
  * archive data commit = D08 2c48bd83 (x1.DATA_COMMIT is set at runtime; D06 raw dirs are tree-identical in both commits),
  * row list = D08 pairs missing from D06 Train/Test (clipper 6 excluded) + a fixed-seed D06 sample for parity.
Extractors: depbee-analyzer e45cb4d (feat/x3-hook-target-context; code_context/obfuscation/package_json identical to d56738c used for D06 X1).
Package code, lifecycle scripts and npm are never executed (static analysis of tarball / archive files only).

usage: python -I -B extract_d08_x3d.py --analyzer-src <src> --inputs <dir with d08_*/d06_* csv> --clipper <csv>
          --archive-repo <sparse clone> --cache-dir <dir> --out <dir> --part {new,parity} [--workers 4]
"""
from __future__ import annotations
import argparse, csv, hashlib, importlib.util, json, random, shutil, sys, tempfile, time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("extract_x3", HERE.parent / "vendor/d06_x3_extraction/extract_x3.py"); X3 = importlib.util.module_from_spec(spec)
sys.modules["extract_x3"] = X3; spec.loader.exec_module(X3)
x1 = X3.x1
D08_COMMIT = "2c48bd83d23ceb16ba7f6c3989d7fb623dcdd554"
KEY = ("package", "old_version", "new_version")
SEED = 20261126


def rd(p): return list(csv.DictReader(open(p, newline="", encoding="utf-8")))


def rows_for(inputs: Path, clipper: Path, part: str):
    base = {tuple(r[k] for k in KEY): r for r in rd(inputs / "d08_baselines.csv")}
    sa = {tuple(r[k] for k in KEY): r for r in rd(inputs / "d08_split_assignment.csv")}
    d6 = {tuple(r[k] for k in KEY) for f in ("d06_train.csv", "d06_test.csv") for r in rd(inputs / f)}
    clip = {tuple(r[k] for k in KEY) for r in rd(clipper)}
    assert len(clip) == 6
    d8 = [(f, r) for f in ("d08_train.csv", "d08_test.csv") for r in rd(inputs / f)]
    assert len(d8) == 5344 + 684
    out = []
    for i, (f, r) in enumerate(d8):
        k = tuple(r[c] for c in KEY); b = base[k]
        out.append({**dict(zip(KEY, k)), "row_id": i, "label": r["label"], "class": b["class"], "split": sa[k]["split"], "splitGroup": sa[k]["splitGroup"],
                    "old_source": b["old_source"], "new_source": b["new_source"], "in_d06": k in d6, "clipper": k in clip})
    if part == "new":
        sel = [r for r in out if not r["in_d06"] and not r["clipper"]]
        assert len(sel) == 2581 and all(r["class"] == "malicious" for r in sel)
    else:  # parity: D06 rows, stratified, fixed seed
        rng = random.Random(SEED); sel = []
        d6r = [r for r in out if r["in_d06"]]
        by = {}
        for r in d6r:
            by.setdefault((r["split"], r["class"], r["splitGroup"] if r["class"] == "malicious" else ""), []).append(r)
        for key in sorted(by):
            g = by[key]; split, cls, grp = key
            n = (3 if split == "train" else 2) if cls == "malicious" else (20 if split == "train" else 5)
            sel += rng.sample(g, min(n, len(g)))
    return sel


def main():
    ap = argparse.ArgumentParser()
    for n in ("--analyzer-src", "--inputs", "--clipper", "--archive-repo", "--cache-dir", "--out", "--part"): ap.add_argument(n, required=True)
    ap.add_argument("--workers", type=int, default=4)
    a = ap.parse_args()
    x1.DATA_COMMIT = D08_COMMIT  # archive checkout + check label use this module global
    rows = rows_for(Path(a.inputs), Path(a.clipper), a.part)
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    (out / f"{a.part}_rows.csv").write_text("row_id,package,old_version,new_version,split,class,splitGroup,old_source,new_source\n" +
        "".join(f'{r["row_id"]},"{r["package"]}",{r["old_version"]},{r["new_version"]},{r["split"]},{r["class"]},{r["splitGroup"]},{r["old_source"]},{r["new_source"]}\n' for r in rows))
    sink_p = out / f"{a.part}.jsonl"
    done = {json.loads(l)["row_id"] for l in sink_p.read_text().splitlines()} if sink_p.is_file() else set()
    todo = [r for r in rows if r["row_id"] not in done]
    print(f"{a.part}: selected {len(rows)}, done {len(done)}, todo {len(todo)}", flush=True)
    Path(a.cache_dir).mkdir(parents=True, exist_ok=True)
    work_parent = Path(tempfile.mkdtemp(prefix=f"x3d08_{a.part}_"))
    t0 = time.time()
    try:
        arch = [r for r in todo if any(r[s].startswith("archive:") for s in ("old_source", "new_source"))]
        reg = [r for r in todo if r not in arch]
        batches = [arch[i:i + x1.BATCH] for i in range(0, len(arch), x1.BATCH)] + ([reg] if reg else [])
        with ProcessPoolExecutor(max_workers=a.workers) as pool, sink_p.open("a") as sink:
            for i, batch in enumerate(batches):
                if any(r[s].startswith("archive:") for r in batch for s in ("old_source", "new_source")):
                    x1._sparse_batch(Path(a.archive_repo), batch)
                jobs = [(r, a.analyzer_src, a.archive_repo, a.cache_dir, str(work_parent), True, True) for r in batch]
                for res in pool.map(X3.extract_pair, jobs, chunksize=1):
                    sink.write(json.dumps(res, ensure_ascii=False) + "\n"); sink.flush()
                print(f"batch {i + 1}/{len(batches)} done ({len(batch)} rows) {time.time() - t0:.0f}s", flush=True)
    finally:
        shutil.rmtree(work_parent, ignore_errors=True)
    print("finished", round(time.time() - t0, 1))


if __name__ == "__main__":
    main()
