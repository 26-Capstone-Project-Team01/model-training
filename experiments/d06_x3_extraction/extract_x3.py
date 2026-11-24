"""D06 Train: static extraction of X3 (x3_context) and D (dependency_change), plus re-extraction of the existing
package_json (except updateInterval/updateType inputs, see below), obfuscation and code_context features for verification.

Source handling is reused unchanged from ../d06_x1_extraction/extract_x1.py (imported by path, sha-checked):
registry tarballs verified with dist.integrity (sha512) or shasum before tarfile filter="data"; malicious archive
from the fixed data commit via sparse checkout. Package code, lifecycle scripts and npm are never executed.
Per-pair failures are kept with status=error and a reason (never filled with 0, never dropped).

publish times are not loaded (fixed 1970-01-01 as in X1), so updateInterval from this run is meaningless and is not
compared; updateType depends only on version strings and is compared.

usage: python -I -B extract_x3.py --analyzer-src <depbee-analyzer src @ feat/x3-hook-target-context> --train <train.csv>
         --baselines <baselines.csv> --archive-repo <sparse clone> --cache-dir <dir> --out <results.jsonl>
         --part {malicious,benign} [--workers N] [--row-ids <file with row ids, pilot>]
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
import time
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
X1_SCRIPT = HERE.parent / "d06_x1_extraction/extract_x1.py"
KEY = ("package", "old_version", "new_version")
EXTRACTORS = ("package_json", "obfuscation", "code_context", "x3_context", "dependency_change")

_spec = importlib.util.spec_from_file_location("extract_x1", X1_SCRIPT)
x1 = importlib.util.module_from_spec(_spec)
sys.modules["extract_x1"] = x1
_spec.loader.exec_module(x1)
_A = None


def _analyzer(src: str, reuse_x1_calls: bool = False, file_cache: bool = False):
    global _A
    if _A is None:
        sys.path.insert(0, src)
        from depbee_analyzer.core import loader
        from depbee_analyzer.core.models import PackageVersionSnapshot
        from depbee_analyzer.core.pipeline import resolve_extractors
        from depbee_analyzer.core.sources import _find_package_json
        _A = dict(loader=loader, Snap=PackageVersionSnapshot, find=_find_package_json, extractors=resolve_extractors(EXTRACTORS))
        if reuse_x1_calls:
            # Speed-up only: within one pair, x3_context's numerator calls the same added_call_features(old, new, versions)
            # that code_context already computed on the same snapshots. Cache the result per pair (cleared in extract_pair).
            from depbee_analyzer.extractors import code_context, x3_context
            original = code_context.added_call_features
            cache = {}

            def cached(old_files, new_files, versions=()):
                key = (str(old_files.root), str(new_files.root), tuple(versions), len(old_files.files), len(new_files.files))
                if key not in cache:
                    cache[key] = original(old_files, new_files, versions)
                return dict(cache[key])

            code_context.added_call_features = cached
            x3_context.added_call_features = cached
            _A["call_cache"] = cache
        if file_cache:
            # Speed-up only: memoise pure per-file functions by the file text's SHA-256 inside a worker process.
            # Campaign pairs often share the same multi-MB payload file, which is otherwise re-analysed in every pair.
            import hashlib as _h
            from depbee_analyzer.extractors import code_context, obfuscation, x3_context

            def memo(fn, limit=4000):
                store = {}

                def wrapped(text):
                    k = _h.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
                    if k not in store:
                        if len(store) >= limit:
                            store.clear()
                        store[k] = fn(text)
                    return store[k]
                return wrapped

            cs = memo(code_context.call_signatures)
            code_context.call_signatures = cs
            x3_context.call_signatures = cs
            fm = memo(obfuscation.file_metrics)
            obfuscation.file_metrics = fm
            x3_context.file_metrics = fm
            x3_context.js_tokens = memo(x3_context.js_tokens)
    return _A


def extract_pair(args: tuple) -> dict:
    row, src, archive_repo, cache_dir, work_parent, reuse, fcache = args
    a = _analyzer(src, reuse, fcache)
    if "call_cache" in a:
        a["call_cache"].clear()
    started = time.time()
    result = {k: row[k] for k in KEY} | {"row_id": row["row_id"], "label": int(row["label"]), "class": row["class"],
                                          "old_source": row["old_source"].split(":")[0], "new_source": row["new_source"].split(":")[0]}
    work = Path(tempfile.mkdtemp(prefix="x3_pair_", dir=work_parent))
    try:
        roots, checks = {}, {}
        for side, version, spec in (("old", row["old_version"], row["old_source"]), ("new", row["new_version"], row["new_source"])):
            if spec.startswith("archive:"):
                roots[side], checks[side] = x1._archive_root(a, Path(archive_repo), spec), "archive@" + x1.DATA_COMMIT[:8]
            elif spec == "registry":
                roots[side], checks[side] = x1._registry_root(a, row["package"], version, Path(cache_dir), work)
            else:
                raise x1.StageError("manifest", f"unknown source {spec!r}")
        snaps = {}
        for side, version in (("old", row["old_version"]), ("new", row["new_version"])):
            try:
                pj = json.loads((roots[side] / "package.json").read_text(encoding="utf-8"))
            except Exception as exc:
                raise x1.StageError("package_json", f"{side}: {type(exc).__name__}: {exc}")
            if not isinstance(pj, dict):
                raise x1.StageError("package_json", f"{side}: not an object")
            snaps[side] = a["Snap"](row["package"], version, datetime(1970, 1, 1, tzinfo=timezone.utc), pj, roots[side])
        feats = {}
        for ex in a["extractors"]:
            try:
                feats |= ex.extract(snaps["old"], snaps["new"])
            except Exception as exc:
                raise x1.StageError(f"extractor:{ex.name}", f"{type(exc).__name__}: {exc}")
        result |= {"status": "ok", "error_stage": "", "error": "", "old_check": checks["old"], "new_check": checks["new"]} | feats
    except x1.StageError as exc:
        result |= {"status": "error", "error_stage": exc.stage, "error": str(exc)[:500]}
    finally:
        shutil.rmtree(work, ignore_errors=True)
    result["seconds"] = round(time.time() - started, 2)
    return result


def main() -> None:
    ap = argparse.ArgumentParser()
    for name in ("--analyzer-src", "--train", "--baselines", "--archive-repo", "--cache-dir", "--out", "--part"):
        ap.add_argument(name, required=True)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--row-ids", type=Path)
    ap.add_argument("--reuse-x1-calls", action="store_true", help="compute added_call_features once per pair (identical output, faster)")
    ap.add_argument("--file-cache", action="store_true", help="memoise pure per-file functions by text hash within a worker (identical output, faster)")
    args = ap.parse_args()
    train = list(csv.DictReader(open(args.train, newline="", encoding="utf-8")))
    base = {tuple(r[k] for k in KEY): r for r in csv.DictReader(open(args.baselines, newline="", encoding="utf-8"))}
    rows = []
    for i, t in enumerate(train):
        b = base[tuple(t[k] for k in KEY)]
        rows.append({**{k: t[k] for k in KEY}, "row_id": i, "label": t["label"], "class": b["class"],
                     "old_source": b["old_source"], "new_source": b["new_source"]})
    if len(rows) != 2767:
        raise SystemExit("expected 2,767 D06 Train pairs")
    rows = [r for r in rows if (r["class"] == "malicious") == (args.part == "malicious")]
    if args.row_ids:
        keep = {int(x) for x in args.row_ids.read_text().split()}
        rows = [r for r in rows if r["row_id"] in keep]
    out = Path(args.out)
    done = {json.loads(l)["row_id"] for l in out.read_text().splitlines()} if out.is_file() else set()
    todo = [r for r in rows if r["row_id"] not in done]
    print(f"{args.part}: selected {len(rows)}, done {len(done)}, todo {len(todo)}", flush=True)
    Path(args.cache_dir).mkdir(parents=True, exist_ok=True)
    work_parent = Path(tempfile.mkdtemp(prefix=f"x3_{args.part}_"))
    try:
        batches = [todo[i:i + x1.BATCH] for i in range(0, len(todo), x1.BATCH)] if args.part == "malicious" else [todo]
        with ProcessPoolExecutor(max_workers=args.workers) as pool, out.open("a") as sink:
            for i, batch in enumerate(batches):
                if args.part == "malicious":
                    x1._sparse_batch(Path(args.archive_repo), batch)
                jobs = [(r, args.analyzer_src, args.archive_repo, args.cache_dir, str(work_parent), args.reuse_x1_calls, args.file_cache) for r in batch]
                for n, res in enumerate(pool.map(extract_pair, jobs, chunksize=1), 1):
                    sink.write(json.dumps(res, ensure_ascii=False) + "\n")
                    sink.flush()
                    if n % 100 == 0:
                        print(f"  batch {i}: {n}/{len(batch)}", flush=True)
                print(f"batch {i + 1}/{len(batches)} done", flush=True)
    finally:
        shutil.rmtree(work_parent, ignore_errors=True)


if __name__ == "__main__":
    main()
