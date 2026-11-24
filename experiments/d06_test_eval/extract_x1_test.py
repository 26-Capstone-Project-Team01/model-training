"""D06 Test 677쌍에 X1(code_context) 6개를 정적으로 추출한다.

../d06_x1_extraction/extract_x1.py(Train용)의 복사본이다. 바꾼 것은 입력 목록과 행 수 검사(2,767 → 677)와 인자 이름(--train → --pairs)뿐이며,
쌍 단위 추출 함수(extract_pair 등)·검증·sparse checkout 절차는 그대로다.

- 패키지 코드·lifecycle script를 실행하지 않는다. npm install을 하지 않는다.
- registry tarball: dist.integrity(sha512) 또는 dist.shasum(sha1)로 검증한 뒤 tarfile filter="data"로 임시 해제.
  검증된 tarball은 --cache-dir에 보관해 재실행 때 재사용한다.
- 악성 archive: 데이터 저장소 고정 커밋(be87ab4c)의 별도 sparse 사본에서 묶음별로 malicious_raw/normal_raw만 체크아웃한다.
- 쌍 단위 실패는 제외하지 않고 status=error와 사유를 남긴다. X1 내부 결측(None)은 빈 칸으로 남긴다.
- 결과는 JSONL에 한 줄씩 추가하며, 이미 끝난 키는 건너뛴다(재시작 가능).

usage: python -I -B extract_x1_test.py --analyzer-src <depbee-analyzer/src> --pairs <test.csv> --baselines <baselines.csv>
         --archive-repo <sparse clone> --cache-dir <dir> --out <results.jsonl> --part {malicious,benign} [--workers N]
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

KEY = ("package", "old_version", "new_version")
DATA_COMMIT = "be87ab4cff66fff1980c4a71be8032b6b47225ba"
BATCH = 60
_ANALYZER = None


def _load_analyzer(src: str):
    global _ANALYZER
    if _ANALYZER is None:
        sys.path.insert(0, src)
        import requests  # noqa: F401
        from depbee_analyzer.core import loader
        from depbee_analyzer.core.models import PackageVersionSnapshot
        from depbee_analyzer.core.sources import _find_package_json
        from depbee_analyzer.extractors.code_context import FEATURE_NAMES, CodeContextExtractor
        _ANALYZER = dict(loader=loader, Snap=PackageVersionSnapshot, find=_find_package_json,
                         names=FEATURE_NAMES, Extractor=CodeContextExtractor)
    return _ANALYZER


class StageError(Exception):
    def __init__(self, stage: str, message: str):
        super().__init__(f"{stage}: {message}")
        self.stage = stage


_PACKUMENTS: dict[str, dict] = {}


def _verified_tarball(a, package: str, version: str, cache_dir: Path) -> bytes:
    import requests
    if package not in _PACKUMENTS:
        try:
            _PACKUMENTS[package] = a["loader"].fetch_packument(package)
        except Exception as exc:
            raise StageError("packument", f"{type(exc).__name__}: {exc}")
    manifest = _PACKUMENTS[package].get("versions", {}).get(version)
    if not isinstance(manifest, dict) or not isinstance(manifest.get("dist"), dict):
        raise StageError("packument", f"version {version} not in registry metadata")
    dist = manifest["dist"]
    cached = cache_dir / f"{package.replace('/', '__')}@{version}.tgz"
    data = cached.read_bytes() if cached.is_file() else None
    if data is None:
        try:
            response = requests.get(dist["tarball"], timeout=120)
            response.raise_for_status()
            data = response.content
        except Exception as exc:
            raise StageError("download", f"{type(exc).__name__}: {exc}")
    integrity = dist.get("integrity") or ""
    sha512 = [t for t in integrity.split() if t.startswith("sha512-")]
    if sha512:
        expected = {base64.b64decode(t[7:]) for t in sha512}
        if hashlib.sha512(data).digest() not in expected:
            raise StageError("integrity", "sha512 mismatch")
        method = "sha512"
    elif dist.get("shasum"):
        if hashlib.sha1(data).hexdigest() != dist["shasum"]:
            raise StageError("integrity", "sha1 mismatch")
        method = "sha1"
    else:
        raise StageError("integrity", "no integrity or shasum in registry metadata")
    if not cached.is_file():
        cached.write_bytes(data)
    return data, method


def _registry_root(a, package, version, cache_dir, work: Path):
    data, method = _verified_tarball(a, package, version, cache_dir)
    target = Path(tempfile.mkdtemp(prefix="x1_reg_", dir=work))
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            tar.extractall(target, filter="data")
    except (tarfile.TarError, OSError) as exc:
        raise StageError("extract", f"{type(exc).__name__}: {exc}")
    try:
        root = a["loader"]._locate_package_root(target, package, version)
    except Exception as exc:
        raise StageError("package_root", str(exc))
    return root, method


def _archive_root(a, archive_repo: Path, spec: str):
    raw = archive_repo / spec[len("archive:"):]
    if not raw.is_dir():
        raise StageError("archive", f"raw directory not checked out: {spec}")
    try:
        return a["find"](raw).parent
    except Exception as exc:
        raise StageError("package_root", str(exc))


def extract_pair(args: tuple) -> dict:
    row, src, archive_repo, cache_dir, work_parent = args
    a = _load_analyzer(src)
    started = time.time()
    result = {k: row[k] for k in KEY} | {"label": int(row["label"]), "class": row["class"],
                                          "old_source": row["old_source"].split(":")[0],
                                          "new_source": row["new_source"].split(":")[0]}
    work = Path(tempfile.mkdtemp(prefix="x1_pair_", dir=work_parent))
    try:
        roots, checks = {}, {}
        for side, version, spec in (("old", row["old_version"], row["old_source"]),
                                    ("new", row["new_version"], row["new_source"])):
            if spec.startswith("archive:"):
                roots[side], checks[side] = _archive_root(a, Path(archive_repo), spec), "archive@" + DATA_COMMIT[:8]
            elif spec == "registry":
                roots[side], checks[side] = _registry_root(a, row["package"], version, Path(cache_dir), work)
            else:
                raise StageError("manifest", f"unknown source {spec!r}")
        snaps = {}
        for side, version in (("old", row["old_version"]), ("new", row["new_version"])):
            try:
                package_json = json.loads((roots[side] / "package.json").read_text(encoding="utf-8"))
            except Exception as exc:
                raise StageError("package_json", f"{side}: {type(exc).__name__}: {exc}")
            if not isinstance(package_json, dict):
                raise StageError("package_json", f"{side}: not an object")
            # X1은 publish 시각을 쓰지 않는다(고정값).
            snaps[side] = a["Snap"](row["package"], version, datetime(1970, 1, 1, tzinfo=timezone.utc),
                                    package_json, roots[side])
        try:
            features = a["Extractor"]().extract(snaps["old"], snaps["new"])
        except Exception as exc:
            raise StageError("extractor", f"{type(exc).__name__}: {exc}")
        result |= {"status": "ok", "error_stage": "", "error": "", "old_check": checks["old"],
                   "new_check": checks["new"]} | {n: features[n] for n in a["names"]}
    except StageError as exc:
        result |= {"status": "error", "error_stage": exc.stage, "error": str(exc)[:500]}
    finally:
        shutil.rmtree(work, ignore_errors=True)
    result["seconds"] = round(time.time() - started, 2)
    return result


def _sparse_batch(archive_repo: Path, rows: list[dict]) -> None:
    patterns = sorted({"/" + r[s][len("archive:"):] + "/" for r in rows for s in ("old_source", "new_source")
                       if r[s].startswith("archive:")})
    git = ["git", "-C", str(archive_repo), "-c", "core.hooksPath=/dev/null"]
    subprocess.run(git + ["sparse-checkout", "set", "--no-cone", "--stdin"], input="\n".join(patterns) + "\n",
                   text=True, check=True)
    subprocess.run(git + ["checkout", "-q", "--detach", DATA_COMMIT], check=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    for name in ("--analyzer-src", "--pairs", "--baselines", "--archive-repo", "--cache-dir", "--out", "--part"):
        ap.add_argument(name, required=True)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--limit", type=int, default=0, help="시험 실행용: 앞에서 N쌍만")
    args = ap.parse_args()
    import csv
    train = list(csv.DictReader(open(args.pairs, newline="", encoding="utf-8")))
    base = {tuple(r[k] for k in KEY): r for r in csv.DictReader(open(args.baselines, newline="", encoding="utf-8"))}
    rows = []
    for t in train:
        key = tuple(t[k] for k in KEY)
        b = base[key]
        rows.append({**{k: t[k] for k in KEY}, "label": t["label"], "class": b["class"],
                     "old_source": b["old_source"], "new_source": b["new_source"]})
    if len(rows) != 677 or len({tuple(r[k] for k in KEY) for r in rows}) != 677:
        raise SystemExit("expected 677 unique D06 Test pairs")
    rows = [r for r in rows if (r["class"] == "malicious") == (args.part == "malicious")]
    out = Path(args.out)
    done = set()
    if out.is_file():
        for line in out.read_text().splitlines():
            d = json.loads(line)
            done.add(tuple(d[k] for k in KEY))
    todo = [r for r in rows if tuple(r[k] for k in KEY) not in done]
    if args.limit:
        todo = todo[:args.limit]
    print(f"{args.part}: total {len(rows)}, done {len(done)}, todo {len(todo)}", flush=True)
    Path(args.cache_dir).mkdir(parents=True, exist_ok=True)
    work_parent = Path(tempfile.mkdtemp(prefix=f"x1_{args.part}_"))
    try:
        batches = [todo[i:i + BATCH] for i in range(0, len(todo), BATCH)] if args.part == "malicious" else [todo]
        with ProcessPoolExecutor(max_workers=args.workers) as pool, out.open("a") as sink:
            for i, batch in enumerate(batches):
                if args.part == "malicious":
                    _sparse_batch(Path(args.archive_repo), batch)
                jobs = [(r, args.analyzer_src, args.archive_repo, args.cache_dir, str(work_parent)) for r in batch]
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
