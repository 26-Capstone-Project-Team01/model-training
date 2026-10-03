"""Fetch train.csv, test.csv, split_assignment.csv from the pinned commit of
npm-malware-package-pairs (data/SOURCE.json) into data/raw/, then sanity-check them.

npm-malware-package-pairs is a private repo, so this needs a GITHUB_TOKEN (or
GH_TOKEN) environment variable with read access to it.

Usage (from anywhere): python scripts/fetch_data.py
"""

from __future__ import annotations

import csv
import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Tuple

BASE_DIR = Path(__file__).resolve().parent.parent
SOURCE_PATH = BASE_DIR / "data" / "SOURCE.json"
RAW_DIR = BASE_DIR / "data" / "raw"

GITHUB_API = "https://api.github.com"


def get_token() -> str:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        raise SystemExit(
            "GITHUB_TOKEN(또는 GH_TOKEN) 환경변수가 필요합니다 — "
            "npm-malware-package-pairs는 private 레포라 인증이 필요합니다."
        )
    return token


def fetch_file(repo: str, path: str, commit: str, token: str) -> bytes:
    url = f"{GITHUB_API}/repos/{repo}/contents/{path}?ref={commit}"
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.raw",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.read()
    except urllib.error.HTTPError as e:
        raise SystemExit(f"{path} 다운로드 실패 ({e.code}): {e.reason}") from e


def count_rows_and_cols(data: bytes) -> Tuple[int, int]:
    reader = csv.reader(data.decode("utf-8").splitlines())
    header = next(reader)
    row_count = sum(1 for _ in reader)
    return row_count, len(header)


def main() -> None:
    source = json.loads(SOURCE_PATH.read_text(encoding="utf-8"))
    repo, commit, files = source["repo"], source["commit"], source["files"]
    token = get_token()

    RAW_DIR.mkdir(parents=True, exist_ok=True)

    downloaded: Dict[str, bytes] = {}
    for local_name, upstream_path in files.items():
        print(f"Fetching {upstream_path} @ {commit[:12]} ...")
        data = fetch_file(repo, upstream_path, commit, token)
        (RAW_DIR / local_name).write_bytes(data)
        downloaded[local_name] = data
        print(f"  -> data/raw/{local_name} ({len(data):,} bytes)")

    # Sanity checks: train/test share the same column count, and split_assignment.csv
    # covers exactly train.csv + test.csv rows.
    train_rows, train_cols = count_rows_and_cols(downloaded["train.csv"])
    test_rows, test_cols = count_rows_and_cols(downloaded["test.csv"])
    assignment_rows, _ = count_rows_and_cols(downloaded["split_assignment.csv"])

    if train_cols != test_cols:
        raise SystemExit(f"train.csv({train_cols}열)과 test.csv({test_cols}열)의 컬럼 수가 다릅니다")
    if assignment_rows != train_rows + test_rows:
        raise SystemExit(
            f"split_assignment.csv 행 수({assignment_rows})가 "
            f"train.csv+test.csv 행 수({train_rows + test_rows})와 일치하지 않습니다"
        )

    source["fetched_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    SOURCE_PATH.write_text(json.dumps(source, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print()
    print(f"OK: train {train_rows}행 / test {test_rows}행 / split_assignment {assignment_rows}행")
    print(f"data/SOURCE.json의 fetched_at을 {source['fetched_at']}로 갱신했습니다")


if __name__ == "__main__":
    main()
