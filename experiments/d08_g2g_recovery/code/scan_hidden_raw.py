"""G2g step 1b: static scan of malicious_raw for code hidden after long whitespace (no execution, no decoding).

diff.txt does not always show the hidden text (e.g. text payloads in files named like fonts, very long lines),
so this reads the files themselves. For every D08 Train malicious pair (G2f fold assignment, clipper 6 excluded):
  * walk malicious_raw/; skip a file whose bytes equal normal_raw/ at the same relative path (unchanged), binary files
    (NUL in the first 4 KiB) and files over 20 MB;
  * find whitespace runs (spaces/tabs/newlines) of >= 100 characters that are followed by non-whitespace text;
  * record per segment: relative path, run length, newline count, hidden-text length, sha1 of the hidden text
    (up to the next 5,000-char whitespace run or end of file), sha1 of its structural skeleton prefix, and marker flags.
Writes only hashes, paths and flags: hidden_raw_segments.csv.
Usage: python -I -B scan_hidden_raw.py --scan <scan dir with pair_index.csv> --data <checkout> --out <dir> [--workers 4]
"""
from __future__ import annotations
import argparse, hashlib, os, re
from multiprocessing import Pool
from pathlib import Path
import sys
import pandas as pd
sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan_pairs import skeleton, sha1  # noqa: E402

RUN = re.compile(r"\s{100,}")
BIG_RUN = re.compile(r"\s{5000,}")
MARKERS = {
    "version_tag": re.compile(r"global\[['\"][^'\"]{1,4}['\"]\]\s*=\s*['\"]\d+-[^'\"]{0,40}['\"]"),  # global['x']='<n>-<tag>'
    "version_tag_globalThis": re.compile(r"globalThis\.\w{1,4}\s*=\s*['\"][A-Z]?\d+-[^'\"]{0,40}['\"]"),  # globalThis.x="<A>n-<tag>"
    "global_V": re.compile(r"global\[['\"]_V['\"]\]"),
    "global_r_require": re.compile(r"global\[['\"]r['\"]\]\s*=\s*require"),
    "dollar_underscore_array": re.compile(r"var\s+_\$_[0-9a-f]{4}\s*=\s*\(function"),
    "iife": re.compile(r"\(function\s*\(\)\s*\{"),
}


def scan_one(job):
    row_id, pdir = job
    mal, nor = Path(pdir) / "malicious_raw", Path(pdir) / "normal_raw"
    out = []
    for root, _, files in os.walk(mal):
        for f in files:
            p = Path(root) / f
            rel = p.relative_to(mal)
            try:
                if p.is_symlink() or p.stat().st_size > 20_000_000: continue
                b = p.read_bytes()
            except OSError:
                continue
            if b"\0" in b[:4096]: continue
            q = nor / rel
            try:
                if q.is_file() and q.stat().st_size == len(b) and q.read_bytes() == b: continue
            except OSError:
                pass
            t = b.decode("utf-8", "replace")
            first = len(t) - len(t.lstrip())
            for k, m in enumerate(RUN.finditer(t)):
                if k >= 200: break                      # cap per file (very large generated files)
                if m.end() >= len(t): continue
                nxt = BIG_RUN.search(t, m.end())
                hidden = t[m.end(): nxt.start() if nxt else len(t)].strip()
                if len(hidden) < 200: continue
                head = hidden[:20000]
                sk = skeleton(head)
                out.append({"row_id": row_id, "path": str(rel), "file_added": int(not q.exists()), "ws_run": m.end() - m.start(),
                            "ws_newlines": t.count("\n", m.start(), m.end()), "at_file_start": int(m.start() <= first),
                            "hidden_len": len(hidden), "hidden_sha1": sha1(hidden), "skeleton_prefix_sha1": sha1(sk[:300]),
                            **{k2: int(bool(rx.search(head))) for k2, rx in MARKERS.items()}})
    return out


def main():
    ap = argparse.ArgumentParser()
    for k in ("scan", "data", "out"): ap.add_argument(f"--{k}", type=Path, required=True)
    ap.add_argument("--workers", type=int, default=4)
    a = ap.parse_args(); a.out.mkdir(parents=True, exist_ok=True)
    idx = pd.read_csv(a.scan / "pair_index.csv", keep_default_na=False)
    jobs = [(int(r.row_id), str(a.data / r.pair_dir)) for r in idx.itertuples(index=False)]
    rows = []
    with Pool(a.workers) as pool:
        for i, r in enumerate(pool.imap_unordered(scan_one, jobs, chunksize=2)):
            rows.extend(r)
            if i % 500 == 0: print("done", i, flush=True)
    df = pd.DataFrame(rows).sort_values(["row_id", "path", "hidden_sha1"]) if rows else pd.DataFrame()
    df.to_csv(a.out / "hidden_raw_segments.csv", index=False, lineterminator="\n")
    print("segments", len(df), "pairs", df.row_id.nunique() if len(df) else 0)


if __name__ == "__main__":
    main()
