"""G2g step 1: static text scan of D08 Train malicious pairs (no code execution, no decoding).

Reads only pairs/<group>/<pair>/diff.txt from a checkout of npm-malware-package-pairs whose pairs/ tree equals
D08 2c48bd83, for every malicious row of the G2f fold assignment (clipper 6 already excluded).
Writes only hashes and counts (never code text):
  pair_index.csv        row -> pair dir, added-line counts
  line_hashes.csv.gz    per pair: sha1 of each distinct normalised added line (N1, N2; N3 = structural skeleton, blank if < 12 chars) + length class
  hidden_segments.csv   per added line that hides code after a long whitespace run: sha1 of hidden text,
                        sha1 of its structural skeleton, marker flags, lengths
Usage: python -I -B scan_pairs.py --data <npm-malware-package-pairs checkout> --ws <d08_recovery> --out <dir>
"""
from __future__ import annotations
import argparse, csv, gzip, hashlib, re
from pathlib import Path
import pandas as pd

KEY = ["package", "old_version", "new_version"]
BLANKS = re.compile(r"[ \t]{100,}")                      # code hidden after >=100 blanks on one line
MAX_LINE = 4000                                           # longer visible lines are not used for line matching (minified bundles)
STR = re.compile(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|`(?:\\.|[^`\\])*`")
NUM = re.compile(r"\b0x[0-9a-fA-F]+\b|\b\d+(?:\.\d+)?\b")
IDENT = re.compile(r"\b[A-Za-z_$][\w$]*\b")
JS_KW = set("var let const function return if else for while do break continue new typeof instanceof in of try catch finally throw "
            "switch case default this null undefined true false delete void async await class extends super import export from require "
            "global window document module exports process".split())
# structural markers of the hidden loader (generic names only; no IOC strings)
MARKERS = {"global_V": re.compile(r"global\[['\"]_V['\"]\]"), "global_r_require": re.compile(r"global\[['\"]r['\"]\]\s*=\s*require"),
           "iife": re.compile(r"\(function\s*\(\)\s*\{"), "string_array_rotation": re.compile(r"\.push\(\s*\w+\.shift\(\)\s*\)"),
           "eval_like": re.compile(r"\beval\b|new Function|Function\("), "from_char_code": re.compile(r"fromCharCode"),
           "atob_or_buffer": re.compile(r"\batob\b|Buffer\.from")}


def sha1(s: str) -> str: return hashlib.sha1(s.encode("utf-8", "surrogatepass")).hexdigest()


def norm1(line: str) -> str:
    """N1: whitespace-insensitive (strip, collapse runs, drop blanks around punctuation)."""
    s = re.sub(r"\s+", " ", line.strip())
    return re.sub(r"\s*([{}()\[\];,=+\-*/<>!&|?:.])\s*", r"\1", s)


def norm2(line: str) -> str:
    """N2: N1 + string/number literals -> placeholders (robust to changed URLs, keys, cookie names)."""
    return NUM.sub("0", STR.sub("S", norm1(line)))


def skeleton(code: str) -> str:
    """Structure only: literals -> S/0, non-keyword identifiers -> i, whitespace removed."""
    s = NUM.sub("0", STR.sub("S", code))
    s = IDENT.sub(lambda m: m.group(0) if m.group(0) in JS_KW else "i", s)
    return re.sub(r"\s+", "", s)


def trivial(n1: str) -> bool:
    return len(re.sub(r"[^\w]", "", n1)) < 8   # braces, 'return;', 'break;', short tokens


def added_lines(diff: Path):
    in_hunk = False
    with open(diff, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if line.startswith("--- unified diff:") or line.startswith("=== "): in_hunk = False; continue
            if line.startswith("@@"): in_hunk = True; continue
            if in_hunk and line.startswith("+") and not line.startswith("+++"): yield line[1:]


def scan_one(job):
    row_id, pdir = job
    diff = Path(pdir) / "diff.txt"
    lines, hidden, n_add, n_long = [], [], 0, 0
    seen = set()
    if diff.exists():
        for ln in added_lines(diff):
            n_add += 1
            m = BLANKS.search(ln)
            if m and m.start() > 0 and not ln[m.start() - 1].isspace() and m.end() < len(ln):
                code = ln[m.end():].strip()
                sk = skeleton(code)
                hidden.append({"row_id": row_id, "ws_run": m.end() - m.start(), "hidden_len": len(code), "hidden_sha1": sha1(code),
                               "skeleton_sha1": sha1(sk), "skeleton_prefix_sha1": sha1(sk[:300]),
                               **{k: int(bool(p.search(code))) for k, p in MARKERS.items()}})
                ln = ln[: m.start()]                       # visible part only for line matching
            if len(ln) > MAX_LINE: n_long += 1; continue
            n1 = norm1(ln)
            if not n1 or trivial(n1) or n1 in seen: continue
            seen.add(n1)
            sk3 = skeleton(ln)
            lines.append((row_id, sha1(n1), sha1(norm2(ln)), sha1(sk3) if len(sk3) >= 12 else "", int(len(n1) > 400)))
    return row_id, diff.exists(), n_add, n_long, lines, hidden


def main():
    from multiprocessing import Pool
    ap = argparse.ArgumentParser()
    for k in ("data", "ws", "out"): ap.add_argument(f"--{k}", type=Path, required=True)
    ap.add_argument("--workers", type=int, default=4)
    a = ap.parse_args(); a.out.mkdir(parents=True, exist_ok=True)
    fa = pd.read_csv(a.ws / "g2f/run/fold_assignment.csv", dtype=str, keep_default_na=False)
    b = pd.read_csv(a.ws / "inputs/baselines.csv", dtype=str, keep_default_na=False)
    rows = fa[fa["class"] == "malicious"].merge(b[KEY + ["new_source"]], on=KEY, how="left", validate="one_to_one")
    assert len(rows) == 3499 and rows.new_source.str.startswith("archive:pairs/").all()
    rows["pair_dir"] = rows.new_source.str.removeprefix("archive:").str.rsplit("/", n=1).str[0]
    jobs = [(int(r.row_id), str(a.data / r.pair_dir)) for r in rows.itertuples(index=False)]
    res = {}
    with Pool(a.workers) as pool:
        for i, r in enumerate(pool.imap_unordered(scan_one, jobs, chunksize=4)):
            res[r[0]] = r
            if i % 250 == 0: print("done", i, flush=True)
    idx, hid = [], []
    with gzip.open(a.out / "line_hashes.csv.gz", "wt", newline="") as gz:
        lw = csv.writer(gz, lineterminator="\n"); lw.writerow(["row_id", "n1_sha1", "n2_sha1", "n3_sha1", "long"])
        for r in rows.itertuples(index=False):
            rid, found, n_add, n_long, lines, hidden = res[int(r.row_id)]
            lw.writerows(lines); hid.extend(hidden)
            idx.append({"row_id": rid, **{k: getattr(r, k) for k in KEY}, "era": r.era, "splitGroup_orig": r.splitGroup_orig,
                        "splitGroup_G2f": r.splitGroup, "component": r.component, "fold_G2f": r.fold, "pair_dir": r.pair_dir,
                        "diff_found": int(found), "added_lines": n_add, "long_lines_skipped": n_long, "distinct_nontrivial": len(lines)})
    pd.DataFrame(idx).to_csv(a.out / "pair_index.csv", index=False, lineterminator="\n")
    pd.DataFrame(hid).to_csv(a.out / "hidden_segments.csv", index=False, lineterminator="\n")
    print("pairs", len(idx), "missing diff", sum(1 - i["diff_found"] for i in idx), "hidden segments", len(hid))


if __name__ == "__main__":
    main()
