"""Collect install-hook command strings (preinstall/install/postinstall/prepare) and dependency specs for D06 Train rows
with installScriptAdded or newDependencyAdded or any dependency change. Reads only package.json (archive at be87ab4c) and
registry packument JSON. No package code is executed.

Usage: python -I -B hook_commands.py --archive-repo <be87 clone> --out <new dir>
"""
from __future__ import annotations
import argparse, hashlib, io, json, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
import numpy as np, pandas as pd, requests

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "d06_x1_cause_analysis"))
import common as c  # noqa: E402

DATA = "be87ab4cff66fff1980c4a71be8032b6b47225ba"
HOOKS = ("preinstall", "install", "postinstall", "prepare")
KEY = ["package", "old_version", "new_version"]


def archive_pj(repo, spec):
    raw = spec[len("archive:"):]
    files = subprocess.run(["git", "-C", str(repo), "ls-tree", "-r", "--name-only", DATA, raw], capture_output=True, text=True, check=True).stdout.split()
    cands = sorted([f for f in files if f.endswith("/package.json") and "/node_modules/" not in f], key=lambda f: f.count("/"))
    if not cands:
        return None
    return json.loads(subprocess.run(["git", "-C", str(repo), "show", f"{DATA}:{cands[0]}"], capture_output=True, text=True, check=True).stdout)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--archive-repo", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=False)
    df = c.frame()
    base = pd.read_csv(io.StringIO(subprocess.run(["git", "-C", str(a.archive_repo), "show", f"{DATA}:derived/pairs/baselines.csv"],
                                                    capture_output=True, text=True, check=True).stdout), keep_default_na=False, dtype=str)
    df = df.merge(base[KEY + ["class", "old_source", "new_source"]].rename(columns={"class": "cls_b"}), on=KEY, how="left", validate="one_to_one")
    assert df.cls_b.notna().all()
    cache, log = {}, open(a.out / "registry_log.jsonl", "w")

    def pack(name):
        if name not in cache:
            t = datetime.now(timezone.utc).isoformat()
            try:
                r = requests.get("https://registry.npmjs.org/" + quote(name, safe="@"), timeout=60)
                st, doc = r.status_code, (r.json() if r.status_code == 200 else None)
            except Exception as e:
                st, doc = f"error:{type(e).__name__}", None
            log.write(json.dumps({"name": name, "fetched_at": t, "status": st}) + "\n")
            cache[name] = doc
            time.sleep(0.05)
        return cache[name]

    rows = []
    # all hard_benign + all malicious + benign with hook/newDep (benign is large; restrict)
    tgt = df[(df["class"] != "benign") | df.installScriptAdded.astype(bool) | df.newDependencyAdded.astype(bool)]
    for r in tgt.itertuples(index=False):
        m = {}
        for side, ver, spec in (("old", r.old_version, r.old_source), ("new", r.new_version, r.new_source)):
            if spec.startswith("archive:"):
                m[side], src = archive_pj(a.archive_repo, spec), "archive"
            else:
                m[side], src = ((pack(r.package) or {}).get("versions") or {}).get(ver), "registry"
        rec = {"row_id": r.row_id, "package": r.package, "old_version": r.old_version, "new_version": r.new_version, "class": r[df.columns.get_loc("class")],
               "campaign": r.campaign, "manifest_ok": m["old"] is not None and m["new"] is not None}
        if rec["manifest_ok"]:
            for side in ("old", "new"):
                sc = m[side].get("scripts") or {}
                for h in HOOKS:
                    rec[f"{side}_{h}"] = sc.get(h, "") if isinstance(sc, dict) else ""
                for f in ("dependencies", "optionalDependencies", "devDependencies", "peerDependencies"):
                    v = m[side].get(f) or {}
                    rec[f"{side}_{f}"] = json.dumps(v if isinstance(v, dict) else {}, sort_keys=True)
                rec[f"{side}_files"] = json.dumps(m[side].get("files")) if m[side].get("files") is not None else ""
                rec[f"{side}_binary"] = json.dumps(m[side].get("binary") or m[side].get("gypfile") or "")
        rows.append(rec)
    log.close()
    out = pd.DataFrame(rows)
    out.to_csv(a.out / "manifests_summary.csv", index=False, lineterminator="\n")
    (a.out / "manifest.json").write_text(json.dumps({"data_commit": DATA, "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "rows": len(out), "manifest_ok": int(out.manifest_ok.sum()), "finished_utc": datetime.now(timezone.utc).isoformat(),
        "outputs": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(a.out.glob("*")) if p.is_file()}}, indent=1) + "\n")
    print(out.groupby("class").manifest_ok.agg(["sum", "size"]))


if __name__ == "__main__":
    main()
