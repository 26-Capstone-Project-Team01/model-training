"""Attack-type survey of malicious pairs added to npm-malware-package-pairs after D06 (D07/D07-B batches and D08).

Read-only: the data repository is accessed only through git object reads (ls-tree, cat-file, show) with lazy fetching
disabled (GIT_NO_LAZY_FETCH=1), so no object is downloaded and neither the index, the working tree nor any ref is changed.
Package code is never extracted or executed; only package.json blobs and tree object ids are read.

Scope: pair directories pairs/<campaign>/<pair_dir>/ whose meta.json exists at DATA_NEW but not at DATA_D06
(pairs/_excluded/ is outside this depth and not counted).

Per pair (new = malicious_raw, old = normal_raw, package root = shallowest package.json outside node_modules):
  js_changed            #.js/.mjs/.cjs files under the package root whose git blob id differs from old or that are new
  new_dep_count         names in new (dependencies U optionalDependencies) not in old (same scope as D06 newDependencyAdded)
  install_script_added  a preinstall/install/postinstall key in new that old does not have (D06 installScriptAdded)
  script_entry_added    any scripts key in new that old does not have (D06 scriptEntryAdded)
  attack_type           PR #13 definition: A = install_script_added or script_entry_added, B = new dependency, C = other
  mastra_like           js_changed == 0 and new_dep_count > 0 and not install_script_added  (mastra-easy-day-js pattern)

Overlap with D06: (package, old, new) keys and packages vs D06 Train (be87 derived/splits/train.csv) and Test-677/Test-674;
payload overlap = any changed-JS git blob id shared with a D06 Train/Test malicious pair (computed the same way from be87 trees).

Usage: python3 -I -B survey.py --data-repo <npm-malware-package-pairs clone> --out <new dir>
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import posixpath
import subprocess
from collections import Counter
from pathlib import Path

DATA_D06 = "be87ab4cff66fff1980c4a71be8032b6b47225ba"   # D06 Train/Test source commit
DATA_NEW = "4498acddcf72c7bd6cb91486e59bb92fdf1824fa"   # main after PR #22 (D08) merge
D08_BASE = "c5b4d32051354299454a4e57f2a08282b10394fb"   # main before PR #22 (D07-B batch commit)
SPLIT_SHA = {"train": "22fbc8752fff5fff90e40b911f6bf7d187769b4566db957d65a37a16be7d2c23",
             "test677": "e8a70053ce639ebc79d7bc8d9402578d3ceaf24853ed31735b5f55c418b8bd73",
             "test674": "604673b95d88009efe5d3200606de972bffa541dea3d75be37163ee501465060"}
HOOKS = ("preinstall", "install", "postinstall")
JS = (".js", ".mjs", ".cjs")
ENV = dict(os.environ, GIT_NO_LAZY_FETCH="1")


class Repo:
    def __init__(self, path):
        self.path = str(path)
        self._blob = {}

    def git(self, *args):
        r = subprocess.run(["git", "-C", self.path, *args], capture_output=True, text=True, env=ENV)
        if r.returncode:
            raise SystemExit(f"git {' '.join(args[:3])} failed (missing object? lazy fetch is disabled): {r.stderr[:300]}")
        return r.stdout

    def blob(self, oid):
        if oid not in self._blob:
            self._blob[oid] = self.git("cat-file", "-p", oid)
        return self._blob[oid]

    def tree(self, commit, path):
        out = {}
        for line in self.git("ls-tree", "-r", "--format=%(objectname) %(path)", commit, "--", path).splitlines():
            oid, p = line.split(" ", 1)
            out[p[len(path) + 1:]] = oid
        return out


def side(repo, commit, base):
    files = {k: v for k, v in repo.tree(commit, base).items() if "/node_modules/" not in "/" + k}
    pjs = sorted((k for k in files if posixpath.basename(k) == "package.json"), key=lambda k: (k.count("/"), k))
    if not pjs:
        return None, {}
    root = posixpath.dirname(pjs[0])
    pref = root + "/" if root else ""
    sub = {k[len(pref):]: v for k, v in files.items() if k.startswith(pref)}
    try:
        pj = json.loads(repo.blob(files[pjs[0]]))
    except json.JSONDecodeError:
        pj = None
    return pj, sub


def deps(pj):
    out = {}
    for f in ("dependencies", "optionalDependencies"):
        v = (pj or {}).get(f)
        if isinstance(v, dict):
            out.update(v)
    return out


def scripts(pj):
    s = (pj or {}).get("scripts")
    return s if isinstance(s, dict) else {}


def pair_features(repo, commit, pair_dir):
    old_pj, old_files = side(repo, commit, f"{pair_dir}/normal_raw")
    new_pj, new_files = side(repo, commit, f"{pair_dir}/malicious_raw")
    if old_pj is None or new_pj is None:
        return {"package_json_ok": False}
    changed_js = sorted(k for k, v in new_files.items() if k.endswith(JS) and old_files.get(k) != v)
    nd = sorted(set(deps(new_pj)) - set(deps(old_pj)))
    so, sn = scripts(old_pj), scripts(new_pj)
    isa = bool(set(sn) & set(HOOKS) - set(so))
    sea = bool(set(sn) - set(so))
    return {"package_json_ok": True, "js_changed": len(changed_js), "changed_js_blob_ids": [new_files[k] for k in changed_js],
            "new_dep_count": len(nd), "new_dep_names": ";".join(nd), "install_script_added": isa, "script_entry_added": sea,
            "install_hook_changed": any(sn.get(k) != so.get(k) for k in HOOKS if k in sn),
            "attack_type": "A" if (isa or sea) else ("B" if nd else "C"),
            "mastra_like": len(changed_js) == 0 and bool(nd) and not isa}


def meta_dirs(repo, commit):
    out = {}
    for line in repo.git("ls-tree", "-r", "--format=%(objectname) %(path)", commit, "--", "pairs").splitlines():
        oid, p = line.split(" ", 1)
        parts = p.split("/")
        if len(parts) == 4 and parts[3] == "meta.json":
            out[posixpath.dirname(p)] = oid
    return out


def read_csv_at(repo, commit, path, sha):
    text = repo.git("show", f"{commit}:{path}")
    got = hashlib.sha256(text.encode()).hexdigest()
    if got != sha:
        raise SystemExit(f"{path}@{commit[:8]} sha256 {got} != {sha}")
    return list(csv.DictReader(io.StringIO(text)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-repo", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=False)
    repo = Repo(a.data_repo)
    new_dirs, old_dirs, base_dirs = meta_dirs(repo, DATA_NEW), meta_dirs(repo, DATA_D06), meta_dirs(repo, D08_BASE)
    added = sorted(set(new_dirs) - set(old_dirs))
    removed = sorted(set(old_dirs) - set(new_dirs))
    rows = []
    for d in added:
        meta = json.loads(repo.blob(new_dirs[d]))
        f = pair_features(repo, DATA_NEW, d)
        rows.append({"pair_dir": d, "campaign": d.split("/")[1], "batch": "D08 (PR #22)" if d not in base_dirs else "D07/D07-B",
                     "collection_round": meta.get("collection_round"), "status": meta.get("status"), "package": meta.get("package"),
                     "old_version": meta.get("normal_version"), "new_version": meta.get("malicious_version"), **f})
    # D06 Train / Test and their malicious payload blob ids (be87 trees via baselines.csv archive paths)
    train = read_csv_at(repo, DATA_D06, "derived/splits/train.csv", SPLIT_SHA["train"])
    t677 = read_csv_at(repo, DATA_D06, "derived/splits/test.csv", SPLIT_SHA["test677"])
    t674 = read_csv_at(repo, DATA_NEW, "derived/splits/test.csv", SPLIT_SHA["test674"])
    key = lambda r: (r["package"], r["old_version"], r["new_version"])
    sets = {"train": {key(r) for r in train}, "test677": {key(r) for r in t677}, "test674": {key(r) for r in t674}}
    base = list(csv.DictReader(io.StringIO(repo.git("show", f"{DATA_D06}:derived/pairs/baselines.csv"))))
    payload = {"train": set(), "test677": set()}
    for b in base:
        if b["class"] != "malicious" or not b["new_source"].startswith("archive:"):
            continue
        k = key(b)
        which = [s for s in ("train", "test677") if k in sets[s]]
        if not which:
            continue
        pdir = posixpath.dirname(b["new_source"][len("archive:"):].rstrip("/"))
        f = pair_features(repo, DATA_D06, pdir)
        for s in which:
            payload[s].update(f.get("changed_js_blob_ids", []))
    for r in rows:
        k = (r["package"], r["old_version"], r["new_version"])
        ids = set(r.get("changed_js_blob_ids") or [])
        for s in ("train", "test677", "test674"):
            r[f"key_in_d06_{s}"] = k in sets[s]
            r[f"package_in_d06_{s}"] = r["package"] in {x[0] for x in sets[s]}
        r["payload_shared_with_d06_train"] = bool(ids & payload["train"])
        r["payload_shared_with_d06_test677"] = bool(ids & payload["test677"])
        r["changed_js_blob_ids"] = ";".join(sorted(ids))
    cols = list(rows[0].keys())
    with open(a.out / "pairs.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)

    def table(name, keys):
        c = Counter()
        for r in rows:
            c[tuple(str(r.get(k)) for k in keys) + ("pairs",)] += 1
            c[tuple(str(r.get(k)) for k in keys) + ("mastra_like",)] += bool(r.get("mastra_like"))
        groups = sorted({k[:-1] for k in c})
        with open(a.out / name, "w", newline="") as fh:
            w = csv.writer(fh, lineterminator="\n")
            w.writerow(list(keys) + ["pairs", "attack_type_A", "attack_type_B", "attack_type_C", "mastra_like", "no_js_change", "new_dependency"])
            for g in groups:
                sel = [r for r in rows if tuple(str(r.get(k)) for k in keys) == g]
                w.writerow(list(g) + [len(sel)] + [sum(r.get("attack_type") == t for r in sel) for t in "ABC"] +
                           [sum(bool(r.get("mastra_like")) for r in sel), sum(r.get("js_changed") == 0 for r in sel), sum((r.get("new_dep_count") or 0) > 0 for r in sel)])
    table("by_batch_round_status.csv", ["batch", "collection_round", "status"])
    table("by_campaign_status.csv", ["campaign", "status"])
    table("by_batch_attack_type.csv", ["batch", "attack_type"])
    ov = {s: {"same_key": sum(r[f"key_in_d06_{s}"] for r in rows), "same_package_pairs": sum(r[f"package_in_d06_{s}"] for r in rows),
              "same_package_names": sorted({r["package"] for r in rows if r[f"package_in_d06_{s}"]})} for s in ("train", "test677", "test674")}
    ov["payload_shared_with_d06_train_pairs"] = sum(r["payload_shared_with_d06_train"] for r in rows)
    ov["payload_shared_with_d06_test677_pairs"] = sum(r["payload_shared_with_d06_test677"] for r in rows)
    ov["payload_shared_by_campaign"] = dict(Counter(r["campaign"] for r in rows if r["payload_shared_with_d06_train"] or r["payload_shared_with_d06_test677"]))
    ov["d06_pair_dirs_removed_at_new_commit"] = len(removed)
    (a.out / "overlap_with_d06.json").write_text(json.dumps(ov, indent=1, ensure_ascii=False) + "\n")
    summary = {"data_commits": {"d06": DATA_D06, "new": DATA_NEW, "before_pr22": D08_BASE}, "pairs_added": len(rows),
               "package_json_ok": sum(r["package_json_ok"] for r in rows),
               "by_batch": dict(Counter(r["batch"] for r in rows)), "by_status": dict(Counter(r["status"] for r in rows)),
               "attack_type": dict(Counter(r.get("attack_type") for r in rows)),
               "mastra_like": [{k: r[k] for k in ("pair_dir", "status", "batch", "new_dep_names")} for r in rows if r.get("mastra_like")]}
    (a.out / "summary.json").write_text(json.dumps(summary, indent=1, ensure_ascii=False) + "\n")
    man = {"script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "git_no_lazy_fetch": True, "read_only": True,
           "split_inputs_sha256": SPLIT_SHA, "outputs": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(a.out.glob("*")) if p.is_file()}}
    (a.out / "manifest.json").write_text(json.dumps(man, indent=1) + "\n")
    print(json.dumps(summary, indent=1, ensure_ascii=False)[:2000])
    print(json.dumps({k: (v if not isinstance(v, dict) or "same_package_names" not in v else {kk: vv for kk, vv in v.items() if kk != "same_package_names"}) for k, v in ov.items()}, indent=1))


if __name__ == "__main__":
    main()
