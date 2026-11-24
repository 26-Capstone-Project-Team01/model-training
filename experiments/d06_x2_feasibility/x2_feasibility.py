"""X2 feasibility survey on D06 Train pairs that add a new dependency (no training, no Test, no package code execution).

Features examined (not yet adopted):
  newDependencyMinAgeHours     = min over added deps d of (T - time[d].created) in hours
  newDependencyMinVersionCount = min over added deps d of #{versions v of d : time[d][v] <= T}
where T = registry publish time of the parent new version, and version counts use the packument `time` map
(not the current `versions` list), so versions removed later are still counted if their time entry survives.

Pair status (never used as a feature):
  no_new_dependency        newDependencyAdded is False (not surveyed here)
  ok                       every added dep resolved -> both features defined
  parent_time_missing      T unavailable
  dep_lookup_failed_all    no added dep resolved
  dep_lookup_failed_partial some but not all resolved -> features left NaN (no min over the subset)
Dep status: ok | http_<code> | no_time_map | no_created | created_after_T (age < 0 kept and flagged).

Only JSON metadata and package.json files are read. Registry responses are logged with fetch time.

Usage: python -I -B x2_feasibility.py --train <be87 train.csv> --baselines <be87 baselines.csv> --archive-repo <partial clone> --out <new dir>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import numpy as np
import pandas as pd
import requests

HERE = Path(__file__).resolve().parent
EXP = HERE.parent
DATA_COMMIT = "be87ab4cff66fff1980c4a71be8032b6b47225ba"
KEY = ["package", "old_version", "new_version"]
DEP_FIELDS = ("dependencies", "optionalDependencies")
REGISTRY = "https://registry.npmjs.org/"


def iso(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


class Registry:
    def __init__(self, log_path):
        self.cache, self.log = {}, open(log_path, "w", encoding="utf-8")

    def get(self, name):
        if name in self.cache:
            return self.cache[name]
        url = REGISTRY + quote(name, safe="@")
        fetched = datetime.now(timezone.utc).isoformat()
        try:
            r = requests.get(url, timeout=60)
            status, doc = r.status_code, (r.json() if r.status_code == 200 else None)
        except Exception as exc:  # network error
            status, doc = f"error:{type(exc).__name__}", None
        rec = {"name": name, "url": url, "fetched_at": fetched, "status": status,
               "time": (doc or {}).get("time"), "versions": sorted((doc or {}).get("versions", {}) or {})}
        self.log.write(json.dumps(rec, ensure_ascii=False) + "\n")
        self.log.flush()
        self.cache[name] = (status, doc)
        time.sleep(0.05)
        return self.cache[name]


def deps(manifest):
    out = {}
    for f in DEP_FIELDS:
        v = manifest.get(f) or {}
        if isinstance(v, dict):
            out.update(v)
    return out


def archive_package_json(repo, spec):
    raw = spec[len("archive:"):]
    files = subprocess.run(["git", "-C", str(repo), "ls-tree", "-r", "--name-only", DATA_COMMIT, raw], capture_output=True, text=True, check=True).stdout.split()
    cands = sorted([f for f in files if f.endswith("/package.json") and "/node_modules/" not in f], key=lambda f: f.count("/"))
    if not cands:
        return None
    txt = subprocess.run(["git", "-C", str(repo), "show", f"{DATA_COMMIT}:{cands[0]}"], capture_output=True, text=True, check=True).stdout
    return json.loads(txt)


def main():
    ap = argparse.ArgumentParser()
    for n in ("--train", "--baselines", "--archive-repo", "--out"):
        ap.add_argument(n, required=True)
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=False)
    reg = Registry(out / "registry_query_log.jsonl")
    train = pd.read_csv(args.train, keep_default_na=False, dtype=str)
    base = pd.read_csv(args.baselines, keep_default_na=False, dtype=str)[KEY + ["class", "old_source", "new_source"]]
    meta = pd.read_csv(EXP / "d06_full35_compare/run/row_metadata.csv", keep_default_na=False, dtype=str)
    train["row_id"] = np.arange(len(train))
    assert (meta[KEY].to_numpy() == train[KEY].to_numpy()).all()
    df = train.merge(base, on=KEY, how="left", validate="one_to_one")
    df["campaign"], df["component"] = meta.campaign.to_numpy(), meta.component.to_numpy()
    tgt = df[df.newDependencyAdded == "True"].rename(columns={"class": "cls"}).copy()
    pair_rows, dep_pair_rows = [], []
    for r in tgt.itertuples(index=False):
        rec = {"row_id": r.row_id, "package": r.package, "old_version": r.old_version, "new_version": r.new_version, "class": r.cls,
               "campaign": r.campaign, "component": r.component, "train_newDependencyCount": int(r.newDependencyCount)}
        manifests, err = {}, ""
        pst, pdoc = reg.get(r.package)
        for side, ver, spec in (("old", r.old_version, r.old_source), ("new", r.new_version, r.new_source)):
            if spec.startswith("archive:"):
                manifests[side] = archive_package_json(Path(args.archive_repo), spec)
                rec[f"{side}_manifest_source"] = "archive"
            else:
                manifests[side] = ((pdoc or {}).get("versions") or {}).get(ver)
                rec[f"{side}_manifest_source"] = "registry"
            if manifests[side] is None:
                err = f"{side}_manifest_missing"
        T = ((pdoc or {}).get("time") or {}).get(r.new_version)
        rec["parent_registry_status"], rec["T"] = pst, T
        if err:
            rec |= {"status": err, "n_added": np.nan}
            pair_rows.append(rec)
            continue
        added = sorted(set(deps(manifests["new"])) - set(deps(manifests["old"])))
        rec["n_added"], rec["n_added_matches_train"] = len(added), len(added) == rec["train_newDependencyCount"]
        if T is None:
            rec["status"] = "parent_time_missing"
            pair_rows.append(rec)
            continue
        tT = iso(T)
        ages, counts, dstat = [], [], []
        for d in added:
            st, doc = reg.get(d)
            tm = (doc or {}).get("time") if doc else None
            info = {"row_id": r.row_id, "dep": d, "spec": str(deps(manifests["new"])[d]), "dep_registry_status": st}
            if st != 200:
                s = f"http_{st}"
            elif not tm:
                s = "no_time_map"
            elif "created" not in tm:
                s = "no_created"
            else:
                age = (tT - iso(tm["created"])).total_seconds() / 3600
                vc = sum(1 for k, v in tm.items() if k not in ("created", "modified") and iso(v) <= tT)
                s = "ok" if age >= 0 else "created_after_T"
                info |= {"age_hours": age, "version_count_at_T": vc, "versions_now": len((doc.get("versions") or {})),
                         "time_entries_total": sum(1 for k in tm if k not in ("created", "modified"))}
                ages.append(age)
                counts.append(vc)
            info["dep_status"] = s
            dstat.append(s)
            dep_pair_rows.append(info)
        if all(s == "ok" for s in dstat):
            rec |= {"status": "ok", "newDependencyMinAgeHours": min(ages), "newDependencyMinVersionCount": min(counts)}
        elif not any(s in ("ok", "created_after_T") for s in dstat):
            rec["status"] = "dep_lookup_failed_all"
        else:
            rec["status"] = "dep_lookup_failed_partial" if any(s.startswith(("http", "no_")) for s in dstat) else "created_after_T"
        rec["dep_statuses"] = ";".join(dstat)
        pair_rows.append(rec)
    P = pd.DataFrame(pair_rows)
    D = pd.DataFrame(dep_pair_rows)
    P.to_csv(out / "pairs.csv", index=False, lineterminator="\n")
    D.to_csv(out / "pair_dependencies.csv", index=False, lineterminator="\n")
    reg.log.close()
    manifest = {"experiment_id": "D06-X2-FEASIBILITY", "nature": "feasibility survey, D06 Train only; no Test, no training, no package code execution",
                "data_commit": DATA_COMMIT, "train_sha256": hashlib.sha256(Path(args.train).read_bytes()).hexdigest(),
                "baselines_sha256": hashlib.sha256(Path(args.baselines).read_bytes()).hexdigest(),
                "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "registry": REGISTRY, "run_finished_utc": datetime.now(timezone.utc).isoformat(),
                "pairs_surveyed": len(P), "outputs": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.glob("*")) if p.is_file()}}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1) + "\n")
    print(P.status.value_counts().to_dict())


if __name__ == "__main__":
    main()
