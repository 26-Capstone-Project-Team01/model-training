"""Feasibility probe for 'relative update anomaly' features (registry packument JSON only; no tarball, no code execution,
no training, no Test). Stratified sample of D06 Train pairs (50 per class, fixed seed). For each pair, records which
inputs exist at the registry today and computes candidate values that only use the packument `time` map, plus
manifest-based values (dist.unpackedSize / dist.fileCount) to measure their availability.

Candidates (not adopted):
  relIntervalRatio       = (T_new - T_old) / median of up to 10 previous inter-release gaps before T_old (time map order)
  priorReleaseCount      = #versions with time < T_new
  releasesIn24hBeforeNew = #versions with T_new - 24h <= time < T_new (excluding new)
  oldGapRatio            = (T_old - previous release) / median previous gaps
  unpackedSizeLogRatio   = log(unpackedSize_new / unpackedSize_old)   (manifest-based)
Usage: python -I -B probe.py --out <new dir>
"""
from __future__ import annotations
import argparse, hashlib, json, sys, time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import quote
import numpy as np, pandas as pd, requests

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "d06_x1_cause_analysis"))
import common as c  # noqa: E402


def iso(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--out", type=Path, required=True)
    out = ap.parse_args().out; out.mkdir(parents=True, exist_ok=False)
    df = c.frame()
    sample = df.groupby("class", group_keys=False).apply(lambda g: g.sample(50, random_state=20261124))
    log = open(out / "registry_log.jsonl", "w"); cache = {}; rows = []
    for r in sample.itertuples():
        if r.package not in cache:
            t0 = datetime.now(timezone.utc).isoformat()
            try:
                resp = requests.get("https://registry.npmjs.org/" + quote(r.package, safe="@"), timeout=60)
                st, doc = resp.status_code, (resp.json() if resp.status_code == 200 else None)
            except Exception as e:
                st, doc = f"error:{type(e).__name__}", None
            log.write(json.dumps({"name": r.package, "fetched_at": t0, "status": st}) + "\n"); log.flush()
            cache[r.package] = (st, doc); time.sleep(0.2)
        st, doc = cache[r.package]
        tm = {k: iso(v) for k, v in ((doc or {}).get("time") or {}).items() if k not in ("created", "modified")}
        vers = (doc or {}).get("versions") or {}
        rec = {"row_id": r.row_id, "class": df.at[r.Index, "class"], "campaign": r.campaign, "registry_status": st,
               "time_map_versions": len(tm), "new_in_time": r.new_version in tm, "old_in_time": r.old_version in tm,
               "new_manifest": r.new_version in vers, "old_manifest": r.old_version in vers}
        if rec["new_in_time"] and rec["old_in_time"]:
            Tn, To = tm[r.new_version], tm[r.old_version]
            before_old = sorted(t for t in tm.values() if t < To)
            seq = before_old + [To]
            gaps = np.diff([t.timestamp() for t in seq[-11:]])
            med = float(np.median(gaps)) if len(gaps) else np.nan
            rec |= {"priorReleaseCount": sum(1 for t in tm.values() if t < Tn),
                    "releasesIn24hBeforeNew": sum(1 for t in tm.values() if Tn - timedelta(hours=24) <= t < Tn),
                    "relIntervalRatio": (Tn - To).total_seconds() / med if med and med > 0 else np.nan,
                    "oldGapRatio": (gaps[-1] / float(np.median(gaps[:-1]))) if len(gaps) > 1 and np.median(gaps[:-1]) > 0 else np.nan,
                    "prior_gaps_used": len(gaps), "new_before_old": Tn < To}
        if rec["new_manifest"] and rec["old_manifest"]:
            a, b = (vers[r.new_version].get("dist") or {}).get("unpackedSize"), (vers[r.old_version].get("dist") or {}).get("unpackedSize")
            rec["unpackedSizeLogRatio"] = float(np.log(a / b)) if a and b else np.nan
        rows.append(rec)
    log.close()
    P = pd.DataFrame(rows); P.to_csv(out / "probe_pairs.csv", index=False, lineterminator="\n")
    cov = P.groupby("class").agg(n=("row_id", "size"), registry_ok=("registry_status", lambda s: (s == 200).mean()), new_in_time=("new_in_time", "mean"),
                                 old_in_time=("old_in_time", "mean"), new_manifest=("new_manifest", "mean"), old_manifest=("old_manifest", "mean"),
                                 time_features=("relIntervalRatio", lambda s: s.notna().mean()), size_feature=("unpackedSizeLogRatio", lambda s: s.notna().mean()))
    cov.round(3).to_csv(out / "coverage_by_class.csv", lineterminator="\n")
    dist = P.groupby("class")[["priorReleaseCount", "releasesIn24hBeforeNew", "relIntervalRatio", "oldGapRatio", "unpackedSizeLogRatio"]].describe(percentiles=[.1, .5, .9]).T
    dist.round(4).to_csv(out / "distribution_by_class.csv", lineterminator="\n")
    (out / "manifest.json").write_text(json.dumps({"script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "sample": "50 per class, random_state 20261124",
        "outputs": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.glob("*")) if p.is_file()}}, indent=1) + "\n")
    print(cov.round(3).to_string()); print(dist.round(3).to_string())


if __name__ == "__main__":
    main()
