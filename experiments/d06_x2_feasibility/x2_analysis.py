"""Summaries for the X2 feasibility survey (reads run/ outputs only; no network, no training).

Usage: python -I -B x2_analysis.py --run run --out analysis
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

GENERIC = re.compile(r"^(individual-compromise(-\d+(?:st|nd|rd|th))?|individuals_case)$")


def spec_type(s):
    s = str(s)
    if re.match(r"^(github:|gitlab:|bitbucket:|git\+|git:|https?:|ssh:)", s) or re.match(r"^[\w.-]+/[\w.-]+(#.*)?$", s):
        return "git_or_url"
    if s.startswith(("file:", "link:", "workspace:")):
        return "file_link_workspace"
    if s.startswith("npm:"):
        return "npm_alias"
    return "registry_range"


def q(v, p):
    return float(np.nanpercentile(v, p)) if len(v) else np.nan


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    out = a.out
    out.mkdir(parents=True, exist_ok=False)
    # keep_default_na=False: a real npm package is named "nan"; numeric columns are converted explicitly
    P = pd.read_csv(a.run / "pairs.csv", keep_default_na=False)
    D = pd.read_csv(a.run / "pair_dependencies.csv", keep_default_na=False)
    for c in ["n_added", "train_newDependencyCount", "newDependencyMinAgeHours", "newDependencyMinVersionCount", "row_id"]:
        P[c] = pd.to_numeric(P[c].replace("", np.nan))
    P["n_added_matches_train"] = P.n_added_matches_train.map({"True": True, "False": False})
    P["T"] = P["T"].replace("", np.nan)
    for c in ["age_hours", "version_count_at_T", "versions_now", "time_entries_total", "row_id"]:
        D[c] = pd.to_numeric(D[c].replace("", np.nan))
    log = {json.loads(l)["name"]: json.loads(l) for l in open(a.run / "registry_query_log.jsonl")}
    D["spec_type"] = D.spec.map(spec_type)
    X = D.merge(P[["row_id", "class", "campaign", "component", "T"]], on="row_id")

    # 1. coverage
    deps = X.drop_duplicates("dep")
    cov = {"pairs": len(P), "pairs_by_class": P["class"].value_counts().to_dict(), "unique_new_dependencies": int(X.dep.nunique()),
           "dependency_pair_links": len(X), "n_added_matches_train_newDependencyCount": bool(P.n_added_matches_train.all()),
           "parent_publish_time_available": int(P["T"].notna().sum()),
           "unique_deps_by_spec_type": deps.spec_type.value_counts().to_dict(),
           "unique_deps_registry_status": deps.dep_registry_status.astype(str).value_counts().to_dict(),
           "unique_deps_with_time_map": int(sum(1 for d in deps.dep if (log[d].get("time") or None))),
           "unique_deps_status": deps.dep_status.value_counts().to_dict(),
           "pair_status": P.status.value_counts().to_dict(),
           "feature_computable_pairs": int((P.status == "ok").sum()),
           "feature_computable_share": float((P.status == "ok").mean())}
    # created vs earliest version time (time-map integrity)
    integ = []
    for d in deps.dep:
        tm = log[d].get("time") or {}
        vt = {k: v for k, v in tm.items() if k not in ("created", "modified")}
        if not vt or "created" not in tm:
            continue
        first = min(datetime.fromisoformat(v.replace("Z", "+00:00")) for v in vt.values())
        created = datetime.fromisoformat(tm["created"].replace("Z", "+00:00"))
        integ.append({"dep": d, "created_minus_first_version_hours": (created - first).total_seconds() / 3600,
                      "security_placeholder": any("security" in k for k in vt), "versions_now": len(log[d].get("versions") or []), "time_entries": len(vt)})
    I = pd.DataFrame(integ)
    I.to_csv(out / "dependency_time_integrity.csv", index=False, lineterminator="\n")
    cov["deps_created_later_than_first_version_gt_1h"] = int((I.created_minus_first_version_hours > 1).sum())
    cov["deps_with_security_placeholder"] = int(I.security_placeholder.sum())
    cov["deps_with_time_entries_gt_versions_now"] = int((I.time_entries > I.versions_now).sum())
    (out / "coverage.json").write_text(json.dumps(cov, indent=1, ensure_ascii=False) + "\n")

    # 2. failure rates by class / campaign, and by spec type
    st = pd.crosstab([P["class"]], P.status, margins=True)
    st.to_csv(out / "status_by_class.csv", lineterminator="\n")
    cs = P.groupby(["class", "campaign"]).status.value_counts().unstack(fill_value=0)
    cs["fail_rate"] = 1 - cs.get("ok", 0) / cs.sum(axis=1)
    cs.reset_index().to_csv(out / "status_by_campaign.csv", index=False, lineterminator="\n")
    pd.crosstab([X["class"], X.spec_type], X.dep_status).reset_index().to_csv(out / "dep_status_by_spec_type.csv", index=False, lineterminator="\n")

    # 3. feature distributions (ok pairs)
    rows = []
    ok = P[P.status == "ok"]
    for c, g in ok.groupby("class"):
        for f in ["newDependencyMinAgeHours", "newDependencyMinVersionCount"]:
            v = g[f].to_numpy(float)
            rows.append({"class": c, "feature": f, "n": len(v), "min": np.min(v), "p10": q(v, 10), "p25": q(v, 25), "median": q(v, 50), "p75": q(v, 75), "max": np.max(v),
                         "share_age_lt_24h": float((v < 24).mean()) if "Age" in f else np.nan, "share_age_lt_7d": float((v < 168).mean()) if "Age" in f else np.nan,
                         "share_age_lt_30d": float((v < 720).mean()) if "Age" in f else np.nan, "share_count_le_1": float((v <= 1).mean()) if "Count" in f else np.nan,
                         "share_count_le_3": float((v <= 3).mean()) if "Count" in f else np.nan})
    pd.DataFrame(rows).to_csv(out / "feature_distribution_by_class.csv", index=False, lineterminator="\n")
    ok.groupby(["class", "campaign"]).agg(n=("row_id", "size"), age_med_h=("newDependencyMinAgeHours", "median"),
                                          vc_med=("newDependencyMinVersionCount", "median")).reset_index().to_csv(out / "feature_by_campaign.csv", index=False, lineterminator="\n")

    # 4. shared dependencies
    sh = X.groupby("dep").agg(pairs=("row_id", "nunique"), classes=("class", lambda s: ";".join(sorted(set(s)))),
                              campaigns=("campaign", lambda s: ";".join(sorted({x for x in s if x}))), components=("component", "nunique"),
                              spec_types=("spec_type", lambda s: ";".join(sorted(set(s)))), status=("dep_status", lambda s: ";".join(sorted(set(s))))).reset_index()
    sh = sh.sort_values("pairs", ascending=False)
    sh.to_csv(out / "shared_dependencies.csv", index=False, lineterminator="\n")

    # 5. young dependencies in benign / hard_benign (age < 30 days at parent publish)
    young = X[(X["class"] != "malicious") & (X.dep_status == "ok") & (X.age_hours < 720)]
    young.merge(P[["row_id", "package", "new_version"]], on="row_id")[["class", "package", "new_version", "dep", "spec", "age_hours", "version_count_at_T"]] \
        .sort_values("age_hours").to_csv(out / "young_dependencies_non_malicious.csv", index=False, lineterminator="\n")

    # 6. NaN-as-signal risk (Train 247 pairs with a new dependency)
    P["feature_nan"] = P.status != "ok"
    risk = P.groupby("feature_nan")["class"].value_counts().unstack(fill_value=0)
    risk["P_malicious"] = risk.get("malicious", 0) / risk.sum(axis=1)
    risk.reset_index().to_csv(out / "nan_signal_risk.csv", index=False, lineterminator="\n")
    man = {"inputs": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(a.run.glob("*")) if p.is_file()},
           "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
           "outputs": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.glob("*")) if p.is_file()}}
    (out / "manifest.json").write_text(json.dumps(man, indent=1) + "\n")


if __name__ == "__main__":
    main()
