"""Verification of an X3/D extraction (pilot or full). No network, no training.

Checks
 1. existing features re-extracted with the X3 branch == stored D06 values (package_json 6 except updateInterval,
    obfuscation 22, X1 6) from ../d06_x1_extraction/analysis/d06_full35.csv
 2. ratio = 1000 * X1 added count / x3diagChangedCodeAddedTokenCount, numerator taken from the same run's X1 value
 3. denominator 0 / small
 4. hook absent vs hook parse failure vs unresolved target (missingness kinds)
 5. partially analysable hook targets (resolved >= 1 and unresolved >= 1)
 6. missing rate and extremes by class
Usage: python -I -B verify_x3.py --jsonl <a.jsonl> [<b.jsonl>] --out <new dir>
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
FULL35 = HERE.parent / "d06_x1_extraction/analysis/d06_full35.csv"
X3 = ["installHookTargetCount", "installHookTargetMaxBytes", "obfHookHexIdentRatio", "obfHookHexNumberRatio",
      "obfHookBracketAccessRatio", "obfHookEscapeDensity", "obfHookShortIdentRatio", "obfHookMeanIdentLength",
      "obfHookWhitespaceRatio", "installHookTargetProcExecCallCount", "installHookTargetNetworkCallCount",
      "addedNetworkCallPer1kAddedTokens", "addedProcExecCallPer1kAddedTokens"]
DIAG = ["x3diagChangedCodeAddedTokenCount", "x3diagChangedFileTokenCount", "x3diagHookTargetUnresolvedCount", "x3diagHookTargetNonJsCount"]
D = ["dependencyRangeChangedCount", "dependencyChangedRatio"]
KEY = ["package", "old_version", "new_version"]


def num(s):
    return pd.to_numeric(s.map(lambda v: {True: 1.0, False: 0.0}.get(v, v) if isinstance(v, bool) else v), errors="coerce")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jsonl", type=Path, nargs="+", required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    out = a.out
    out.mkdir(parents=True, exist_ok=False)
    R = pd.DataFrame([json.loads(l) for p in a.jsonl for l in p.read_text().splitlines()])
    rep = {"pairs": len(R), "status": R.groupby(["class", "status"]).size().reset_index().values.tolist()}
    ok = R[R.status == "ok"].copy()
    ref = pd.read_csv(FULL35, dtype=str, keep_default_na=False)
    ref["row_id"] = np.arange(len(ref))
    m = ok.merge(ref, on="row_id", suffixes=("", "_ref"))
    assert (m[KEY].to_numpy() == m[[k + "_ref" for k in KEY]].to_numpy()).all(), "row_id/key mismatch"
    # 1. existing features
    cols = [c for c in ref.columns if c not in KEY + ["label", "row_id", "updateInterval"]]
    diffs = []
    for col in cols:
        if col == "updateType":
            bad = m[col].astype(str) != m[col + "_ref"]
        else:
            new = num(m[col])
            old = pd.to_numeric(m[col + "_ref"].replace({"True": "1", "False": "0", "": np.nan}))
            bad = ~((new.isna() & old.isna()) | np.isclose(new, old, rtol=1e-12, atol=0, equal_nan=False))
        for r in m[bad].itertuples():
            diffs.append({"row_id": r.row_id, "feature": col, "new": getattr(r, col), "stored": getattr(r, col + "_ref")})
    pd.DataFrame(diffs, columns=["row_id", "feature", "new", "stored"]).to_csv(out / "existing_feature_diffs.csv", index=False, lineterminator="\n")
    rep["existing_features_compared"] = len(cols)
    rep["existing_feature_mismatches"] = len(diffs)
    # 2. ratio arithmetic and numerator identity
    for name, x1c in [("addedNetworkCallPer1kAddedTokens", "addedNetworkCallCount"), ("addedProcExecCallPer1kAddedTokens", "addedProcExecCallCount")]:
        den, numr, ratio = num(ok.x3diagChangedCodeAddedTokenCount), num(ok[x1c]), num(ok[name])
        exp = np.where((den > 0) & numr.notna(), 1000 * numr / den.where(den > 0), np.nan)
        rep[f"{name}_arith_ok"] = bool(np.allclose(ratio.fillna(-1), pd.Series(exp, index=ok.index).fillna(-1), rtol=1e-12))
    rep["numerator_from_same_run_matches_stored_x1"] = rep["existing_feature_mismatches"] == 0 or not any(d["feature"] in ("addedNetworkCallCount", "addedProcExecCallCount") for d in diffs)
    # 3. denominators
    den = num(ok.x3diagChangedCodeAddedTokenCount)
    tot = num(ok.x3diagChangedFileTokenCount)
    numer = num(ok.addedNetworkCallCount) + num(ok.addedProcExecCallCount)
    rep["denominator"] = {"A_zero": int((den == 0).sum()), "A_zero_with_calls": int(((den == 0) & (numer > 0)).sum()),
                          "A_lt_20": int(((den > 0) & (den < 20)).sum()), "A_lt_100": int(((den > 0) & (den < 100)).sum()),
                          "A_gt_B": int((den > tot).sum()), "A_none": int(den.isna().sum())}
    small = ok[(den > 0) & (den < 100)][["row_id", "class", "package", "x3diagChangedCodeAddedTokenCount", "addedNetworkCallCount",
                                         "addedProcExecCallCount", "addedNetworkCallPer1kAddedTokens", "addedProcExecCallPer1kAddedTokens"]]
    small.to_csv(out / "small_denominator_rows.csv", index=False, lineterminator="\n")
    # 4/5. missingness kinds
    present = ok.installScriptPresent.astype(str) == "True"
    cnt, unres = num(ok.installHookTargetCount), num(ok.x3diagHookTargetUnresolvedCount)
    kind = np.select([cnt.isna(), cnt > 0, unres > 0, num(ok.x3diagHookTargetNonJsCount) > 0, present],
                     ["hook_parse_failed", "targets_analysed", "zero_targets_unresolved_only", "zero_targets_non_js_only", "hook_present_no_changed_js_target"],
                     "no_install_hook")
    ok["x3_hook_state"] = kind
    ok["partial_targets"] = (cnt > 0) & (unres > 0)
    st = ok.groupby(["class", "x3_hook_state"]).size().unstack(fill_value=0)
    st.to_csv(out / "hook_state_by_class.csv", lineterminator="\n")
    rep["partial_targets_rows"] = ok[ok.partial_targets][["row_id", "class", "package"]].values.tolist()
    rep["no_hook_but_targets"] = int(((~present) & (cnt > 0)).sum())
    # 6. missing rate and extremes by class
    rows = []
    for col in X3 + D + DIAG:
        v = num(ok[col])
        for cls, g in v.groupby(ok["class"]):
            rows.append({"feature": col, "class": cls, "n": len(g), "missing": float(g.isna().mean()), "gt0": float((g > 0).mean()),
                         "p50": g.median(), "p95": g.quantile(.95), "max": g.max(), "min": g.min()})
    pd.DataFrame(rows).to_csv(out / "missing_and_extremes_by_class.csv", index=False, lineterminator="\n")
    ext = []
    for col in X3 + D:
        v = num(ok[col])
        for idx in v.nlargest(3).index:
            ext.append({"feature": col, "row_id": ok.row_id[idx], "class": ok["class"][idx], "package": ok.package[idx], "value": v[idx]})
    pd.DataFrame(ext).to_csv(out / "top_values.csv", index=False, lineterminator="\n")
    ok[["row_id", "class"] + KEY + X3 + D + DIAG + ["x3_hook_state", "partial_targets"]].to_csv(out / "x3d_values.csv", index=False, lineterminator="\n")
    rep["inputs"] = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in a.jsonl}
    rep["script_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    (out / "report.json").write_text(json.dumps(rep, indent=1, default=str) + "\n")
    print(json.dumps({k: v for k, v in rep.items() if k not in ("inputs", "status")}, indent=1, default=str))
    print(st.to_string())


if __name__ == "__main__":
    main()
