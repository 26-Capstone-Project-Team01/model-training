"""Parity check: D08-commit re-extraction of a D06 sample vs saved D06 X1 / X3 / D values and the frozen D08 base features.
usage: python -I -B check_parity.py --jsonl parity.jsonl --mt <model-training exp/d06-x3-test-final experiments dir> --inputs <dir> --out <dir>"""
import argparse, json
from pathlib import Path
import numpy as np, pandas as pd

KEY = ["package", "old_version", "new_version"]
X1 = ["installHookNewProgramCount", "installHookArgsChanged", "installHookRefFileChanged", "installHookNewExternalExecCount", "addedProcExecCallCount", "addedNetworkCallCount"]
X3 = ["installHookTargetCount", "installHookTargetMaxBytes", "obfHookHexIdentRatio", "obfHookHexNumberRatio", "obfHookBracketAccessRatio", "obfHookEscapeDensity",
      "obfHookShortIdentRatio", "obfHookMeanIdentLength", "obfHookWhitespaceRatio", "installHookTargetProcExecCallCount", "installHookTargetNetworkCallCount",
      "addedNetworkCallPer1kAddedTokens", "addedProcExecCallPer1kAddedTokens"]
D = ["dependencyRangeChangedCount", "dependencyChangedRatio"]


def norm(v):
    if v is None or (isinstance(v, float) and np.isnan(v)) or v == "": return None
    if isinstance(v, bool) or v in ("True", "False", "true", "false"): return 1.0 if str(v).lower() == "true" else 0.0
    try: return float(v)
    except (TypeError, ValueError): return str(v)


def same(a, b):
    a, b = norm(a), norm(b)
    if a is None or b is None: return a is None and b is None
    if isinstance(a, float) and isinstance(b, float): return abs(a - b) <= 1e-9 * max(1.0, abs(a), abs(b))
    return a == b


def main():
    ap = argparse.ArgumentParser()
    for n in ("--jsonl", "--mt", "--inputs", "--out"): ap.add_argument(n, required=True)
    a = ap.parse_args(); mt, inp, out = Path(a.mt), Path(a.inputs), Path(a.out); out.mkdir(parents=True, exist_ok=True)
    J = pd.DataFrame([json.loads(l) for l in open(a.jsonl)])
    rd = lambda p: pd.read_csv(p, dtype=str, keep_default_na=False)
    ref_x1 = pd.concat([rd(mt / "d06_x1_extraction/analysis/d06_full35.csv"), rd(mt / "d06_test_eval/analysis/d06_test_full35.csv")])
    ref_x3 = pd.concat([rd(mt / "d06_x3_extraction/analysis/d06_x3d.csv"), rd(mt / "d06_x3_extraction/test_analysis/d06_test_x3d.csv")])
    base = pd.concat([rd(inp / "d08_train.csv"), rd(inp / "d08_test.csv")])
    BASE = [c for c in base.columns if c not in KEY + ["label", "updateInterval"]]  # updateInterval: extractor uses fixed publish time
    rows, n_cmp = [], 0
    for src, cols, ref in (("X1(d06_full35)", X1, ref_x1), ("X3D(d06_x3d)", X3 + D, ref_x3), ("base28(D08 frozen)", BASE, base)):
        m = J.merge(ref, on=KEY, how="left", suffixes=("", "_ref"), indicator=True)
        for _, r in m.iterrows():
            if r["status"] != "ok":
                rows.append({"source": src, **{k: r[k] for k in KEY}, "feature": "*", "extracted": r["status"], "reference": r.get("error", ""), "match": False}); continue
            if r["_merge"] != "both":
                rows.append({"source": src, **{k: r[k] for k in KEY}, "feature": "*", "extracted": "", "reference": "missing in reference", "match": False}); continue
            for c in cols:
                ref_c = c + "_ref" if c + "_ref" in m.columns else c
                n_cmp += 1
                if not same(r.get(c), r.get(ref_c)):
                    rows.append({"source": src, **{k: r[k] for k in KEY}, "feature": c, "extracted": r.get(c), "reference": r.get(ref_c), "match": False})
    M = pd.DataFrame(rows, columns=["source"] + KEY + ["feature", "extracted", "reference", "match"])
    M.to_csv(out / "parity_mismatches.csv", index=False)
    summ = {"pairs": len(J), "status": {f"{a}|{b}": int(n) for (a, b), n in J.groupby(["class", "status"]).size().items()}, "values_compared": n_cmp,
            "mismatches": len(M), "mismatch_by_source_feature": {f"{a}|{b}": int(n) for (a, b), n in M.groupby(["source", "feature"]).size().items()}}
    (out / "parity_summary.json").write_text(json.dumps(summ, indent=1) + "\n"); print(json.dumps(summ, indent=1))


if __name__ == "__main__":
    main()
