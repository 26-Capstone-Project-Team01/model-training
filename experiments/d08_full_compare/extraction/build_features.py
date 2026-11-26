"""Merge X1 / X3 / D for every D08 pair: D06 Train/Test-677 rows reuse the saved D06 extraction, the 2,581 new rows come from
extract_d08_x3d.py (new.jsonl). Clipper 6 pairs are not extracted (status=excluded_clipper). Errors stay empty with a status.
X1 booleans are encoded exactly as run_test_eval.encode_x1 (True/False -> 1/0). Output: features_x1x3d_d08.csv, status csv, manifest.
usage: python -I -B build_features.py --new-jsonl new.jsonl --mt <exp/d06-x3-test-final experiments> --inputs <dir> --clipper <csv> --out <dir>"""
import argparse, hashlib, json
from pathlib import Path
import numpy as np, pandas as pd

KEY = ["package", "old_version", "new_version"]
X1 = ["installHookNewProgramCount", "installHookArgsChanged", "installHookRefFileChanged", "installHookNewExternalExecCount", "addedProcExecCallCount", "addedNetworkCallCount"]
X1_BOOL = {"installHookArgsChanged", "installHookRefFileChanged"}
X3 = ["installHookTargetCount", "installHookTargetMaxBytes", "obfHookHexIdentRatio", "obfHookHexNumberRatio", "obfHookBracketAccessRatio", "obfHookEscapeDensity",
      "obfHookShortIdentRatio", "obfHookMeanIdentLength", "obfHookWhitespaceRatio", "installHookTargetProcExecCallCount", "installHookTargetNetworkCallCount",
      "addedNetworkCallPer1kAddedTokens", "addedProcExecCallPer1kAddedTokens"]
D = ["dependencyRangeChangedCount", "dependencyChangedRatio"]
COLS = X1 + X3 + D


def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def enc(frame):
    out = frame[KEY].copy()
    for c in COLS:
        s = frame[c].astype(str).replace({"nan": "", "None": ""})
        if c in X1_BOOL:
            assert set(s) <= {"True", "False", ""}, c
            out[c] = s.map({"True": 1.0, "False": 0.0, "": np.nan}).astype(float)
        else:
            out[c] = pd.to_numeric(s.replace("", np.nan), errors="raise").astype(float)
    return out


def main():
    ap = argparse.ArgumentParser()
    for n in ("--new-jsonl", "--mt", "--inputs", "--clipper", "--out"): ap.add_argument(n, required=True)
    a = ap.parse_args(); mt, inp, out = Path(a.mt), Path(a.inputs), Path(a.out); out.mkdir(parents=True, exist_ok=False)
    rd = lambda p: pd.read_csv(p, dtype=str, keep_default_na=False)
    d8 = pd.concat([rd(inp / "d08_train.csv").assign(split="train"), rd(inp / "d08_test.csv").assign(split="test")], ignore_index=True)[KEY + ["split"]]
    clip = set(map(tuple, rd(a.clipper)[KEY].values))
    # D06 saved: X1 (train d06_full35, test d06_test_full35) + X3/D (d06_x3d, d06_test_x3d) with their status files
    x1 = pd.concat([rd(mt / "d06_x1_extraction/analysis/d06_full35.csv"), rd(mt / "d06_test_eval/analysis/d06_test_full35.csv")])
    x3 = pd.concat([rd(mt / "d06_x3_extraction/analysis/d06_x3d.csv"), rd(mt / "d06_x3_extraction/test_analysis/d06_test_x3d.csv")])
    st6 = pd.concat([rd(mt / "d06_x3_extraction/analysis/d06_x3d_status.csv"), rd(mt / "d06_x3_extraction/test_analysis/d06_test_x3d_status.csv")])
    old = x1[KEY + X1].merge(x3[KEY + X3 + D], on=KEY, how="outer", validate="one_to_one")
    old = enc(old).assign(source="d06_saved")
    stc = "status" if "status" in st6.columns else st6.columns[3]
    old = old.merge(st6[KEY + [stc]].rename(columns={stc: "extract_status"}), on=KEY, how="left")
    # new extraction
    J = pd.DataFrame([json.loads(l) for l in open(a.new_jsonl)])
    assert J.row_id.is_unique
    new = enc(J.assign(**{c: J[c] if c in J.columns else np.nan for c in COLS})).assign(source="d08_new_extraction")
    new["extract_status"] = J.status.values; new["error_stage"] = J.get("error_stage", "").values
    F = d8.merge(pd.concat([old, new], ignore_index=True), on=KEY, how="left", validate="one_to_one")
    k = F[KEY].apply(tuple, axis=1)
    F.loc[k.isin(clip), "source"] = "excluded_clipper"; F.loc[k.isin(clip), "extract_status"] = "excluded_clipper"
    F["source"] = F.source.fillna("missing"); F["extract_status"] = F.extract_status.fillna("missing")
    F.to_csv(out / "features_x1x3d_d08.csv", index=False, lineterminator="\n")
    S = F.groupby(["split", "source", "extract_status"]).size().rename("pairs").reset_index(); S.to_csv(out / "coverage.csv", index=False)
    na = F[F.source != "excluded_clipper"][COLS].isna().groupby(F.split).sum().T; na.to_csv(out / "missing_values_by_feature.csv")
    errs = F[F.extract_status.isin(["error", "missing"])][KEY + ["split", "source", "extract_status", "error_stage"]]
    errs.to_csv(out / "errors_and_missing_pairs.csv", index=False)
    (out / "manifest.json").write_text(json.dumps({"rows": len(F), "coverage": S.to_dict("records"), "errors_or_missing": len(errs),
        "inputs_sha256": {"new_jsonl": sha(a.new_jsonl)}, "features": COLS, "x1_bool_encoding": "True->1, False->0 (run_test_eval.encode_x1)"}, indent=1, default=str) + "\n")
    print(S.to_string(index=False)); print("errors/missing:", len(errs))


if __name__ == "__main__":
    main()
