"""D06 Test 677쌍의 X1 추출 결과를 기존 29개 feature와 병합하고 검증한다(학습·예측·성능 계산 없음).

병합 형식은 ../d06_x1_extraction/analyze_x1.py(Train)의 병합 부분과 같다:
행 순서 = test.csv, 열 = 키 3 + 29개 + X1 6개 + label, bool X1은 "True"/"False"/빈 칸, 개수 X1은 nullable int,
추출 실패(status != ok)는 X1 6개를 빈 칸으로 둔다(0으로 채우지 않음).

usage: python -I -B merge_x1_test.py --test <test.csv(be87ab4c)> --test-main <test.csv(main 4498acd)> --baselines <baselines.csv>
        --groups <malicious_pair_groups.csv> --x1 <malicious.jsonl> <benign.jsonl> --train-full35 <../d06_x1_extraction/analysis/d06_full35.csv>
        --train-schema <../d06_x1_extraction/analysis/d06_full35_schema.json> --out <dir>
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import pandas as pd

KEY = ["package", "old_version", "new_version"]
X1 = ["installHookNewProgramCount", "installHookArgsChanged", "installHookRefFileChanged",
      "installHookNewExternalExecCount", "addedProcExecCallCount", "addedNetworkCallCount"]
X1_BOOL = {"installHookArgsChanged", "installHookRefFileChanged"}
VANT3 = {("vant", "4.9.11", "4.9.12"), ("vant", "4.9.11", "4.9.13"), ("vant", "4.9.11", "4.9.14")}
TEST_SHA = "e8a70053ce639ebc79d7bc8d9402578d3ceaf24853ed31735b5f55c418b8bd73"
TEST_MAIN_SHA = "604673b95d88009efe5d3200606de972bffa541dea3d75be37163ee501465060"


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser()
    for n in ("--test", "--test-main", "--baselines", "--groups", "--train-full35", "--train-schema", "--out"):
        ap.add_argument(n, required=True)
    ap.add_argument("--x1", nargs="+", required=True)
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    checks = {"input_sha256": {"test": sha(args.test), "test_main": sha(args.test_main), "baselines": sha(args.baselines),
                               "groups": sha(args.groups), "x1": {Path(p).name: sha(p) for p in args.x1}}}
    assert checks["input_sha256"]["test"] == TEST_SHA and checks["input_sha256"]["test_main"] == TEST_MAIN_SHA

    test = pd.read_csv(args.test, keep_default_na=False, dtype=str)
    feature29 = [c for c in test.columns if c not in KEY + ["label"]]
    assert len(feature29) == 29 and len(test) == 677 and not test.duplicated(KEY).any()
    base = pd.read_csv(args.baselines, keep_default_na=False, dtype=str)[KEY + ["class"]]
    groups = pd.read_csv(args.groups, keep_default_na=False, dtype=str)[KEY + ["splitGroup"]]
    rows = [json.loads(line) for p in args.x1 for line in Path(p).read_text().splitlines()]
    x1 = pd.DataFrame(rows)
    for k in KEY:
        x1[k] = x1[k].astype(str)
    meta = test[KEY + ["label"]].merge(base, on=KEY, how="left", validate="one_to_one") \
        .merge(groups, on=KEY, how="left", validate="one_to_one")
    meta["splitGroup"] = meta["splitGroup"].fillna("")
    merged = meta.merge(x1[KEY + ["status", "error_stage", "error", "old_check", "new_check", "seconds"] + X1],
                        on=KEY, how="left", validate="one_to_one", indicator=True)
    checks |= {
        "test_rows": len(test), "x1_rows": len(x1), "x1_duplicate_keys": int(x1.duplicated(KEY).sum()),
        "test_pairs_without_x1_row": int((merged["_merge"] == "left_only").sum()),
        "x1_rows_not_in_test": int(len(x1.merge(test[KEY], on=KEY, how="left", indicator=True).query("_merge == 'left_only'"))),
        "label_class_consistent": bool(((merged.label == "1") == (merged["class"] == "malicious")).all()),
        "class_counts": merged["class"].value_counts().to_dict(),
    }
    merged = merged.drop(columns="_merge")
    merged["status"] = merged["status"].fillna("missing_row")

    # object로 바꿔 둔다: Test는 bool X1에 결측이 없으면 dtype이 bool이 되어 None 대입이 실패한다(pandas 3).
    # Train(analyze_x1.py)은 결측이 있어 처음부터 object였다. 출력 형식은 같다.
    x1_values = merged[KEY + X1].copy().astype({c: object for c in X1})
    failed = merged["status"] != "ok"
    for c in X1:
        x1_values.loc[failed, c] = None
    full35 = test.merge(x1_values, on=KEY, how="left", validate="one_to_one")
    full35 = full35[KEY + feature29 + X1 + ["label"]]
    assert full35[KEY + feature29 + ["label"]].equals(test[KEY + feature29 + ["label"]]), "keys/29 feature/label changed"
    for c in X1:
        if c in X1_BOOL:
            full35[c] = full35[c].map({True: "True", False: "False", "True": "True", "False": "False"}).fillna("")
        else:
            full35[c] = pd.to_numeric(full35[c], errors="coerce").astype("Int64")
    full35.to_csv(out / "d06_test_full35.csv", index=False, lineterminator="\n")
    status = merged[KEY + ["label", "class", "splitGroup", "status", "error_stage", "error", "old_check", "new_check", "seconds"]].copy()
    status["excluded_in_test674"] = status[KEY].apply(tuple, axis=1).isin(VANT3)
    status.to_csv(out / "d06_test_x1_status.csv", index=False, lineterminator="\n")

    # --- 검증: Train full35와 열·형식 동일성 ---
    train35 = pd.read_csv(args.train_full35, keep_default_na=False, dtype=str, nrows=5)
    schema_train = json.loads(Path(args.train_schema).read_text())
    re35 = pd.read_csv(out / "d06_test_full35.csv", keep_default_na=False, dtype=str)
    checks |= {
        "columns_identical_to_train_full35": list(re35.columns) == list(train35.columns),
        "schema_columns_identical": [c["column"] for c in schema_train] == list(re35.columns),
        "bool_x1_values_seen": {c: sorted(set(re35[c].unique())) for c in X1_BOOL},
        "bool_x1_values_ok": all(set(re35[c].unique()) <= {"True", "False", ""} for c in X1_BOOL),
        "int_x1_non_integer_strings": {c: int((~re35[c].str.fullmatch(r"\d*")).sum()) for c in X1 if c not in X1_BOOL},
        "keys_label_29_unchanged_vs_test_csv": bool(re35[KEY + feature29 + ["label"]].equals(test[KEY + feature29 + ["label"]])),
        "status_counts": status["status"].value_counts().to_dict(),
        "failed_pairs": status[status.status != "ok"][KEY + ["class", "error_stage", "error"]].to_dict("records"),
        "x1_missing_in_ok_rows": {c: int((re35.loc[(status.status == "ok").values, c] == "").sum()) for c in X1},
        "x1_missing_total": {c: int((re35[c] == "").sum()) for c in X1},
        "x1_missing_in_ok_by_class": {c: status[(status.status == "ok").values & (re35[c] == "").values]["class"].value_counts().to_dict() for c in X1},
        "source_check_counts": {"old": status.old_check.value_counts(dropna=False).to_dict(), "new": status.new_check.value_counts(dropna=False).to_dict()},
    }
    # --- Test-674: 키 기준 필터가 main test.csv와 같은지 ---
    main674 = pd.read_csv(args.test_main, keep_default_na=False, dtype=str)
    t674 = re35[~re35[KEY].apply(tuple, axis=1).isin(VANT3)].reset_index(drop=True)
    checks |= {
        "vant3_present_in_677": int(re35[KEY].apply(tuple, axis=1).isin(VANT3).sum()),
        "test674_rows": len(t674),
        "test674_equals_main_test_csv_on_33_cols": bool(t674[list(main674.columns)].equals(main674)),
        "test674_class_counts": status[~status.excluded_in_test674]["class"].value_counts().to_dict(),
    }
    schema = schema_train  # 같은 열·자료형 정의를 그대로 기록
    (out / "d06_test_full35_schema.json").write_text(json.dumps(schema, indent=1, ensure_ascii=False) + "\n")
    checks["output_sha256"] = {p.name: sha(p) for p in sorted(out.glob("d06_test_*"))}
    (out / "validation.json").write_text(json.dumps(checks, indent=1, ensure_ascii=False, default=str) + "\n")
    print(json.dumps({k: v for k, v in checks.items() if k not in ("failed_pairs", "output_sha256")}, indent=1, ensure_ascii=False, default=str))
    print("failed_pairs:", json.dumps(checks["failed_pairs"], ensure_ascii=False))


if __name__ == "__main__":
    main()
