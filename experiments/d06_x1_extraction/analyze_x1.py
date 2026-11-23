"""D06 X1 추출 결과를 기존 29개 feature와 병합하고 분포·중복성을 분석한다(학습 없음).

usage: python -I -B analyze_x1.py --train <train.csv> --baselines <baselines.csv> --groups <malicious_pair_groups.csv>
         --x1 <malicious.jsonl> <benign.jsonl> --out <dir>
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

KEY = ["package", "old_version", "new_version"]
X1 = ["installHookNewProgramCount", "installHookArgsChanged", "installHookRefFileChanged",
      "installHookNewExternalExecCount", "addedProcExecCallCount", "addedNetworkCallCount"]
X1_BOOL = {"installHookArgsChanged", "installHookRefFileChanged"}
CLASSES = ["malicious", "benign", "hard_benign"]


def auc(pos: np.ndarray, neg: np.ndarray) -> float:
    """Mann-Whitney AUC (동점 0.5). 결측은 호출 전에 뺀다."""
    if len(pos) == 0 or len(neg) == 0:
        return float("nan")
    allv = np.concatenate([pos, neg])
    ranks = pd.Series(allv).rank(method="average").to_numpy()
    return float((ranks[: len(pos)].sum() - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg)))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", required=True)
    ap.add_argument("--baselines", required=True)
    ap.add_argument("--groups", required=True)
    ap.add_argument("--x1", nargs="+", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    train = pd.read_csv(args.train, keep_default_na=False, dtype=str)
    feature29 = [c for c in train.columns if c not in KEY + ["label"]]
    assert len(feature29) == 29 and len(train) == 2767 and not train.duplicated(KEY).any()
    base = pd.read_csv(args.baselines, keep_default_na=False, dtype=str)[KEY + ["class"]]
    groups = pd.read_csv(args.groups, keep_default_na=False, dtype=str)[KEY + ["splitGroup"]]
    rows = [json.loads(line) for path in args.x1 for line in Path(path).read_text().splitlines()]
    x1 = pd.DataFrame(rows)
    for k in KEY:
        x1[k] = x1[k].astype(str)
    dup = x1.duplicated(KEY).sum()
    meta = train[KEY + ["label"]].merge(base, on=KEY, how="left", validate="one_to_one") \
        .merge(groups, on=KEY, how="left", validate="one_to_one")
    meta["splitGroup"] = meta["splitGroup"].fillna("")
    merged = meta.merge(x1[KEY + ["status", "error_stage", "error", "old_check", "new_check", "seconds"] + X1],
                        on=KEY, how="left", validate="one_to_one", indicator=True)
    checks = {
        "train_rows": len(train), "x1_rows": len(x1), "x1_duplicate_keys": int(dup),
        "train_pairs_without_x1_row": int((merged["_merge"] == "left_only").sum()),
        "x1_rows_not_in_train": int(len(x1.merge(train[KEY], on=KEY, how="left", indicator=True)
                                         .query("_merge == 'left_only'"))),
        "label_class_consistent": bool(((merged.label == "1") == (merged["class"] == "malicious")).all()),
        "class_counts": merged["class"].value_counts().to_dict(),
    }
    merged = merged.drop(columns="_merge")
    merged["status"] = merged["status"].fillna("missing_row")

    # --- 35개 feature 데이터셋(실패·결측은 빈 칸, 0으로 채우지 않음) ---
    x1_values = merged[KEY + X1].copy()
    failed = merged["status"] != "ok"
    for c in X1:
        x1_values.loc[failed, c] = None
    full35 = train.merge(x1_values, on=KEY, how="left", validate="one_to_one")
    full35 = full35[KEY + feature29 + X1 + ["label"]]
    assert full35[feature29 + ["label"]].equals(train[feature29 + ["label"]]), "29 feature/label changed"
    for c in X1:
        if c in X1_BOOL:
            full35[c] = full35[c].map({True: "True", False: "False", "True": "True", "False": "False"}).fillna("")
        else:
            full35[c] = pd.to_numeric(full35[c], errors="coerce").astype("Int64")
    full35.to_csv(out / "d06_full35.csv", index=False, lineterminator="\n")
    status = merged[KEY + ["label", "class", "splitGroup", "status", "error_stage", "error", "old_check", "new_check", "seconds"]]
    status.to_csv(out / "d06_x1_status.csv", index=False, lineterminator="\n")
    schema = [{"column": c, "group": "id"} for c in KEY] + \
             [{"column": c, "group": "full29", "dtype": "category[major,minor,patch]" if c == "updateType"
               else ("bool" if c in ("installScriptPresent", "installScriptAdded", "scriptEntryAdded", "newDependencyAdded")
                     else "float")} for c in feature29] + \
             [{"column": c, "group": "x1", "dtype": "bool (nullable)" if c in X1_BOOL else "int (nullable)"} for c in X1] + \
             [{"column": "label", "group": "target", "dtype": "int 0/1"}]
    (out / "d06_full35_schema.json").write_text(json.dumps(schema, indent=1, ensure_ascii=False) + "\n")

    # --- 분석용 숫자 프레임 ---
    df = merged.copy()
    feats = train.set_index(KEY)[feature29]
    df = df.join(feats, on=KEY)
    for c in X1:
        v = df[c].map(lambda x: np.nan if x is None or (isinstance(x, float) and np.isnan(x)) else float(x))
        df[c] = v.where(df.status == "ok")
    for c in feature29:
        if c == "updateType":
            continue
        df[c] = df[c].map(lambda s: np.nan if s == "" else (1.0 if s == "True" else 0.0 if s == "False" else float(s)))
    report: dict = {"checks": checks}

    # A. 추출 상태와 분포
    report["status_by_class"] = pd.crosstab(df["class"], df.status).to_dict()
    report["errors"] = df[df.status != "ok"].groupby(["class", "error_stage"]).size().rename("n").reset_index().to_dict("records")
    dist = []
    for c in X1:
        for cls in CLASSES:
            s = df.loc[df["class"] == cls, c]
            ok = df.loc[df["class"] == cls, "status"] == "ok"
            dist.append({"feature": c, "class": cls, "n": len(s), "extract_failed": int((~ok).sum()),
                         "missing_in_ok": int(s[ok].isna().sum()), "nonzero": int((s > 0).sum()),
                         "nonzero_rate_of_observed": float((s > 0).sum() / s.notna().sum()) if s.notna().sum() else np.nan,
                         "values": {str(int(k)): int(v) for k, v in s.dropna().value_counts().sort_index().head(8).items()}})
    pd.DataFrame(dist).to_csv(out / "x1_distribution.csv", index=False, lineterminator="\n")
    report["distribution"] = dist

    # 단일 feature 분리도(결측 제외)
    sep = []
    for c in X1 + [f for f in feature29 if f != "updateType"]:
        mal = df.loc[df["class"] == "malicious", c].dropna().to_numpy()
        for neg in ("benign", "hard_benign"):
            other = df.loc[df["class"] == neg, c].dropna().to_numpy()
            sep.append({"feature": c, "group": "x1" if c in X1 else "full29", "vs": neg, "auc": auc(mal, other),
                        "mal_missing": int(df.loc[df["class"] == "malicious", c].isna().sum()),
                        "neg_missing": int(df.loc[df["class"] == neg, c].isna().sum())})
    pd.DataFrame(sep).to_csv(out / "single_feature_auc.csv", index=False, lineterminator="\n")

    # B. 중복성: X1과 29개 Spearman(쌍별 결측 제외)
    num29 = [f for f in feature29 if f != "updateType"]
    corr = df[X1 + num29].corr(method="spearman").loc[X1, num29]
    corr.to_csv(out / "x1_vs_full29_spearman.csv", lineterminator="\n")
    top = {c: corr.loc[c].abs().sort_values(ascending=False).head(5).round(3).to_dict() for c in X1}
    report["top_spearman"] = top

    report["newprog_vs_installScriptAdded"] = (
        df.assign(newprog=df.installHookNewProgramCount.fillna(-1).astype(int))
        .groupby(["class", "installScriptAdded", "newprog"]).size().rename("n").reset_index().to_dict("records"))
    examples = {}
    d = df[(df.installScriptAdded == 1) & (df.installHookNewProgramCount == 0)]
    examples["installScriptAdded_true_newprog_0"] = d[KEY + ["class", "splitGroup"]].head(8).to_dict("records")
    d = df[(df.installScriptAdded == 0) & (df.installHookNewProgramCount > 0)]
    examples["installScriptAdded_false_newprog_pos"] = d[KEY + ["class", "splitGroup"]].head(8).to_dict("records")

    # installScriptAdded 같은 층 안에서 X1이 주는 추가 정보
    strata = []
    for isa in (0.0, 1.0):
        for c in X1:
            for cls in CLASSES:
                s = df.loc[(df.installScriptAdded == isa) & (df["class"] == cls), c]
                strata.append({"installScriptAdded": bool(isa), "feature": c, "class": cls, "n": len(s),
                               "observed": int(s.notna().sum()), "nonzero": int((s > 0).sum())})
    pd.DataFrame(strata).to_csv(out / "x1_within_installScriptAdded.csv", index=False, lineterminator="\n")

    # 파일 변경·난독화와의 관계
    df["obf_changed_any"] = (df.obfChangedFileCount > 0).astype(float)
    rel = []
    for c in X1:
        for cls in CLASSES:
            sub = df[df["class"] == cls]
            rel.append({"feature": c, "class": cls,
                        "nonzero_and_no_changed_js": int(((sub[c] > 0) & (sub.obfChangedFileCount == 0)).sum()),
                        "nonzero_with_changed_js": int(((sub[c] > 0) & (sub.obfChangedFileCount > 0)).sum()),
                        "zero_with_changed_js": int(((sub[c] == 0) & (sub.obfChangedFileCount > 0)).sum())})
    pd.DataFrame(rel).to_csv(out / "x1_vs_changed_js.csv", index=False, lineterminator="\n")
    for c in ["addedProcExecCallCount", "addedNetworkCallCount", "installHookRefFileChanged"]:
        examples[f"{c}_pos_benign_or_hard"] = df[(df[c] > 0) & (df["class"] != "malicious")] \
            .sort_values(c, ascending=False)[KEY + ["class", c]].head(8).to_dict("records")
        examples[f"{c}_zero_malicious_with_changed_js"] = df[(df[c] == 0) & (df["class"] == "malicious") & (df.obfChangedFileCount > 0)] \
            .groupby("splitGroup").size().sort_values(ascending=False).head(10).to_dict()
        examples[f"{c}_pos_malicious_top"] = df[(df[c] > 0) & (df["class"] == "malicious")] \
            .sort_values(c, ascending=False)[KEY + ["splitGroup", c]].head(6).to_dict("records")
    report["examples"] = examples

    # 캠페인 집중
    camp = []
    mal = df[df["class"] == "malicious"]
    for c in X1:
        pos = mal[mal[c] > 0]
        g = pos.groupby("splitGroup").size().sort_values(ascending=False)
        camp.append({"feature": c, "malicious_nonzero": len(pos), "campaigns": int(len(g)),
                     "top_campaign": g.index[0] if len(g) else "", "top_share": float(g.iloc[0] / len(pos)) if len(g) else np.nan,
                     "by_campaign": g.head(8).to_dict()})
    report["campaign_concentration"] = camp

    (out / "analysis_report.json").write_text(json.dumps(report, indent=1, ensure_ascii=False, default=str) + "\n")
    print(json.dumps(checks, ensure_ascii=False))


if __name__ == "__main__":
    main()
