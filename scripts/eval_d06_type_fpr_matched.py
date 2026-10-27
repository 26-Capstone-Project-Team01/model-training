"""D06 유형별(A/B/C)·동일 FPR 평가표: 저장된 3-fold CV out-of-fold 예측만으로 계산한다.
모델을 다시 학습하지 않고, Test(677쌍)는 읽지 않는다.

비교 대상
- 모델: E06, E09(results/diagnostics/d06_diag01_pair_predictions.csv),
  E10 alpha=0.25, 0.75(results/e10/d06_e10_pair_predictions.csv).
  E10 alpha=0 / 0.5는 E06 / E09와 pair별 pred·proba·fold가 완전히 같아(run_e10_campaign_weight_alpha.py
  에서 재사용) 별도 행으로 넣지 않는다.
- 규칙(train.csv의 bool feature만 사용):
  R1 = installScriptAdded
  R2 = installScriptAdded OR scriptEntryAdded            (= 유형 A)
  R3 = installScriptAdded OR scriptEntryAdded OR newDependencyAdded  (= 유형 A ∪ B)

유형(악성 Recall 분해용, 모든 pair에 붙인다)
- A: installScriptAdded OR scriptEntryAdded
- B: A가 아니고 newDependencyAdded
- C: 나머지

임계값 선택(모델)
- Train 정상 1,839쌍(benign 1,600 + hard_benign 239)의 OOF proba를 3 fold 합쳐서(pooled) 쓴다.
- 목표 FPR에서 허용 FP 수 k = floor(target_fpr * 1839)(규칙 FPR에 맞출 때는 그 규칙의 FP 수를
  그대로 k로 쓴다 — 부동소수점 반올림으로 k가 1 작아지는 것을 막기 위해).
- 정상 점수를 내림차순 b_1 >= b_2 >= ... 로 놓으면 FP <= k를 만족하는 가장 낮은 임계값은
  b_(k+1)이고 판정은 proba > b_(k+1)(엄격한 부등호)이다. CSV의 threshold 컬럼이 이 b_(k+1)이며,
  decision_rule 컬럼에 판정식을 적는다. b_(k+1)과 같은 점수의 정상 pair는 동점이라 모두 함께 빠지고
  (그래서 달성 FPR이 목표보다 낮을 수 있다), 같은 점수의 악성 pair도 탐지되지 않는다.
- proba는 float_precision="round_trip"으로 읽는다. pandas 기본 parser는 17자리 소수를 1 ulp 다른 값으로
  읽을 수 있어, 동점 판정과 임계값 재적용이 저장된 값과 어긋날 수 있기 때문이다.
- 기존 기본 임계값 0.5(pred 컬럼) 행도 함께 남겨 기존 집계와 대조한다.

지표
- 전체 FPR(정상 1,839), hard benign FPR(hard_benign 239), 전체 Recall(악성 928),
  A/B/C Recall, 캠페인 평균 Recall(악성 campaign 컬럼 = upstream splitGroup 19개, individuals_case는
  run_cv_e06_e09.campaign_recall_breakdown과 같이 한 묶음으로 센다; 캠페인별 Recall의 단순 평균).

train.csv
- data/raw/train.csv(.gitignore 대상, train_model.py와 같은 위치)를 읽는다. data/SOURCE.json은 읽기만
  하고 수정하지 않는다. 고정 커밋 be87ab4cf의 derived/splits/train.csv와 SHA-256이 같은지 확인한다.
- 파일이 없으면 둘 중 하나로 train.csv만 가져온다(test.csv·split_assignment.csv는 받지 않음):
    python scripts/eval_d06_type_fpr_matched.py --fetch-train-from-clone <npm-malware-package-pairs 클론 경로>
    GITHUB_TOKEN=... python scripts/eval_d06_type_fpr_matched.py --fetch-train-from-github
  또는 직접: git -C <클론> show be87ab4cff66fff1980c4a71be8032b6b47225ba:derived/splits/train.csv > data/raw/train.csv

출력(results/type_fpr/)
- d06_type_fpr_matched.csv: 방법 x 운영점별 지표
- d06_type_fpr_matched_campaign_recall.csv: 방법 x 운영점 x 캠페인별 Recall
- d06_type_fpr_matched.md: 요약 보고서

Usage (from the repo root):
    python scripts/eval_d06_type_fpr_matched.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import subprocess
import sys
from pathlib import Path

import numpy as np
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
SOURCE_PATH = BASE_DIR / "data" / "SOURCE.json"
TRAIN_PATH = BASE_DIR / "data" / "raw" / "train.csv"
DIAG01_PRED_PATH = BASE_DIR / "results" / "diagnostics" / "d06_diag01_pair_predictions.csv"
E10_PRED_PATH = BASE_DIR / "results" / "e10" / "d06_e10_pair_predictions.csv"
CV_FOLD_METRICS_PATH = BASE_DIR / "results" / "cv" / "d06_e06_e09_3fold_cv.csv"
E10_FOLD_METRICS_PATH = BASE_DIR / "results" / "e10" / "d06_e10_fold_metrics.csv"

OUT_DIR = BASE_DIR / "results" / "type_fpr"
OUT_CSV = OUT_DIR / "d06_type_fpr_matched.csv"
OUT_CAMPAIGN_CSV = OUT_DIR / "d06_type_fpr_matched_campaign_recall.csv"
OUT_MD = OUT_DIR / "d06_type_fpr_matched.md"

TRAIN_REPO = "26-Capstone-Project-Team01/npm-malware-package-pairs"
TRAIN_COMMIT = "be87ab4cff66fff1980c4a71be8032b6b47225ba"
TRAIN_UPSTREAM_PATH = "derived/splits/train.csv"
TRAIN_SHA256 = "22fbc8752fff5fff90e40b911f6bf7d187769b4566db957d65a37a16be7d2c23"
N_TRAIN, N_MALICIOUS, N_BENIGN, N_HARD_BENIGN = 2767, 928, 1839, 239

KEY = ["package", "old_version", "new_version", "label"]
TYPES = ("A", "B", "C")
TARGET_FPRS = {"fpr_1pct": 0.01, "fpr_5pct": 0.05}
RULES = {
    "R1": "installScriptAdded",
    "R2": "installScriptAdded OR scriptEntryAdded",
    "R3": "installScriptAdded OR scriptEntryAdded OR newDependencyAdded",
}
MODELS = ("E06", "E09", "E10_a0.25", "E10_a0.75")


# ---------------------------------------------------------------- train.csv

def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_train(data: bytes) -> None:
    if sha256_of(data) != TRAIN_SHA256:
        raise SystemExit(f"가져온 train.csv의 SHA-256이 고정값({TRAIN_SHA256[:12]}...)과 다릅니다 — 저장하지 않습니다")
    TRAIN_PATH.parent.mkdir(parents=True, exist_ok=True)
    TRAIN_PATH.write_bytes(data)
    print(f"data/raw/train.csv 저장 ({len(data):,} bytes, {TRAIN_COMMIT[:9]}:{TRAIN_UPSTREAM_PATH})")


def fetch_train_from_clone(clone: Path) -> None:
    data = subprocess.run(
        ["git", "-C", str(clone), "show", f"{TRAIN_COMMIT}:{TRAIN_UPSTREAM_PATH}"],
        capture_output=True, check=True,
    ).stdout
    write_train(data)


def fetch_train_from_github() -> None:
    # fetch_data.py의 GitHub API 호출만 재사용한다(main()은 SOURCE.json을 고치므로 부르지 않는다).
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import fetch_data  # noqa: E402

    write_train(fetch_data.fetch_file(TRAIN_REPO, TRAIN_UPSTREAM_PATH, TRAIN_COMMIT, fetch_data.get_token()))


def load_train() -> pd.DataFrame:
    source = json.loads(SOURCE_PATH.read_text(encoding="utf-8"))
    if source["commit"] != TRAIN_COMMIT:
        raise SystemExit(f"data/SOURCE.json의 commit({source['commit'][:9]})이 이 평가의 고정 커밋({TRAIN_COMMIT[:9]})과 다릅니다")
    if not TRAIN_PATH.exists():
        raise SystemExit(
            "data/raw/train.csv가 없습니다. --fetch-train-from-clone <클론 경로> 또는 "
            "--fetch-train-from-github(GITHUB_TOKEN 필요)로 train.csv만 가져오세요(모듈 docstring 참고)."
        )
    if sha256_of(TRAIN_PATH.read_bytes()) != TRAIN_SHA256:
        raise SystemExit(f"data/raw/train.csv가 {TRAIN_COMMIT[:9]}:{TRAIN_UPSTREAM_PATH}와 다릅니다(SHA-256 불일치)")
    train = pd.read_csv(TRAIN_PATH, dtype={"old_version": str, "new_version": str}, float_precision="round_trip")
    assert len(train) == N_TRAIN and (train["label"] == 1).sum() == N_MALICIOUS, "train.csv 행 수가 예상과 다릅니다"
    assert not train.duplicated(KEY).any()
    return train


def add_types(train: pd.DataFrame) -> pd.DataFrame:
    is_a = train["installScriptAdded"] | train["scriptEntryAdded"]
    is_b = ~is_a & train["newDependencyAdded"]
    train = train.copy()
    train["type"] = np.select([is_a, is_b], ["A", "B"], "C")
    train["R1"] = train["installScriptAdded"].astype(int)
    train["R2"] = is_a.astype(int)
    train["R3"] = (is_a | train["newDependencyAdded"]).astype(int)
    return train


# ---------------------------------------------------------------- predictions

def load_predictions(train: pd.DataFrame) -> dict[str, pd.DataFrame]:
    dtype = {"old_version": str, "new_version": str}
    diag = pd.read_csv(DIAG01_PRED_PATH, dtype=dtype, float_precision="round_trip")
    e10 = pd.read_csv(E10_PRED_PATH, dtype=dtype, float_precision="round_trip")
    variants = {
        "E06": diag[diag["variant"] == "E06"],
        "E09": diag[diag["variant"] == "E09"],
        "E10_a0.25": e10[e10["alpha"] == 0.25],
        "E10_a0.75": e10[e10["alpha"] == 0.75],
    }
    feats = train[KEY + ["type"]]
    out = {}
    for name, df in variants.items():
        df = df[KEY + ["class", "campaign", "fold", "pred", "proba"]].reset_index(drop=True)
        assert len(df) == N_TRAIN and not df.duplicated(KEY).any(), f"{name}: 행 수/중복 이상"
        merged = df.merge(feats, on=KEY, how="inner", validate="one_to_one")
        assert len(merged) == N_TRAIN, f"{name}: train.csv와 1:1로 결합되지 않습니다"
        assert ((merged["class"] == "malicious") == (merged["label"] == 1)).all()
        out[name] = merged
    return out


def pair_frame(preds: dict[str, pd.DataFrame], train: pd.DataFrame) -> pd.DataFrame:
    """class/campaign/type이 붙은 2,767쌍 기준 프레임(규칙 평가용). class와 campaign은 모델 예측
    파일에서 가져온다(train.csv에는 없다)."""
    base = preds["E06"][KEY + ["class", "campaign", "type"]]
    return base.merge(train[KEY + ["R1", "R2", "R3"]], on=KEY, how="inner", validate="one_to_one")


# ---------------------------------------------------------------- thresholds & metrics

def select_threshold(benign_scores: np.ndarray, max_fp: int) -> float:
    """FP(proba > t) <= max_fp를 만족하는 가장 낮은 t(= max_fp+1번째로 높은 정상 점수)를 돌려준다.
    t와 동점인 정상 점수는 모두 음성으로 남는다."""
    s = np.sort(benign_scores)[::-1]
    if max_fp >= len(s):
        return -math.inf
    return float(s[max_fp])


def metrics(df: pd.DataFrame, pred: np.ndarray) -> tuple[dict, pd.DataFrame]:
    pred = np.asarray(pred).astype(bool)
    is_mal = (df["label"] == 1).to_numpy()
    is_hard = (df["class"] == "hard_benign").to_numpy()
    fp = int((pred & ~is_mal).sum())
    hard_fp = int((pred & is_hard).sum())
    tp = int((pred & is_mal).sum())
    row = {
        "fp": fp, "achieved_fpr": fp / N_BENIGN,
        "hard_benign_fp": hard_fp, "hard_benign_fpr": hard_fp / N_HARD_BENIGN,
        "tp": tp, "recall": tp / N_MALICIOUS,
    }
    for t in TYPES:
        m = is_mal & (df["type"] == t).to_numpy()
        row[f"n_{t}"] = int(m.sum())
        row[f"tp_{t}"] = int((pred & m).sum())
        row[f"recall_{t}"] = row[f"tp_{t}"] / row[f"n_{t}"]
    mal = df.loc[is_mal, ["campaign"]].assign(caught=pred[is_mal])
    camp = mal.groupby("campaign")["caught"].agg(n="size", caught="sum").reset_index()
    camp["recall"] = camp["caught"] / camp["n"]
    row["n_campaigns"] = len(camp)
    row["campaign_mean_recall"] = float(camp["recall"].mean())
    return row, camp


def evaluate(preds: dict[str, pd.DataFrame], pairs: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    rows, camp_rows = [], []

    def record(method, kind, op, target_fpr, max_fp, threshold, rule, df, pred, ties=(None, None)):
        row, camp = metrics(df, pred)
        rows.append({
            "method": method, "method_type": kind, "operating_point": op,
            "target_fpr": target_fpr, "target_max_fp": max_fp,
            "threshold": threshold, "decision_rule": rule,
            "benign_ties_at_threshold": ties[0], "malicious_ties_at_threshold": ties[1],
            **row,
        })
        camp_rows.append(camp.assign(method=method, operating_point=op))

    rule_fp = {}
    for rule, definition in RULES.items():
        pred = pairs[rule].to_numpy()
        record(rule, "rule", "rule", None, None, None, definition, pairs, pred)
        rule_fp[rule] = rows[-1]["fp"]

    targets = [(op, fpr, int(math.floor(fpr * N_BENIGN + 1e-9))) for op, fpr in TARGET_FPRS.items()]
    targets += [(f"match_{r}", rule_fp[r] / N_BENIGN, rule_fp[r]) for r in RULES]

    for name in MODELS:
        df = preds[name]
        proba = df["proba"].to_numpy()
        benign = proba[(df["label"] == 0).to_numpy()]
        malicious = proba[(df["label"] == 1).to_numpy()]
        record(name, "model", "default_0.5", None, None, 0.5, "proba >= threshold", df, df["pred"].to_numpy())
        for op, target_fpr, max_fp in targets:
            thr = select_threshold(benign, max_fp)
            ties = (int((benign == thr).sum()), int((malicious == thr).sum()))
            record(name, "model", op, target_fpr, max_fp, thr, "proba > threshold", df, proba > thr, ties)
            assert rows[-1]["fp"] <= max_fp

    table = pd.DataFrame(rows)
    camp = pd.concat(camp_rows, ignore_index=True)[["method", "operating_point", "campaign", "n", "caught", "recall"]]
    return table, camp


# ---------------------------------------------------------------- consistency checks

def check_against_existing(table: pd.DataFrame, preds: dict[str, pd.DataFrame]) -> list[str]:
    """기존 fold별 집계(threshold 0.5)를 합산한 값과 default_0.5 행이 같은지, 선택한 임계값이 실제로
    '목표 FPR을 넘지 않는 가장 낮은 임계값'인지(모든 관측 점수 후보를 전수 확인) 검사한다."""
    notes = []
    cv = pd.read_csv(CV_FOLD_METRICS_PATH)
    e10 = pd.read_csv(E10_FOLD_METRICS_PATH)
    for name, df in preds.items():
        assert ((df["proba"] >= 0.5).astype(int) == df["pred"]).all(), f"{name}: pred가 proba >= 0.5와 다릅니다"
    existing = {
        "E06": cv[cv["variant"] == "E06"], "E09": cv[cv["variant"] == "E09"],
        "E10_a0.25": e10[e10["alpha"] == 0.25], "E10_a0.75": e10[e10["alpha"] == 0.75],
    }
    for name, folds in existing.items():
        row = table[(table["method"] == name) & (table["operating_point"] == "default_0.5")].iloc[0]
        assert row["tp"] == folds["tp"].sum() and row["fp"] == folds["fp"].sum(), f"{name}: 기존 fold 집계와 다릅니다"
        notes.append(f"{name}: threshold 0.5 TP {row['tp']} / FP {row['fp']} = 기존 fold 집계 합과 일치")

    for name in MODELS:
        df = preds[name]
        proba = df["proba"].to_numpy()
        is_ben = (df["label"] == 0).to_numpy()
        candidates = np.unique(proba)
        fp_at = np.array([(proba[is_ben] > c).sum() for c in candidates])
        for _, row in table[(table["method"] == name) & table["target_max_fp"].notna()].iterrows():
            lowest = candidates[fp_at <= row["target_max_fp"]].min()
            assert lowest == row["threshold"], f"{name} {row['operating_point']}: 전수 탐색 결과와 임계값이 다릅니다"
    notes.append("모든 모델·운영점: 관측 점수 전체를 후보로 전수 탐색한 '가장 낮은 유효 임계값'과 선택한 임계값이 같음")
    return notes


# ---------------------------------------------------------------- report

def fmt(x: float) -> str:
    return f"{x * 100:.1f}%"


def write_report(table: pd.DataFrame, notes: list[str]) -> None:
    lines = [
        "# D06 유형별·동일 FPR 평가 (Train 3-fold CV OOF)",
        "",
        f"- 데이터: `{TRAIN_COMMIT[:9]}:{TRAIN_UPSTREAM_PATH}` (Train 2,767쌍 = 악성 928 / 정상 1,839, "
        "그중 hard benign 239). Test 677쌍은 사용하지 않음.",
        "- 예측: 기존 저장 OOF 예측(E06·E09 = `results/diagnostics/d06_diag01_pair_predictions.csv`, "
        "E10 α=0.25·0.75 = `results/e10/d06_e10_pair_predictions.csv`). 재학습 없음. "
        "E10 α=0·0.5는 E06·E09와 동일해 제외.",
        "- 유형: A = installScriptAdded OR scriptEntryAdded / B = A 아님 AND newDependencyAdded / C = 나머지 "
        "(악성 A 734 · B 52 · C 142).",
        "- 규칙: " + " / ".join(f"{k} = {v}" for k, v in RULES.items()) + ".",
        "- 임계값: 정상 1,839쌍의 OOF 점수를 3 fold 합쳐(pooled) 허용 FP 수 k = floor(목표 FPR × 1,839) 이하가 "
        "되는 가장 낮은 임계값 t = (k+1)번째로 높은 정상 점수, 판정은 proba > t. t와 같은 점수의 정상·악성 pair는 "
        "모두 음성(동점 처리)이라 달성 FPR이 목표보다 낮을 수 있음. 규칙 FPR에 맞출 때는 규칙의 FP 수를 그대로 "
        "k로 씀. 기존 기본값(default_0.5)은 proba >= 0.5.",
        "- 캠페인 평균 Recall: 악성 campaign(splitGroup) 19개의 캠페인별 Recall 단순 평균"
        "(individuals_case는 한 묶음).",
        "",
        "| 방법 | 운영점 | 목표 FPR | 달성 FPR (FP) | hard benign FPR | Recall | A | B | C | 캠페인 평균 |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for _, r in table.iterrows():
        target = "–" if pd.isna(r["target_fpr"]) else fmt(r["target_fpr"])
        lines.append(
            f"| {r['method']} | {r['operating_point']} | {target} | {fmt(r['achieved_fpr'])} ({r['fp']}) "
            f"| {fmt(r['hard_benign_fpr'])} | {fmt(r['recall'])} | {fmt(r['recall_A'])} | {fmt(r['recall_B'])} "
            f"| {fmt(r['recall_C'])} | {fmt(r['campaign_mean_recall'])} |"
        )
    lines += [
        "",
        "## 해석 시 주의",
        "",
        "- 임계값을 3개 fold 모델의 OOF 점수를 합쳐 하나로 정했다. fold마다 모델이 달라 점수 척도가 조금씩 "
        "다를 수 있으며, fold별로 임계값을 따로 정한 `results/e10/d06_e10_fpr_matched_recall.csv`와는 "
        "수치가 다르다.",
        "- default_0.5 행의 TP·FP는 기존 fold별 집계의 합과 같다. 다만 Recall은 2,767쌍 전체(pooled) 기준이라 "
        "기존 fold별 Recall의 단순 평균(E06 54.2%, E09 70.5%)과 다르다(fold 크기 가중 차이).",
        "- 임계값을 평가에 쓴 정상 1,839쌍으로 직접 정했으므로 달성 FPR은 그 표본에서의 값이다(별도 검증셋 아님).",
        "- R2는 유형 A의 정의와 같아 A Recall이 100%, B·C가 0%가 되는 것이 정의상 당연하다.",
        "",
        "## 검증",
        "",
        *[f"- {n}" for n in notes],
        "",
        "## 출력",
        "",
        "- `results/type_fpr/d06_type_fpr_matched.csv`",
        "- `results/type_fpr/d06_type_fpr_matched_campaign_recall.csv`",
        "",
        "재현: `python scripts/eval_d06_type_fpr_matched.py` (train.csv 준비 방법은 스크립트 docstring 참고).",
    ]
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--fetch-train-from-clone", type=Path, metavar="PATH",
                       help="npm-malware-package-pairs 로컬 클론에서 고정 커밋의 train.csv만 가져온다")
    group.add_argument("--fetch-train-from-github", action="store_true",
                       help="GitHub API(GITHUB_TOKEN)로 고정 커밋의 train.csv만 가져온다")
    args = parser.parse_args()

    if args.fetch_train_from_clone:
        fetch_train_from_clone(args.fetch_train_from_clone)
    elif args.fetch_train_from_github:
        fetch_train_from_github()

    train = add_types(load_train())
    mal_types = train.loc[train["label"] == 1, "type"].value_counts().to_dict()
    assert mal_types == {"A": 734, "B": 52, "C": 142}, f"악성 유형 개수가 예상과 다릅니다: {mal_types}"
    assert (train["label"] == 0).sum() == N_BENIGN

    preds = load_predictions(train)
    assert (preds["E06"]["class"] == "hard_benign").sum() == N_HARD_BENIGN
    pairs = pair_frame(preds, train)
    table, camp = evaluate(preds, pairs)
    notes = check_against_existing(table, preds)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    table.to_csv(OUT_CSV, index=False)
    camp.to_csv(OUT_CAMPAIGN_CSV, index=False)
    write_report(table, notes)

    show = ["method", "operating_point", "target_fpr", "fp", "achieved_fpr", "hard_benign_fpr", "recall",
            "recall_A", "recall_B", "recall_C", "campaign_mean_recall"]
    with pd.option_context("display.width", 200, "display.max_columns", None):
        print(table[show].round(4).to_string(index=False))
    for n in notes:
        print(n)
    print(f"\n저장: {OUT_CSV.relative_to(BASE_DIR)}, {OUT_CAMPAIGN_CSV.relative_to(BASE_DIR)}, {OUT_MD.relative_to(BASE_DIR)}")


if __name__ == "__main__":
    main()
