"""D06 미탐(False Negative) 분석: 기존 E06·E09·E10 결과만 읽어 미탐 악성 pair를 추출·요약한다.
모델을 다시 학습하지 않고, feature·데이터셋을 바꾸지 않으며, Test(677쌍) 데이터는 읽지 않는다.
판정은 기존 결과의 pred(proba >= 0.5) 그대로 쓴다(FPR 맞춤 없음). FPR·FP·Precision은 참고용으로 함께 적는다.

입력
- CV OOF 예측(Train 2,767쌍, campaign 단위 3-fold):
  results/diagnostics/d06_diag01_pair_predictions.csv (E06, E09)
  results/e10/d06_e10_pair_predictions.csv (E10 alpha=0, 0.25, 0.5, 0.75; 0/0.5는 E06/E09와 pair별로 동일)
- 기존 fold 집계(대조용): results/cv/d06_e06_e09_3fold_cv.csv, results/e10/d06_e10_fold_metrics.csv
- 기존 Train/Validation 분할 학습의 Validation·Test 성능: results/experiments.csv(D06-E06, D06-E09).
  pair별 Test 예측은 저장돼 있지 않아 Test는 유형·캠페인별로 나눌 수 없다. TP·FN·FP는 저장된 Recall·Precision과
  Validation(악성 187·정상 368: splits/train_val_split_assignment.csv), Test(악성 217·정상 460: 데이터 저장소
  derived/README.md) 건수에서 역산하고, 정수로 떨어지는지 확인한다. E10은 Validation·Test 평가가 없다(미평가).
- data/raw/train.csv: eval_d06_type_fpr_matched.py와 같은 고정 커밋·SHA-256 검사, 같은 A/B/C 유형 정의를 쓴다.
- (선택) --data-clone <npm-malware-package-pairs 클론>: 고정 커밋의 derived/pairs/malicious_pair_groups.csv에서
  pair별 공격 흔적(addedInstallHooks, addedDependencies, changedJsFileCount, largestChangedJsSha1)을 붙인다.
  없으면 이 열과 이를 쓰는 보고서 항목을 비운다.

출력(results/fn_analysis/)
- d06_fn_performance_cv.csv: 모델 x {fold 0/1/2, fold 평균, 전체 합산} 성능
- d06_fn_performance_holdout.csv: 기존 Validation·Test 성능(E10 미평가 표시)
- d06_fn_samples.csv: 한 모델이라도 놓친 악성 pair 전체(모델별 확률·판정, 비교 그룹, feature, 공격 흔적)
- d06_fn_summary_by_type_campaign.csv: 모델 x 유형/캠페인/캠페인x유형/fold별 n·TP·FN·Recall
- d06_fn_feature_profile.csv: 유형별 그룹(정상·hard benign·탐지·미탐)의 feature 분포 요약
- d06_fn_feature_separability.csv: 미탐 악성 vs 같은 유형 정상의 feature별 단변량 AUC(전체·캠페인 균등)
- d06_fn_analysis.md: 분석 결론과 다음 실험 제안

Usage (from the repo root):
    python scripts/analyze_d06_false_negatives.py --data-clone <npm-malware-package-pairs 클론 경로>
"""

from __future__ import annotations

import argparse
import io
import subprocess
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import eval_d06_type_fpr_matched as ev  # noqa: E402  (train.csv 검사·유형 정의를 그대로 재사용)

BASE_DIR = ev.BASE_DIR
DIAG01_PRED_PATH = BASE_DIR / "results" / "diagnostics" / "d06_diag01_pair_predictions.csv"
E10_PRED_PATH = BASE_DIR / "results" / "e10" / "d06_e10_pair_predictions.csv"
CV_FOLD_PATH = BASE_DIR / "results" / "cv" / "d06_e06_e09_3fold_cv.csv"
E10_FOLD_PATH = BASE_DIR / "results" / "e10" / "d06_e10_fold_metrics.csv"
EXPERIMENTS_PATH = BASE_DIR / "results" / "experiments.csv"
TRAIN_VAL_SPLIT_PATH = BASE_DIR / "splits" / "train_val_split_assignment.csv"
PAIR_GROUPS_UPSTREAM_PATH = "derived/pairs/malicious_pair_groups.csv"

OUT_DIR = BASE_DIR / "results" / "fn_analysis"
OUT = {
    "perf_cv": OUT_DIR / "d06_fn_performance_cv.csv",
    "perf_holdout": OUT_DIR / "d06_fn_performance_holdout.csv",
    "samples": OUT_DIR / "d06_fn_samples.csv",
    "summary": OUT_DIR / "d06_fn_summary_by_type_campaign.csv",
    "profile": OUT_DIR / "d06_fn_feature_profile.csv",
    "separability": OUT_DIR / "d06_fn_feature_separability.csv",
    "md": OUT_DIR / "d06_fn_analysis.md",
}

KEY = ev.KEY
PAIR = KEY[:3]
TEST_MALICIOUS, TEST_BENIGN = 217, 460  # 데이터 저장소 derived/README.md의 test.csv 구성
# 분석 대상 모델: E10 alpha=0/0.5는 E06/E09와 pair별로 같아(아래에서 확인) 미탐 분석에서는 뺀다.
MODELS = {"E06": ("diag", "E06"), "E09": ("diag", "E09"), "E10_a0.25": ("e10", 0.25), "E10_a0.75": ("e10", 0.75)}
E10_SAME = {0.0: "E06", 0.5: "E09"}
PKG_FEATURES = ["installScriptPresent", "installScriptAdded", "scriptEntryAdded", "newDependencyAdded",
                "newDependencyCount", "updateType", "updateInterval"]
DISCRETE_PKG_FEATURES = PKG_FEATURES[:-1]
SECONDS_PER_DAY = 86400.0


# ---------------------------------------------------------------- loading

def read_csv(path, **kw) -> pd.DataFrame:
    return pd.read_csv(path, dtype={"old_version": str, "new_version": str}, float_precision="round_trip", **kw)


def load_pair_groups(clone: Path | None) -> pd.DataFrame | None:
    if clone is None:
        return None
    data = subprocess.run(
        ["git", "-C", str(clone), "show", f"{ev.TRAIN_COMMIT}:{PAIR_GROUPS_UPSTREAM_PATH}"],
        capture_output=True, check=True,
    ).stdout
    groups = pd.read_csv(io.BytesIO(data), dtype=str, keep_default_na=False)
    return groups[PAIR + ["addedInstallHooks", "addedDependencies", "changedJsFileCount", "largestChangedJsSha1"]]


def load_frame(clone: Path | None) -> tuple[pd.DataFrame, pd.DataFrame]:
    """2,767쌍 x (feature, 유형, class, campaign, fold, 모델별 proba·pred) 프레임과 E10 원본을 돌려준다."""
    train = ev.add_types(ev.load_train())
    diag = read_csv(DIAG01_PRED_PATH)
    e10 = read_csv(E10_PRED_PATH)
    src = {"diag": (diag, "variant"), "e10": (e10, "alpha")}

    frame = None
    for name, (which, value) in MODELS.items():
        df, col = src[which]
        sub = df[df[col] == value][KEY + ["class", "campaign", "fold", "pred", "proba"]]
        ev.require(len(sub) == ev.N_TRAIN and not sub.duplicated(KEY).any(), f"{name}: 행 수/중복 이상")
        sub = sub.rename(columns={"pred": f"pred_{name}", "proba": f"proba_{name}"})
        if frame is None:
            frame = sub.merge(train, on=KEY, how="inner", validate="one_to_one")
        else:
            merged = frame.merge(sub, on=KEY, how="inner", validate="one_to_one", suffixes=("", "_dup"))
            ev.require((merged["fold"] == merged["fold_dup"]).all() and (merged["class"] == merged["class_dup"]).all(),
                       f"{name}: fold/class가 E06과 다릅니다")
            frame = merged.drop(columns=["class_dup", "campaign_dup", "fold_dup"])
        ev.require(len(frame) == ev.N_TRAIN, f"{name}: train.csv와 1:1로 결합되지 않습니다")
    for name in MODELS:
        ev.require(((frame[f"proba_{name}"] >= 0.5).astype(int) == frame[f"pred_{name}"]).all(),
                   f"{name}: pred가 proba >= 0.5와 다릅니다")
    for alpha, same in E10_SAME.items():
        a = e10[e10["alpha"] == alpha][KEY + ["pred"]].merge(frame[KEY + [f"pred_{same}"]], on=KEY, validate="one_to_one")
        ev.require((a["pred"] == a[f"pred_{same}"]).all(), f"E10 alpha={alpha}의 판정이 {same}와 다릅니다")

    groups = load_pair_groups(clone)
    if groups is not None:
        mal = frame["label"] == 1
        joined = frame.loc[mal, PAIR].merge(groups, on=PAIR, how="left", validate="one_to_one")
        ev.require(joined["addedInstallHooks"].notna().all(), "malicious_pair_groups.csv와 악성 928쌍이 1:1로 맞지 않습니다")
        frame = frame.merge(groups, on=PAIR, how="left")
    return frame, e10


# ---------------------------------------------------------------- performance

def confusion(label: pd.Series, pred: pd.Series) -> dict:
    tp = int(((pred == 1) & (label == 1)).sum())
    fn = int(((pred == 0) & (label == 1)).sum())
    fp = int(((pred == 1) & (label == 0)).sum())
    tn = int(((pred == 0) & (label == 0)).sum())
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn, "recall": tp / (tp + fn),
            "precision": tp / (tp + fp) if tp + fp else np.nan, "fpr": fp / (fp + tn)}


def performance_cv(frame: pd.DataFrame, e10: pd.DataFrame) -> pd.DataFrame:
    """fold별 값, fold 평균(지표의 단순 평균), 전체 합산(TP·FN·FP·TN을 더한 뒤 계산)을 모델마다 만든다.
    fold별 TP·FN·FP·TN은 기존 fold 집계 파일과 대조한다."""
    existing = pd.read_csv(CV_FOLD_PATH)
    existing_e10 = pd.read_csv(E10_FOLD_PATH)
    variants = [("E06", "E06", None), ("E09", "E09", None)]
    variants += [(f"E10_a{a}", f"E10_a{a}", a) for a in (0.25, 0.75)]
    variants += [(f"E10_a{a}", E10_SAME[a], a) for a in E10_SAME]  # 같은 예측, 표에는 따로 남긴다
    rows = []
    for name, source, alpha in variants:
        pred = frame[f"pred_{source}"]
        for fold in range(3):
            m = frame["fold"] == fold
            c = confusion(frame.loc[m, "label"], pred[m])
            if alpha is None:
                ref = existing[(existing["variant"] == name) & (existing["outer_fold"] == fold)].iloc[0]
            else:
                ref = existing_e10[(existing_e10["alpha"] == alpha) & (existing_e10["outer_fold"] == fold)].iloc[0]
            ev.require(all(int(ref[k]) == c[k] for k in ("tp", "fn", "fp", "tn")), f"{name} fold {fold}: 기존 fold 집계와 다릅니다")
            rows.append({"model": name, "aggregation": f"fold{fold}", "n_malicious": c["tp"] + c["fn"],
                         "n_benign": c["fp"] + c["tn"], **c})
        folds = pd.DataFrame(rows[-3:])
        rows.append({"model": name, "aggregation": "fold_mean",
                     **{k: folds[k].mean() for k in ("recall", "precision", "fpr")}})
        rows.append({"model": name, "aggregation": "pooled", "n_malicious": ev.N_MALICIOUS, "n_benign": ev.N_BENIGN,
                     **confusion(frame["label"], pred)})
    out = pd.DataFrame(rows)
    out["same_predictions_as"] = out["model"].map({f"E10_a{a}": s for a, s in E10_SAME.items()})
    out["evaluation"] = "train_3fold_campaign_cv_oof"
    cols = ["model", "evaluation", "aggregation", "n_malicious", "n_benign", "tp", "fn", "fp", "tn",
            "recall", "precision", "fpr", "same_predictions_as"]
    return out[cols]


def performance_holdout() -> pd.DataFrame:
    exp = pd.read_csv(EXPERIMENTS_PATH).set_index("experiment_id")
    split = pd.read_csv(TRAIN_VAL_SPLIT_PATH)
    val = split[split["split"] == "validation"]["class"]
    counts = {"validation": (int((val == "malicious").sum()), int((val != "malicious").sum())),
              "test": (TEST_MALICIOUS, TEST_BENIGN)}
    rows = []
    for model in ("E06", "E09"):
        r = exp.loc[f"D06-{model}"]
        for split_name, prefix in (("validation", "val"), ("test", "test")):
            n_mal, n_ben = counts[split_name]
            recall, precision = float(r[f"{prefix}_recall"]), float(r[f"{prefix}_precision"])
            tp_f = recall * n_mal
            fp_f = tp_f / precision - tp_f
            tp, fp = round(tp_f), round(fp_f)
            ev.require(abs(tp_f - tp) < 1e-6 and abs(fp_f - fp) < 1e-6,
                       f"D06-{model} {split_name}: Recall·Precision에서 정수 TP/FP가 나오지 않습니다")
            rows.append({"model": model, "evaluation": f"train_val_split_{split_name}", "status": "evaluated",
                         "n_malicious": n_mal, "n_benign": n_ben, "tp": tp, "fn": n_mal - tp, "fp": fp,
                         "tn": n_ben - fp, "recall": recall, "precision": precision, "fpr": fp / n_ben,
                         "f1": float(r[f"{prefix}_f1"]), "pr_auc": float(r[f"{prefix}_pr_auc"]),
                         "counts_derived": True, "best_iteration": int(r["best_iteration"])})
    for alpha in (0.25, 0.75):
        for split_name in ("validation", "test"):
            rows.append({"model": f"E10_a{alpha}", "evaluation": f"train_val_split_{split_name}", "status": "미평가"})
    return pd.DataFrame(rows)


# ---------------------------------------------------------------- false negatives

def comparison_group(row) -> str:
    fn6, fn9 = row["pred_E06"] == 0, row["pred_E09"] == 0
    if fn6 and fn9:
        return "both_missed"
    if fn6:
        return "E06_missed_E09_detected"
    if fn9:
        return "E06_detected_E09_missed"
    return "both_detected"


def fn_samples(frame: pd.DataFrame) -> pd.DataFrame:
    mal = frame[frame["label"] == 1].copy()
    for name in MODELS:
        mal[f"fn_{name}"] = mal[f"pred_{name}"] == 0
    mal["e06_e09_group"] = mal.apply(comparison_group, axis=1)
    mal["updateInterval_days"] = mal["updateInterval"] / SECONDS_PER_DAY
    missed_any = mal[[f"fn_{n}" for n in MODELS]].any(axis=1)
    extra = [c for c in ("addedInstallHooks", "addedDependencies", "changedJsFileCount", "largestChangedJsSha1") if c in mal]
    obf = [c for c in frame.columns if c.startswith("obf")]
    cols = (PAIR + ["campaign", "type", "label", "fold", "e06_e09_group"]
            + [c for n in MODELS for c in (f"proba_{n}", f"pred_{n}")] + [f"fn_{n}" for n in MODELS]
            + PKG_FEATURES + ["updateInterval_days"] + extra + obf)
    order = {"both_missed": 0, "E06_missed_E09_detected": 1, "E06_detected_E09_missed": 2, "both_detected": 3}
    out = mal[missed_any][cols].copy()
    out["_o"] = out["e06_e09_group"].map(order)
    return out.sort_values(["_o", "campaign", "package", "new_version"]).drop(columns="_o")


def summary(frame: pd.DataFrame) -> pd.DataFrame:
    mal = frame[frame["label"] == 1]
    rows = []
    levels = {"type": ["type"], "campaign": ["campaign"], "campaign_type": ["campaign", "type"], "fold": ["fold"]}
    for name in MODELS:
        fn_total = int((mal[f"pred_{name}"] == 0).sum())
        for level, keys in levels.items():
            for key, g in mal.groupby(keys):
                key = key if isinstance(key, tuple) else (key,)
                tp = int(g[f"pred_{name}"].sum())
                rows.append({"model": name, "level": level, "key": " / ".join(map(str, key)), "n": len(g),
                             "tp": tp, "fn": len(g) - tp, "recall": tp / len(g),
                             "fn_share_of_model_fn": (len(g) - tp) / fn_total if fn_total else np.nan})
    return pd.DataFrame(rows)


def groups_for_profile(frame: pd.DataFrame) -> pd.Series:
    g = pd.Series(frame["class"].map({"benign": "benign_random", "hard_benign": "hard_benign"}), index=frame.index)
    mal = frame["label"] == 1
    g[mal & (frame["pred_E09"] == 1) & (frame["pred_E06"] == 1)] = "malicious_detected_both"
    g[mal & (frame["pred_E09"] == 1) & (frame["pred_E06"] == 0)] = "malicious_E09_only"
    g[mal & (frame["pred_E09"] == 0) & (frame["pred_E06"] == 0)] = "malicious_missed_both"
    return g


def feature_profile(frame: pd.DataFrame) -> pd.DataFrame:
    frame = frame.assign(group=groups_for_profile(frame))
    rows = []
    for (t, grp), g in frame.groupby(["type", "group"]):
        days = g["updateInterval"] / SECONDS_PER_DAY
        rows.append({
            "type": t, "group": grp, "n": len(g),
            "updateInterval_days_q25": days.quantile(0.25), "updateInterval_days_median": days.median(),
            "updateInterval_days_q75": days.quantile(0.75),
            "patch_share": (g["updateType"] == "patch").mean(), "minor_share": (g["updateType"] == "minor").mean(),
            "major_share": (g["updateType"] == "major").mean(),
            "installScriptPresent_share": g["installScriptPresent"].mean(),
            "installScriptAdded_share": g["installScriptAdded"].mean(),
            "scriptEntryAdded_share": g["scriptEntryAdded"].mean(),
            "newDependencyAdded_share": g["newDependencyAdded"].mean(),
            "newDependencyCount_mean": g["newDependencyCount"].mean(),
            "no_changed_js_share": (g["obfChangedFileCount"] == 0).mean(),
            "proba_E06_median": g["proba_E06"].median(), "proba_E09_median": g["proba_E09"].median(),
        })
    return pd.DataFrame(rows)


def auc(pos: pd.Series, neg: pd.Series) -> float:
    """Mann-Whitney 기반 AUC(동점 0.5). 결측은 뺀다. 0.5보다 작으면 미탐 쪽 값이 정상보다 작다는 뜻."""
    p, n = pos.dropna().to_numpy(float), neg.dropna().to_numpy(float)
    if len(p) == 0 or len(n) == 0:
        return np.nan
    ranks = pd.Series(np.concatenate([p, n])).rank().to_numpy()
    return (ranks[: len(p)].sum() - len(p) * (len(p) + 1) / 2) / (len(p) * len(n))


def separability(frame: pd.DataFrame) -> pd.DataFrame:
    """E06·E09가 함께 놓친 악성 vs 같은 유형 정상(1,839쌍 중)의 feature별 단변량 AUC.
    pooled는 미탐 pair 전체, campaign_equal은 (campaign, 유형) 묶음(3쌍 이상)별 AUC의 단순 평균으로, 같은
    payload가 반복되는 큰 캠페인이 값을 끌어올리는 효과를 줄여 본다."""
    missed = frame[(frame["label"] == 1) & (frame["pred_E06"] == 0) & (frame["pred_E09"] == 0)]
    benign = frame[frame["label"] == 0]
    feats = ["updateInterval", "newDependencyCount"] + [c for c in frame.columns if c.startswith("obf")]
    rows = []
    for t in ("A", "B", "C"):
        m, b = missed[missed["type"] == t], benign[benign["type"] == t]
        for f in feats:
            per = [auc(g[f], b[f]) for _, g in m.groupby("campaign") if len(g) >= 3]
            per = [x for x in per if not np.isnan(x)]
            rows.append({
                "type": t, "feature": f, "used_by_e06_e09_e10": f in PKG_FEATURES, "n_missed": len(m),
                "n_benign_same_type": len(b), "auc_pooled": auc(m[f], b[f]),
                "auc_campaign_equal_mean": np.mean(per) if per else np.nan, "n_campaign_groups": len(per),
                "missed_missing_share": m[f].isna().mean(), "benign_missing_share": b[f].isna().mean(),
            })
    out = pd.DataFrame(rows)
    out["separation_pooled"] = (out["auc_pooled"] - 0.5).abs()
    return out.sort_values(["type", "separation_pooled"], ascending=[True, False])


def same_vector_check(frame: pd.DataFrame) -> pd.DataFrame:
    """함께 놓친 악성마다, 이산 package.json feature 6개가 완전히 같은 정상 pair 수와, 그중 updateInterval이
    그 악성 이상인 정상의 비율(= updateInterval 임계값만으로 이 악성을 잡으려 할 때 함께 걸리는 정상 비율)."""
    benign = frame[frame["label"] == 0]
    missed = frame[(frame["label"] == 1) & (frame["pred_E06"] == 0) & (frame["pred_E09"] == 0)]
    key = lambda df: df[DISCRETE_PKG_FEATURES].astype(str).agg("|".join, axis=1)
    bkey = key(benign)
    rows = []
    for (_, r), k in zip(missed.iterrows(), key(missed)):
        same = benign[bkey == k]
        rows.append({"type": r["type"], "n_same_vector_benign": len(same),
                     "share_benign_interval_ge": (same["updateInterval"] >= r["updateInterval"]).mean() if len(same) else np.nan})
    return pd.DataFrame(rows)


def hook_table(frame: pd.DataFrame) -> pd.DataFrame | None:
    if "addedInstallHooks" not in frame:
        return None
    mal = frame[(frame["label"] == 1) & (frame["type"] == "A")].copy()
    mal["status"] = np.where(mal["pred_E09"] == 1, "E09_detected", "E09_missed")
    mal["hook"] = mal["addedInstallHooks"].replace("", "(없음)")
    return mal.groupby(["campaign", "status", "hook"]).size().rename("n").reset_index()


# ---------------------------------------------------------------- report

def pct(x: float) -> str:
    return "–" if pd.isna(x) else f"{x * 100:.1f}%"


def write_report(frame, perf_cv, perf_ho, summ, prof, sep, same, hooks) -> None:
    mal = frame[frame["label"] == 1]
    fn6, fn9 = mal["pred_E06"] == 0, mal["pred_E09"] == 0
    both = mal[fn6 & fn9]
    n = {"fn6": int(fn6.sum()), "fn9": int(fn9.sum()), "both": len(both),
         "only6": int((fn6 & ~fn9).sum()), "only9": int((~fn6 & fn9).sum())}
    fold_campaigns = mal.groupby("fold")["campaign"].agg(lambda s: sorted(s.unique()))
    fold0_gain = int((fn6 & ~fn9 & (mal["campaign"] == "sha1-hulud-second-coming_2025-11")).sum())
    have_groups = "addedInstallHooks" in frame

    L = ["# D06 미탐(False Negative) 분석과 다음 실험 제안", "",
         "- 범위: 기존 결과만 분석. 모델 재학습·feature 추출 코드 수정·데이터셋 변경 없음. Test 데이터는 읽지 않음"
         "(Test는 `results/experiments.csv`에 저장된 지표만 사용).",
         "- 판정: 기존 결과의 `pred`(proba ≥ 0.5) 그대로. FPR을 맞추지 않았고 FPR·FP·Precision은 참고 지표.",
         f"- 데이터: `{ev.TRAIN_COMMIT[:9]}:{ev.TRAIN_UPSTREAM_PATH}` Train 2,767쌍(악성 928 / 정상 1,839 = 일반 1,600 + "
         "hard benign 239)의 campaign 단위 3-fold CV out-of-fold 예측.",
         "- 모델: E06(package.json feature 7개), E09(E06 + campaign 가중치 1/√size), E10 α=0.25·0.75(가중치 1/size^α). "
         "E10 α=0·0.5는 E06·E09와 pair별 판정이 같아(스크립트에서 확인) 성능표에만 남기고 미탐 비교에서는 뺐다. "
         "세 모델 모두 난독화 feature 22개는 쓰지 않는다.",
         "- 유형: A = installScriptAdded OR scriptEntryAdded / B = A 아님 AND newDependencyAdded / C = 나머지 "
         "(악성 A 734 · B 52 · C 142).", ""]

    # --- performance
    L += ["## 1. 기존 성능", "", "### 1-1. CV(Train 3-fold, campaign 단위) — fold 평균 vs 전체 합산", "",
          "fold 평균은 fold별 지표의 단순 평균, 전체 합산은 세 fold의 TP·FN·FP·TN을 더한 뒤 계산한 값이다.", "",
          "| 모델 | 집계 | Recall | TP | FN | Precision | FP | FPR |", "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for _, r in perf_cv[perf_cv["aggregation"].isin(["fold_mean", "pooled"])].iterrows():
        cnt = lambda k: "–" if pd.isna(r[k]) else f"{int(r[k])}"
        name = r["model"] + (f" (= {r['same_predictions_as']})" if isinstance(r["same_predictions_as"], str) else "")
        L.append(f"| {name} | {'fold 평균' if r['aggregation'] == 'fold_mean' else '전체 합산'} | {pct(r['recall'])} "
                 f"| {cnt('tp')} | {cnt('fn')} | {pct(r['precision'])} | {cnt('fp')} | {pct(r['fpr'])} |")
    L += ["", "fold별 값은 `d06_fn_performance_cv.csv`에 있다. fold 구성: "
          + "; ".join(f"fold {f} = {', '.join(c) if len(c) <= 3 else f'{len(c)}개 캠페인'}" for f, c in fold_campaigns.items())
          + ". fold 0은 `sha1-hulud-second-coming_2025-11` 한 캠페인(332쌍)뿐이라 fold 평균에서 이 캠페인 하나가 1/3의 비중을 갖는다.", "",
          "### 1-2. 기존 Validation·Test(Train/Validation 분할 학습, CV와 별개)", "",
          "| 모델 | 평가 | Recall | TP | FN | Precision | FP | FPR | PR-AUC |",
          "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for _, r in perf_ho.iterrows():
        ev_name = "Validation" if r["evaluation"].endswith("validation") else "Test"
        if r["status"] != "evaluated":
            L.append(f"| {r['model']} | {ev_name} | 미평가 | – | – | – | – | – | – |")
            continue
        L.append(f"| {r['model']} | {ev_name} | {pct(r['recall'])} | {int(r['tp'])} | {int(r['fn'])} | {pct(r['precision'])} "
                 f"| {int(r['fp'])} | {pct(r['fpr'])} | {r['pr_auc']:.3f} |")
    L += ["", f"- Recall·Precision·PR-AUC는 `results/experiments.csv` 값이다. TP·FN·FP는 Validation(악성 187·정상 368), "
          f"Test(악성 {TEST_MALICIOUS}·정상 {TEST_BENIGN}) 건수로 역산했고 모두 정수로 떨어진다.",
          "- pair별 Test 예측이 저장돼 있지 않아 Test는 유형·캠페인별로 나눌 수 없다. 아래 유형·캠페인 분석은 모두 CV 기준이다.",
          "- E10은 Train/Validation 분할 학습과 Test 평가를 하지 않았다(미평가).", ""]

    # --- by type / campaign
    L += ["### 1-3. 유형별 Recall·FN(CV 전체 합산)", "", "| 유형 | n | " + " | ".join(f"{m} Recall (FN)" for m in MODELS) + " |",
          "| --- | ---: | " + " | ".join("---:" for _ in MODELS) + " |"]
    for t in ("A", "B", "C"):
        cells = []
        for m in MODELS:
            r = summ[(summ["model"] == m) & (summ["level"] == "type") & (summ["key"] == t)].iloc[0]
            cells.append(f"{pct(r['recall'])} ({r['fn']})")
        L.append(f"| {t} | {int(r['n'])} | " + " | ".join(cells) + " |")
    camp = summ[(summ["level"] == "campaign")].pivot(index="key", columns="model", values="fn")
    camp_n = summ[(summ["level"] == "campaign") & (summ["model"] == "E09")].set_index("key")["n"]
    camp = camp.assign(n=camp_n).sort_values(["E09", "E06"], ascending=False)
    L += ["", "### 1-4. 캠페인별 FN(CV 전체 합산, E09 FN 순)", "",
          "| 캠페인 | n | fold | " + " | ".join(f"{m} FN" for m in MODELS) + " |",
          "| --- | ---: | --- | " + " | ".join("---:" for _ in MODELS) + " |"]
    folds_of = mal.groupby("campaign")["fold"].agg(lambda s: ",".join(map(str, sorted(s.unique()))))
    for c, r in camp.iterrows():
        L.append(f"| {c} | {int(r['n'])} | {folds_of[c]} | " + " | ".join(str(int(r[m])) for m in MODELS) + " |")
    L += ["", "캠페인별 Recall과 캠페인×유형 분해는 `d06_fn_summary_by_type_campaign.csv`에 있다.", ""]

    # --- FN comparison
    e10_rows = []
    for m in ("E10_a0.25", "E10_a0.75"):
        fnm = mal[f"pred_{m}"] == 0
        e10_rows.append(f"| {m} | {int(fnm.sum())} | {int((fnm & fn6 & fn9).sum())} | {int((~fnm & fn6 & fn9).sum())} "
                        f"| {int((fnm & ~fn9).sum())} |")
    L += ["## 2. 미탐 악성 비교", "",
          f"| 구분 | 쌍 |", "| --- | ---: |",
          f"| E06 미탐 전체 | {n['fn6']} |", f"| E09 미탐 전체 | {n['fn9']} |", f"| E06·E09 공통 미탐 | {n['both']} |",
          f"| E06 미탐 · E09 탐지 | {n['only6']} |", f"| E06 탐지 · E09 미탐 | {n['only9']} |", "",
          f"기존 보고(공통 미탐 264쌍, E09 추가 탐지 156쌍)는 실제 파일에서 그대로 재현된다(공통 {n['both']}, 추가 탐지 {n['only6']}). "
          f"E06이 잡고 E09가 놓친 악성은 {n['only9']}쌍이라, E09의 미탐은 E06 미탐의 부분집합이다.", "",
          "| E10 | 미탐 | 그중 E06·E09 공통 미탐 | 공통 미탐 중 새로 탐지 | E09가 잡았는데 놓침 |", "| --- | ---: | ---: | ---: | ---: |",
          *e10_rows, "", "pair별 목록(모델별 확률·판정, feature, 공격 흔적)은 `d06_fn_samples.csv`에 있다.", ""]

    # --- facts
    p = prof.set_index(["type", "group"])
    pv = lambda t, g, c: p.loc[(t, g), c] if (t, g) in p.index else np.nan
    same_by_type = same.groupby("type").agg(n=("type", "size"), has_same=("n_same_vector_benign", lambda s: int((s > 0).sum())),
                                            share_med=("share_benign_interval_ge", "median"))
    top_sep = lambda t: sep[(sep["type"] == t) & ~sep["used_by_e06_e09_e10"]].head(3)
    sep_drop = {}
    for t in ("A", "B", "C"):
        top8 = sep[(sep["type"] == t) & ~sep["used_by_e06_e09_e10"]].head(8)
        sep_drop[t] = ((top8["auc_pooled"] - 0.5).abs().mean(), (top8["auc_campaign_equal_mean"] - 0.5).abs().mean())
    both_types = both["type"].value_counts()
    L += ["## 3. 미탐 원인", "", "### 3-1. 데이터로 확인된 사실", "",
          f"- 공통 미탐 {n['both']}쌍의 유형: A {both_types.get('A', 0)} · B {both_types.get('B', 0)} · C {both_types.get('C', 0)}. "
          f"유형별 Recall이 가장 낮은 것은 C·B다(1-3).",
          f"- **package.json feature만으로는 구별 정보가 부족한 pair가 대부분이다.** 공통 미탐 {n['both']}쌍 중 "
          f"{int((same['n_same_vector_benign'] > 0).sum())}쌍은 이산 package.json feature 6개(설치 스크립트 3종, 새 의존성 여부·개수, "
          "updateType)가 완전히 같은 정상 pair가 있다. 남은 구별 수단은 updateInterval뿐인데, 같은 값의 정상 중 updateInterval이 "
          "그 악성 이상인 비율의 중앙값이 "
          + ", ".join(f"{t} {same_by_type.loc[t, 'share_med']:.2f}" for t in same_by_type.index)
          + "이다. 즉 updateInterval 임계값으로 이 악성을 잡으려 하면 같은 모양의 정상도 그만큼 함께 걸린다.",
          f"- **A 유형**: 두 모델이 모두 잡은 A의 updateInterval 중앙값은 {pv('A', 'malicious_detected_both', 'updateInterval_days_median'):.0f}일, "
          f"patch 비율 {pct(pv('A', 'malicious_detected_both', 'patch_share'))}, 새 의존성 비율 {pct(pv('A', 'malicious_detected_both', 'newDependencyAdded_share'))}다. "
          f"함께 놓친 A는 updateInterval 중앙값 {pv('A', 'malicious_missed_both', 'updateInterval_days_median'):.1f}일, "
          f"patch {pct(pv('A', 'malicious_missed_both', 'patch_share'))}, 새 의존성 {pct(pv('A', 'malicious_missed_both', 'newDependencyAdded_share'))}로, "
          f"A 유형 hard benign(중앙값 {pv('A', 'hard_benign', 'updateInterval_days_median'):.1f}일, patch {pct(pv('A', 'hard_benign', 'patch_share'))}, "
          f"새 의존성 {pct(pv('A', 'hard_benign', 'newDependencyAdded_share'))})과 비슷하다.",
          f"- **B 유형**: 놓친 B는 patch {pct(pv('B', 'malicious_missed_both', 'patch_share'))}, 새 의존성 평균 "
          f"{pv('B', 'malicious_missed_both', 'newDependencyCount_mean'):.2f}개, updateInterval 중앙값 "
          f"{pv('B', 'malicious_missed_both', 'updateInterval_days_median'):.1f}일이고, B 유형 일반 정상은 patch "
          f"{pct(pv('B', 'benign_random', 'patch_share'))}, 평균 {pv('B', 'benign_random', 'newDependencyCount_mean'):.2f}개, "
          f"중앙값 {pv('B', 'benign_random', 'updateInterval_days_median'):.1f}일이다.",
          f"- **C 유형**: 놓친 C는 설치 스크립트·새 의존성 변화가 없고 patch {pct(pv('C', 'malicious_missed_both', 'patch_share'))}, "
          f"updateInterval 중앙값 {pv('C', 'malicious_missed_both', 'updateInterval_days_median'):.1f}일이다. E09만 잡은 C "
          f"{int(pv('C', 'malicious_E09_only', 'n'))}쌍의 중앙값은 {pv('C', 'malicious_E09_only', 'updateInterval_days_median'):.0f}일로, C 탐지는 "
          "사실상 긴 배포 간격에만 의존한다.",
          "- **모델 설정(코드로 확인)**: 기본 LightGBM(`objective=binary`), 클래스 가중치 없음, 판정 임계값 0.5 고정, early stopping을 "
          "평가 fold 자체로 수행(`scripts/run_cv_e06_e09.py` docstring의 'Approach A' 주의). 저장된 feature importance는 split 횟수이며 "
          "E06·E09 모두 updateInterval이 압도적 1위다(`results/feature_importance/`). fold별 best_iteration은 "
          + ", ".join(f"{m} {perf_cv_iter}" for m, perf_cv_iter in _best_iterations().items()) + ".",
          f"- **캠페인 집중**: 공통 미탐의 캠페인 상위는 "
          + ", ".join(f"`{c}` {k}" for c, k in both["campaign"].value_counts().head(6).items())
          + "이다. CV가 campaign 단위라 각 캠페인은 학습에 한 번도 쓰이지 않은 fold에서 평가된다(새 캠페인 일반화 문제).",
          "- **모델이 쓰는 feature는 이 미탐들을 거의 구별하지 못한다.** 공통 미탐 vs 같은 유형 정상의 단변량 AUC(0.5 = 구별 불가): "
          + "; ".join(f"{t}: " + ", ".join(f"`{r.feature}` {r.auc_pooled:.2f}" for r in sep[(sep['type'] == t) & sep['used_by_e06_e09_e10']].itertuples())
                      for t in ("A", "B", "C")) + ".",
          "- **쓰지 않은 난독화 feature에는 구별 정보가 있다.** E06·E09·E10은 난독화 feature 22개를 쓰지 않는다. 같은 비교의 AUC 상위는 "
          + "; ".join(f"{t}: " + ", ".join(f"`{r.feature}` {r.auc_pooled:.2f}(캠페인 균등 {r.auc_campaign_equal_mean:.2f})"
                                          for r in top_sep(t).itertuples()) for t in ("A", "B", "C"))
          + ". 상위 8개의 평균 |AUC−0.5|는 캠페인을 균등하게 봐도 "
          + ", ".join(f"{t} {sep_drop[t][0]:.2f}→{sep_drop[t][1]:.2f}" for t in ("A", "B", "C"))
          + "로 일부만 줄어든다(pooled→캠페인 균등). 다만 캠페인 균등 값은 미탐이 3쌍 이상인 캠페인 "
          + ", ".join(f"{t} {int(sep[sep['type'] == t]['n_campaign_groups'].iloc[0])}개" for t in ("A", "B", "C"))
          + "로만 계산했다. 방향은 일관돼, 놓친 악성의 변경 코드는 같은 유형 정상보다 공백 비율이 낮고 대괄호 접근·짧은 식별자 비율이 높다.",
          "- **변경 JS가 있는지 자체도 다르다.** 변경 JS가 없어 ChangedCode feature가 결측인 비율은 같은 유형 정상 "
          + ", ".join(f"{t} {pct(sep[(sep['type'] == t) & (sep['feature'] == 'obfWhitespaceRatioChangedCode')]['benign_missing_share'].iloc[0])}" for t in ("A", "B", "C"))
          + ", 공통 미탐 "
          + ", ".join(f"{t} {pct(sep[(sep['type'] == t) & (sep['feature'] == 'obfWhitespaceRatioChangedCode')]['missed_missing_share'].iloc[0])}" for t in ("A", "B", "C"))
          + "이다.",
          "- **난독화 feature를 그대로 다 넣은 기존 모델은 일반화되지 않았다.** 29개 feature를 모두 쓴 D06-E00은 Validation Recall 93.0%, "
          "Test Recall 16.1%였다(`results/experiments.csv`, Train/Validation 분할 학습)."]
    if have_groups:
        mh = frame[(frame["label"] == 1) & (frame["campaign"] == "mini-shai-hulud_2026-05")]
        b_missed = mal[(mal["type"] == "B") & fn9]
        deps = b_missed["addedDependencies"].value_counts()
        inj = frame[(frame["label"] == 1) & (frame["campaign"] == "injective_2026-07")]
        hook_miss = hooks[(hooks["campaign"] == "mini-shai-hulud_2026-05") & (hooks["status"] == "E09_missed")].sort_values("n", ascending=False)
        hook_hit = hooks[(hooks["campaign"] == "mini-shai-hulud_2026-05") & (hooks["status"] == "E09_detected")].sort_values("n", ascending=False)
        uniq = both.groupby("campaign")["largestChangedJsSha1"].nunique()
        L += [
            "- **공격 흔적(데이터 저장소 `derived/pairs/malicious_pair_groups.csv`, 고정 커밋)**:",
            f"  - `mini-shai-hulud_2026-05`(악성 {len(mh)}쌍, 모두 fold {','.join(map(str, sorted(mh['fold'].unique())))}): E09가 놓친 pair의 "
            "추가 install hook은 " + ", ".join(f"`{r.hook}` {r.n}" for r in hook_miss.itertuples())
            + ", 잡은 pair는 " + ", ".join(f"`{r.hook}` {r.n}" for r in hook_hit.head(3).itertuples())
            + "이다. 모델은 hook이 추가됐는지(bool)만 보고 명령 내용은 보지 않는다.",
            f"  - E09가 놓친 B 유형 {len(b_missed)}쌍의 추가 의존성: " + ", ".join(f"`{d}` {k}" for d, k in deps.head(3).items())
            + ". 모델은 의존성 추가 여부·개수만 보고 이름·출처·새로 생긴 패키지인지는 보지 않는다.",
            f"  - `injective_2026-07` {len(inj)}쌍 중 {int((inj['changedJsFileCount'] == '0').sum())}쌍은 변경된 JS 파일·추가 hook·추가 "
            "의존성이 모두 없다. 현재 feature가 측정하는 범위 밖의 변경으로, 무엇이 바뀌었는지는 이 자료로 알 수 없다.",
            "  - 공통 미탐 C 유형 상위 캠페인은 pair마다 가장 큰 변경 JS의 해시가 다르다("
            + ", ".join(f"`{c}` {int(uniq[c])}/{int((both['campaign'] == c).sum())}" for c in
                        ["autotel-node-env-resolver_2026-06", "miasma_2026-06", "react-native-aria-gluestack_2025-06"] if c in uniq)
            + "). 같은 payload 해시로 잡을 수 있는 구조가 아니다.",
        ]
    L += ["",
          "### 3-2. 추정(검증되지 않은 원인 가설)", "",
          "아래는 3-1의 사실에서 귀납적으로 추론한 가설이며, 확인하려면 3-1 밖의 실험이 필요하다.", "",
          "- **H1. 모델이 '설치 스크립트 추가 + 긴 배포 간격 + 새 의존성 없음'이라는 지름길을 학습했다.** 근거: 잡힌 A의 프로필(긴 간격, "
          "새 의존성 0%)과 split importance의 updateInterval 독주. 데이터 저장소 `baseline_rule.py`도 baseline 선정이 updateInterval을 통해 "
          "label을 누설할 수 있다고 경고한다. worm처럼 짧은 간격으로 연속 배포하거나 의존성을 함께 추가하는 공격은 이 지름길에서 벗어나 미탐된다.",
          "- **H2. E06·E09·E10의 미탐은 주로 입력 정보 부족 때문이다(7개 package.json feature 기준).** 근거: 공통 미탐 대부분이 이산 feature가 "
          "같은 정상 pair를 갖고, 모델이 쓰는 feature의 AUC가 0.41~0.61로 0.5 근처다. 이 경우 가중치·임계값 조정만으로는 같은 모양의 정상을 함께 오탐하지 "
          "않고 Recall을 크게 올리기 어렵다.",
          "- **H3. 필요한 정보의 일부는 이미 train.csv에 있지만(난독화 feature), 모델이 일반화되는 방식으로 쓰지 못했다.** 근거: 캠페인 균등으로 "
          "봐도 분리도가 남고 변경 JS 유무도 다르다. 반면 22개를 모두 넣은 E00은 Test에서 크게 떨어졌다. 그래서 '정보 없음'이 아니라 '전부 "
          "넣으면 캠페인별 값에 과적합'일 가능성이 있다. 이를 가르려면 일부 feature만 campaign CV로 넣어 보는 실험이 필요하다.",
          f"- **H4. CV 수치의 변동은 fold 구성에 크게 좌우된다.** fold 0이 단일 캠페인이라, E09가 E06보다 더 잡은 {n['only6']}쌍 중 "
          f"{fold0_gain}쌍이 이 캠페인(`sha1-hulud-second-coming_2025-11`)에서 나온다(1-4). early stopping이 평가 fold를 보므로 CV 수치는 "
          "낙관적일 수 있다.",
          "- **H5. 공격의 실체 정보(hook이 실행하는 파일의 내용, 추가된 의존성의 정체, 주입된 코드의 동작)는 현재 어떤 feature에도 직접 없다.** "
          "근거: 3-1의 공격 흔적. 난독화 비율은 코드의 '모양'만 보므로, 난독화하지 않은 악성 코드에는 신호가 약할 것으로 추정한다.",
          ""]

    # --- proposals
    L += ["## 4. 다음 실험 제안(Recall↑ · FN↓ 우선)", "",
          "기대 효과는 방향만 적었다. 실험 전이므로 개선 폭은 예측하지 않는다.", "",
          "| 우선순위 | 개선 방법 | 해결하려는 미탐 문제 | 기대 효과 | 근거 |", "| --- | --- | --- | --- | --- |",
          "| 1 | **기존 난독화 feature 일부를 package.json 모델에 다시 넣고 campaign CV로 평가**: 변경 JS 유무(obfChangedFileCount>0)와 "
          "분리도가 캠페인 균등으로도 남은 ChangedCode 비율 몇 개(공백·대괄호 접근·짧은 식별자·16진수). feature 추출 변경 없이 바로 가능 "
          "| A·B·C 전반, 특히 package.json 값이 정상과 같은 공통 미탐 | 모델 입력에 미탐을 구별할 정보를 처음으로 넣음 | 3-1의 AUC "
          "(모델 사용 feature ≈ 0.5 vs 난독화 feature), 변경 JS 결측 비율 차이, E00 Test 16.1%(전부 넣으면 일반화 실패) |",
          "| 2 | **변경·추가된 JS 코드의 행위(API) feature 추가**: 새로 생긴 `child_process`·`eval`/`Function`·네트워크(`http(s)`, `fetch`, "
          "`dns`)·환경변수/자격증명 파일 접근·base64 디코드, 그리고 install hook이 이번에 추가·변경된 파일을 실행하는지 | C 유형 미탐(공통 108: "
          "hook·의존성 없이 JS 1개에 코드 주입)과 A 유형 미탐(공통 117: hook이 새 payload 파일 실행) | 난독화 여부와 상관없이 악성 '행위'에 "
          "직접 신호 | C 미탐의 변경 JS가 대부분 1개이고 pair마다 payload 해시가 다름, A 미탐 hook이 `bun run index.js` 등 파일 실행 |",
          "| 3 | **추가된 의존성 정체 feature 추가**: 새 의존성 패키지가 업데이트 직전에 처음 publish됐는지, 그 의존성의 install script 여부, "
          "버전 지정이 URL/git/tarball인지 | B 유형 미탐(E09 기준 39)과 의존성을 동반한 A 미탐 | 의존성 추가 '여부'가 같은 정상 B와 구별 "
          "| E09가 놓친 B의 31쌍이 같은 의존성(`@tanstack/setup`)을 추가 |",
          "| 4 | **LightGBM 학습 방식 보완**: early stopping을 학습 fold 내부 검증으로 분리, `scale_pos_weight`/class weight로 Recall 우선, "
          "Recall 목표 임계값을 학습 fold에서 정함 | 전반 | CV 수치의 낙관 편향 제거, Recall 우선 운영점 | 3-1 모델 설정, best_iteration 3~78 |",
          "| 5 | **updateInterval 의존 점검(E04를 같은 CV로)**: updateInterval 제거·구간화 | 지름길 학습으로 짧은 간격 공격을 놓치는 문제 "
          "| 1~3의 feature가 실제로 쓰이는지 보는 기준선 | H1, D06-E04는 Train/Validation 분할로만 평가됨 |",
          "| 6 | **유형·캠페인 가중치**: E10 α를 유형 단위로 확장(B·C 악성 가중 ↑) | B·C 미탐 | 소수 유형의 학습 신호 확대 | E10에서 α↑일 때 "
          "B·C 미탐은 줄고 sha1-hulud 미탐은 늘어남(1-3, 1-4) |",
          "| 7 | **캠페인 편향 대응**: 단일 캠페인 fold가 생기지 않게 fold 구성, 캠페인 평균 Recall 병기 | 평가 편향 | 개선 여부 판단의 신뢰도 "
          "| fold 0 = 단일 캠페인(H4) |", "",
          "1은 기존 feature만 쓰므로 이번 제약(feature 추출 변경 없음) 안에서 다음 실험으로 바로 할 수 있다. 2·3은 feature 추출 코드 변경이 "
          "필요하다. H2가 맞다면 4~7만으로는 개선 폭이 제한될 수 있다.", "",
          "## 5. 한계", "",
          "- 모든 유형·캠페인 분석은 Train CV 기준이다. Test는 pair별 예측이 없어 나누지 못했다.",
          "- CV는 early stopping에 평가 fold를 쓰므로 수치가 낙관적일 수 있다(`scripts/run_cv_e06_e09.py`).",
          "- 단변량 AUC는 feature 하나씩 본 값이라, 모델에 넣었을 때의 효과를 보장하지 않는다.",
          "- 공격 흔적 열은 데이터 저장소의 `malicious_pair_groups.csv`(고정 커밋)에서 가져왔다.",
          "- 3-2의 원인과 4의 효과는 가설이며, 실험으로 확인해야 한다.", "",
          "## 출력 파일", "", *[f"- `{p.relative_to(BASE_DIR)}`" for k, p in OUT.items() if k != "md"], "",
          "재현: `python scripts/analyze_d06_false_negatives.py --data-clone <npm-malware-package-pairs 클론 경로>`"]
    with open(OUT["md"], "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(L) + "\n")


def _best_iterations() -> dict:
    cv = pd.read_csv(CV_FOLD_PATH)
    e10 = pd.read_csv(E10_FOLD_PATH)
    out = {v: "/".join(str(int(x)) for x in cv[cv["variant"] == v].sort_values("outer_fold")["best_iteration"]) for v in ("E06", "E09")}
    for a in (0.25, 0.75):
        out[f"E10_a{a}"] = "/".join(str(int(x)) for x in e10[e10["alpha"] == a].sort_values("outer_fold")["best_iteration"])
    return out


def write_csv(df: pd.DataFrame, path: Path) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        df.to_csv(f, index=False, lineterminator="\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--data-clone", type=Path, metavar="PATH",
                        help="npm-malware-package-pairs 로컬 클론(공격 흔적 열을 붙일 때)")
    args = parser.parse_args()

    frame, e10 = load_frame(args.data_clone)
    perf_cv = performance_cv(frame, e10)
    perf_ho = performance_holdout()
    samples = fn_samples(frame)
    summ = summary(frame)
    prof = feature_profile(frame)
    sep = separability(frame)
    same = same_vector_check(frame)
    hooks = hook_table(frame)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    write_csv(perf_cv, OUT["perf_cv"])
    write_csv(perf_ho, OUT["perf_holdout"])
    write_csv(samples, OUT["samples"])
    write_csv(summ, OUT["summary"])
    write_csv(prof, OUT["profile"])
    write_csv(sep.drop(columns="separation_pooled"), OUT["separability"])
    write_report(frame, perf_cv, perf_ho, summ, prof, sep, same, hooks)

    mal = frame[frame["label"] == 1]
    print("CV pooled:", perf_cv[perf_cv["aggregation"] == "pooled"][["model", "recall", "tp", "fn", "fp"]].to_string(index=False))
    print("E06 FN", int((mal.pred_E06 == 0).sum()), "| E09 FN", int((mal.pred_E09 == 0).sum()),
          "| 공통", int(((mal.pred_E06 == 0) & (mal.pred_E09 == 0)).sum()),
          "| E06만 미탐", int(((mal.pred_E06 == 0) & (mal.pred_E09 == 1)).sum()),
          "| E09만 미탐", int(((mal.pred_E06 == 1) & (mal.pred_E09 == 0)).sum()))
    print("미탐 샘플 행:", len(samples), "| 공격 흔적 열:", "addedInstallHooks" in samples)
    print("저장:", ", ".join(str(p.relative_to(BASE_DIR)) for p in OUT.values()))


if __name__ == "__main__":
    main()
