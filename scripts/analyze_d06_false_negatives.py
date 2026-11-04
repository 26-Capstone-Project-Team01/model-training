"""D06 미탐(False Negative) 분석: 기존 E06·E09·E10의 Train campaign CV OOF 예측만 읽어 미탐 악성 pair를 운영점별로 추출·요약한다.
모델을 다시 학습하지 않고, feature·데이터셋을 바꾸지 않는다. Train 2,767쌍 밖의 데이터와 그 지표는 읽지도 참조하지도 않는다.
모델 비교·제안 근거는 Train campaign 3-fold CV out-of-fold(OOF) 예측만 쓴다.

운영점(모든 표·CSV에 operating_point 열로 남긴다)
- default_0.5: 기존 결과의 pred(proba >= 0.5) 그대로. 모델마다 FPR이 달라 모델 비교 기준으로 쓰지 않는다.
- fpr_1pct, fpr_5pct: eval_d06_type_fpr_matched.py와 같은 규약. 정상 1,839쌍의 OOF proba를 3 fold 합쳐(pooled)
  허용 FP 수 k = floor(목표 FPR x 1,839), 임계값 t = (k+1)번째로 높은 정상 점수(ev.select_threshold), 판정 proba > t
  (동점은 음성). 임계값과 TP·FP·무작위 정상 FP·hard benign FP·유형별 TP·캠페인별 탐지 수가
  results/type_fpr/d06_type_fpr_matched*.csv와 같은지 require()로 대조한다.
- md 결론(미탐 원인·제안)은 PRIMARY_OP(fpr_5pct) 기준이다.

입력
- CV OOF 예측(Train 2,767쌍, campaign 단위 3-fold):
  results/diagnostics/d06_diag01_pair_predictions.csv (E06, E09)
  results/e10/d06_e10_pair_predictions.csv (E10 alpha=0, 0.25, 0.5, 0.75; 0/0.5는 E06/E09와 pair별 pred가 같다)
- 기존 fold 집계(대조용): results/cv/d06_e06_e09_3fold_cv.csv, results/e10/d06_e10_fold_metrics.csv
- 같은 규약의 기존 평가 결과(대조용): results/type_fpr/d06_type_fpr_matched.csv, d06_type_fpr_matched_campaign_recall.csv
- data/raw/train.csv: eval_d06_type_fpr_matched.py와 같은 고정 커밋·SHA-256 검사, 같은 A/B/C 유형 정의를 쓴다.
- --data-clone <npm-malware-package-pairs 클론>: 고정 커밋(data/SOURCE.json)의 derived/pairs/malicious_pair_groups.csv를
  git show로만 읽어 pair별 공격 흔적(addedInstallHooks, addedDependencies, changedJsFileCount, largestChangedJsSha1)을 붙인다.
  작업 트리·레지스트리의 현재 상태는 읽지 않는다.

출력(results/fn_analysis/)
- d06_fn_performance_cv.csv: 운영점 x 모델 x {fold 0/1/2, fold 평균, 전체 합산} 성능(무작위 정상·hard benign FPR 분리)
- d06_fn_samples.csv: 운영점별로 한 모델이라도 놓친 악성 pair 전체(모델별 확률·판정, 비교 그룹, feature, 공격 흔적)
- d06_fn_summary_by_type_campaign.csv: 운영점 x 모델 x 유형/캠페인/캠페인x유형/fold별 n·TP·FN·Recall
- d06_fn_feature_profile.csv: 운영점 x 유형별 그룹(정상·hard benign·탐지·미탐)의 feature 분포 요약
- d06_fn_feature_separability.csv: 운영점별 공통 미탐 악성 vs 같은 유형 정상의 feature별 단변량 AUC(전체·캠페인 균등)
- d06_fn_analysis.md: 분석 결론과 다음 실험 제안

Usage (from the repo root):
    python scripts/analyze_d06_false_negatives.py --data-clone <npm-malware-package-pairs 클론 경로>
"""

from __future__ import annotations

import argparse
import io
import math
import subprocess
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import eval_d06_type_fpr_matched as ev  # noqa: E402  (train.csv 검사·유형 정의·임계값 규약을 그대로 재사용)

BASE_DIR = ev.BASE_DIR
DIAG01_PRED_PATH = ev.DIAG01_PRED_PATH
E10_PRED_PATH = ev.E10_PRED_PATH
CV_FOLD_PATH = ev.CV_FOLD_METRICS_PATH
E10_FOLD_PATH = ev.E10_FOLD_METRICS_PATH
PAIR_GROUPS_UPSTREAM_PATH = "derived/pairs/malicious_pair_groups.csv"

OUT_DIR = BASE_DIR / "results" / "fn_analysis"
OUT = {
    "perf_cv": OUT_DIR / "d06_fn_performance_cv.csv",
    "samples": OUT_DIR / "d06_fn_samples.csv",
    "summary": OUT_DIR / "d06_fn_summary_by_type_campaign.csv",
    "profile": OUT_DIR / "d06_fn_feature_profile.csv",
    "separability": OUT_DIR / "d06_fn_feature_separability.csv",
    "md": OUT_DIR / "d06_fn_analysis.md",
}

KEY = ev.KEY
PAIR = KEY[:3]
require = ev.require
# 분석 대상 모델: E10 alpha=0/0.5는 E06/E09와 pair별 판정이 같아(아래에서 확인) 0.5 성능표에만 남긴다.
MODELS = {"E06": ("diag", "E06"), "E09": ("diag", "E09"), "E10_a0.25": ("e10", 0.25), "E10_a0.75": ("e10", 0.75)}
E10_SAME = {0.0: "E06", 0.5: "E09"}
OPS = ("default_0.5", *ev.TARGET_FPRS)  # ev.TARGET_FPRS = fpr_1pct, fpr_5pct
OP_LABEL = {"default_0.5": "0.5 고정", "fpr_1pct": "FPR 1%", "fpr_5pct": "FPR 5%"}
PRIMARY_OP = "fpr_5pct"
PKG_FEATURES = ["installScriptPresent", "installScriptAdded", "scriptEntryAdded", "newDependencyAdded",
                "newDependencyCount", "updateType", "updateInterval"]
DISCRETE_PKG_FEATURES = PKG_FEATURES[:-1]
SECONDS_PER_DAY = 86400.0
SHA1_HULUD = "sha1-hulud-second-coming_2025-11"


# ---------------------------------------------------------------- loading

def read_csv(path, **kw) -> pd.DataFrame:
    return pd.read_csv(path, dtype={"old_version": str, "new_version": str}, float_precision="round_trip", **kw)


def load_pair_groups(clone: Path) -> pd.DataFrame:
    data = subprocess.run(
        ["git", "-C", str(clone), "show", f"{ev.TRAIN_COMMIT}:{PAIR_GROUPS_UPSTREAM_PATH}"],
        capture_output=True, check=True,
    ).stdout
    groups = pd.read_csv(io.BytesIO(data), dtype=str, keep_default_na=False)
    return groups[PAIR + ["addedInstallHooks", "addedDependencies", "changedJsFileCount", "largestChangedJsSha1"]]


def load_frame(clone: Path) -> pd.DataFrame:
    """2,767쌍 x (feature, 유형, class, campaign, fold, 모델별 proba·pred(0.5), 공격 흔적) 프레임."""
    train = ev.add_types(ev.load_train())
    diag = read_csv(DIAG01_PRED_PATH)
    e10 = read_csv(E10_PRED_PATH)
    src = {"diag": (diag, "variant"), "e10": (e10, "alpha")}

    frame = None
    for name, (which, value) in MODELS.items():
        df, col = src[which]
        sub = df[df[col] == value][KEY + ["class", "campaign", "fold", "pred", "proba"]]
        require(len(sub) == ev.N_TRAIN and not sub.duplicated(KEY).any(), f"{name}: 행 수/중복 이상")
        sub = sub.rename(columns={"pred": f"pred_{name}", "proba": f"proba_{name}"})
        if frame is None:
            frame = sub.merge(train, on=KEY, how="inner", validate="one_to_one")
        else:
            merged = frame.merge(sub, on=KEY, how="inner", validate="one_to_one", suffixes=("", "_dup"))
            require((merged["fold"] == merged["fold_dup"]).all() and (merged["class"] == merged["class_dup"]).all(),
                    f"{name}: fold/class가 E06과 다릅니다")
            frame = merged.drop(columns=["class_dup", "campaign_dup", "fold_dup"])
        require(len(frame) == ev.N_TRAIN, f"{name}: train.csv와 1:1로 결합되지 않습니다")
    classes = frame["class"].value_counts().to_dict()
    require(classes == {"malicious": ev.N_MALICIOUS, "benign": ev.N_RANDOM_BENIGN, "hard_benign": ev.N_HARD_BENIGN},
            f"class 구성이 예상(무작위 정상 {ev.N_RANDOM_BENIGN} = 정상 {ev.N_BENIGN} - hard benign {ev.N_HARD_BENIGN})과 다릅니다: {classes}")
    require(((frame["class"] == "malicious") == (frame["label"] == 1)).all(), "class == malicious와 label == 1이 다릅니다")
    for name in MODELS:
        require(((frame[f"proba_{name}"] >= 0.5).astype(int) == frame[f"pred_{name}"]).all(),
                f"{name}: pred가 proba >= 0.5와 다릅니다")
    for alpha, same in E10_SAME.items():
        a = e10[e10["alpha"] == alpha][KEY + ["pred", "fold"]].merge(frame[KEY + [f"pred_{same}", "fold"]], on=KEY,
                                                                     validate="one_to_one", suffixes=("", "_base"))
        require(len(a) == ev.N_TRAIN and (a["pred"] == a[f"pred_{same}"]).all() and (a["fold"] == a["fold_base"]).all(),
                f"E10 alpha={alpha}의 판정·fold가 {same}와 다릅니다")

    groups = load_pair_groups(clone)
    mal = frame["label"] == 1
    joined = frame.loc[mal, PAIR].merge(groups, on=PAIR, how="left", validate="one_to_one")
    require(joined["addedInstallHooks"].notna().all(), "malicious_pair_groups.csv와 악성 928쌍이 1:1로 맞지 않습니다")
    return frame.merge(groups, on=PAIR, how="left")


# ---------------------------------------------------------------- operating points

def operating_points(frame: pd.DataFrame) -> dict[str, dict[str, tuple[float, str]]]:
    """op -> model -> (threshold, decision_rule). FPR 운영점은 eval_d06_type_fpr_matched.evaluate()와 같은 규약."""
    benign = (frame["label"] == 0).to_numpy()
    out = {"default_0.5": {m: (0.5, "proba >= threshold") for m in MODELS}}
    for op, fpr in ev.TARGET_FPRS.items():
        k = int(math.floor(fpr * ev.N_BENIGN + 1e-9))
        out[op] = {m: (ev.select_threshold(frame[f"proba_{m}"].to_numpy()[benign], k), "proba > threshold") for m in MODELS}
    return out


def at_op(frame: pd.DataFrame, thr: dict, op: str) -> pd.DataFrame:
    """pred_<model> 열을 그 운영점의 판정으로 바꾼 사본."""
    f = frame.copy()
    for m in MODELS:
        t, rule = thr[op][m]
        p = f[f"proba_{m}"]
        f[f"pred_{m}"] = ((p >= t) if rule == "proba >= threshold" else (p > t)).astype(int)
    return f


def check_type_fpr(frames: dict[str, pd.DataFrame], thr: dict) -> str:
    """임계값·판정이 eval_d06_type_fpr_matched.py의 저장 결과와 같은지 대조한다."""
    table = pd.read_csv(ev.OUT_CSV, float_precision="round_trip")
    camp = pd.read_csv(ev.OUT_CAMPAIGN_CSV)
    for op in OPS:
        f = frames[op]
        mal = (f["label"] == 1).to_numpy()
        for m in MODELS:
            r = table[(table["method"] == m) & (table["operating_point"] == op)]
            require(len(r) == 1, f"type_fpr 결과에 {m} {op} 행이 1개가 아닙니다")
            r = r.iloc[0]
            pred = (f[f"pred_{m}"] == 1).to_numpy()
            got = {"threshold": thr[op][m][0], "decision_rule": thr[op][m][1],
                   "tp": int((pred & mal).sum()), "fp": int((pred & ~mal).sum()),
                   "random_benign_fp": int((pred & (f["class"] == "benign").to_numpy()).sum()),
                   "hard_benign_fp": int((pred & (f["class"] == "hard_benign").to_numpy()).sum()),
                   **{f"tp_{t}": int((pred & mal & (f["type"] == t).to_numpy()).sum()) for t in ev.TYPES}}
            bad = {k: (v, r[k]) for k, v in got.items() if v != r[k]}
            require(not bad, f"{m} {op}: type_fpr 결과와 다릅니다(이 스크립트, type_fpr): {bad}")
            caught = f[mal].groupby("campaign")[f"pred_{m}"].sum().astype(int).to_dict()
            ref = camp[(camp["method"] == m) & (camp["operating_point"] == op)].set_index("campaign")["caught"]
            require(caught == ref.astype(int).to_dict(), f"{m} {op}: 캠페인별 탐지 수가 type_fpr 결과와 다릅니다")
    return ("모든 모델 x 운영점(0.5 고정, FPR 1%, FPR 5%)의 임계값·판정식·TP·FP·무작위 정상 FP·hard benign FP·유형별 TP·"
            "캠페인별 탐지 수가 `results/type_fpr/d06_type_fpr_matched.csv`·`d06_type_fpr_matched_campaign_recall.csv`와 같음")


# ---------------------------------------------------------------- performance

def confusion(df: pd.DataFrame, pred: pd.Series) -> dict:
    label, cls, pred = df["label"], df["class"], pred == 1
    tp = int((pred & (label == 1)).sum())
    fn = int((~pred & (label == 1)).sum())
    fp = int((pred & (label == 0)).sum())
    tn = int((~pred & (label == 0)).sum())
    row = {"tp": tp, "fn": fn, "fp": fp, "tn": tn, "recall": tp / (tp + fn),
           "precision": tp / (tp + fp) if tp + fp else np.nan, "fpr": fp / (fp + tn)}
    for c, col in (("benign", "random_benign"), ("hard_benign", "hard_benign")):
        n, k = int((cls == c).sum()), int((pred & (cls == c)).sum())
        row.update({f"n_{col}": n, f"fp_{col}": k, f"fpr_{col}": k / n if n else np.nan})
    return row


def performance_cv(frames: dict[str, pd.DataFrame], thr: dict) -> pd.DataFrame:
    """운영점 x 모델마다 fold별 값, fold 평균(지표의 단순 평균), 전체 합산(TP·FN·FP·TN을 더한 뒤 계산)을 만든다.
    0.5 고정의 fold별 TP·FN·FP·TN은 기존 fold 집계 파일과 대조한다."""
    existing = pd.read_csv(CV_FOLD_PATH)
    existing_e10 = pd.read_csv(E10_FOLD_PATH)

    def ref(name: str, fold: int) -> pd.Series:
        if name in ("E06", "E09"):
            return existing[(existing["variant"] == name) & (existing["outer_fold"] == fold)].iloc[0]
        alpha = float(name.split("_a")[1])
        return existing_e10[(existing_e10["alpha"] == alpha) & (existing_e10["outer_fold"] == fold)].iloc[0]

    rows = []
    for op in OPS:
        f = frames[op]
        variants = [(m, m) for m in MODELS]
        if op == "default_0.5":
            variants += [(f"E10_a{a}", s) for a, s in E10_SAME.items()]  # 같은 예측, 0.5 표에만 따로 남긴다
        for name, source in variants:
            pred = f[f"pred_{source}"]
            head = {"operating_point": op, "model": name, "threshold": thr[op][source][0],
                    "decision_rule": thr[op][source][1]}
            folds = []
            for fold in range(3):
                m = f["fold"] == fold
                c = confusion(f[m], pred[m])
                if op == "default_0.5":
                    r = ref(name, fold)
                    require(all(int(r[k]) == c[k] for k in ("tp", "fn", "fp", "tn")), f"{name} fold {fold}: 기존 fold 집계와 다릅니다")
                folds.append({**head, "aggregation": f"fold{fold}", "n_malicious": c["tp"] + c["fn"],
                              "n_benign": c["fp"] + c["tn"], **c})
            fd = pd.DataFrame(folds)
            mean = {k: fd[k].mean() for k in ("recall", "precision", "fpr", "fpr_random_benign", "fpr_hard_benign")}
            rows += folds
            rows.append({**head, "aggregation": "fold_mean", **mean})
            rows.append({**head, "aggregation": "pooled", "n_malicious": ev.N_MALICIOUS, "n_benign": ev.N_BENIGN,
                         **confusion(f, pred)})
    out = pd.DataFrame(rows)
    out["same_predictions_as"] = out["model"].map({f"E10_a{a}": s for a, s in E10_SAME.items()})
    out["evaluation"] = "train_3fold_campaign_cv_oof"
    pooled = out[out["aggregation"] == "pooled"]
    require((pooled["n_random_benign"] == ev.N_RANDOM_BENIGN).all() and (pooled["n_hard_benign"] == ev.N_HARD_BENIGN).all(),
            "전체 합산의 무작위 정상·hard benign 분모가 1,600·239가 아닙니다")
    cols = ["operating_point", "model", "evaluation", "aggregation", "threshold", "decision_rule", "n_malicious", "n_benign",
            "tp", "fn", "fp", "tn", "recall", "precision", "fpr", "n_random_benign", "fp_random_benign", "fpr_random_benign",
            "n_hard_benign", "fp_hard_benign", "fpr_hard_benign", "same_predictions_as"]
    return out[cols]


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


def fn_samples(f: pd.DataFrame, op: str) -> pd.DataFrame:
    mal = f[f["label"] == 1].copy()
    for name in MODELS:
        mal[f"fn_{name}"] = mal[f"pred_{name}"] == 0
    mal["e06_e09_group"] = mal.apply(comparison_group, axis=1)
    mal["updateInterval_days"] = mal["updateInterval"] / SECONDS_PER_DAY
    mal["operating_point"] = op
    missed_any = mal[[f"fn_{n}" for n in MODELS]].any(axis=1)
    extra = ["addedInstallHooks", "addedDependencies", "changedJsFileCount", "largestChangedJsSha1"]
    obf = [c for c in f.columns if c.startswith("obf")]
    cols = (["operating_point"] + PAIR + ["campaign", "type", "label", "fold", "e06_e09_group"]
            + [c for n in MODELS for c in (f"proba_{n}", f"pred_{n}")] + [f"fn_{n}" for n in MODELS]
            + PKG_FEATURES + ["updateInterval_days"] + extra + obf)
    order = {"both_missed": 0, "E06_missed_E09_detected": 1, "E06_detected_E09_missed": 2, "both_detected": 3}
    out = mal[missed_any][cols].copy()
    out["_o"] = out["e06_e09_group"].map(order)
    return out.sort_values(["_o", "campaign", "package", "new_version", "old_version"], kind="mergesort").drop(columns="_o")


def summary(f: pd.DataFrame, op: str) -> pd.DataFrame:
    mal = f[f["label"] == 1]
    rows = []
    levels = {"type": ["type"], "campaign": ["campaign"], "campaign_type": ["campaign", "type"], "fold": ["fold"]}
    for name in MODELS:
        fn_total = int((mal[f"pred_{name}"] == 0).sum())
        for level, keys in levels.items():
            for key, g in mal.groupby(keys):
                key = key if isinstance(key, tuple) else (key,)
                tp = int(g[f"pred_{name}"].sum())
                rows.append({"operating_point": op, "model": name, "level": level, "key": " / ".join(map(str, key)),
                             "n": len(g), "tp": tp, "fn": len(g) - tp, "recall": tp / len(g),
                             "fn_share_of_model_fn": (len(g) - tp) / fn_total if fn_total else np.nan})
    return pd.DataFrame(rows)


def groups_for_profile(f: pd.DataFrame) -> pd.Series:
    g = pd.Series(f["class"].map({"benign": "benign_random", "hard_benign": "hard_benign"}), index=f.index)
    mal = f["label"] == 1
    g[mal & (f["pred_E09"] == 1) & (f["pred_E06"] == 1)] = "malicious_detected_both"
    g[mal & (f["pred_E09"] == 1) & (f["pred_E06"] == 0)] = "malicious_E09_only"
    g[mal & (f["pred_E09"] == 0) & (f["pred_E06"] == 1)] = "malicious_E06_only"
    g[mal & (f["pred_E09"] == 0) & (f["pred_E06"] == 0)] = "malicious_missed_both"
    return g


def feature_profile(f: pd.DataFrame, op: str) -> pd.DataFrame:
    f = f.assign(group=groups_for_profile(f))
    rows = []
    for (t, grp), g in f.groupby(["type", "group"]):
        days = g["updateInterval"] / SECONDS_PER_DAY
        rows.append({
            "operating_point": op, "type": t, "group": grp, "n": len(g),
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


def missed_both(f: pd.DataFrame) -> pd.DataFrame:
    return f[(f["label"] == 1) & (f["pred_E06"] == 0) & (f["pred_E09"] == 0)]


def separability(f: pd.DataFrame, op: str) -> pd.DataFrame:
    """E06·E09가 함께 놓친 악성 vs 같은 유형 정상(1,839쌍 중)의 feature별 단변량 AUC.
    pooled는 미탐 pair 전체, campaign_equal은 (campaign, 유형) 묶음(3쌍 이상)별 AUC의 단순 평균으로, 같은
    payload가 반복되는 큰 캠페인이 값을 끌어올리는 효과를 줄여 본다."""
    missed = missed_both(f)
    benign = f[f["label"] == 0]
    feats = ["updateInterval", "newDependencyCount"] + [c for c in f.columns if c.startswith("obf")]
    rows = []
    for t in ev.TYPES:
        m, b = missed[missed["type"] == t], benign[benign["type"] == t]
        for feat in feats:
            per = [auc(g[feat], b[feat]) for _, g in m.groupby("campaign") if len(g) >= 3]
            per = [x for x in per if not np.isnan(x)]
            rows.append({
                "operating_point": op, "type": t, "feature": feat, "used_by_e06_e09_e10": feat in PKG_FEATURES,
                "n_missed": len(m), "n_benign_same_type": len(b), "auc_pooled": auc(m[feat], b[feat]),
                "auc_campaign_equal_mean": np.mean(per) if per else np.nan, "n_campaign_groups": len(per),
                "missed_missing_share": m[feat].isna().mean(), "benign_missing_share": b[feat].isna().mean(),
            })
    out = pd.DataFrame(rows)
    out["separation_pooled"] = (out["auc_pooled"] - 0.5).abs()
    return out.sort_values(["type", "separation_pooled", "feature"], ascending=[True, False, True], kind="mergesort")


def same_vector_check(f: pd.DataFrame) -> pd.DataFrame:
    """함께 놓친 악성마다, 이산 package.json feature 6개가 완전히 같은 정상 pair 수와, 그중 updateInterval이
    그 악성 이상인 정상의 비율(= updateInterval 임계값만으로 이 악성을 잡으려 할 때 함께 걸리는 정상 비율)."""
    benign = f[f["label"] == 0]
    missed = missed_both(f)
    key = lambda df: df[DISCRETE_PKG_FEATURES].astype(str).agg("|".join, axis=1)
    bkey = key(benign)
    rows = []
    for (_, r), k in zip(missed.iterrows(), key(missed), strict=True):
        same = benign[bkey == k]
        rows.append({"type": r["type"], "n_same_vector_benign": len(same),
                     "share_benign_interval_ge": (same["updateInterval"] >= r["updateInterval"]).mean() if len(same) else np.nan})
    return pd.DataFrame(rows, columns=["type", "n_same_vector_benign", "share_benign_interval_ge"])


def hook_table(f: pd.DataFrame) -> pd.DataFrame:
    mal = f[(f["label"] == 1) & (f["type"] == "A")].copy()
    mal["status"] = np.where(mal["pred_E09"] == 1, "E09_detected", "E09_missed")
    mal["hook"] = mal["addedInstallHooks"].replace("", "(없음)")
    return mal.groupby(["campaign", "status", "hook"]).size().rename("n").reset_index()


# ---------------------------------------------------------------- report

def pct(x: float) -> str:
    return "–" if pd.isna(x) else f"{x * 100:.1f}%"


def top_counts(s: pd.Series, k: int) -> list[tuple[str, int]]:
    """값별 개수 상위 k개(개수 내림차순, 같으면 값 오름차순)로 결정적 순서를 고정한다."""
    vc = s.value_counts()
    return sorted(vc.items(), key=lambda kv: (-kv[1], str(kv[0])))[:k]


def _best_iterations() -> dict:
    cv = pd.read_csv(CV_FOLD_PATH)
    e10 = pd.read_csv(E10_FOLD_PATH)
    out = {v: cv[cv["variant"] == v].sort_values("outer_fold")["best_iteration"].astype(int).tolist() for v in ("E06", "E09")}
    for a in (0.25, 0.75):
        out[f"E10_a{a}"] = e10[e10["alpha"] == a].sort_values("outer_fold")["best_iteration"].astype(int).tolist()
    return out


def write_report(frames, thr, perf_cv, summ, prof, sep, check_note) -> None:
    P = PRIMARY_OP
    fp_ = frames[P]
    mal_all = frames["default_0.5"][frames["default_0.5"]["label"] == 1]
    pooled = perf_cv[perf_cv["aggregation"] == "pooled"].set_index(["operating_point", "model"])
    srow = lambda op, m, level, key: summ[(summ["operating_point"] == op) & (summ["model"] == m)
                                         & (summ["level"] == level) & (summ["key"] == key)].iloc[0]
    camp_mean = (summ[summ["level"] == "campaign"].groupby(["operating_point", "model"])["recall"].mean())
    k_of = {op: int(math.floor(fpr * ev.N_BENIGN + 1e-9)) for op, fpr in ev.TARGET_FPRS.items()}

    def fn_sets(op):
        mal = frames[op][frames[op]["label"] == 1]
        fn6, fn9 = mal["pred_E06"] == 0, mal["pred_E09"] == 0
        return mal, fn6, fn9

    n_by_op = {}
    for op in OPS:
        mal, fn6, fn9 = fn_sets(op)
        n_by_op[op] = {"fn6": int(fn6.sum()), "fn9": int(fn9.sum()), "both": int((fn6 & fn9).sum()),
                       "only6": int((fn6 & ~fn9).sum()), "only9": int((~fn6 & fn9).sum())}
    # 이전 보고(0.5 고정: 공통 미탐 264, E09 추가 탐지 156)가 그대로 재현되는지 확인한다.
    require(n_by_op["default_0.5"]["both"] == 264 and n_by_op["default_0.5"]["only6"] == 156,
            f"0.5 고정의 공통 미탐·E09 추가 탐지가 이전 보고(264·156)와 다릅니다: {n_by_op['default_0.5']}")

    mal, fn6, fn9 = fn_sets(P)
    both = mal[fn6 & fn9]
    n = n_by_op[P]
    same = same_vector_check(fp_)
    hooks = hook_table(fp_)
    p = prof[prof["operating_point"] == P].set_index(["type", "group"])
    pv = lambda t, g, c: p.loc[(t, g), c] if (t, g) in p.index else np.nan
    s = sep[sep["operating_point"] == P]
    fold_campaigns = mal_all.groupby("fold")["campaign"].agg(lambda x: sorted(x.unique()))
    n_sha1 = int((mal_all["campaign"] == SHA1_HULUD).sum())
    require(fold_campaigns[0] == [SHA1_HULUD], "fold 0이 sha1-hulud 단일 캠페인이 아닙니다")
    fold0_gain = int((fn6 & ~fn9 & (mal["campaign"] == SHA1_HULUD)).sum())
    m05, f6_05, f9_05 = fn_sets("default_0.5")
    fold0_gain_05 = int((f6_05 & ~f9_05 & (m05["campaign"] == SHA1_HULUD)).sum())
    best_it = _best_iterations()
    it_all = [x for v in best_it.values() for x in v]

    # 0.5 고정 vs FPR 5%의 E06·E09 비교(요약용)
    d = lambda op, m, c: pooled.loc[(op, m), c]
    tp_d05 = int(d("default_0.5", "E09", "tp") - d("default_0.5", "E06", "tp"))
    tp_dP = int(d(P, "E09", "tp") - d(P, "E06", "tp"))
    bc_1pct = {m: int(srow("fpr_1pct", m, "type", "B")["tp"] + srow("fpr_1pct", m, "type", "C")["tp"]) for m in MODELS}
    require(not any(bc_1pct.values()), f"FPR 1%에서 B·C TP가 0이 아닌 모델이 있습니다(보고서 문장 전제): {bc_1pct}")
    best_tp = max(MODELS, key=lambda m: (d(P, m, "tp"), m))
    best_camp = max(MODELS, key=lambda m: (camp_mean[(P, m)], m))

    L = ["# D06 미탐(False Negative) 분석과 다음 실험 제안 (Train campaign 3-fold CV OOF)", "",
         "- 범위: 기존 저장 OOF 예측만 분석. 모델 재학습·feature 추출 코드 수정·데이터셋 변경 없음. Train 2,767쌍 밖의 데이터와 "
         "그 지표는 읽지도 참조하지도 않음. 모델 비교·제안 근거는 Train campaign CV OOF만 사용.",
         f"- 데이터: `{ev.TRAIN_COMMIT[:9]}:{ev.TRAIN_UPSTREAM_PATH}` Train 2,767쌍(악성 928 / 정상 1,839 = 무작위 정상 "
         f"{ev.N_RANDOM_BENIGN:,} + hard benign {ev.N_HARD_BENIGN})의 campaign 단위 3-fold CV out-of-fold 예측. 공격 흔적 열은 같은 "
         f"고정 커밋의 `{PAIR_GROUPS_UPSTREAM_PATH}`(git show).",
         "- 모델: E06(package.json feature 7개), E09(E06 + campaign 가중치 1/√size), E10 α=0.25·0.75(가중치 1/size^α). "
         "E10 α=0·0.5는 E06·E09와 pair별 pred·fold가 일치해(스크립트에서 확인) 0.5 고정 성능 CSV에만 남기고 비교에서는 뺐다. "
         "네 모델 모두 난독화 feature 22개는 쓰지 않는다.",
         "- 유형: A = installScriptAdded OR scriptEntryAdded / B = A 아님 AND newDependencyAdded / C = 나머지 "
         "(악성 A 734 · B 52 · C 142).",
         "- 운영점: `default_0.5` = 기존 pred(proba ≥ 0.5). 모델마다 FPR이 달라 모델 비교 기준으로 쓰지 않는다. "
         f"`fpr_1pct`·`fpr_5pct` = `scripts/eval_d06_type_fpr_matched.py`와 같은 규약: 정상 1,839쌍의 OOF 점수를 3 fold 합쳐(pooled) "
         f"허용 FP k = floor(목표 FPR × 1,839)(1% → {k_of['fpr_1pct']}, 5% → {k_of['fpr_5pct']}), 임계값 t = (k+1)번째로 높은 정상 점수, "
         "판정 proba > t(동점은 음성).",
         f"- 결론(0·4·5절) 기준 운영점: **{OP_LABEL[P]}**. 네 모델의 전체 FP가 같은 상한(≤ {k_of[P]}) 아래에 있어 비교할 수 있고, "
         "FPR 1%에서는 네 모델 모두 B·C 악성을 하나도 잡지 못해 B·C의 탐지/미탐 차이를 볼 수 없다. 0.5 고정과 FPR 1% 결과는 1~3절 표와 "
         "CSV에 함께 남겼다.",
         "",
         "## 0. 요약", "",
         f"- 0.5 고정에서 E09는 E06보다 TP가 {tp_d05}쌍 많지만 전체 FP도 {int(d('default_0.5', 'E09', 'fp'))} vs "
         f"{int(d('default_0.5', 'E06', 'fp'))}(FPR {pct(d('default_0.5', 'E09', 'fpr'))} vs {pct(d('default_0.5', 'E06', 'fpr'))})로 운영점이 다르다. "
         f"같은 {OP_LABEL[P]}에서는 TP 차이가 {tp_dP}쌍(E06 {int(d(P, 'E06', 'tp'))}, E09 {int(d(P, 'E09', 'tp'))})이다.",
         f"- {OP_LABEL[P]}에서 TP가 가장 많은 모델은 {best_tp}({int(d(P, best_tp, 'tp'))}/928, Recall {pct(d(P, best_tp, 'recall'))}), "
         f"캠페인 평균 Recall이 가장 높은 모델은 {best_camp}({pct(camp_mean[(P, best_camp)])})다.",
         "- FPR 1%에서 유형 B·C 악성 TP 합: " + ", ".join(f"{m} {v}" for m, v in bc_1pct.items()) + ". FPR 1%의 탐지는 모두 A 유형에서 나온다.",
         f"- {OP_LABEL[P]}의 FP 구성(무작위 정상 / hard benign): "
         + ", ".join(f"{m} {int(d(P, m, 'fp_random_benign'))}({pct(d(P, m, 'fpr_random_benign'))}) / "
                     f"{int(d(P, m, 'fp_hard_benign'))}({pct(d(P, m, 'fpr_hard_benign'))})" for m in MODELS)
         + ". 같은 전체 FPR이라도 hard benign 비중이 모델마다 다르다.",
         f"- {OP_LABEL[P]}에서 E06·E09 공통 미탐은 {n['both']}쌍(A {int((both['type'] == 'A').sum())} · B {int((both['type'] == 'B').sum())} "
         f"· C {int((both['type'] == 'C').sum())})이다. 원인과 제안은 4·5절.",
         "",
         "## 1. 운영점별 성능 (CV 전체 합산)", "",
         "| 운영점 | 모델 | 판정 | TP | FN | Recall | 전체 FP (FPR) | 무작위 정상 FP (FPR, /1,600) | hard benign FP (FPR, /239) | 캠페인 평균 Recall |",
         "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for op in OPS:
        for m in MODELS:
            r = pooled.loc[(op, m)]
            rule = f"≥ {r['threshold']:.4f}" if r["decision_rule"] == "proba >= threshold" else f"> {r['threshold']:.4f}"
            L.append(f"| {OP_LABEL[op]} | {m} | proba {rule} | {int(r['tp'])} | {int(r['fn'])} | {pct(r['recall'])} "
                     f"| {int(r['fp'])} ({pct(r['fpr'])}) | {int(r['fp_random_benign'])} ({pct(r['fpr_random_benign'])}) "
                     f"| {int(r['fp_hard_benign'])} ({pct(r['fpr_hard_benign'])}) | {pct(camp_mean[(op, m)])} |")
    L += ["",
          f"- 검증: {check_note}. 0.5 고정의 fold별 TP·FN·FP·TN은 기존 fold 집계(`results/cv`, `results/e10`)와 같다.",
          "- 캠페인 평균 Recall은 악성 campaign(splitGroup) 19개의 캠페인별 Recall 단순 평균이다.",
          "- fold별 값·fold 평균·Precision은 `d06_fn_performance_cv.csv`에 있다. fold 구성: "
          + "; ".join(f"fold {fo} = {', '.join(c) if len(c) <= 3 else f'{len(c)}개 캠페인'}" for fo, c in fold_campaigns.items())
          + f". fold 0은 `{SHA1_HULUD}` 한 캠페인({n_sha1}쌍)뿐이다.",
          "- FPR 운영점의 임계값은 평가에 쓴 정상 1,839쌍으로 직접 정했으므로 달성 FPR은 그 표본에서의 값이다(별도 검증셋 아님).",
          ""]

    # --- by type
    L += ["## 2. 유형별·캠페인별 Recall", "", "### 2-1. 유형별 Recall (FN)", "",
          "| 운영점 | 유형 | n | " + " | ".join(MODELS) + " |", "| --- | --- | ---: | " + " | ".join("---:" for _ in MODELS) + " |"]
    for op in OPS:
        for t in ev.TYPES:
            cells = [srow(op, m, "type", t) for m in MODELS]
            L.append(f"| {OP_LABEL[op]} | {t} | {int(cells[0]['n'])} | " + " | ".join(f"{pct(r['recall'])} ({int(r['fn'])})" for r in cells) + " |")
    folds_of = mal_all.groupby("campaign")["fold"].agg(lambda x: ",".join(map(str, sorted(x.unique()))))
    multi_fold = sorted(c for c, v in folds_of.items() if "," in v)
    require(multi_fold == ["individuals_case"], f"여러 fold에 걸친 campaign이 individuals_case 하나가 아닙니다(보고서 문장 전제): {multi_fold}")
    camp_n = mal_all["campaign"].value_counts()
    camps = sorted(camp_n.index, key=lambda c: (-camp_n[c], c))
    for op in OPS:
        L += ["", f"### 2-2. 캠페인별 Recall (FN), {OP_LABEL[op]}", "",
              "| 캠페인 | n | fold | " + " | ".join(MODELS) + " |", "| --- | ---: | --- | " + " | ".join("---:" for _ in MODELS) + " |"]
        for c in camps:
            cells = [srow(op, m, "campaign", c) for m in MODELS]
            L.append(f"| {c} | {int(camp_n[c])} | {folds_of[c]} | " + " | ".join(f"{pct(r['recall'])} ({int(r['fn'])})" for r in cells) + " |")
        if op == "fpr_1pct":
            L += ["", "pooled 기준, 임계값 방식에 민감하다(6절: fold별 임계값이면 FPR 1% TP와 캠페인별 Recall이 크게 달라진다)."]
    L += ["", "캠페인×유형·fold별 분해는 `d06_fn_summary_by_type_campaign.csv`에 있다.", ""]

    # --- FN comparison
    L += ["## 3. 미탐 악성 비교", "", "| 구분 | " + " | ".join(OP_LABEL[op] for op in OPS) + " |",
          "| --- | " + " | ".join("---:" for _ in OPS) + " |"]
    for key, label in (("fn6", "E06 미탐 전체"), ("fn9", "E09 미탐 전체"), ("both", "E06·E09 공통 미탐"),
                       ("only6", "E06 미탐 · E09 탐지"), ("only9", "E06 탐지 · E09 미탐")):
        L.append(f"| {label} | " + " | ".join(str(n_by_op[op][key]) for op in OPS) + " |")
    subset_ops = [OP_LABEL[op] for op in OPS if n_by_op[op]["only9"] == 0]
    L += ["", "0.5 고정의 공통 미탐 264쌍·E09 추가 탐지 156쌍은 이전 보고와 같다(스크립트에서 확인). "
          + (f"{', '.join(subset_ops)}에서는 E09의 미탐이 E06 미탐의 부분집합이다." if subset_ops else "")
          + " 같은 FPR에서는 두 모델이 서로 다른 pair를 놓친다(E06 탐지 · E09 미탐 행).", "",
          "| 운영점 | E10 | 미탐 | 그중 E06·E09 공통 미탐 | 공통 미탐 중 새로 탐지 | E09가 잡았는데 놓침 |",
          "| --- | --- | ---: | ---: | ---: | ---: |"]
    for op in OPS:
        mo, f6, f9 = fn_sets(op)
        for m in ("E10_a0.25", "E10_a0.75"):
            fnm = mo[f"pred_{m}"] == 0
            L.append(f"| {OP_LABEL[op]} | {m} | {int(fnm.sum())} | {int((fnm & f6 & f9).sum())} | {int((~fnm & f6 & f9).sum())} "
                     f"| {int((fnm & ~f9).sum())} |")
    L += ["", "pair별 목록(운영점별, 모델별 확률·판정, feature, 공격 흔적)은 `d06_fn_samples.csv`에 있다.", ""]

    # --- facts (PRIMARY_OP)
    top_sep = lambda t: s[(s["type"] == t) & ~s["used_by_e06_e09_e10"]].head(3)
    sep_drop = {}
    for t in ev.TYPES:
        top8 = s[(s["type"] == t) & ~s["used_by_e06_e09_e10"]].head(8)
        sep_drop[t] = ((top8["auc_pooled"] - 0.5).abs().mean(), (top8["auc_campaign_equal_mean"] - 0.5).abs().mean())
    used_auc = s[s["used_by_e06_e09_e10"]]["auc_pooled"]
    same_by_type = same.groupby("type")["share_benign_interval_ge"].median()
    mh = mal[mal["campaign"] == "mini-shai-hulud_2026-05"]
    hook_miss = hooks[(hooks["campaign"] == "mini-shai-hulud_2026-05") & (hooks["status"] == "E09_missed")].sort_values(["n", "hook"], ascending=[False, True])
    hook_hit = hooks[(hooks["campaign"] == "mini-shai-hulud_2026-05") & (hooks["status"] == "E09_detected")].sort_values(["n", "hook"], ascending=[False, True])
    b_missed = mal[(mal["type"] == "B") & fn9]
    deps = top_counts(b_missed["addedDependencies"], 3)
    inj = mal[mal["campaign"] == "injective_2026-07"]
    uniq = both.groupby("campaign")["largestChangedJsSha1"].nunique()
    both_c, both_a = both[both["type"] == "C"], both[both["type"] == "A"]
    c_one_js = (both_c["changedJsFileCount"] == "1").mean() if len(both_c) else np.nan
    a_hooks = top_counts(both_a["addedInstallHooks"].replace("", "(없음)"), 2)
    tc = lambda op, m, t: int(srow(op, m, "type", t)["tp"])
    alpha_models = [("0", "E06"), ("0.25", "E10_a0.25"), ("0.5", "E09"), ("0.75", "E10_a0.75")]
    sha1_fn = {m: int(srow(P, m, "campaign", SHA1_HULUD)["fn"]) for _, m in alpha_models}
    n_same = int((same["n_same_vector_benign"] > 0).sum())
    # 4-1 결론(same_claim)과 H2 근거(same_basis) 문구를 계산값으로 고른다: 0건(0/0 포함) / 전부 / 과반 / 그 미만.
    same_frac = f"({n_same}/{n['both']})"
    if n_same == 0:
        same_claim, same_basis = f"없다{same_frac}", f"동일한 이산 feature의 정상 pair를 가진 공통 미탐은 없고{same_frac}"
    else:
        same_q, same_ga, same_da = (("전부", "가", "다") if n_same == n["both"] else ("대부분", "이", "이다") if 2 * n_same > n["both"]
                                    else ("일부", "가", "다"))
        same_claim = f"{same_q}{same_frac}{same_da}"
        same_basis = f"공통 미탐 {same_q}{same_frac}{same_ga} 이산 feature가 같은 정상 pair를 갖고"

    L += [f"## 4. 미탐 원인 ({OP_LABEL[P]} 기준)", "", "### 4-1. 데이터로 확인된 사실", "",
          f"- 공통 미탐 {n['both']}쌍의 유형: A {len(both_a)} · B {int((both['type'] == 'B').sum())} · C {len(both_c)}. "
          "유형별 Recall(E06 / E09): " + ", ".join(f"{t} {pct(srow(P, 'E06', 'type', t)['recall'])} / {pct(srow(P, 'E09', 'type', t)['recall'])}"
                                                   for t in ev.TYPES) + "(2-1).",
          f"- **package.json feature만으로는 구별 정보가 부족한 pair가 {same_claim}.** 공통 미탐 {n['both']}쌍 중 "
          f"{n_same}쌍은 이산 package.json feature 6개(설치 스크립트 3종, 새 의존성 여부·개수, "
          "updateType)가 완전히 같은 정상 pair가 있다. 남은 구별 수단은 updateInterval뿐인데, 같은 값의 정상 중 updateInterval이 "
          "그 악성 이상인 비율의 중앙값이 "
          + ", ".join(f"{t} {v:.2f}" for t, v in same_by_type.items())
          + "이다. 즉 updateInterval 임계값으로 이 악성을 잡으려 하면 같은 모양의 정상도 그만큼 함께 걸린다.",
          f"- **A 유형**: 두 모델이 모두 잡은 A의 updateInterval 중앙값은 {pv('A', 'malicious_detected_both', 'updateInterval_days_median'):.0f}일, "
          f"patch 비율 {pct(pv('A', 'malicious_detected_both', 'patch_share'))}, 새 의존성 비율 {pct(pv('A', 'malicious_detected_both', 'newDependencyAdded_share'))}다. "
          f"함께 놓친 A는 updateInterval 중앙값 {pv('A', 'malicious_missed_both', 'updateInterval_days_median'):.1f}일, "
          f"patch {pct(pv('A', 'malicious_missed_both', 'patch_share'))}, 새 의존성 {pct(pv('A', 'malicious_missed_both', 'newDependencyAdded_share'))}이고, "
          f"A 유형 hard benign은 중앙값 {pv('A', 'hard_benign', 'updateInterval_days_median'):.1f}일, patch {pct(pv('A', 'hard_benign', 'patch_share'))}, "
          f"새 의존성 {pct(pv('A', 'hard_benign', 'newDependencyAdded_share'))}다.",
          f"- **B 유형**: 놓친 B는 patch {pct(pv('B', 'malicious_missed_both', 'patch_share'))}, 새 의존성 평균 "
          f"{pv('B', 'malicious_missed_both', 'newDependencyCount_mean'):.2f}개, updateInterval 중앙값 "
          f"{pv('B', 'malicious_missed_both', 'updateInterval_days_median'):.1f}일이고, B 유형 무작위 정상은 patch "
          f"{pct(pv('B', 'benign_random', 'patch_share'))}, 평균 {pv('B', 'benign_random', 'newDependencyCount_mean'):.2f}개, "
          f"중앙값 {pv('B', 'benign_random', 'updateInterval_days_median'):.1f}일이다.",
          f"- **C 유형**: 놓친 C는 설치 스크립트·새 의존성 변화가 없고 patch {pct(pv('C', 'malicious_missed_both', 'patch_share'))}, "
          f"updateInterval 중앙값 {pv('C', 'malicious_missed_both', 'updateInterval_days_median'):.1f}일이다. 한 모델이라도 잡은 C의 수와 "
          "updateInterval 중앙값: "
          + ", ".join(f"{g} {int(pv('C', g, 'n')) if not pd.isna(pv('C', g, 'n')) else 0}쌍"
                      + ("" if pd.isna(pv('C', g, 'n')) else f"({pv('C', g, 'updateInterval_days_median'):.0f}일)")
                      for g in ("malicious_detected_both", "malicious_E09_only", "malicious_E06_only"))
          + ".",
          "- **모델 설정(코드로 확인)**: 기본 LightGBM(`objective=binary`), 클래스 가중치 없음(E06), 학습·기존 보고의 판정 임계값 0.5, "
          "early stopping을 평가 fold 자체로 수행(`scripts/run_cv_e06_e09.py` docstring의 'Approach A' 주의). 저장된 feature importance는 "
          "split 횟수이며 E06·E09 모두 updateInterval이 압도적 1위다(`results/feature_importance/`). fold별 best_iteration은 "
          + ", ".join(f"{m} {'/'.join(map(str, v))}" for m, v in best_it.items()) + ".",
          "- **캠페인 집중**: 공통 미탐의 캠페인 상위는 "
          + ", ".join(f"`{c}` {k}" for c, k in top_counts(both["campaign"], 6))
          + "이다. CV가 campaign 단위라 공유 공격 캠페인은 fold 사이에서 분리되고, 학습에 한 번도 쓰이지 않은 fold에서 평가된다(새 캠페인 "
          "일반화 문제). 예외로 " + ", ".join(f"`{c}`(fold {folds_of[c]})" for c in multi_fold)
          + "는 독립 사건을 모은 보고용 묶음이라 여러 fold에 걸친다(`scripts/run_cv_e06_e09.py`의 `is_shared_attack_split_group` 참고). "
          "따라서 이 묶음의 Recall은 leave-campaign-out 검증 결과로 읽지 않는다.",
          f"- **모델이 쓰는 feature 중 AUC를 잰 수치형 2개(updateInterval, newDependencyCount)는 이 미탐들을 약하게만 구별한다.** "
          f"공통 미탐 vs 같은 유형 정상의 단변량 AUC(0.5 = 구별 불가, 범위 {used_auc.min():.2f}~{used_auc.max():.2f}): "
          + "; ".join(f"{t}: " + ", ".join(f"`{r.feature}` {r.auc_pooled:.2f}" for r in s[(s['type'] == t) & s['used_by_e06_e09_e10']].itertuples())
                      for t in ev.TYPES) + ".",
          "- **쓰지 않은 난독화 feature에는 구별 정보가 있다.** E06·E09·E10은 난독화 feature 22개를 쓰지 않는다. 같은 비교의 AUC 상위는 "
          + "; ".join(f"{t}: " + ", ".join(f"`{r.feature}` {r.auc_pooled:.2f}(캠페인 균등 {r.auc_campaign_equal_mean:.2f})"
                                          for r in top_sep(t).itertuples()) for t in ev.TYPES)
          + ". 상위 8개의 평균 |AUC−0.5|는 pooled→캠페인 균등으로 "
          + ", ".join(f"{t} {sep_drop[t][0]:.2f}→{sep_drop[t][1]:.2f}" for t in ev.TYPES)
          + "다. 캠페인 균등 값은 미탐이 3쌍 이상인 캠페인 "
          + ", ".join(f"{t} {int(s[s['type'] == t]['n_campaign_groups'].iloc[0])}개" for t in ev.TYPES)
          + "로만 계산했다.",
          "- **변경 JS가 있는지 자체도 다르다.** 변경 JS가 없어 ChangedCode feature가 결측인 비율은 같은 유형 정상 "
          + ", ".join(f"{t} {pct(s[(s['type'] == t) & (s['feature'] == 'obfWhitespaceRatioChangedCode')]['benign_missing_share'].iloc[0])}" for t in ev.TYPES)
          + ", 공통 미탐 "
          + ", ".join(f"{t} {pct(s[(s['type'] == t) & (s['feature'] == 'obfWhitespaceRatioChangedCode')]['missed_missing_share'].iloc[0])}" for t in ev.TYPES)
          + "이다.",
          "- **난독화 feature를 모두 넣은 모델의 일반화는 근거 없음(미검증).** 29개 feature를 모두 쓴 D06-E00은 Train campaign CV 결과가 "
          "없다(`results/cv`·`results/e10`에는 E06·E09·E10만 있다). 이 분석에서는 E00의 일반화 여부를 판단하지 않는다.",
          "- **공격 흔적(데이터 저장소 `derived/pairs/malicious_pair_groups.csv`, 고정 커밋)**:",
          f"  - `mini-shai-hulud_2026-05`(악성 {len(mh)}쌍, fold {','.join(map(str, sorted(mh['fold'].unique())))}): E09가 놓친 pair의 "
          "추가 install hook은 " + (", ".join(f"`{r.hook}` {r.n}" for r in hook_miss.itertuples()) or "없음")
          + ", 잡은 pair는 " + (", ".join(f"`{r.hook}` {r.n}" for r in hook_hit.head(3).itertuples()) or "없음")
          + "이다. 모델은 hook이 추가됐는지(bool)만 보고 명령 내용은 보지 않는다.",
          f"  - 공통 미탐 A {len(both_a)}쌍의 추가 install hook 상위: " + ", ".join(f"`{h}` {k}" for h, k in a_hooks) + ".",
          f"  - E09가 놓친 B 유형 {len(b_missed)}쌍의 추가 의존성: " + ", ".join(f"`{dep}` {k}" for dep, k in deps)
          + ". 모델은 의존성 추가 여부·개수만 보고 이름·출처·새로 생긴 패키지인지는 보지 않는다.",
          f"  - `injective_2026-07` {len(inj)}쌍 중 {int((inj['changedJsFileCount'] == '0').sum())}쌍은 변경된 JS 파일이 없다"
          f"(그중 E09 미탐 {int(((inj['changedJsFileCount'] == '0') & (inj['pred_E09'] == 0)).sum())}쌍).",
          f"  - 공통 미탐 C {len(both_c)}쌍 중 변경 JS 파일이 1개인 비율은 {pct(c_one_js)}이고, 상위 캠페인에서 `largestChangedJsSha1`(가장 큰 변경 JS "
          "파일 전체의 해시) 고유값 수는 " + ", ".join(f"`{c}` {int(uniq[c])}/{int((both['campaign'] == c).sum())}" for c, _ in top_counts(both_c["campaign"], 3))
          + "로, 이 열의 파일 전체 해시는 대부분 pair마다 다르다. 주입된 payload 자체나 다른 변경 파일의 해시가 재사용되는지는 이 열만으로 "
          "알 수 없어 미검증이다.",
          ""]

    L += ["### 4-2. 추정(검증되지 않은 원인 가설)", "",
          "아래는 4-1의 사실에서 귀납적으로 추론한 가설이며, 확인하려면 4-1 밖의 실험이 필요하다.", "",
          "- **H1. 모델이 '설치 스크립트 추가 + 긴 배포 간격'이라는 지름길을 학습했다.** 근거: 4-1의 A 유형 프로필(잡힌 A와 놓친 A의 "
          "updateInterval 차이)과 split importance의 updateInterval 독주. baseline 규칙 설계도 updateInterval을 통한 label 누수를 경계한다"
          "(`be87ab4cf:derived/pairs/baseline_rule.py` L21-24: 악성 직전 후보를 날짜 경계로 일괄 제외하면 정상 hotfix까지 빠져 악성 "
          "baseline만 체계적으로 오래되고 updateInterval로 label이 누수되므로, 일괄 제외 대신 clean 검증을 쓴다). worm처럼 짧은 간격으로 "
          "연속 배포하는 공격은 이 지름길에서 벗어나 미탐될 것으로 추정한다.",
          f"- **H2. E06·E09·E10의 미탐은 주로 입력 정보 부족 때문이다(7개 package.json feature 기준).** 근거: {same_basis}"
          f", 모델이 쓰는 feature 중 AUC를 잰 수치형 2개(updateInterval, newDependencyCount)의 AUC가 "
          f"{used_auc.min():.2f}~{used_auc.max():.2f}으로 약하다. 이 경우 가중치·임계값 조정만으로는 "
          "같은 모양의 정상을 함께 오탐하지 않고 Recall을 크게 올리기 어렵다. 0.5 고정에서 E09가 더 잡은 pair 상당수가 같은 FPR에서는 "
          f"차이로 남지 않는 것(0절: TP 차이 {tp_d05} → {tp_dP})도 이와 맞는다.",
          "- **H3. 필요한 정보의 일부는 이미 train.csv에 있다(난독화 feature).** 근거: 캠페인 균등으로 봐도 분리도가 남고 변경 JS 유무도 다르다. "
          "모두 넣었을 때 캠페인별 값에 과적합하는지는 campaign CV 근거가 없어 미검증이다. 이를 가르려면 일부 feature만 campaign CV로 넣어 보는 "
          "실험이 필요하다.",
          f"- **H4. CV 수치의 변동은 fold 구성과 운영점에 크게 좌우된다.** fold 0이 단일 캠페인(`{SHA1_HULUD}`)이라 fold 평균에서 이 캠페인이 1/3 "
          f"비중을 갖는다. E09가 E06보다 더 잡은 pair 중 이 캠페인은 0.5 고정에서 {fold0_gain_05}/{n_by_op['default_0.5']['only6']}쌍, "
          f"{OP_LABEL[P]}에서 {fold0_gain}/{n['only6']}쌍이다. early stopping이 평가 fold를 보므로 CV 수치는 낙관적일 수 있다.",
          "- **H5. 공격의 실체 정보(hook이 실행하는 파일의 내용, 추가된 의존성의 정체, 주입된 코드의 동작)는 현재 어떤 feature에도 직접 없다.** "
          "근거: 4-1의 공격 흔적. 난독화 비율은 코드의 '모양'만 보므로, 난독화하지 않은 악성 코드에는 신호가 약할 것으로 추정한다.",
          ""]

    # --- proposals
    bc = lambda t: "/".join(str(tc(P, m, t)) for _, m in alpha_models)
    L += ["## 5. 다음 실험 제안(같은 FPR에서 Recall↑ · FN↓ 우선)", "",
          f"근거 수치는 모두 Train campaign CV OOF, {OP_LABEL[P]} 기준이다. 기대 효과는 방향만 적었고 개선 폭은 예측하지 않는다. "
          "효과 확인도 같은 CV·같은 FPR(1%, 5%)·유형별·캠페인별 Recall과 무작위 정상/hard benign FPR 분리로 한다.", "",
          "| 우선순위 | 개선 방법 | 해결하려는 미탐 문제 | 기대 효과 | 근거 |", "| --- | --- | --- | --- | --- |",
          "| 1 | **기존 난독화 feature 일부를 package.json 모델에 다시 넣고 campaign CV로 평가**: 변경 JS 유무(obfChangedFileCount>0)와 "
          "분리도가 캠페인 균등으로도 남은 ChangedCode 비율 몇 개(공백·대괄호 접근·짧은 식별자·16진수). feature 추출 변경 없이 바로 가능 "
          f"| A·B·C 전반, 특히 package.json 값이 정상과 같은 공통 미탐 | 모델 입력에 미탐을 구별할 정보를 처음으로 넣음 | 4-1의 AUC "
          f"(AUC를 잰 수치형 2개(updateInterval, newDependencyCount) {used_auc.min():.2f}~{used_auc.max():.2f} vs 난독화 feature 상위), 변경 JS 결측 비율 차이. 29개 전부 넣은 E00은 "
          "campaign CV 근거 없음(미검증) |",
          "| 2 | **변경·추가된 JS 코드의 행위(API) feature 추가**: 새로 생긴 `child_process`·`eval`/`Function`·네트워크(`http(s)`, `fetch`, "
          "`dns`)·환경변수/자격증명 파일 접근·base64 디코드, 그리고 install hook이 이번에 추가·변경된 파일을 실행하는지 "
          f"| C 유형 미탐(공통 {len(both_c)}: hook·의존성 없이 JS에 코드 주입)과 A 유형 미탐(공통 {len(both_a)}) | 난독화 여부와 상관없이 악성 "
          f"'행위'에 직접 신호 | 공통 미탐 C의 변경 JS 1개 비율 {pct(c_one_js)}, 가장 큰 변경 JS 파일 전체 해시가 대부분 pair마다 다름(payload 자체 해시 재사용은 미검증), 공통 미탐 A의 hook 상위 "
          + ", ".join(f"`{h}`" for h, _ in a_hooks) + " |",
          "| 3 | **추가된 의존성 정체 feature 추가**: 새 의존성 패키지가 업데이트 직전에 처음 publish됐는지, 그 의존성의 install script 여부, "
          f"버전 지정이 URL/git/tarball인지 | B 유형 미탐(E09 기준 {len(b_missed)})과 의존성을 동반한 A 미탐 | 의존성 추가 '여부'가 같은 정상 B와 구별 "
          f"| E09가 놓친 B의 추가 의존성 상위: " + ", ".join(f"`{dep}` {k}" for dep, k in deps[:1]) + " |",
          "| 4 | **LightGBM 학습 방식 보완**: early stopping을 학습 fold 내부 검증으로 분리, `scale_pos_weight`/class weight로 Recall 우선, "
          f"Recall 목표 임계값을 학습 fold에서 정함 | 전반 | CV 수치의 낙관 편향 제거, Recall 우선 운영점 | 4-1 모델 설정, best_iteration "
          f"{min(it_all)}~{max(it_all)} |",
          "| 5 | **updateInterval 의존 점검(E04를 같은 CV로)**: updateInterval 제거·구간화 | 지름길 학습으로 짧은 간격 공격을 놓치는 문제 "
          "| 1~3의 feature가 실제로 쓰이는지 보는 기준선 | H1. D06-E04는 campaign CV 결과가 없다 |",
          "| 6 | **유형·캠페인 가중치**: E10 α를 유형 단위로 확장(B·C 악성 가중 ↑) | B·C 미탐 | 소수 유형의 학습 신호 확대 "
          f"| {OP_LABEL[P]}에서 α=0/0.25/0.5/0.75의 B TP {bc('B')}, C TP {bc('C')}, `{SHA1_HULUD}` FN "
          + "/".join(str(sha1_fn[m]) for _, m in alpha_models) + "(2-1, 2-2). pooled 기준, 임계값 방식에 민감(6절) |",
          "| 7 | **캠페인 편향 대응**: 단일 캠페인 fold가 생기지 않게 fold 구성, 캠페인 평균 Recall 병기 | 평가 편향 | 개선 여부 판단의 신뢰도 "
          "| fold 0 = 단일 캠페인(H4) |", "",
          "1은 기존 feature만 쓰므로 이번 제약(feature 추출 변경 없음) 안에서 다음 실험으로 바로 할 수 있다. 2·3은 feature 추출 코드 변경이 "
          "필요하다. H2가 맞다면 4~7만으로는 개선 폭이 제한될 수 있다.", "",
          "## 6. 한계", "",
          "- 모든 수치는 Train campaign CV OOF 기준이다. 최종 일반화 성능 추정이 아니다.",
          "- FPR 운영점의 임계값은 3 fold의 OOF 점수를 합쳐 하나로 정했고, 같은 정상 1,839쌍에서 달성 FPR을 쟀다. 결과는 임계값 방식에 민감하다. "
          "fold별로 같은 규약의 임계값을 쓰면 FPR 1% TP가 E06 222→534, E09 399→506, E10_a0.25 517→543, E10_a0.75 267→365로 달라지고"
          "(E06 fold 0 sha1-hulud 0→324), FPR 5% 전체 TP 순서는 같지만 B·C TP는 바뀐다(예: E10_a0.75 B 13→3). 이 수치는 Revy 검증 값으로, "
          "저장 OOF로 별도 계산했으며 이 스크립트는 계산하지 않는다.",
          "- CV는 early stopping에 평가 fold를 쓰므로 수치가 낙관적일 수 있다(`scripts/run_cv_e06_e09.py`).",
          "- 단변량 AUC는 feature 하나씩 본 값이라, 모델에 넣었을 때의 효과를 보장하지 않는다.",
          "- 공격 흔적 열은 데이터 저장소의 `malicious_pair_groups.csv`(고정 커밋)에서 가져왔다.",
          "- 4-2의 원인과 5의 효과는 가설이며, 실험으로 확인해야 한다.", "",
          "## 출력 파일", "", *[f"- `{q.relative_to(BASE_DIR).as_posix()}`" for k, q in OUT.items() if k != "md"], "",
          "재현: `python scripts/analyze_d06_false_negatives.py --data-clone <npm-malware-package-pairs 클론 경로>`"]
    with open(OUT["md"], "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(L) + "\n")


def write_csv(df: pd.DataFrame, path: Path) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        df.to_csv(f, index=False, lineterminator="\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--data-clone", type=Path, metavar="PATH", required=True,
                        help="npm-malware-package-pairs 로컬 클론(고정 커밋에서 git show로만 읽는다)")
    args = parser.parse_args()

    frame = load_frame(args.data_clone)
    thr = operating_points(frame)
    frames = {op: at_op(frame, thr, op) for op in OPS}
    check_note = check_type_fpr(frames, thr)
    perf_cv = performance_cv(frames, thr)
    samples = pd.concat([fn_samples(frames[op], op) for op in OPS], ignore_index=True)
    summ = pd.concat([summary(frames[op], op) for op in OPS], ignore_index=True)
    prof = pd.concat([feature_profile(frames[op], op) for op in OPS], ignore_index=True)
    sep = pd.concat([separability(frames[op], op) for op in OPS], ignore_index=True)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    write_csv(perf_cv, OUT["perf_cv"])
    write_csv(samples, OUT["samples"])
    write_csv(summ, OUT["summary"])
    write_csv(prof, OUT["profile"])
    write_csv(sep.drop(columns="separation_pooled"), OUT["separability"])
    write_report(frames, thr, perf_cv, summ, prof, sep, check_note)

    show = perf_cv[(perf_cv["aggregation"] == "pooled") & perf_cv["same_predictions_as"].isna()]
    print(show[["operating_point", "model", "threshold", "tp", "fn", "fp", "fp_random_benign", "fp_hard_benign"]].to_string(index=False))
    print(check_note)
    print("미탐 샘플 행:", len(samples))
    print("저장:", ", ".join(q.relative_to(BASE_DIR).as_posix() for q in OUT.values()))


if __name__ == "__main__":
    main()
