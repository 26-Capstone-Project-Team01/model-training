"""Train a LightGBM classifier to detect malicious npm package updates."""

import json
import random
import re
from pathlib import Path
from typing import Dict, List, Sequence, Set, Tuple

import lightgbm as lgb
import pandas as pd
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score

BASE_DIR = Path(__file__).resolve().parent
RAW_DATA_DIR = BASE_DIR / "data" / "raw"
DATA_SOURCE_PATH = BASE_DIR / "data" / "SOURCE.json"

# Fetched into place by scripts/fetch_data.py (see data/SOURCE.json for the pinned
# npm-malware-package-pairs commit); not committed to this repo (see .gitignore).
TRAIN_PATH = RAW_DATA_DIR / "train.csv"
TEST_PATH = RAW_DATA_DIR / "test.csv"

# Upstream split metadata: carries class + splitGroup for every pair, keyed by ID_COLS.
UPSTREAM_SPLIT_ASSIGNMENT_PATH = RAW_DATA_DIR / "split_assignment.csv"

# Model-training's own artifact, anchored to this file's location (not cwd) so it always
# lands in the same place regardless of where train_model.py is invoked from.
SPLIT_ASSIGNMENT_PATH = BASE_DIR / "splits" / "train_val_split_assignment.csv"

# Experiment identity: DATA_VERSION tracks which upstream data snapshot is reflected
# (bump when new data is fetched), EXPERIMENT_ID/NAME identify this run within that
# data version. Bump these by hand before each new run (see results/experiments.csv).
DATA_VERSION = "D06"
EXPERIMENT_ID = "E08"
EXPERIMENT_NAME = "campaign_sample_weight"
EXPERIMENT_NOTES = (
    "D06-E00과 동일 데이터/분할/29개 feature/하이퍼파라미터/seed(20261002). "
    "실제 학습 Train(악성 741개, Validation 분리 후)에서 campaign(=악성 splitGroup) 크기가 "
    "극단적으로 불균형(1위 332개 vs 1개뿐인 campaign 4개)한 문제를 완화하기 위해, 악성 pair에 "
    "campaign 단위 sample weight = 1/sqrt(campaign_size)를 적용하고 악성 weight 합이 741이 "
    "되도록 정규화. individuals_case(및 구 individual-compromise*)는 하나의 campaign으로 묶지 "
    "않고 pair마다 독립 campaign(size=1)으로 처리. benign/hard_benign weight=1 유지. "
    "Validation/Test에는 가중치를 적용하지 않음(둘 다 weight=1)."
)
# Feature columns to drop in addition to DROP_COLS, for ablation experiments
# (e.g. EXCLUDED_FEATURES = ["updateType"] for an updateType-ablation run).
EXCLUDED_FEATURES: List[str] = []

# D06-E08: campaign-level sample weighting for malicious Train rows (see compute_sample_weights).
# False reproduces plain D06-E00-style unweighted training.
USE_CAMPAIGN_WEIGHTING = True

EXPERIMENT_KEY = f"{DATA_VERSION}-{EXPERIMENT_ID}"
EXPERIMENT_TAG = f"{DATA_VERSION}_{EXPERIMENT_ID}_{EXPERIMENT_NAME}"

# All three anchored to this file's location (not cwd) so they always land in the same
# place regardless of where train_model.py is invoked from.
MODEL_PATH = BASE_DIR / "models" / f"{EXPERIMENT_TAG}.txt"
FEATURE_IMPORTANCE_PATH = BASE_DIR / "results" / "feature_importance" / f"{EXPERIMENT_TAG}.csv"
EXPERIMENTS_LOG_PATH = BASE_DIR / "results" / "experiments.csv"

TARGET_COL = "label"
ID_COLS = ["package", "old_version", "new_version"]
DROP_COLS = ID_COLS + [TARGET_COL]
CATEGORICAL_COLS = ["updateType"]

VAL_SIZE = 0.2
RANDOM_STATE = 20261002

# Generic "bucket" splitGroups (npm-malware-package-pairs' make_malicious_pair_groups.py
# GENERIC_BUCKET_CAMPAIGN) collect unrelated single-package compromises under one placeholder
# name. Treating that name as a real shared group would union every unrelated package under it
# into one artificial component — exactly what this split is meant to avoid.
GENERIC_BUCKET_SPLIT_GROUP = re.compile(r"^(individual-compromise(-\d+(?:st|nd|rd|th))?|individuals_case)$")


def is_shared_attack_split_group(split_group) -> bool:
    return bool(split_group) and not GENERIC_BUCKET_SPLIT_GROUP.match(split_group)


def compute_sample_weights(train_df: pd.DataFrame) -> pd.Series:
    """Campaign-level sample weight for malicious Train rows, to offset a few campaigns
    dominating the malicious count (e.g. one campaign alone is 332 of 741 Train malicious pairs).

    weight = 1/sqrt(campaign_size), then rescaled so malicious weights sum to the malicious row
    count (benign/hard_benign are unaffected, weight=1) — this redistributes attention across
    campaigns without shifting the overall malicious:benign balance that unweighted training sees.
    Generic-bucket splitGroups (is_shared_attack_split_group) are not a real shared campaign, so
    each of those rows is its own singleton campaign (size=1) rather than being pooled together.
    """
    merged = load_merged_assignment(train_df)
    weight = pd.Series(1.0, index=train_df.index)

    is_malicious = (merged["class"] == "malicious").to_numpy()
    if not is_malicious.any():
        return weight

    def campaign_key(idx: int, split_group) -> str:
        if pd.notna(split_group) and is_shared_attack_split_group(split_group):
            return split_group
        return f"singleton:{idx}"

    campaign_keys = pd.Series(
        [campaign_key(i, sg) for i, sg in zip(merged.index, merged["splitGroup"])],
        index=merged.index,
    )
    mal_keys = campaign_keys[is_malicious]
    campaign_size = mal_keys.map(mal_keys.value_counts())
    raw_weight = 1.0 / campaign_size.pow(0.5)
    weight.loc[is_malicious] = (raw_weight * (is_malicious.sum() / raw_weight.sum())).to_numpy()
    return weight


class UnionFind:
    """Disjoint-set over arbitrary hashable node labels, with path compression."""

    def __init__(self) -> None:
        self.parent: Dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb


def load_merged_assignment(train_df: pd.DataFrame) -> pd.DataFrame:
    """Attach class/splitGroup from the upstream split_assignment.csv, joined on ID_COLS."""
    upstream = pd.read_csv(UPSTREAM_SPLIT_ASSIGNMENT_PATH)
    merged = train_df[ID_COLS].merge(
        upstream[ID_COLS + ["class", "splitGroup"]], on=ID_COLS, how="left"
    )
    missing = merged[merged["class"].isna()]
    if not missing.empty:
        raise ValueError(
            f"{UPSTREAM_SPLIT_ASSIGNMENT_PATH}에서 매칭되지 않은 pair가 있습니다:\n{missing[ID_COLS]}"
        )
    return merged


def assign_components(merged: pd.DataFrame) -> pd.Series:
    """Union package with its malicious splitGroup so neither can be split across train/validation."""
    uf = UnionFind()
    for _, row in merged.iterrows():
        pkg_node = f"pkg:{row['package']}"
        if row["class"] == "malicious" and pd.notna(row["splitGroup"]) and is_shared_attack_split_group(row["splitGroup"]):
            uf.union(pkg_node, f"grp:{row['splitGroup']}")
    return merged["package"].map(lambda pkg: uf.find(f"pkg:{pkg}"))


def choose_validation_components(merged: pd.DataFrame) -> Set[str]:
    """Pick whole connected components for validation so per-class ratios land close to VAL_SIZE."""
    sizes = merged.groupby("component").size()
    multi_components = sizes[sizes > 1].index.tolist()
    singleton_components = sizes[sizes == 1].index.tolist()

    target_val = {cls: round(count * VAL_SIZE) for cls, count in merged["class"].value_counts().items()}

    multi_class_counts = {
        comp: merged.loc[merged["component"] == comp, "class"].value_counts().to_dict()
        for comp in multi_components
    }

    # Exact search over the (small) set of multi-row components: there are few enough of these
    # that brute-forcing every subset is cheap, and it finds the combination closest to target_val.
    candidates = list(multi_class_counts.items())
    best_cost = float("inf")
    best_subsets: List[Tuple[str, ...]] = []
    for mask in range(1 << len(candidates)):
        achieved: Dict[str, int] = {}
        subset = []
        for i, (comp, counts) in enumerate(candidates):
            if mask & (1 << i):
                subset.append(comp)
                for cls, n in counts.items():
                    achieved[cls] = achieved.get(cls, 0) + n
        cost = sum(abs(achieved.get(cls, 0) - target_val.get(cls, 0)) for cls in target_val)
        subset_key = tuple(sorted(subset))
        if cost < best_cost:
            best_cost, best_subsets = cost, [subset_key]
        elif cost == best_cost:
            best_subsets.append(subset_key)

    chosen = random.Random(RANDOM_STATE).choice(sorted(set(best_subsets)))
    val_components: Set[str] = set(chosen)

    achieved_val: Dict[str, int] = {}
    for comp in val_components:
        for cls, n in multi_class_counts[comp].items():
            achieved_val[cls] = achieved_val.get(cls, 0) + n

    # Fill the remaining per-class budget from singleton components (one pair each), mirroring
    # the upstream script's seeded random fill for classes without a structural grouping.
    singleton_df = merged[merged["component"].isin(singleton_components)]
    for cls in target_val:
        remaining = max(target_val[cls] - achieved_val.get(cls, 0), 0)
        pool: Sequence[Tuple[str, str, str, str]] = sorted(
            singleton_df.loc[singleton_df["class"] == cls, ID_COLS + ["component"]].itertuples(
                index=False, name=None
            )
        )
        picked = random.Random(RANDOM_STATE).sample(pool, min(remaining, len(pool)))
        val_components.update(row[-1] for row in picked)

    return val_components


def save_split_assignment(merged: pd.DataFrame, val_components: Set[str]) -> None:
    out = merged[ID_COLS + ["class", "splitGroup", "component"]].copy()
    out["split"] = out["component"].apply(lambda c: "validation" if c in val_components else "train")
    out["assignedBy"] = out["component"].map(merged.groupby("component").size() > 1).map(
        {True: "connectedComponent", False: f"random(seed={RANDOM_STATE})"}
    )
    SPLIT_ASSIGNMENT_PATH.parent.mkdir(parents=True, exist_ok=True)
    out.drop(columns="component").to_csv(SPLIT_ASSIGNMENT_PATH, index=False)
    print(f"Split assignment saved to {SPLIT_ASSIGNMENT_PATH}")


def build_features(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series, List[str]]:
    y = df[TARGET_COL]
    X = df.drop(columns=DROP_COLS + EXCLUDED_FEATURES)
    for col in CATEGORICAL_COLS:
        if col in X.columns:
            X[col] = X[col].astype("category")
    return X, y, list(X.columns)


def split_train_validation(full_train_df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Package+splitGroup-aware validation split (see choose_validation_components)."""
    merged = load_merged_assignment(full_train_df)
    merged["component"] = assign_components(merged)
    val_components = choose_validation_components(merged)
    save_split_assignment(merged, val_components)

    assignment = merged[ID_COLS + ["component"]].copy()
    assignment["split"] = assignment["component"].apply(
        lambda c: "validation" if c in val_components else "train"
    )
    full_train_df = full_train_df.merge(assignment[ID_COLS + ["split"]], on=ID_COLS, how="left")
    train_df = full_train_df[full_train_df["split"] == "train"].drop(columns="split").reset_index(drop=True)
    val_df = full_train_df[full_train_df["split"] == "validation"].drop(columns="split").reset_index(drop=True)
    return train_df, val_df


def main() -> None:
    full_train_df = pd.read_csv(TRAIN_PATH)
    test_df = pd.read_csv(TEST_PATH)

    # test.csv's own train/test split already prevents package & splitGroup leakage;
    # this split only needs to keep the same guarantee within train.csv for validation.
    train_df, val_df = split_train_validation(full_train_df)

    X_train, y_train, feature_cols = build_features(train_df)
    X_val, y_val, _ = build_features(val_df)
    X_test, y_test, _ = build_features(test_df)

    train_weight = compute_sample_weights(train_df) if USE_CAMPAIGN_WEIGHTING else None

    train_set = lgb.Dataset(
        X_train,
        label=y_train,
        weight=train_weight,
        categorical_feature=CATEGORICAL_COLS,
        feature_name=feature_cols,
    )
    val_set = lgb.Dataset(
        X_val,
        label=y_val,
        categorical_feature=CATEGORICAL_COLS,
        feature_name=feature_cols,
        reference=train_set,
    )

    params = {
        "objective": "binary",
        "metric": ["binary_logloss", "auc"],
        "verbosity": -1,
    }

    booster = lgb.train(
        params,
        train_set,
        num_boost_round=500,
        valid_sets=[train_set, val_set],
        valid_names=["train", "val"],
        callbacks=[lgb.early_stopping(stopping_rounds=50), lgb.log_evaluation(50)],
    )

    # val metrics (same booster/iteration the training used for early stopping).
    val_pred_proba = booster.predict(X_val, num_iteration=booster.best_iteration)
    val_pred = (val_pred_proba >= 0.5).astype(int)
    val_recall = recall_score(y_val, val_pred)
    val_precision = precision_score(y_val, val_pred)
    val_f1 = f1_score(y_val, val_pred)
    val_pr_auc = average_precision_score(y_val, val_pred_proba)

    print(f"[val] Recall:    {val_recall:.4f}")
    print(f"[val] Precision: {val_precision:.4f}")
    print(f"[val] F1:        {val_f1:.4f}")
    print(f"[val] PR-AUC:    {val_pr_auc:.4f}")

    # test.csv is untouched by training/early stopping — used only for final evaluation.
    y_pred_proba = booster.predict(X_test, num_iteration=booster.best_iteration)
    y_pred = (y_pred_proba >= 0.5).astype(int)

    recall = recall_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    pr_auc = average_precision_score(y_test, y_pred_proba)

    print(f"[test] Recall:    {recall:.4f}")
    print(f"[test] Precision: {precision:.4f}")
    print(f"[test] F1:        {f1:.4f}")
    print(f"[test] PR-AUC:    {pr_auc:.4f}")

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    booster.save_model(MODEL_PATH)
    print(f"Model saved to {MODEL_PATH}")

    importance = pd.DataFrame(
        {"feature": booster.feature_name(), "importance": booster.feature_importance()}
    ).sort_values("importance", ascending=False)
    FEATURE_IMPORTANCE_PATH.parent.mkdir(parents=True, exist_ok=True)
    importance.to_csv(FEATURE_IMPORTANCE_PATH, index=False)
    print(f"Feature importance saved to {FEATURE_IMPORTANCE_PATH}")

    upstream_commit = json.loads(DATA_SOURCE_PATH.read_text(encoding="utf-8"))["commit"]
    record = pd.DataFrame([{
        "experiment_id": EXPERIMENT_KEY,
        "data_version": DATA_VERSION,
        "upstream_data_commit": upstream_commit,
        "experiment_name": EXPERIMENT_NAME,
        "used_features": ";".join(feature_cols),
        "excluded_features": ";".join(EXCLUDED_FEATURES),
        "train_samples": len(train_df),
        "val_samples": len(val_df),
        "test_samples": len(test_df),
        "val_recall": val_recall,
        "val_precision": val_precision,
        "val_f1": val_f1,
        "val_pr_auc": val_pr_auc,
        "test_recall": recall,
        "test_precision": precision,
        "test_f1": f1,
        "test_pr_auc": pr_auc,
        "best_iteration": booster.best_iteration,
        "model_file": str(MODEL_PATH.relative_to(BASE_DIR)),
        "notes": EXPERIMENT_NOTES,
    }])
    EXPERIMENTS_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    record.to_csv(
        EXPERIMENTS_LOG_PATH,
        mode="a",
        header=not EXPERIMENTS_LOG_PATH.exists(),
        index=False,
    )
    print(f"Experiment record appended to {EXPERIMENTS_LOG_PATH}")


if __name__ == "__main__":
    main()
