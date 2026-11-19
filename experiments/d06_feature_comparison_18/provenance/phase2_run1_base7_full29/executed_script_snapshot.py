"""Isolated D06 development pilot; never reads Test or modifies existing outputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
import sklearn
from sklearn.tree import DecisionTreeClassifier, export_text

ID = ["package", "old_version", "new_version"]
KEY = ID + ["label"]
CLASSES = ["malicious", "benign", "hard_benign"]
HASHES = ["largestChangedJsSha1", "changedJsSetSha1"]
GENERIC = re.compile(r"^(individual-compromise(-\d+(?:st|nd|rd|th))?|individuals_case)$")
SANITIZE = [f"obf{metric}{suffix}" for metric in ["MeanIdentLength", "WhitespaceRatio"]
            for suffix in ["New", "ChangedCode"]]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, data):
    Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def strict_join(left, right, columns):
    """Exact one-to-one keyed join, including independent label consistency."""
    for frame in [left, right]:
        require(not frame[ID].isna().any().any(), "missing identifier")
        require(not frame.duplicated(ID).any(), "duplicate identifier")
        require(set(frame.label).issubset({0, 1}), "invalid label")
    left_keys = set(map(tuple, left[KEY].to_numpy()))
    right_keys = set(map(tuple, right[KEY].to_numpy()))
    require(left_keys == right_keys, "join keys or labels differ")
    return left.merge(right[KEY + columns], on=KEY, how="left", validate="one_to_one", sort=False)


def shared_campaign(value):
    return bool(value) and not GENERIC.fullmatch(value)


def components(frame):
    parent = {}

    def find(node):
        parent.setdefault(node, node)
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    def union(a, b):
        a, b = find(a), find(b)
        parent[max(a, b)] = min(a, b)

    for row in frame.itertuples(index=False):
        pkg = "package:" + row.package
        find(pkg)
        if row.label == 1:
            if shared_campaign(row.splitGroup):
                union(pkg, "campaign:" + row.splitGroup)
            for name in HASHES:
                value = getattr(row, name)
                if value:
                    union(pkg, name + ":" + value)
    roots = [find("package:" + pkg) for pkg in frame.package]
    canonical = {root: f"component_{i:04d}" for i, root in enumerate(sorted(set(roots)))}
    return pd.Series([canonical[root] for root in roots], index=frame.index)


def check_disjoint(left, right):
    for column in ["component", "package"] + HASHES + ["splitGroup"]:
        a, b = set(left[column]), set(right[column])
        if column == "splitGroup":
            a, b = {v for v in a if shared_campaign(v)}, {v for v in b if shared_campaign(v)}
        else:
            a.discard("")
            b.discard("")
        require(not a.intersection(b), f"split overlap: {column}")


def component_counts(frame):
    return frame.groupby(["component", "class"]).size().unstack(fill_value=0).reindex(columns=CLASSES, fill_value=0)


def outer_folds(frame):
    counts = component_counts(frame)
    assignment, loads = {}, np.zeros((3, 3), dtype=int)
    malicious = counts.index[counts.malicious > 0]
    for group in sorted(malicious, key=lambda g: (-int(counts.loc[g, "malicious"]), g)):
        fold = min(range(3), key=lambda f: (loads[f, 0], f))
        assignment[group] = fold
        loads[fold] += counts.loc[group].to_numpy()
    normal = counts.index[counts.malicious == 0]
    target = np.maximum(counts.sum().to_numpy()[1:] / 3, 1)
    for group in sorted(normal, key=lambda g: (-int(counts.loc[g].sum()), g)):
        sizes = counts.loc[group].to_numpy()
        fold = min(range(3), key=lambda f: (float(np.sum((loads[f, 1:] + sizes[1:]) ** 2 / target)), f))
        assignment[group] = fold
        loads[fold] += sizes
    result = frame.component.map(assignment).astype(int)
    for fold in range(3):
        check_disjoint(frame[result != fold], frame[result == fold])
    return result


def inner_split(frame, seed):
    counts = component_counts(frame)
    target = counts.sum().to_numpy() * .25
    scale = np.maximum(target, 1)
    current, selected = np.zeros(3), []
    for group in np.random.default_rng(seed).permutation(sorted(counts.index)):
        candidate = current + counts.loc[group].to_numpy()
        if np.sum(((candidate - target) / scale) ** 2) < np.sum(((current - target) / scale) ** 2):
            selected.append(group)
            current = candidate
    calibration = frame[frame.component.isin(selected)]
    fit = frame[~frame.component.isin(selected)]
    require(set(fit.label) == {0, 1}, "fit requires both labels")
    require((calibration.label == 0).any(), "calibration has no normal rows")
    check_disjoint(fit, calibration)
    return fit, calibration


def decide(scores, threshold, rule, mode):
    decision = np.asarray(scores) >= threshold
    if mode == "OR":
        return decision | rule
    if mode == "AND":
        return decision & rule
    require(mode == "ML", "unknown decision mode")
    return decision


def calibrate(scores, labels, rule, mode, target):
    scores, labels, rule = np.asarray(scores), np.asarray(labels), np.asarray(rule, bool)
    require(len(scores) == len(labels) == len(rule), "calibration lengths differ")
    require(np.isfinite(scores).all(), "invalid score")
    normal = labels == 0
    count = int(normal.sum())
    require(count > 0 and 0 <= target < 1, "invalid calibration population or target")
    budget = math.floor(count * target + 1e-12)
    forced = int((normal & rule).sum()) if mode == "OR" else 0
    result = {"target_fpr": target, "calibration_normal": count, "budget": budget,
              "rule_fp": int((normal & rule).sum()), "forced_fp": forced, "decision_rule": ">="}
    if forced > budget:
        return dict(result, status="impossible", threshold=None, calibration_fp=None, ties=None)
    eligible = normal & (~rule if mode == "OR" else rule if mode == "AND" else True)
    eligible_scores = scores[eligible]
    remaining = budget - forced
    boundary = None
    if len(eligible_scores) <= remaining:
        threshold = -np.inf
        ties = 0
    else:
        boundary = float(np.sort(eligible_scores)[::-1][remaining])
        threshold = float(np.nextafter(boundary, np.inf))
        ties = int((eligible_scores == boundary).sum())
    fp = int(decide(scores, threshold, rule, mode)[normal].sum())
    require(fp <= budget, "calibration exceeded FP budget")
    return dict(result, status="ok", threshold=threshold, boundary=boundary, calibration_fp=fp, ties=ties)


def sanitize(frame):
    result = frame.copy()
    for column in SANITIZE:
        result.loc[result[column] == 0, column] = np.nan
    return result


def rules(frame):
    r1 = frame.installScriptAdded.to_numpy(bool)
    r2 = r1 | frame.scriptEntryAdded.to_numpy(bool)
    obf = ((frame.obfHexIdentRatioNew > 0) & (frame.obfHexIdentRatioChange > 0)).to_numpy()
    return {"R1": r1, "R2": r2, "R3": r2 | frame.newDependencyAdded.to_numpy(bool),
            "R_obf": obf, "R2_and_obf": r2 & obf}


def load_data(workspace, spec):
    paths = {name: workspace / spec[f"{name}_input"] for name in ["train", "groups", "classes"]}
    for name, path in paths.items():
        require(digest(path) == spec[f"{name}_sha256"], f"input hash mismatch: {name}")
    train = pd.read_csv(paths["train"], float_precision="round_trip")
    features = [c for c in train if c not in KEY]
    require(len(features) == 29 and len(train) == 2767, "unexpected training shape")
    predictions = pd.read_csv(paths["classes"], float_precision="round_trip", keep_default_na=False)
    require(set(predictions.variant) == {"E06", "E09"}, "unexpected source variants")
    a = strict_join(train, predictions[predictions.variant == "E06"], ["class", "campaign"])
    b = strict_join(train, predictions[predictions.variant == "E09"], ["class", "campaign"])
    require(a[["class", "campaign"]].equals(b[["class", "campaign"]]), "variant metadata differ")
    require(a.groupby("class").size().to_dict() == {"benign": 1600, "hard_benign": 239, "malicious": 928}, "class counts differ")
    require(((a.label == 1) == (a["class"] == "malicious")).all(), "class/label mismatch")
    for column in ["splitGroup"] + HASHES:
        a[column] = ""
    a["row_id"] = np.arange(len(a))
    groups = pd.read_csv(paths["groups"], keep_default_na=False)
    mal = strict_join(a[a.label == 1].drop(columns=["splitGroup"] + HASHES), groups, ["splitGroup"] + HASHES)
    require((mal.campaign == mal.splitGroup).all(), "campaign metadata differ")
    a.loc[mal.row_id, ["splitGroup"] + HASHES] = mal[["splitGroup"] + HASHES].to_numpy()
    require(set(a.updateType) <= {"major", "minor", "patch"}, "unknown updateType")
    for name in ["installScriptPresent", "installScriptAdded", "scriptEntryAdded", "newDependencyAdded"]:
        require(a[name].isin([True, False]).all(), "invalid Boolean feature")
    a["component"] = components(a)
    a["outer_fold"] = outer_folds(a)
    a["type"] = np.where(a.installScriptAdded | a.scriptEntryAdded, "A", np.where(a.newDependencyAdded, "B", "C"))
    return a, features, paths


def feature_matrix(frame, columns, variant):
    x = frame[columns].copy()
    if variant == "M_missingness":
        return x.isna().astype(float)
    if variant == "M_full_sanitized":
        x = sanitize(x)
    for column in x:
        if column == "updateType":
            x[column] = pd.Categorical(x[column], categories=["major", "minor", "patch"])
        else:
            x[column] = x[column].astype(float)
            require(not np.isinf(x[column]).any(), "infinite feature")
    return x


def fit_weights(frame):
    weight = np.ones(len(frame))
    malicious = frame.label.to_numpy() == 1
    keys = frame.loc[malicious].apply(lambda r: r.splitGroup if shared_campaign(r.splitGroup) else "package:" + r.package, axis=1)
    raw = 1 / np.sqrt(keys.map(keys.value_counts()).to_numpy())
    weight[malicious] = raw * malicious.sum() / raw.sum()
    return weight


def train_model(fit, calibration, outer, columns, variant, rounds, spec, model_path):
    matrices = [feature_matrix(part, columns, variant) for part in [fit, calibration, outer]]
    y = fit.label.to_numpy().copy()
    if variant.endswith("_shuffled"):
        y = np.random.default_rng(spec["model_seed"] + int(outer.outer_fold.iloc[0])).permutation(y)
    started = time.perf_counter()
    if variant.startswith("T_"):
        for matrix in matrices:
            if "updateType" in matrix:
                matrix["updateType"] = matrix.updateType.cat.codes.astype(float)
        model = DecisionTreeClassifier(max_depth=3, random_state=spec["model_seed"])
        model.fit(matrices[0], y)
        cal_scores = model.predict_proba(matrices[1])[:, 1]
        outer_scores = model.predict_proba(matrices[2])[:, 1]
        model_path.with_suffix(".txt").write_text(export_text(model, feature_names=columns), encoding="utf-8")
        write_json(model_path.with_suffix(".json"), {"features": columns,
            "children_left": model.tree_.children_left.tolist(), "children_right": model.tree_.children_right.tolist(),
            "feature": model.tree_.feature.tolist(), "threshold": model.tree_.threshold.tolist(),
            "value": model.tree_.value.tolist(), "missing_go_to_left": model.tree_.missing_go_to_left.tolist()})
        importance = model.feature_importances_
        trained_rounds = 1
    else:
        weights = fit_weights(fit) if variant == "M_base_weighted" else None
        categories = ["updateType"] if "updateType" in matrices[0] and variant != "M_missingness" else []
        dataset = lgb.Dataset(matrices[0], label=y, weight=weights, categorical_feature=categories, feature_name=columns)
        model = lgb.train(spec["lightgbm"], dataset, num_boost_round=rounds)
        cal_scores = model.predict(matrices[1], num_threads=2)
        outer_scores = model.predict(matrices[2], num_threads=2)
        model.save_model(str(model_path.with_suffix(".txt")))
        importance = model.feature_importance(importance_type="gain")
        trained_rounds = model.current_iteration()
    for scores in [cal_scores, outer_scores]:
        require(np.isfinite(scores).all() and ((scores >= 0) & (scores <= 1)).all(), "invalid predictions")
    return cal_scores, outer_scores, {"fit_seconds": time.perf_counter() - started, "trained_rounds": trained_rounds}, importance


def metrics(frame, pred):
    pred = np.asarray(pred, bool)
    malicious = frame.label.to_numpy() == 1
    tp, fp = int((pred & malicious).sum()), int((pred & ~malicious).sum())
    result = {"rows": len(frame), "tp": tp, "fp": fp, "fn": int(malicious.sum()) - tp,
              "tn": int((~malicious).sum()) - fp, "recall": tp / malicious.sum() if malicious.any() else np.nan,
              "fpr": fp / (~malicious).sum() if (~malicious).any() else np.nan}
    for cls in ["benign", "hard_benign"]:
        mask = frame["class"].to_numpy() == cls
        n, f = int(mask.sum()), int((pred & mask).sum())
        result[f"{cls}_n"], result[f"{cls}_fp"], result[f"{cls}_fpr"] = n, f, f / n if n else np.nan
    for typ in ["A", "B", "C"]:
        mask = malicious & (frame.type.to_numpy() == typ)
        n, detected = int(mask.sum()), int((pred & mask).sum())
        result[f"{typ}_n"], result[f"{typ}_tp"], result[f"{typ}_recall"] = n, detected, detected / n if n else np.nan
    return result


def export_results(data, decisions, thresholds, predictions, splits, training, importance, output, largest):
    decisions = pd.concat(decisions, ignore_index=True)
    pd.concat(predictions, ignore_index=True).to_csv(output / "predictions.csv", index=False, lineterminator="\n")
    pd.concat(splits, ignore_index=True).to_csv(output / "splits.csv", index=False, lineterminator="\n")
    decisions.to_csv(output / "pair_decisions.csv", index=False, lineterminator="\n")
    pd.DataFrame(thresholds).to_csv(output / "thresholds.csv", index=False, lineterminator="\n")
    pd.DataFrame(training).to_csv(output / "training.csv", index=False, lineterminator="\n")
    pd.DataFrame(importance).to_csv(output / "feature_importance.csv", index=False, lineterminator="\n")
    groupcols = ["scenario", "seed", "rounds", "variant", "operating_point", "policy"]
    metric_rows, group_rows, deltas = [], [], []
    for keys, decision in decisions.groupby(groupcols, sort=True):
        metadata = dict(zip(groupcols, keys))
        require(not decision.duplicated("row_id").any(), "duplicate OOF decision")
        indexed = decision.set_index("row_id")
        for fold in [-1, 0, 1, 2]:
            selected = decision if fold == -1 else decision[decision.fold == fold]
            if selected.empty:
                continue
            for exclusion in [False, True]:
                rows = data.loc[selected.row_id]
                if exclusion:
                    rows = rows[~rows.component.isin(largest)]
                pred = indexed.loc[rows.row_id, "pred"].to_numpy(bool)
                m = dict(metadata, fold=fold, exclude_largest3=exclusion, **metrics(rows, pred))
                mal = rows[rows.label == 1]
                values = indexed.loc[mal.row_id, "pred"].to_numpy(bool)
                m["component_macro_recall"] = float(pd.Series(values, index=mal.index).groupby(mal.component).mean().mean()) if len(mal) else np.nan
                m["campaign_macro_recall"] = float(pd.Series(values, index=mal.index).groupby(mal.campaign).mean().mean()) if len(mal) else np.nan
                m["folds_present"] = int(selected.fold.nunique())
                metric_rows.append(m)
        mal = data.loc[decision.row_id]
        mal = mal[mal.label == 1]
        for group_by in ["campaign", "component"]:
            for name, rows in mal.groupby(group_by):
                caught = int(indexed.loc[rows.row_id, "pred"].sum())
                group_rows.append(dict(metadata, group_by=group_by, group=name, n=len(rows), tp=caught, recall=caught / len(rows)))
        if metadata["variant"] != "M_base" and metadata["scenario"] != "rules":
            base = decisions[(decisions.scenario == metadata["scenario"]) & (decisions.seed == metadata["seed"]) &
                             (decisions["rounds"] == metadata["rounds"]) & (decisions.variant == "M_base") &
                             (decisions.operating_point == metadata["operating_point"]) & (decisions.policy == metadata["policy"])]
            paired = decision.merge(base[["row_id", "pred"]], on="row_id", suffixes=("", "_base"), validate="one_to_one")
            if len(paired) == len(data):
                truth = data.loc[paired.row_id, "label"].to_numpy() == 1
                new, old = paired.pred.to_numpy(bool), paired.pred_base.to_numpy(bool)
                deltas.append(dict(metadata, n=len(paired), tp_gain=int((truth & new & ~old).sum()),
                    tp_lost=int((truth & ~new & old).sum()), fp_added=int((~truth & new & ~old).sum()),
                    fp_removed=int((~truth & ~new & old).sum())))
    pd.DataFrame(metric_rows).to_csv(output / "metrics.csv", index=False, lineterminator="\n")
    pd.DataFrame(group_rows).to_csv(output / "group_metrics.csv", index=False, lineterminator="\n")
    pd.DataFrame(deltas).to_csv(output / "paired_deltas.csv", index=False, lineterminator="\n")
    table = pd.DataFrame(metric_rows)
    table = table[(table.fold == -1) & ~table.exclude_largest3 & (table.policy == "ML") & (table.scenario == "primary")]
    lines = ["# D06 방향 가능성 실험", "", "개발자료 진단이다. 독립 최종 성능이 아니다.", "",
             "| 방법 | 운영점 | TP | FP | 정상 FPR | 어려운 정상 FP |", "|---|---|---:|---:|---:|---:|"]
    for row in table.itertuples():
        lines.append(f"| {row.variant} | {row.operating_point} | {row.tp} | {row.fp} | {row.fpr:.3%} | {row.hard_benign_fp} |")
    lines.extend(["", "규칙 결합은 전체 결정의 calibration FP 예산을 검사했다. 불가능한 fold는 thresholds.csv에 기록했고 성능으로 위장하지 않았다.",
                  "일부 fold만 가능한 결합의 pooled metrics는 folds_present를 확인해야 한다. 완전한 3fold 결과와 직접 비교하면 안 된다.",
                  "캠페인 평균에는 individuals_case 보고용 묶음이 포함된다. component 평균도 별도로 제공한다.",
                  "검증: Test 미열람, 외부 fold 학습·calibration 미사용, package/campaign/nonempty-hash 분리."])
    (output / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def run(workspace, spec_path):
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    criteria_path = spec_path.parent / "decision_criteria.json"
    require(criteria_path.is_file(), "decision criteria must be preregistered")
    json.loads(criteria_path.read_text(encoding="utf-8"))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = workspace / "temp/detection-feasibility/phase2/runs" / f"run_{stamp}_{uuid.uuid4().hex[:8]}"
    output.mkdir(parents=True, exist_ok=False)
    (output / "models").mkdir()
    manifest = {"status": "running", "started_utc": stamp, "spec_path": str(spec_path), "spec_sha256": digest(spec_path),
                "decision_criteria_path": str(criteria_path), "decision_criteria_sha256": digest(criteria_path),
                "script_sha256": digest(__file__), "argv": sys.argv, "python": platform.python_version(),
                "packages": {"lightgbm": lgb.__version__, "pandas": pd.__version__, "numpy": np.__version__, "sklearn": sklearn.__version__},
                "read_test": False, "remote_writes": False}
    write_json(output / "manifest.json", manifest)
    try:
        data, all_features, paths = load_data(workspace, spec)
        base = spec["features"]["M_base"]
        obf = base + spec["features"]["M_obf_extra"]
        feature_sets = {"M_base": base, "M_obf": obf, "M_full": all_features,
            "M_obf_no_interval": [f for f in obf if f != "updateInterval"], "M_base_weighted": base,
            "T_obf": obf, "M_full_sanitized": all_features, "M_missingness": all_features,
            "M_base_shuffled": base, "M_obf_shuffled": obf}
        require(len(obf) == 15 and all(set(cols) <= set(all_features) for cols in feature_sets.values()), "feature whitelist mismatch")
        write_json(output / "feature_sets.json", feature_sets)
        zero_counts = {name: {cls: int(((data["class"] == cls) & (data[name] == 0)).sum()) for cls in CLASSES} for name in SANITIZE}
        write_json(output / "zero_sensitivity_counts.json", zero_counts)
        data[KEY + ["row_id", "class", "campaign", "component", "outer_fold", "type"] + HASHES].to_csv(output / "outer_assignment.csv", index=False, lineterminator="\n")
        largest = component_counts(data).sort_values("malicious", ascending=False, kind="stable").head(3).index.tolist()
        manifest.update(inputs={name: {"path": str(path), "sha256": digest(path)} for name, path in paths.items()},
                        rows=len(data), feature_count=len(all_features), components=int(data.component.nunique()),
                        malicious_components=int(data[data.label == 1].component.nunique()), largest3_components=largest)
        write_json(output / "manifest.json", manifest)
        schedules = [("primary", spec["primary_seed"], spec["rounds"], spec["primary_models"] + spec["diagnostic_models"]),
                     ("calibration_seed", spec["calibration_sensitivity_seed"], spec["rounds"], spec["seed_sensitivity_models"]),
                     ("rounds_50", spec["primary_seed"], 50, spec["round_sensitivity"]["models"])]
        decisions, thresholds, predictions, splits, training, importance = [], [], [], [], [], []
        for fold in range(3):
            outer = data[data.outer_fold == fold]
            for rule_name, pred in rules(outer).items():
                decisions.append(pd.DataFrame({"scenario": "rules", "seed": spec["primary_seed"], "rounds": 0,
                    "variant": rule_name, "operating_point": "fixed", "policy": "fixed", "fold": fold,
                    "row_id": outer.row_id.to_numpy(), "pred": pred.astype(int)}))
        for scenario, seed, rounds, variants in schedules:
            for fold in range(3):
                outer = data[data.outer_fold == fold]
                fit, calibration = inner_split(data[data.outer_fold != fold], seed + fold)
                check_disjoint(fit, outer)
                check_disjoint(calibration, outer)
                for stage, part in [("fit", fit), ("calibration", calibration), ("outer", outer)]:
                    splits.append(pd.DataFrame({"scenario": scenario, "seed": seed, "rounds": rounds, "fold": fold,
                                               "stage": stage, "row_id": part.row_id.to_numpy(), "component": part.component.to_numpy()}))
                cal_rules, out_rules = rules(calibration), rules(outer)
                for variant in variants:
                    identity = {"scenario": scenario, "seed": seed, "rounds": rounds, "variant": variant, "fold": fold}
                    model_path = output / "models" / f"{scenario}_{variant}_fold{fold}"
                    cal_score, out_score, train_info, gain = train_model(fit, calibration, outer, feature_sets[variant], variant, rounds, spec, model_path)
                    training.append(dict(identity, **train_info, fit_rows=len(fit), calibration_rows=len(calibration), outer_rows=len(outer),
                        fit_malicious=int(fit.label.sum()), calibration_malicious=int(calibration.label.sum()),
                        calibration_normal=int((calibration.label == 0).sum()), calibration_hard=int((calibration["class"] == "hard_benign").sum())))
                    importance.extend(dict(identity, feature=f, gain=float(g)) for f, g in zip(feature_sets[variant], gain, strict=True))
                    for stage, part, score in [("calibration", calibration, cal_score), ("outer", outer, out_score)]:
                        predictions.append(pd.DataFrame(dict(identity, stage=stage, row_id=part.row_id.to_numpy(), score=score)))
                    decisions.append(pd.DataFrame(dict(identity, operating_point="default_0.5", policy="ML",
                        row_id=outer.row_id.to_numpy(), pred=(out_score >= .5).astype(int))))
                    policies = [("ML", "ML", "R1"), ("R1_OR_ML", "OR", "R1"), ("R_obf_OR_ML", "OR", "R_obf"), ("R2_AND_ML", "AND", "R2")]
                    if variant in spec["diagnostic_models"]:
                        policies = policies[:1]
                    for target in [.01, .05]:
                        op = f"cal_fpr_{int(target * 100)}pct"
                        for policy, mode, rule_name in policies:
                            calibrated = calibrate(cal_score, calibration.label.to_numpy(), cal_rules[rule_name], mode, target)
                            thresholds.append(dict(identity, operating_point=op, policy=policy, **calibrated))
                            if calibrated["status"] == "ok":
                                pred = decide(out_score, calibrated["threshold"], out_rules[rule_name], mode)
                                decisions.append(pd.DataFrame(dict(identity, operating_point=op, policy=policy,
                                    row_id=outer.row_id.to_numpy(), pred=pred.astype(int))))
                    print(f"done {scenario} fold={fold} {variant}", flush=True)
        export_results(data, decisions, thresholds, predictions, splits, training, importance, output, largest)
        for name, path in paths.items():
            require(digest(path) == manifest["inputs"][name]["sha256"], "input changed while running")
        require(digest(spec_path) == manifest["spec_sha256"], "spec changed while running")
        require(digest(criteria_path) == manifest["decision_criteria_sha256"], "decision criteria changed while running")
        manifest.update(status="completed", completed_utc=datetime.now(timezone.utc).isoformat(),
                        trained_models=len(training), validation=["input hashes", "strict joins", "three-way group disjointness",
                        "calibration budgets", "OOF row uniqueness", "feature whitelists", "unchanged input hashes"])
        manifest["outputs"] = [{"path": str(p.relative_to(output)), "sha256": digest(p), "bytes": p.stat().st_size}
                               for p in sorted(output.rglob("*")) if p.is_file() and p.name != "manifest.json"]
        write_json(output / "manifest.json", manifest)
        print(f"completed {output}", flush=True)
    except Exception as exc:
        manifest.update(status="failed", error_type=type(exc).__name__, error=str(exc))
        write_json(output / "manifest.json", manifest)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--spec", type=Path)
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    spec_path = args.spec or workspace / "temp/detection-feasibility/phase2/evaluation_spec.json"
    run(workspace, spec_path.resolve())


if __name__ == "__main__":
    main()
