"""EXP-BLEND-01 prototype: can depbee serve the full29 + full35 score blend? No training, no Test 677.

  python -I -B scripts/blend_a_prototype.py repro     reproduce the a4a5280 A1-A3 numbers from the saved scores
  python -I -B scripts/blend_a_prototype.py profile   column order, types and missing pattern of the stored 35-feature CSV
  python -I -B scripts/blend_a_prototype.py nan       the blend's selections when X1 is missing (NaN) or full35 is not scored
  python -I -B scripts/blend_a_prototype.py timing    load and single-row inference cost, 1 model against 2

Every input is read from this repository's git objects at the two pinned commits below (git show):
nothing is checked out and no model file is written. Every mode exits 1 when one of its checks fails.
Outputs: results/blend_a_integration_check/ (UTF-8, LF). timing.json differs on every run.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import math
import os
import platform
import statistics
import subprocess
import time
from pathlib import Path

import numpy as np
import pandas as pd

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "results" / "blend_a_integration_check"
MAIN = "e2672817428f4107bbf41f40cbe78496083b5ab5"  # origin/main: PR #13 bundle (full29 models and scores)
BLEND = "a4a5280ed256924090d8a2b8b1e165324b42eddd"  # origin/exp/d06-x1-blend-a: full35 models, scores, X1, A1-A3
B18 = "experiments/d06_feature_comparison_18"
C35 = "experiments/d06_full35_compare/run"
X1 = "experiments/d06_x1_extraction"
BA = "experiments/d06_x1_blend_a"
SPLITS = {20261109: "split1", 20261110: "split2"}
WEIGHTS = {"A1": 0.1, "A2": 0.2, "A3": 0.3}  # weight of full35, fixed in a4a5280 before its evaluation
VARIANTS = ["full29", "full35", *WEIGHTS]
TARGETS = {"cal1": 0.01, "cal5": 0.05}  # calibration false positive budget: floor(normal rows * target)
SHAI = "shai-hulud-original_2025-09"
CLASSES = ("malicious", "benign", "hard_benign")
CATEGORIES = ["major", "minor", "patch"]
SIDES = {"one_model": ["full29"], "two_models": ["full29", "full35"]}  # what the timing mode compares
TRAIN_SHA256 = "22fbc8752fff5fff90e40b911f6bf7d187769b4566db957d65a37a16be7d2c23"  # D06 train.csv, PR #13 README 4


def show(commit: str, path: str) -> bytes:
    command = ["git", "-C", str(REPO), "show", f"{commit}:{path}"]
    return subprocess.run(command, capture_output=True, check=True).stdout


def table(commit: str, path: str, **options) -> pd.DataFrame:
    return pd.read_csv(io.BytesIO(show(commit, path)), **options)


def write(name: str, frame: pd.DataFrame) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    frame.to_csv(OUT / name, index=False, lineterminator="\n", encoding="utf-8")


def write_json(name: str, value: dict) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    text = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    (OUT / name).write_text(text, encoding="utf-8", newline="\n")


def paired_scores() -> pd.DataFrame:
    """One row per (seed, fold, stage, row_id): both saved scores, the three blends, the row's class.

    Scores are parsed with pandas' default float parser, as the a4a5280 loaders do, so thresholds compare exactly.
    """
    key = ["seed", "fold", "stage", "row_id"]
    a = table(MAIN, f"{B18}/scores/saved_scores.csv")
    a = a[a.model == "full29"][key + ["score"]].rename(columns={"score": "full29"})
    b = table(BLEND, f"{C35}/scores.csv")
    b = b[b.variant == "full35"][key + ["score"]].rename(columns={"score": "full35"})
    m = a.merge(b, on=key, how="outer", validate="one_to_one", indicator=True)
    if not (m["_merge"] == "both").all() or len(m) != 8548:
        raise SystemExit("full29 and full35 scores do not pair 1:1")
    meta = table(BLEND, f"{C35}/row_metadata.csv", keep_default_na=False)
    columns = ["row_id", "label", "class", "campaign", "type"]
    m = m.drop(columns="_merge").merge(meta[columns], on="row_id", validate="many_to_one")
    m["split"] = m.seed.map(SPLITS)
    for name, weight in WEIGHTS.items():
        m[name] = (1 - weight) * m.full29 + weight * m.full35
    return m


def fpr_threshold(scores: np.ndarray, labels: np.ndarray, target: float) -> tuple[float, int]:
    """PR #13 snapshot calibrate(), mode ML (executed_script_snapshot.py:154-180), written again here: the lowest
    threshold that keeps the normal rows selected (score >= threshold) within floor(normal rows * target)."""
    normal = np.sort(scores[labels == 0])[::-1]
    budget = math.floor(len(normal) * target + 1e-12)
    threshold = -math.inf if len(normal) <= budget else float(np.nextafter(normal[budget], np.inf))
    assert int((normal >= threshold).sum()) <= budget
    return threshold, budget


def metrics(g: pd.DataFrame, selected: np.ndarray) -> dict:
    """Counts of one group of outer rows. Random and hard benign false positives are kept apart."""
    malicious = g.label.to_numpy() == 1
    cls, campaign, kind = g["class"].to_numpy(), g.campaign.to_numpy(), g.type.to_numpy()
    tp = int((selected & malicious).sum())
    row = {"tp": tp, "fn": int(malicious.sum()) - tp, "fp": int((selected & ~malicious).sum()),
           "recall": tp / malicious.sum(), "precision": tp / max(int(selected.sum()), 1),
           "candidates": int(selected.sum())}
    for name in CLASSES[1:]:
        n, hit = int((cls == name).sum()), int((selected & (cls == name)).sum())
        row |= {f"{name}_n": n, f"{name}_fp": hit, f"{name}_fpr": hit / n}
    row["campaign_macro"] = pd.Series(selected[malicious]).groupby(campaign[malicious]).mean().mean()
    row["tp_excl_shai"] = int((selected & malicious & (campaign != SHAI)).sum())
    for name in "ABC":  # feature-based proxy types of the PR #13 snapshot (load_data)
        n, hit = int((malicious & (kind == name)).sum()), int((selected & malicious & (kind == name)).sum())
        row |= {f"{name}_n": n, f"{name}_tp": hit, f"{name}_recall": hit / n if n else math.nan}
    return row


def evaluate(m: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """(per fold, per split, per campaign) at each operating point: the threshold comes from that fold's
    calibration rows and is applied to its outer rows, per variant, as in a4a5280 blend_eval.py."""
    cal, outer = m[m.stage == "calibration"], m[m.stage == "outer"]
    folds, summary, campaigns = [], [], []
    for op, target in TARGETS.items():
        for variant in VARIANTS:
            selected = pd.Series(False, index=outer.index)
            for (split, fold), g in outer.groupby(["split", "fold"]):
                c = cal[(cal.split == split) & (cal.fold == fold)]
                threshold, budget = fpr_threshold(c[variant].to_numpy(), c.label.to_numpy(), target)
                hit = g[variant].to_numpy() >= threshold
                selected[g.index] = hit
                counted = metrics(g, hit)
                folds.append({
                    "op": op, "variant": variant, "split": split, "fold": fold,
                    "calibration_normal": int((c.label == 0).sum()), "budget": budget, "threshold": threshold,
                    "calibration_fp": int(((c[variant] >= threshold) & (c.label == 0)).sum()),
                    **{k: counted[k] for k in ("tp", "fn", "fp", "benign_fp", "hard_benign_fp")}})
            for split, g in outer.groupby("split"):
                summary.append({"op": op, "variant": variant, "split": split,
                                **metrics(g, selected[g.index].to_numpy())})
                for campaign, c in g[g.label == 1].groupby("campaign"):
                    campaigns.append({"op": op, "variant": variant, "split": split, "campaign": campaign,
                                      "n": len(c), "tp": int(selected[c.index].sum()),
                                      "recall": selected[c.index].mean()})
    return pd.DataFrame(folds), pd.DataFrame(summary), pd.DataFrame(campaigns)


def threshold_options(m: pd.DataFrame, folds: pd.DataFrame, summary: pd.DataFrame) -> pd.DataFrame:
    """One threshold for all three folds, three ways, next to the per-fold operating point. Development outer
    rows of fold models only: a list of options, not a choice. pooled_oof is fitted on the rows it is shown on."""
    outer, rows = m[m.stage == "outer"], []
    keep = ["tp", "fn", "fp", "recall", "benign_fpr", "hard_benign_fpr", "campaign_macro"]
    for variant in VARIANTS:
        for split, g in outer.groupby("split"):
            per_fold = folds[(folds.op == "cal1") & (folds.variant == variant) & (folds.split == split)]
            reference = summary[(summary.op == "cal1") & (summary.variant == variant) & (summary.split == split)]
            rows.append({"variant": variant, "split": split, "option": "per_fold_cal1", "threshold": math.nan,
                         **reference.iloc[0][keep].to_dict()})
            options = {
                "mean_of_fold_cal1": per_fold.threshold.mean(),
                "median_of_fold_cal1": per_fold.threshold.median(),
                "pooled_oof_1pct": fpr_threshold(g[variant].to_numpy(), g.label.to_numpy(), 0.01)[0],
            }
            for option, threshold in options.items():
                counted = metrics(g, g[variant].to_numpy() >= threshold)
                rows.append({"variant": variant, "split": split, "option": option, "threshold": threshold,
                             **{k: counted[k] for k in keep}})
    return pd.DataFrame(rows)


def compare(folds: pd.DataFrame, summary: pd.DataFrame) -> pd.DataFrame:
    """a4a5280's stored numbers beside the ones computed here (cal1 only: a4a5280 has no FPR 5% point)."""
    rows = []
    original = table(BLEND, f"{BA}/blend_summary.csv", float_precision="round_trip")
    original = original[original.op == "cal1"].rename(columns={"hard_fp": "hard_benign_fp"})
    mine = summary[summary.op == "cal1"]
    for metric in ["tp", "fn", "fp", "hard_benign_fp", "benign_fp", "candidates", "tp_excl_shai",
                   "recall", "precision", "campaign_macro"]:
        joined = original[["variant", "split", metric]].merge(
            mine[["variant", "split", metric]], on=["variant", "split"], how="outer", validate="one_to_one",
            suffixes=("_original", "_reproduced"))
        rows += [{"table": "blend_summary.csv", "variant": v, "split": s, "fold": "", "metric": metric,
                  "original": a, "reproduced": b} for v, s, a, b in joined.itertuples(index=False)]
    original = table(BLEND, f"{BA}/blend_fold_cal1.csv", float_precision="round_trip")
    mine = folds[folds.op == "cal1"].rename(columns={"threshold": "thr"})
    for metric in ["thr", "tp", "fp"]:
        joined = original[["variant", "split", "fold", metric]].merge(
            mine[["variant", "split", "fold", metric]], on=["variant", "split", "fold"], how="outer",
            validate="one_to_one", suffixes=("_original", "_reproduced"))
        rows += [{"table": "blend_fold_cal1.csv", "variant": v, "split": s, "fold": f, "metric": metric,
                  "original": a, "reproduced": b} for v, s, f, a, b in joined.itertuples(index=False)]
    result = pd.DataFrame(rows)
    result["match"] = result.original == result.reproduced  # exact, floats included; NaN (a missing row) is False
    return result


def repro() -> int:
    m = paired_scores()
    folds, summary, campaigns = evaluate(m)
    compared = compare(folds, summary)
    pinned = json.loads((REPO / "data" / "SOURCE.json").read_text(encoding="utf-8"))["commit"]
    manifest = json.loads(show(BLEND, f"{C35}/manifest.json"))
    checks = {
        "paired_rows": len(m),
        "rows_by_split_and_stage": {f"{s}/{t}": int(n) for (s, t), n in m.groupby(["split", "stage"]).size().items()},
        "data_commit_of_scores": manifest["data_commit"],
        "data_commit_equals_data_SOURCE_json": manifest["data_commit"] == pinned,
        "read_test": False,
        "compared_values": len(compared),
        "mismatches": int((~compared.match).sum()),
    }
    write("repro_summary.csv", summary)
    write("repro_folds.csv", folds)
    write("repro_campaign_recall.csv", campaigns)
    write("repro_vs_a4a5280.csv", compared)
    write("threshold_options.csv", threshold_options(m, folds, summary))
    write_json("repro_checks.json", checks)
    print(json.dumps(checks, indent=2))
    return 0 if checks["mismatches"] == 0 and checks["data_commit_equals_data_SOURCE_json"] else 1


def stored_features() -> tuple[pd.DataFrame, list[dict], pd.DataFrame, list[str], list[str]]:
    """The stored 2,767-row Train CSV as text, its schema, row metadata, and the two model feature orders."""
    raw = table(BLEND, f"{X1}/analysis/d06_full35.csv", dtype=str, keep_default_na=False)
    schema = json.loads(show(BLEND, f"{X1}/analysis/d06_full35_schema.json"))
    meta = table(BLEND, f"{C35}/row_metadata.csv", dtype=str, keep_default_na=False)
    index = table(MAIN, f"{B18}/model_index.csv")
    training = table(BLEND, f"{C35}/training.csv")
    full29 = index[index.feature_set == "full29"].feature_order.iloc[0].split()
    full35 = training[training.variant == "full35"].feature_order.iloc[0].split()
    return raw, schema, meta, full29, full35


def profile(train_csv: Path | None) -> int:
    raw, schema, meta, full29, full35 = stored_features()
    keys = ["package", "old_version", "new_version", "label"]
    added, programs = raw.installScriptAdded, raw.installHookNewProgramCount
    checks = {
        "rows": len(raw),
        "columns_equal_schema": list(raw.columns) == [c["column"] for c in schema],
        "feature_columns_equal_full35_model_order": list(raw.columns[3:-1]) == full35,
        "first_29_equal_full29_model_order": full35[:29] == full29,
        "keys_and_label_equal_row_metadata": bool((raw[keys].to_numpy() == meta[keys].to_numpy()).all()),
        "rows_with_all_six_x1_empty": int((raw[full35[29:]] == "").all(axis=1).sum()),
        # the 29 features of registry rows come from registry metadata, X1 from the tarball's package.json
        "installScriptAdded_true_but_no_new_hook_program": {
            k: int(((added == "True") & (programs == "0") & (meta["class"] == k)).sum()) for k in CLASSES},
        "installScriptAdded_false_but_new_hook_program": {
            k: int(((added == "False") & ~programs.isin(["0", ""]) & (meta["class"] == k)).sum()) for k in CLASSES},
    }
    if train_csv is not None:
        data = train_csv.read_bytes()
        if hashlib.sha256(data).hexdigest() != TRAIN_SHA256:
            raise SystemExit("--train-csv is not the D06 train.csv that PR #13 pins")
        train = pd.read_csv(io.BytesIO(data), dtype=str, keep_default_na=False)
        checks["train_csv_columns"] = list(train.columns) == [*keys[:3], *full29, "label"]
        checks["cells_differing_from_train_csv_as_text"] = int(
            (raw[list(train.columns)].to_numpy() != train.to_numpy()).sum())
    rows = []
    for position, column in enumerate(schema):
        s = raw[column["column"]]
        number = pd.to_numeric(s.replace({"": np.nan, "True": "1", "False": "0"}), errors="coerce")
        rows.append({
            "position": position, "column": s.name, "group": column["group"],
            "schema_dtype": column.get("dtype", ""),
            "empty": int((s == "").sum()),
            **{f"empty_{k}": int(((s == "") & (meta["class"] == k)).sum()) for k in CLASSES},
            "distinct": s.nunique(),
            "values": "|".join(sorted(set(s))) if s.nunique() <= 4 else "",
            "min": number.min() if column["group"] in ("full29", "x1") and s.name != "updateType" else "",
            "max": number.max() if column["group"] in ("full29", "x1") and s.name != "updateType" else "",
        })
    write("feature_csv_profile.csv", pd.DataFrame(rows))
    write_json("feature_csv_checks.json", checks)
    print(json.dumps(checks, indent=2))
    required = ["columns_equal_schema", "feature_columns_equal_full35_model_order",
                "first_29_equal_full29_model_order", "keys_and_label_equal_row_metadata"]
    return 0 if all(checks[k] for k in required) else 1


def encode(raw: pd.DataFrame, names: list[str]) -> np.ndarray:
    """Model input built the way depbee's LightGBMPredictor.encode builds it (depbee 759cc68,
    src/depbee/inference/lightgbm.py:121-149): true/false -> 1/0, missing -> NaN, updateType -> its position
    in [major, minor, patch], every other value as a float. Python's float() is exact, like round_trip."""
    def number(value: str) -> float:
        return math.nan if value == "" else 1.0 if value == "True" else 0.0 if value == "False" else float(value)

    columns = [raw[name].map(CATEGORIES.index).astype(float) if name == "updateType" else raw[name].map(number)
               for name in names]
    return np.column_stack(columns).astype(float)


def nan_policy() -> int:
    """What a shipped blend would do when X1 cannot be computed. The full35 fold models score the outer rows
    again with X1 inputs replaced by NaN, and two fallbacks are computed from the saved scores. Thresholds stay
    those of the stored calibration scores, as a shipped threshold would stay fixed."""
    import lightgbm as lgb

    features, _, _, _, names35 = stored_features()
    x35 = encode(features, names35)
    cases = {  # columns of the full35 input replaced by NaN
        "stored": [],
        "ref_file_nan": [names35.index("installHookRefFileChanged")],  # the hooked file cannot be resolved
        "hook4_nan": list(range(29, 33)),  # the install hook command cannot be parsed (code_context.py:319-323)
        "all6_nan": list(range(29, 35)),  # X1 was not extracted at all
    }
    m = paired_scores()
    cal, outer = m[m.stage == "calibration"], m[m.stage == "outer"].copy()
    for seed, split in SPLITS.items():
        for fold in range(3):
            raw = show(BLEND, f"{C35}/models/full35_{split}_fold{fold}.txt")
            booster = lgb.Booster(model_str=raw.decode("utf-8"))
            rows = outer[(outer.seed == seed) & (outer.fold == fold)]
            for name, columns in cases.items():
                x = x35[rows.row_id.to_numpy()].copy()
                x[:, columns] = np.nan
                outer.loc[rows.index, f"s35_{name}"] = booster.predict(x, num_threads=1)
    difference = float((outer.s35_stored - outer.full35).abs().max())
    outer["s35_use_full29"] = outer.full29  # fallback: the blend becomes the full29 score
    outer["s35_drop"] = 0.0  # fallback: the component adds nothing and the weights are not rescaled
    result = []
    for op, target in TARGETS.items():
        for variant, weight in WEIGHTS.items():
            thresholds = {key: fpr_threshold(c[variant].to_numpy(), c.label.to_numpy(), target)[0]
                          for key, c in cal.groupby(["split", "fold"])}
            limit = np.array([thresholds[key] for key in zip(outer.split, outer.fold, strict=True)])
            reference = outer[variant].to_numpy() >= limit
            for name in [*cases, "use_full29", "drop"]:
                hit = ((1 - weight) * outer.full29 + weight * outer[f"s35_{name}"]).to_numpy() >= limit
                for split, g in outer.groupby("split"):
                    pick, malicious = (outer.split == split).to_numpy(), g.label.to_numpy() == 1
                    result.append({
                        "op": op, "variant": variant, "x1_case": name, "split": split, **metrics(g, hit[pick]),
                        "tp_lost_vs_stored": int((reference[pick] & ~hit[pick] & malicious).sum()),
                        "tp_gained_vs_stored": int((~reference[pick] & hit[pick] & malicious).sum()),
                        "fp_added_vs_stored": int((~reference[pick] & hit[pick] & ~malicious).sum())})
    result = pd.DataFrame(result)
    stored = result[result.x1_case == "stored"]
    unchanged = int(stored[["tp_lost_vs_stored", "tp_gained_vs_stored", "fp_added_vs_stored"]].to_numpy().sum()) == 0
    write("nan_policy.csv", result)
    print(json.dumps({"largest_abs_difference_from_saved_full35": difference,
                      "stored_case_selects_the_same_rows": unchanged}, indent=2))
    return 0 if difference <= 1e-12 and unchanged else 1


def timing(repeats: int, sample: int) -> int:
    started = time.perf_counter()
    import lightgbm as lgb  # only this mode and nan need it
    import_seconds = time.perf_counter() - started

    def load(raw: bytes):
        """What LightGBMPredictor.__init__ does with a model (same file, lines 87-115): hash, parse, inspect."""
        hashlib.sha256(raw).hexdigest()
        booster = lgb.Booster(model_str=raw.decode("utf-8"))
        booster.dump_model(), booster.num_model_per_iteration(), booster.feature_name(), booster.pandas_categorical
        return booster

    def alternating(measure) -> dict:
        """measure(side) for one model and for two, `repeats` times each, swapping the order every repeat."""
        runs = {side: [] for side in SIDES}
        for repeat in range(repeats):
            for side in (list(SIDES) if repeat % 2 == 0 else list(SIDES)[::-1]):
                runs[side].append(measure(side))
        return {side: {"median": statistics.median(v), "min": min(v), "max": max(v)} for side, v in runs.items()}

    def load_ms(models: dict) -> dict:
        def measure(side: str) -> float:
            t = time.perf_counter()
            for name in SIDES[side]:
                load(models[name])
            return (time.perf_counter() - t) * 1e3

        return alternating(measure)

    features, _, _, names29, names35 = stored_features()
    inputs = {"full29": encode(features, names29), "full35": encode(features, names35)}
    saved = paired_scores()
    keys = [(seed, split, fold) for seed, split in SPLITS.items() for fold in range(3)]
    models = {key: {"full29": show(MAIN, f"{B18}/models/full29_{key[1]}_fold{key[2]}.txt"),
                    "full35": show(BLEND, f"{C35}/models/full35_{key[1]}_fold{key[2]}.txt")} for key in keys}
    # predict(num_threads=1) lowers LightGBM's thread count for the rest of the process, and dump_model then runs
    # faster. A CLI run loads its model before any predict, so those loads are timed first, for all pairs.
    fresh = {key: load_ms(models[key]) for key in keys}
    pairs, differences, compared_scores = [], [], 0
    for key in keys:
        seed, split, fold = key
        rows = saved[(saved.seed == seed) & (saved.fold == fold)]
        boosters = {name: load(raw) for name, raw in models[key].items()}
        for name, booster in boosters.items():  # the scores depbee would give are the stored ones
            got = booster.predict(inputs[name][rows.row_id.to_numpy()], num_threads=1)
            differences.append(float(np.abs(got - rows[name].to_numpy()).max()))
            compared_scores += len(rows)
        picked = rows[rows.stage == "outer"].sort_values("row_id").row_id.to_numpy()[:sample]
        values = {name: [inputs[name][i].tolist() for i in picked] for name in boosters}
        expected = rows[rows.stage == "outer"].set_index("row_id").loc[picked, "A2"].to_numpy()

        def per_row(side: str, **options) -> list:
            """Each picked row through each model of the side, one row per call as depbee predicts."""
            return [[boosters[name].predict(np.array([values[name][i]], dtype=float), num_threads=1, **options)[0]
                     for name in SIDES[side]] for i in range(len(picked))]

        def predict_us(side: str) -> float:
            t = time.perf_counter()
            scores = per_row(side)
            blended = [float(s[0]) if len(s) == 1 else (1 - WEIGHTS["A2"]) * s[0] + WEIGHTS["A2"] * s[1]
                       for s in scores]
            elapsed = time.perf_counter() - t
            if side == "two_models":  # the timed work produced the stored A2 scores
                differences.append(float(np.abs(np.array(blended) - expected).max()))
            return elapsed * 1e6 / len(picked)

        def explain_us(side: str) -> float:
            t = time.perf_counter()
            per_row(side, pred_contrib=True)
            return (time.perf_counter() - t) * 1e6 / len(picked)

        pairs.append({
            "split": split, "fold": fold, "rows_timed": len(picked),
            "model_bytes": {name: len(raw) for name, raw in models[key].items()},
            "trees": {name: booster.num_trees() for name, booster in boosters.items()},
            "load_ms_before_any_predict": fresh[key],
            "predict_us_per_row": alternating(predict_us),
            "explain_us_per_row": alternating(explain_us)})
    for pair, key in zip(pairs, keys, strict=True):  # as a later request of a long-lived mcp or dashboard loads
        pair["load_ms_after_predict"] = load_ms(models[key])
    measures = ("load_ms_before_any_predict", "load_ms_after_predict", "predict_us_per_row", "explain_us_per_row")
    result = {
        "note": "fold models stand in for the missing full-data models; timing differs on every run",
        "environment": {"platform": platform.platform(), "processor": platform.processor(),
                        "logical_cpus": os.cpu_count(), "python": platform.python_version(),
                        "lightgbm": lgb.__version__, "numpy": np.__version__, "pandas": pd.__version__},
        "import_lightgbm_seconds_once": import_seconds,
        "repeats_per_side": repeats, "order": "alternating", "predict_threads": 1,
        "scores_compared_with_saved": compared_scores,
        "largest_abs_difference_from_saved_scores": max(differences),
        "overall_median": {side: {k: statistics.median(p[k][side]["median"] for p in pairs) for k in measures}
                           for side in SIDES},
        "pairs": pairs,
    }
    write_json("timing.json", result)
    print(json.dumps({k: result[k] for k in result if k != "pairs"}, indent=2))
    return 0 if max(differences) <= 1e-12 else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("mode", choices=["repro", "profile", "nan", "timing"])
    parser.add_argument("--train-csv", type=Path, help="profile: the D06 train.csv, to compare its 29 features")
    parser.add_argument("--repeats", type=int, default=7, help="timing: runs per side and model pair")
    parser.add_argument("--sample", type=int, default=200, help="timing: outer rows scored one by one")
    args = parser.parse_args()
    if args.mode == "repro":
        return repro()
    if args.mode == "profile":
        return profile(args.train_csv)
    if args.mode == "nan":
        return nan_policy()
    return timing(args.repeats, args.sample)


if __name__ == "__main__":
    raise SystemExit(main())
