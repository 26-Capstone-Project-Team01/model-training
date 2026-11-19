"""D06 18모델 인계 묶음 검증(표준 라이브러리만 사용, 모델 로드·추론·학습 없음).

사용: python -I -B -X utf8 verify_bundle.py [--train-csv <train.csv>]
묶음 무결성 검사가 통과하면 종료 코드 0, 하나라도 어긋나면 1이다.
외부 입력(학습 특징 CSV, 저장소의 class 파일)은 주어졌거나 있을 때만 확인한다.
확인하지 못한 외부 입력은 종료 코드와 별개로 마지막에 "외부 입력 검증 미완료"로 출력한다.
"""
import argparse
import csv
import hashlib
import json
import math
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
FEATURE_SETS = ("base7", "full29", "no_interval28")
SPLITS = {"split1": 20261109, "split2": 20261110}
N_ROWS = 2767
CLASSES_CSV = HERE.parent.parent / "results/diagnostics/d06_diag01_pair_predictions.csv"
errors = []


def check(cond, msg):
    if not cond:
        errors.append(msg)
    return cond


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_csv(path):
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def check_sums():
    listed = {}
    for line in (HERE / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        m = re.fullmatch(r"([0-9a-f]{64}) [ *](.+)", line)  # sha256sum text("  ") and binary(" *") forms
        if check(m is not None, f"SHA256SUMS 형식 오류: {line[:80]}"):
            listed[m.group(2)] = m.group(1)
    for rel, digest in listed.items():
        p = HERE / rel
        if check(p.is_file(), f"SHA256SUMS 파일 없음: {rel}"):
            check(sha(p) == digest, f"SHA256 불일치: {rel}")
    present = {p.relative_to(HERE).as_posix() for p in HERE.rglob("*")
               if p.is_file() and p.name != "SHA256SUMS" and "__pycache__" not in p.parts}
    check(not present - set(listed), f"SHA256SUMS에 없는 파일: {sorted(present - set(listed))}")


def check_index():
    index = json.loads((HERE / "model_index.json").read_text(encoding="utf-8"))
    models = index["models"]
    rows = read_csv(HERE / "model_index.csv")
    check(len(models) == 18 and len(rows) == 18, "model_index 행 수가 18이 아님")
    for m, r in zip(models, rows):
        check({k: str(v) for k, v in m.items()} == r, f"model_index csv/json 불일치: {m['model_id']}")
    keys = Counter((m["feature_set"], m["split"], m["outer_fold"]) for m in models)
    want = {(fs, s, f) for fs in FEATURE_SETS for s in SPLITS for f in range(3)}
    check(set(keys) == want and max(keys.values()) == 1, "선택 key가 3특징x2분할x3fold와 다름")
    run_manifests = {}
    for folder in ("phase2_run1_base7_full29", "phase2_run2_no_interval28"):
        man = json.loads((HERE / f"provenance/{folder}/manifest.public.json").read_text(encoding="utf-8"))
        run_manifests[folder] = {o["path"].replace("\\", "/"): o["sha256"] for o in man["outputs"]}
        run_manifests[folder]["__script"] = man["script_sha256"]
    for m in models:
        fs, folder = m["feature_set"], Path(m["source_script_snapshot"]).parent.name
        if not check((HERE / m["bundle_model_path"]).is_file(), f"모델 파일 없음: {m['model_id']}"):
            continue
        check(m["inner_seed"] == SPLITS[m["split"]], f"seed/split 불일치: {m['model_id']}")
        check(m["posthoc"] == (fs == "no_interval28"), f"posthoc 표시 오류: {m['model_id']}")
        check(m["model_id"] == f"{fs}_{m['split']}_fold{m['outer_fold']}", f"model_id 형식: {m['model_id']}")
        # 원 run manifest가 기록한 모델 해시와 묶음 모델 해시를 대조한다.
        check(run_manifests[folder].get(m["source_model_path"]) == m["model_sha256"] == sha(HERE / m["bundle_model_path"]),
              f"원 run 모델 해시와 다름: {m['model_id']}")
        check(run_manifests[folder]["__script"] == m["source_script_sha256"] == sha(HERE / m["source_script_snapshot"]),
              f"실행 코드 스냅샷 해시 불일치: {m['model_id']}")
        text = (HERE / m["bundle_model_path"]).read_text(encoding="utf-8")
        found = re.search(r"^feature_names=(.*)$", text, re.MULTILINE)
        names = found.group(1).split(" ") if found else []
        source_sets = json.loads((HERE / f"provenance/{folder}/feature_sets.json").read_text(encoding="utf-8"))
        check(names == m["feature_order"].split(" ") == index["feature_sets"][fs]["features"]
              == source_sets[m["source_variant"]] and len(names) == m["feature_count"],
              f"feature 순서 불일치: {m['model_id']}")
        trees = len(re.findall(r"^Tree=\d+$", text, re.MULTILINE))
        check(trees == m["actual_rounds"] and m["requested_rounds"] == 200 and m["early_stopping"] is False,
              f"rounds 불일치: {m['model_id']} (트리 {trees})")
    check(index["feature_sets"]["no_interval28"]["features"]
          == [f for f in index["feature_sets"]["full29"]["features"] if f != "updateInterval"], "28개 = 29개 - updateInterval 아님")
    return index


def check_inputs(index, train_csv):
    inputs = index["inputs"]
    spec1 = json.loads((HERE / "provenance/phase2_run1_base7_full29/evaluation_spec.json").read_text(encoding="utf-8"))
    spec2 = json.loads((HERE / "provenance/phase2_run2_no_interval28/executed_spec.json").read_text(encoding="utf-8"))
    for name in ("train", "groups", "classes"):
        check(spec1[f"{name}_sha256"] == spec2[f"{name}_sha256"] == inputs[name]["sha256"], f"입력 해시 기록 불일치: {name}")
    check(sha(HERE / inputs["groups"]["bundle_path"]) == inputs["groups"]["sha256"], "groups 입력 해시 불일치")
    notes = []
    if CLASSES_CSV.is_file():
        check(sha(CLASSES_CSV) == inputs["classes"]["sha256"], "results/diagnostics/d06_diag01_pair_predictions.csv 해시 불일치")
    else:
        notes.append("class 파일 해시 미확인(저장소의 results/diagnostics/d06_diag01_pair_predictions.csv 없음)")
    meta = read_csv(HERE / "scores/row_metadata.csv")
    if train_csv:
        check(sha(train_csv) == inputs["train"]["sha256"], "train.csv SHA256 불일치")
        train = read_csv(train_csv)
        check([(r["package"], r["old_version"], r["new_version"], r["label"]) for r in train]
              == [(r["package"], r["old_version"], r["new_version"], r["label"]) for r in meta], "train.csv 행 순서와 row_id 불일치")
        header = list(train[0]) if train else []
        check([c for c in header if c in index["feature_sets"]["full29"]["features"]] == index["feature_sets"]["full29"]["features"],
              "train.csv 특징 열 순서 불일치")
    else:
        notes.append("학습 특징 CSV 해시·행 순서·특징 열 순서 미확인(--train-csv 미지정)")
    return meta, notes


def check_splits(index, meta):
    check([int(r["row_id"]) for r in meta] == list(range(N_ROWS)), "row_metadata row_id가 0..2766이 아님")
    check(Counter(r["class"] for r in meta) == {"malicious": 928, "benign": 1600, "hard_benign": 239}, "row_metadata class 수 불일치")
    check(all((r["label"] == "1") == (r["class"] == "malicious") for r in meta), "row_metadata label/class 불일치")
    outer_of = {int(r["row_id"]): int(r["outer_fold"]) for r in meta}
    stages, raw_lines = {}, {}
    for split, seed in SPLITS.items():
        path = HERE / f"splits/{split}.csv"
        rows = read_csv(path)
        raw_lines[split] = path.read_bytes().split(b"\n")
        check(list(rows[0]) == ["scenario", "seed", "rounds", "fold", "stage", "row_id", "component", "model"], f"{split} 헤더 불일치")
        check(len(rows) == 3 * 3 * N_ROWS and {r["seed"] for r in rows} == {str(seed)}, f"{split} 행 수 또는 seed 오류")
        groups = defaultdict(lambda: defaultdict(list))
        comps = defaultdict(lambda: defaultdict(set))
        for r in rows:
            k = (r["model"], int(r["fold"]))
            groups[k][r["stage"]].append(int(r["row_id"]))
            comps[k][r["stage"]].add(r["component"])
        for k, st in groups.items():
            ids = st["fit"] + st["calibration"] + st["outer"]
            name = f"{split} {k}"
            check(set(st) == {"fit", "calibration", "outer"}, f"{name} stage 종류 오류")
            check(len(ids) == len(set(ids)) == N_ROWS and set(ids) == set(range(N_ROWS)), f"{name} row_id 누락·중복")
            check(set(st["outer"]) == {i for i, f in outer_of.items() if f == k[1]}, f"{name} outer가 row_metadata outer_fold와 다름")
            c = comps[k]
            check(not (c["fit"] & c["calibration"] or c["fit"] & c["outer"] or c["calibration"] & c["outer"]), f"{name} component가 stage 사이에 겹침")
            stages[(split, *k)] = {s: set(v) for s, v in st.items()}
    for m in index["models"]:
        st = stages.get((m["split"], m["feature_set"], m["outer_fold"]))
        if check(st is not None, f"분할 없음: {m['model_id']}"):
            check((len(st["fit"]), len(st["calibration"]), len(st["outer"])) == (m["fit_rows"], m["calibration_rows"], m["outer_rows"]),
                  f"분할 크기와 학습 기록 불일치: {m['model_id']}")
    for fs in FEATURE_SETS:
        for f in range(3):
            a, b = stages.get(("split1", fs, f)), stages.get(("split2", fs, f))
            if a and b:
                check(a["outer"] == b["outer"] and a["fit"] != b["fit"], f"{fs} fold{f}: split1/2 outer 동일·fit 상이 조건 위반")
    # 원 saved_splits.csv 바이트 복원: 모델 블록마다 split1 행, split2 행 순서.
    src = index["saved_splits_source"]
    head = raw_lines["split1"][0]
    check(head == raw_lines["split2"][0], "split1/split2 헤더 바이트 다름")
    i_model = head.decode().split(",").index("model")
    body = {s: [ln for ln in raw_lines[s][1:] if ln] for s in SPLITS}
    rebuilt = [head]
    for model in src["model_block_order"]:
        for s in SPLITS:
            rebuilt += [ln for ln in body[s] if ln.decode().split(",")[i_model] == model]
    data = b"\n".join(rebuilt) + b"\n"
    check(len(data) == src["bytes"] and hashlib.sha256(data).hexdigest() == src["sha256"], "split1+split2가 원 saved_splits.csv를 재구성하지 못함")
    return stages


def check_scores(index, meta, stages):
    rows = read_csv(HERE / "scores/saved_scores.csv")
    check(len(rows) == 25644, f"saved_scores 행 수 {len(rows)} != 25644")
    by_id = {r["row_id"]: r for r in meta}
    seen = defaultdict(lambda: defaultdict(list))
    cols = ["package", "old_version", "new_version", "label", "class", "campaign", "component"]
    for r in rows:
        seen[(r["model"], r["seed"], int(r["fold"]))][r["stage"]].append(int(r["row_id"]))
        m = by_id.get(r["row_id"])
        check(m is not None and all(r[c] == m[c] for c in cols), f"점수 행 메타데이터 불일치: row_id {r['row_id']}")
        try:
            s = float(r["score"])
            check(math.isfinite(s) and 0.0 <= s <= 1.0, f"점수 범위 오류: {r['score']}")
        except ValueError:
            check(False, f"점수 형식 오류: {r['score']}")
    split_of = {str(v): k for k, v in SPLITS.items()}
    for m in index["models"]:
        got = seen.pop((m["feature_set"], str(m["inner_seed"]), m["outer_fold"]), {})
        st = stages.get((split_of[str(m["inner_seed"])], m["feature_set"], m["outer_fold"]), {})
        check(set(got) == {"calibration", "outer"}, f"점수 stage 오류: {m['model_id']}")
        for stage in ("calibration", "outer"):
            ids = got.get(stage, [])
            check(len(ids) == len(set(ids)) and set(ids) == st.get(stage), f"점수와 분할 {stage} 대응 불일치: {m['model_id']}")
    check(not seen, f"색인에 없는 점수 묶음: {sorted(seen)}")
    var = {(r["model"], r["seed"]): (r["variant"], r["source_scenario"]) for r in rows}
    for m in index["models"]:
        check(var.get((m["feature_set"], str(m["inner_seed"]))) == (m["source_variant"], m["source_scenario"]),
              f"점수의 variant/scenario 불일치: {m['model_id']}")


def check_public_copies():
    pc = json.loads((HERE / "provenance/public_copies.json").read_text(encoding="utf-8"))
    for c in pc["copied_original_bytes"]:
        check(sha(HERE / c["bundle_path"]) == c["sha256"], f"원본 바이트 사본 해시 불일치: {c['bundle_path']}")
    for c in pc["public_copies"]:
        text = (HERE / c["bundle_path"]).read_text(encoding="utf-8")
        check(sha(HERE / c["bundle_path"]) == c["public_sha256"], f"공개용 사본 해시 불일치: {c['bundle_path']}")
        check(not re.search(r"[A-Za-z]:[\\/]+Users", text), f"공개용 사본에 사용자 절대경로 남음: {c['bundle_path']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train-csv", type=Path, help="데이터 저장소 be87ab4의 derived/splits/train.csv")
    args = parser.parse_args()
    sys.stdout.reconfigure(errors="replace")
    notes = []
    try:
        check_sums()
        index = check_index()
        meta, notes = check_inputs(index, args.train_csv)
        stages = check_splits(index, meta)
        check_scores(index, meta, stages)
        check_public_copies()
    except (OSError, KeyError, ValueError, AttributeError, IndexError) as exc:
        errors.append(f"검증 중단: {type(exc).__name__}: {exc}")
    if errors:
        print(f"실패 {len(errors)}건")
        for e in errors[:50]:
            print(" -", e)
    else:
        print("묶음 무결성 통과: 모델 18개 해시·선택 key·feature 순서·rounds, split1/split2 row_id 완전성·stage 비중복,"
              " 점수 대응, 묶음 안 그룹 입력 해시, 원 saved_splits 재구성")
    if notes:
        print(f"외부 입력 검증 미완료 {len(notes)}건(아래 항목은 확인하지 않았다):")
        for n in notes:
            print(" -", n)
    elif not errors:  # an abort before check_inputs leaves notes empty, so completion is claimed only on a clean run
        print("외부 입력 검증 완료: 학습 특징 CSV 해시·행 순서·특징 열 순서, class 파일 해시")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
