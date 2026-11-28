# D08 G2g 그룹 복구

브랜치 `exp/d08-g2g-recovery`(`exp/d08-full-model-compare` `937e45a`에서 생성). 기존 브랜치·실험 폴더·데이터는 수정하지 않는다.
결과와 이전 기록 비교: `REPORT.md`. 이 단계에서는 모델 학습·Test 평가를 하지 않았다.

## 1. 구성
| 경로 | 내용 |
|---|---|
| `mappings/merge_G2g.json` | G2g 그룹 매핑(group_merge 9, row_override 60) |
| `mappings/family_membership.csv` | Skimmer 27쌍·Hidden-loader 46쌍과 판정 근거 요약 |
| `mappings/make_g2g_summary.json` | 매핑 생성 요약 |
| `evidence/evidence_skimmer.csv`, `evidence_hidden.csv`, `decide_summary.json` | 공격 관련성 판정 근거(해시·개수·표지 플래그) |
| `folds/fold_assignment.csv` | G2g 5-fold 배정(G2f와 같은 형식, `P`의 install-hook 키는 G2f와 같은 방식으로 `sha1[:16]` 태그) |
| `folds/build_info.json`, `build_info_G2f_guard.json` | 입력·설정·출력 해시, G2f 재현 가드 결과 |
| `compare/pair_group_changes.csv`, `fold_counts.csv`, `compare_summary.json` | G2f 대비 쌍별 그룹·fold 변경과 집계 |
| `code/` | 분석 스크립트(아래 2절) |
| `run_g2g.sh` | 전체 재현 실행 |

## 2. 스크립트
1. `scan_pairs.py`: Train 악성 3,499쌍 `diff.txt`의 추가 줄을 정규화해 줄 해시(N1/N2/N3)를 만든다.
2. `scan_hidden_raw.py`: `malicious_raw/`의 바뀐 텍스트 파일에서 긴 공백 뒤 숨겨진 코드를 찾아 해시와 표지 플래그를 남긴다.
3. `decide_families.py`: 두 계열의 소속을 정한다(기준 `SKIM_MIN=20`, `GENERIC_GROUPS=3`, 표지 목록).
4. `make_g2g.py`: `merge_G2f.json` + 소속 목록 → `merge_G2g.json`.
5. `build_folds.py`: `run_g2f.py`와 같은 준비 과정으로 fold만 다시 계산한다. lightgbm·sklearn이 없으면 import용 빈 모듈만 등록한다(모델 코드 호출 없음).
6. `compare_g2f_g2g.py`: G2f와 G2g 비교.

정적 분석만 한다. 패키지 코드·설치 스크립트는 실행하지 않고, 숨겨진 코드는 복호화하지 않는다. 출력에는 코드 원문을 쓰지 않는다.

## 3. 입력
- 데이터: npm-malware-package-pairs D08 `2c48bd83`(`pairs/` 트리; main `4eee000`과 같음). train/split_assignment/malicious_pair_groups/baselines와 D06 train은 `run_m1m4.EXPECTED` 해시로 확인한다.
- G2f: `exp/d08-g2f-group-leakage`의 `mappings/merge_G2f.json`(sha256 `0348d779…`), `mappings/dev_exclusion_clipper6.csv`, `results/g2f_60run/run/fold_assignment.csv`.
- 코드: `run_m1m4.py`(sha256 `6e70c17c…`), PR #13 snapshot(`049bf00c…`, main `experiments/d06_feature_comparison_18/provenance/phase2_run1_base7_full29/executed_script_snapshot.py`).

## 4. 작업공간 구성
스크립트는 이전 작업공간의 상대 경로를 따른다. 세 브랜치에서 다음처럼 꺼내 둔다(merge 불필요).
```
<WS>/run_m1m4.py            <- exp/d08-g2f-group-leakage: experiments/d08_g2f_group_leakage/code/run_m1m4.py
<WS>/pr13_snapshot.py       <- main: .../phase2_run1_base7_full29/executed_script_snapshot.py
<WS>/inputs/                <- 데이터 저장소 D08: derived/splits/train.csv, split_assignment.csv,
                               derived/pairs/malicious_pair_groups.csv, baselines.csv; D06 be87ab4c train.csv -> d06_train.csv
<WS>/g2f/config/            <- exp/d08-g2f-group-leakage: mappings/merge_G2f.json, dev_exclusion_clipper6.csv
<WS>/g2f/run/               <- exp/d08-g2f-group-leakage: results/g2f_60run/run/
```
실행: `bash run_g2g.sh <WS> <데이터 체크아웃> <출력 폴더>`. 환경: Python 3.13.18, pandas 3.0.5, numpy 2.5.3(이 단계는 lightgbm 불필요).
