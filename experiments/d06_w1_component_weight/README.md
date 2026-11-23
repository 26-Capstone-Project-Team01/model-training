# D06-W1: 연결그룹 1/√n 가중치 (full29 대비)

상태: D06 개발자료(Train 2,767쌍) 탐색 실험. 모델·임계값 선정 결과가 아니며 독립 일반화 성능을 주장하지 않는다.

## 1. 목적

9차 회의(11/20)의 모델 작업 순서 2단계 "기존 29개 Feature 모델과 W1·X1을 각각 비교" 중 W1이다.
악성 학습 자료는 큰 연결그룹 몇 개가 대부분을 차지한다(악성 928쌍 중 716쌍이 가장 큰 component 3개).
W1은 Feature는 그대로 두고 학습 가중치만 바꿔, 큰 그룹이 학습을 지배하는 효과를 줄였을 때
Recall·FN, 검토 후보량, 정상·Hard benign 오탐, 유형·캠페인별 성능이 어떻게 바뀌는지 본다. X1과는 결합하지 않았다.

## 2. 가중치 계산 (`run_w1.py`의 `weights_component`)

- 각 outer fold의 **fit 행 안에서만** 계산한다(calibration·outer 행은 보지 않음).
- 악성 행: 같은 연결그룹(component)에 속한 fit 악성 행 수를 n이라 할 때 raw = 1/√n.
- 정규화: 악성 가중치 합이 fit 악성 행 수와 같도록 raw × (악성 수 / Σraw). 정상·Hard benign = 1.
- component는 PR #13 정의를 그대로 쓴다: package, 실제 campaign(범용 묶음 `individual-compromise*`, `individuals_case` 제외),
  비어 있지 않은 악성 payload 해시(`largestChangedJsSha1`, `changedJsSetSha1`)를 공유하면 묶은 연결 그룹.
- component ID는 Feature에 넣지 않는다. 모델 입력은 full29와 같은 29개다.
- 비교용 `w1_splitgroup`(선정 대상 아님): 기존 `train_model.py`의 `compute_sample_weights`(D06-E08/E09/E10) 정의.
  key = 실제 splitGroup, 범용 묶음 행은 각각 크기 1. 정규화는 같다.

두 정의의 fit 가중치 비교(`run/weight_comparison.csv`):

| split | fold | fit 악성 | component 그룹 | splitGroup key | 가중치가 다른 행 |
|---|---:|---:|---:|---:|---:|
| split1 | 0 | 447 | 15 | 17 | 447 |
| split1 | 1 | 518 | 2 | 2 | 0 (동일) |
| split1 | 2 | 379 | 16 | 18 | 379 |
| split2 | 0 | 373 | 47 | 58 | 373 |
| split2 | 1 | 412 | 15 | 22 | 412 |
| split2 | 2 | 411 | 24 | 25 | 411 |

## 3. 학습 조건

- 데이터: D06. `26-Capstone-Project-Team01/npm-malware-package-pairs` 커밋 `be87ab4cff66fff1980c4a71be8032b6b47225ba`의
  `derived/splits/train.csv`(SHA-256 `22fbc8752fff5fff90e40b911f6bf7d187769b4566db957d65a37a16be7d2c23`).
  그룹·class 입력 해시는 `run/manifest.json`. Test 677은 읽지 않았다. D07·D08·Tracky 자료는 쓰지 않았다.
- 코드: PR #13 run1 학습 스냅샷 `../d06_feature_comparison_18/provenance/phase2_run1_base7_full29/executed_script_snapshot.py`
  (SHA-256 `049bf00c…`)를 **수정 없이 import**해 데이터 적재, component·outer 3fold, 내부 분할, Feature 행렬을 쓴다.
- 분할: PR #13과 같은 outer 3fold, split1(inner seed 20261109)·split2(20261110). 실행 시 fit/calibration/outer row_id가
  PR #13 `splits/`와 같은지 확인하고 다르면 멈춘다.
- LightGBM 4.7.0: `objective=binary`, `metric=binary_logloss`, `deterministic=true`, `force_col_wise=true`, `num_threads=2`,
  `seed=20261109`, 200 rounds, early stopping 없음. full29와 다른 것은 fit 행 sample weight뿐이다.
- 실행 환경: Python 3.13, lightgbm 4.7.0, pandas 3.0.6, numpy 2.5.3, scikit-learn 1.9.1(스냅샷 import에 필요).

## 4. 재현 검증 (`run/verification.json`)

- 같은 코드로 가중치 없는 full29 6개를 다시 학습: 모델 내용이 PR #13과 CR 줄바꿈만 다르고 같음(6/6),
  저장 점수 최대 차이 1.1e-16, 트리 수(split1 fold1 149) 동일. 따라서 W1과 full29의 차이는 가중치로만 생긴다.
- `run/training.csv`의 `full29_repro` 행 `pr13_model_sha256_match=False`는 원 바이트(CRLF) 비교 결과이며 내용은 같다.
  재현 모델·점수는 PR #13과 중복이라 이 폴더에 두지 않았다(`run_w1.py`를 실행하면 다시 생성된다).
- `evaluate_w1.py`는 PR #13 full29의 thresholds/ranking/low_scores/recall_examples를 저장 점수로 다시 계산해
  PR #13 `evaluation/`과 일치할 때만 W1을 평가한다(PR #13에 phase7 평가 코드가 없어 명세대로 다시 구현).
- 같은 W1 실행을 다시 했을 때 모델 12개와 가중치·학습 기록이 바이트 단위로 같았다.

## 5. full29와의 비교 (outer 3fold 합산; 상세는 `run/evaluation/`)

기준선은 PR #13 저장 점수(재학습 없이 재사용)다. 표의 임계값은 PR #13이 미리 정한 표시 지점이며 운영 기준이 아니다.

| split | 점수 이상 | full29 TP/FN/FP | W1 TP/FN/FP | W1 검토 후보 (full29) | W1 정상·Hard benign 오탐 (full29) |
|---|---:|---|---|---:|---|
| split1 | 0.01 | 712/216/15 | 708/220/17 | 725 (727) | 12·5 (9·6) |
| split1 | 0.05 | 685/243/9 | 686/242/9 | 695 (694) | 4·5 (5·4) |
| split1 | 0.1 | 676/252/5 | 629/299/7 | 636 (681) | 3·4 (4·1) |
| split1 | 0.5 | 604/324/3 | 566/362/4 | 570 (607) | 3·1 (2·1) |
| split2 | 0.01 | 751/177/31 | 768/160/33 | 801 (782) | 17·16 (16·15) |
| split2 | 0.05 | 708/220/16 | 724/204/18 | 742 (724) | 7·11 (6·10) |
| split2 | 0.1 | 696/232/12 | 709/219/15 | 724 (708) | 5·10 (5·7) |
| split2 | 0.5 | 658/270/6 | 643/285/4 | 647 (664) | 2·2 (3·3) |

- fold 안 상위 비율에 든 악성(10/30/50%): split1 276/764/896 → 275/766/893, split2 278/780/907 → 278/784/907.
- 공격 유형(A/B/C, Feature 기반 대리 분류) 0.5 기준 TP: A split1 541→546, split2 593→585; B(52쌍) split1 41→1, split2 41→26;
  C(142쌍) split1 22→19, split2 24→32. 캠페인별은 `run/evaluation/group_recall.csv`.
- B 하락의 대부분은 mini-shai-hulud(outer fold1) 46쌍이다. split1 fold1은 fit 악성 그룹이 2개라 가중치가 0.89/1.19로
  거의 균등한데도 이 46쌍의 fold 안 순위 중앙값이 상위 3.3% → 19.1%로 내려갔다. 점수 척도만이 아니라 순위가 바뀌었다.
- 결론: 방향이 split에 따라 엇갈리며(split2 저임계값 TP +16~17, split1 0.1·0.5 TP −38~−47) W1이 full29보다
  일관되게 낫다는 근거는 없다.

## 6. 한계

- D06 2,767쌍은 이미 Feature 선택에 쓰인 개발자료이고 두 split은 같은 행을 다시 쓰므로 독립 관측이 아니다.
- outer fold가 3개뿐이고 큰 component 3개가 악성의 77%를 차지한다. fold 하나(특히 fold1)의 변화가 합산 결과를 좌우한다.
- 가중치를 바꾸면 점수 척도가 달라져 고정 임계값 비교는 척도 차이를 함께 반영한다. 순위 지표를 같이 봐야 한다.
- 시간 순서 holdout이 아니며 미래·배포 분포 성능을 추정하지 않는다. Test 677로 임계값을 고르지 않았다.
- A/B/C는 Feature에서 만든 대리 분류이고, 캠페인 평균에는 `individuals_case` 보고용 묶음이 포함된다.
- `w1_splitgroup`은 정의 차이를 보기 위한 감도 분석이며 선택 후보가 아니다.

## 7. 재현 방법

```bash
# 1) 입력 준비: 작업공간 <ws> 아래에 PR #13 README 5절의 상대 경로대로 train.csv, train_malicious_groups.csv,
#    d06_diag01_pair_predictions.csv, evaluation_spec.json, decision_criteria.json을 둔다.
# 2) 학습(출력 폴더는 새로 만든다)
python -I -B experiments/d06_w1_component_weight/run_w1.py --workspace <ws> --out <new_dir>
# 3) 평가(PR #13 full29 재계산 일치 확인 후 W1 평가; <new_dir>/evaluation 생성)
python -I -B experiments/d06_w1_component_weight/evaluate_w1.py --run <new_dir>
```

## 8. 파일

| 경로 | 내용 |
|---|---|
| `run_w1.py`, `evaluate_w1.py` | 학습·평가 코드 |
| `run/models/` | W1 모델 12개(`w1_component`·`w1_splitgroup` × split1·split2 × fold0~2), LightGBM native text |
| `run/scores.csv` | W1 모델의 calibration·outer 점수(`row_id`는 PR #13 `scores/row_metadata.csv`와 같음) |
| `run/row_metadata.csv` | row_id별 쌍 정보, class, campaign, component, outer_fold, 유형(A/B/C) |
| `run/fit_weights.csv`, `run/weight_comparison.csv` | fit 행별 두 가중치와 fold별 비교 |
| `run/training.csv`, `run/manifest.json`, `run/verification.json` | 학습 기록, 입력 해시·조건, 재현 검증 |
| `run/evaluation/` | thresholds, ranking, low_scores, recall_examples, group_recall, paired_vs_full29 |

분할 파일과 full29 기준선 모델·점수는 PR #13 `experiments/d06_feature_comparison_18/`을 그대로 쓴다.
