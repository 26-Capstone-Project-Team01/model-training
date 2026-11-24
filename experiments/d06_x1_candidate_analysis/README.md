# D06 최종 후보 상세 분석: full29 · full35 · A1~A3 (운영점별 득실, 캠페인, 임계값)

상태: D06 개발자료 진단. **모델 학습 없음**. `../d06_x1_fair_compare/`(커밋 `55ced8c`)의 저장 점수와 calibration 임계값을 그대로 다시 적용해
행 단위로 집계했다. Test 677 미사용. 결합 가중치·목표 FPR·임계값은 이 분석에서 고르지 않았다.
D06 outer는 이미 X1·A 설계와 원인 분석에 쓰인 개발 결과이므로 최종 일반화 성능이 아니다.

## 1. 분석 조건

- 모델: base7, full29, no_interval28, full35, A1(0.9·full29+0.1·full35), A2(0.8/0.2), A3(0.7/0.3). 정의는 `../d06_x1_fair_compare/README.md` 2절.
- 데이터: D06 Train 2,767쌍(악성 928, 무작위 정상 1,600, Hard benign 239), PR #13 outer 3-fold × split1(20261109)·split2(20261110).
  outer fold 945/911/911(악성 332/298/298). 두 split의 outer 행은 같다.
- 임계값: `../d06_x1_fair_compare/calibration_attainment.csv`의 `threshold`(calibration에서만 구한 목표 FPR 1·3·5% 임계값, PR #13 `calibrate` ML 정책)를
  같은 split·fold의 outer 점수에 적용. 점수 ≥ 임계값이면 양성.
- 비교 기준: 득실(`gain_loss_*`)과 캠페인 증감은 같은 split·같은 목표 FPR의 full29 선택과 비교했다.
- 집계: split별로 outer 3 fold를 합산. fold마다 모델·임계값이 다르다.
- 확인: 재계산한 TP·FP가 `../d06_x1_fair_compare/fair_comparison.csv`의 calFPR 1·3·5% 행(7 모델 × 3 목표 × 2 split = 42행, TP·FP 84칸)과 모두 같다
  (스크립트가 실행 시 `consistency with fair_comparison.csv: mismatches = 0`을 출력).

## 2. 파일과 컬럼

### `gain_loss_vs_full29.csv` — full29 대비 득실 요약 (24행 = 목표 3 × 모델 4 × split 2)

| 컬럼 | 의미 |
|---|---|
| `op` | `calFPR1%` / `calFPR3%` / `calFPR5%` |
| `variant` | full35, A1, A2, A3 |
| `split` | split1 / split2 |
| `TP_full29`, `TP_v` | 같은 운영점에서 full29와 해당 모델의 TP (outer 합산) |
| `gained` | full29는 놓쳤고 모델은 잡은 악성 수 |
| `lost` | full29는 잡았고 모델은 놓친 악성 수 |
| `net` | gained − lost (= TP_v − TP_full29) |
| `gained_top_campaign`, `gained_top_share` | gained 중 가장 많은 캠페인과 그 비중 |
| `benignFP_full29`, `benignFP_v` | 무작위 정상(1,600) 중 양성 판정 수 |
| `hardFP_full29`, `hardFP_v` | Hard benign(239) 중 양성 판정 수 |
| `fp_added`, `fp_removed` | full29는 음성·모델은 양성인 정상 수 / 그 반대 |

### `gain_loss_cases.csv` — 득실 행 목록 (1,086행)

| 컬럼 | 의미 |
|---|---|
| `op`, `variant`, `split`, `fold` | 운영점, 모델, split, outer fold |
| `change` | `gained` / `lost` (위 정의) |
| `row_id`, `package`, `new_version` | D06 Train 행 번호(PR #13 row_id)와 패키지 |
| `campaign`, `type` | 캠페인(splitGroup), 공격 유형 대리 분류(A/B/C, PR #13 스냅샷 정의) |
| `full29`, `full35`, `score_v` | 저장된 full29·full35 점수와 해당 모델 점수 |

### `campaign_tp_by_op.csv` — 캠페인별 TP (114행)

| 컬럼 | 의미 |
|---|---|
| `op`, `split`, `campaign` | 운영점, split, 캠페인 |
| `n` | 그 캠페인의 악성 수 (outer 전체 = 928 중) |
| `fold` | 그 캠페인이 속한 outer fold |
| `TP_full29` … `TP_A3` | 모델별 TP |
| `d_full35` … `d_A3` | full29 대비 TP 차이 (FN 차이는 부호 반대, Recall = TP/n) |

### `net_gain_concentration.csv` — 순증가와 shai-hulud-original 제외 순증가 (6행)

| 컬럼 | 의미 |
|---|---|
| `op`, `split` | 운영점, split |
| `net_<모델>` | full29 대비 TP 순증가 |
| `net_<모델>_exShai` | `shai-hulud-original_2025-09`(186쌍, outer fold 2)를 뺀 순증가 |

### `campaign_direction_counts.csv` — 캠페인 Recall 증감 방향 (24행)

| 컬럼 | 의미 |
|---|---|
| `op`, `split`, `variant` | 운영점, split, 모델 |
| `campaigns` | 악성 5쌍 이상 캠페인 수 (14) |
| `up`, `down`, `same` | full29 대비 TP가 늘어난 / 줄어든 / 같은 캠페인 수 |

### `threshold_stats.csv` — 임계값 통계 (21행 = 모델 7 × 목표 3)

| 컬럼 | 의미 |
|---|---|
| `variant`, `target` | 모델, 목표 FPR |
| `min`, `max`, `mean`, `std` | 6개 split·fold의 임계값(확률 점수) 통계. `std`는 pandas 기본(표본 표준편차, ddof=1) |
| `max_over_min` | max / min |

### `per_fold_operating.csv` — fold별 운영점 (126행 = 모델 7 × 목표 3 × split 2 × fold 3)

| 컬럼 | 의미 |
|---|---|
| `variant`, `target`, `split`, `fold` | 모델, 목표, split, outer fold |
| `threshold`, `cal_fpr` | calibration 임계값과 calibration에서 실제 FPR (`calibration_attainment.csv`) |
| `outer_fpr`, `outer_fp`, `outer_hard_fp` | outer fold(정상 613)의 FPR, FP 수, Hard benign FP 수 |
| `tp`, `mal`, `recall` | outer fold의 TP, 악성 수, Recall |
| `fpr_gap` | outer_fpr − cal_fpr |

### `fpr_gap_stats.csv` — `fpr_gap`의 모델·목표별 평균·최소·최대 (21행, 비율 단위)

### `outer_rows_with_selections.csv` — outer 행별 점수와 선택 (5,534행 = 2,767 × split 2)

| 컬럼 | 의미 |
|---|---|
| `seed`, `fold`, `stage`, `row_id`, `split` | inner seed, outer fold, `outer`, 행 번호, split |
| `base7` … `A3` | 모델별 점수 |
| `package`, `new_version`, `label`, `class`, `campaign`, `component`, `type` | 행 메타데이터 |
| `sel_<모델>_<목표>` | 해당 모델·목표 FPR 임계값에서 양성 여부 (True/False) |

### `cand.py` — 위 9개 CSV를 만든다.

## 3. 주요 수치 (이 폴더 CSV에서 확인)

| 목표 | 모델 | 새로 잡음 s1 / s2 | 새로 놓침 s1 / s2 | 순증가 | shai-orig 제외 순증가 |
|---|---|---|---|---|---|
| 1% | full35 | 51 / 70 | 14 / 36 | +37 / +34 | +10 / −12 |
| 1% | A1 | 17 / 46 | 0 / 1 | +17 / +45 | +4 / +14 |
| 1% | A2 | 25 / 47 | 0 / 1 | +25 / +46 | +5 / +14 |
| 1% | A3 | 27 / 49 | 0 / 1 | +27 / +48 | +5 / +16 |
| 3% | A1 / A2 / A3 | 15·21·22 / 37·44·54 | 0·0·0 / 0·3·6 | | +4·10·11 / +13·14·11 |
| 5% | A1 / A2 / A3 | 26·35·38 / 36·38·38 | 0·0·0 / 3·4·4 | | +13·21·21 / +7·6·6 |

- 1%에서 A1~A3가 놓친 1건은 같은 행이다: `art-template` 4.13.3(individuals_case, split2 fold1; full29 0.0157, full35 0.00005).
- 1%에서 A1~A3의 새 탐지 중 shai-hulud-original 비중은 65~81%다.
- fold별: 이득은 outer fold 2에서 나오고, fold 0은 모든 모델 Recall 1.0, fold 1은 A가 full29와 같다(`per_fold_operating.csv`).

## 4. 부동소수점 읽기 방식과 경계 판정 (재현 시 필수)

- `fair.py`는 점수 CSV를 pandas 기본 파서로 읽고 그 값으로 임계값을 계산했다. `calibration_attainment.csv`의 `threshold`는 Python `repr`로 저장돼 있다.
- 재현하려면 **점수는 기본 파서로, 임계값은 `float_precision="round_trip"`으로** 읽어야 한다. `cand.py`가 그렇게 한다.
- 확인: 처음에 임계값을 기본 파서로 읽었을 때 `fair_comparison.csv`와 4칸, 점수까지 `round_trip`으로 읽었을 때 3칸이 달랐다.
  임계값이 calibration 정상 점수 바로 위(`nextafter`)에 놓이므로, 마지막 자리 차이로 outer의 몇 행이 경계를 넘나든다.
- 해석: 모델 사이 차이가 몇 행 수준(예: A1~A3 사이 2~10행)이면 이 경계 민감도와 같은 크기라서 의미 있는 차이로 보기 어렵다.

## 5. 임계값 범위에 관한 주의

- 확인: 6개 split·fold의 임계값이 모델에 따라 수백~수천 배 차이 난다(`threshold_stats.csv`, 예: full29 1% 5.47e-05~0.0479, A2 1% 4.42e-05~0.138).
  outer FPR은 calibration FPR과 fold별로 −2.4~+4.1%p 다르다(`fpr_gap_stats.csv`).
- 이것만으로 서비스 운영이 불안정하다고 단정할 수 없다. 이유:
  - fold마다 학습 데이터·모델이 다르다. 배포 모델은 하나이며 임계값도 하나로 정한다.
  - 점수가 0과 1 근처에 몰려 있어, 확률 값의 배율 차이가 순위 차이를 그대로 뜻하지 않는다.
  - calibration 정상이 fold당 약 307개라 1% 임계값은 정상 3건의 순위로 정해진다. 이것은 표본 크기 한계이며, 운영 환경의 정상 분포에서의 변동은 측정하지 않았다.
- 운영 안정성을 판단하려면 배포 모델 기준의 별도 분석(예: calibration 부트스트랩, 독립 정상 데이터에서의 FPR)이 필요하며, 이 폴더에서는 하지 않았다.

## 6. 한계

- D06 개발 결과. 독립 검증 없음. outer fold 3개가 각각 큰 캠페인 하나에 지배된다.
- split1·split2는 같은 outer 행이라 독립 관측이 아니다.
- 정상 구성(Hard benign 13%)과 악성 비율(33.5%)이 실제 배포와 다르다.

## 7. 입력과 재현

- 기준: 이 브랜치 `exp/d06-x1-candidate-analysis`는 `exp/d06-x1-fair-compare` `55ced8c` 위에 있다. 입력은 모두 이 브랜치 안에 있다.
- 입력 (저장소 상대 경로)
  - `experiments/d06_feature_comparison_18/scores/saved_scores.csv` (base7, full29, no_interval28)
  - `experiments/d06_full35_compare/run/scores.csv` (full35), `run/row_metadata.csv`
  - `experiments/d06_x1_extraction/analysis/d06_full35.csv` (행 메타데이터 결합)
  - `experiments/d06_x1_cause_analysis/common.py` (로더)
  - `experiments/d06_x1_fair_compare/calibration_attainment.csv` (임계값), `fair_comparison.csv` (일치 확인)
- 외부 입력 없음(D06 원본 `train.csv`나 데이터 저장소 불필요).
- 환경: Python 3.13, pandas 3.0.6, numpy 2.5.3 (common.py는 numpy·pandas만 사용).
- 실행: 저장소 루트에서 `python -I -B experiments/d06_x1_candidate_analysis/cand.py` → 이 폴더에 CSV 9개를 덮어쓴다.
- 검증: 임시 작업공간에서 만든 CSV 9개와, 경로만 저장소 상대 경로로 바꾼 이 스크립트로 다시 만든 CSV 9개가 바이트 단위로 같았다.
  계산 코드는 바꾸지 않았다(바꾼 것: 입력 기준 경로, 출력 경로, 사용법 docstring).
