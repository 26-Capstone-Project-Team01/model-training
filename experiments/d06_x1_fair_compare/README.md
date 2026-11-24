# D06 공정 비교: PR #13 모델 · full35 · A1~A3 (같은 Split·Fold·calibration 정책)

상태: D06 개발자료 진단. **모델 학습 없음** — 저장된 예측 점수만 읽어 계산했다. Test 677은 읽지 않았다.
결합 가중치·임계값 정책·목표 FPR은 미리 정한 값이며 outer 결과로 고르지 않았다.
D06 outer는 이미 X1 설계·원인 분석·A 설계에 쓰인 개발 결과이므로 **최종 일반화 성능이 아니다**.

표기: "확인" = 이 폴더의 CSV 또는 저장소 파일에서 직접 계산·확인한 사실. "해석" = 그 사실에 대한 판단(검증되지 않음).

---

## 1. 이 비교를 한 이유

- 이전 실험 기록(`results/experiments.csv`)의 D06-E06 Recall 60.8%, D06-E09 71.0%는 **Test 677에서 임계값 0.5 고정**으로 평가한 값이다.
- A1~A3의 Recall 81~89%(`../d06_x1_blend_a/`)는 **D06 Train의 outer fold에서, calibration 데이터로 정한 FPR 1% 임계값**으로 평가한 값이다.
- 평가 데이터·분할·임계값 정책이 모두 달라 두 숫자를 직접 비교할 수 없다. 그래서 **같은 평가 행, 같은 Split/Fold, 같은 calibration 정책, 같은 목표 FPR**에서
  비교할 수 있는 모델만 모아 다시 계산했다. 핵심 질문은 "같은 오탐 수준에서 어떤 모델이 악성을 더 많이 잡는가"이다.

## 2. 비교 대상 7개 모델

모두 PR #13 학습 스냅샷(`../d06_feature_comparison_18/provenance/phase2_run1_base7_full29/executed_script_snapshot.py`, SHA-256 `049bf00c…`)과
같은 학습 조건이다: LightGBM 4.7.0, `objective=binary, metric=binary_logloss, verbosity=-1, num_threads=2, deterministic=true, force_col_wise=true, seed=20261109`,
최대 200 rounds, early stopping 없음, 검증 세트 없음, sample weight 없음, fit 행으로만 학습, `updateType`은 범주형 `[major, minor, patch]`, 결측 NaN.

| 모델 | Feature | 출처 | 비고 |
|---|---|---|---|
| `base7` | package.json 7개: installScriptPresent, installScriptAdded, scriptEntryAdded, newDependencyAdded, newDependencyCount, updateType, updateInterval | PR #13 저장 점수 (`model=base7`) | E06과 Feature 세트가 같다. 실제 rounds 6개 모두 200 (확인: `model_index.csv`) |
| `full29` | 기존 29개 (package.json 7 + 난독화 22) | PR #13 저장 점수 (`model=full29`) | split1 fold1만 실제 149 rounds (더 나눌 분기가 없어 멈춤) |
| `no_interval28` | full29 − updateInterval | PR #13 저장 점수 (`model=no_interval28`) | PR #13에서 사후 추가된 변형. split1 fold1 151 rounds |
| `full35` | full29 + X1 6개 | `../d06_full35_compare/run/scores.csv` (`variant=full35`) | 같은 스냅샷 import, PR #13 full29 재학습이 모델 내용·점수 일치(최대 차 1.1e-16)를 확인한 실험. split1 fold1 138 rounds |
| `A1` | full29·full35 점수 결합 | 이 스크립트에서 계산 | `0.9·full29 + 0.1·full35` (확률 공간) |
| `A2` | 〃 | 〃 | `0.8·full29 + 0.2·full35` |
| `A3` | 〃 | 〃 | `0.7·full29 + 0.3·full35` |

A1~A3의 결합 규칙과 해석은 `../d06_x1_blend_a/README.md`. 여기서는 같은 규칙을 calibration 행에도 적용해 목표 FPR 임계값을 다시 구했다.

## 3. E06·E09와 PR #13 모델의 차이 (확인)

| 항목 | D06-E06 / D06-E09 (`train_model.py`, `results/experiments.csv`) | PR #13 `base7` |
|---|---|---|
| Feature | package.json 7개 (두 실험 같음) | 같은 7개 |
| 학습 데이터 | D06 Train 2,767 중 train 2,212 / validation 555 (`splits/train_val_split_assignment.csv`, 분할 seed 20261002) | outer fold별 fit 1,292~1,437행 |
| 학습 방식 | `num_boost_round=500`, validation으로 early stopping 50 → best_iteration E06 6, E09 7 | 200 rounds 고정, early stopping 없음 |
| 파라미터 | `objective=binary`, `metric=[binary_logloss, auc]`, `verbosity=-1` (나머지 기본값) | 위 2절 파라미터 |
| 가중치 | E06 없음. E09는 악성에 `1/sqrt(campaign 크기)`, 악성 가중치 합 정규화, individuals_case는 pair마다 크기 1 | 없음 |
| 평가 | Test 677, 임계값 0.5 | D06 Train outer fold, calibration 임계값 |

- PR #13 `base7`은 **E06과 같은 Feature를 PR #13 방식으로 학습한 모델**이지 E06 자체가 아니다.
- E09와 비슷한 PR #13 변형 `M_base_weighted`(base7 + 악성 가중치 1/√n)가 PR #13 phase2 primary(split1)에서 학습됐으나, 가중치 키가 다르고
  (스냅샷 `fit_weights`: 실제 splitGroup, 범용 묶음은 `package:`) **점수가 PR #13 묶음에 저장되지 않았다**. 그래서 이 비교에 넣지 않았다.
- E06·E09의 D06 Train 예측은 `results/diagnostics/d06_diag01_pair_predictions.csv`(2,767행 × 2)에 있다. 이것은 CV01 3-fold
  (`splits/cv_3fold_assignment.csv`, fold 945/912/910, PR #13 fold와 번호 일치 54%) OOF이고 calibration 단계가 없으며,
  `PROJECT_HANDOFF.md`에 따르면 early stopping에 평가 fold를 사용했다. **같은 실험으로 취급할 수 없어 참고 출력만 한다**(9절).
- D06-E00(full29, early stopping)은 D06 Train 전체로 학습해 outer로 쓸 수 있는 점수가 없다. PR #13 `full29`가 같은 Feature 세트를 대신한다.

## 4. 데이터와 Split/Fold

- 데이터: `26-Capstone-Project-Team01/npm-malware-package-pairs` 커밋 `be87ab4cff66fff1980c4a71be8032b6b47225ba`의
  `derived/splits/train.csv` (SHA-256 `22fbc8752fff5fff90e40b911f6bf7d187769b4566db957d65a37a16be7d2c23`).
  2,767쌍 = 악성 928 + 무작위 정상 1,600 + Hard benign 239. Test 677은 사용하지 않았다.
- outer 3-fold: PR #13 component 단위 분할(같은 package, 실제 캠페인, 악성 payload 해시를 공유하면 같은 component).
  fold 행 945 / 911 / 911, 악성 332 / 298 / 298, 정상(무작위+Hard) 613 / 613 / 613. **split1과 split2에서 outer는 같다.**
  fold 0의 악성은 sha1-hulud-second-coming 한 캠페인뿐이다.
- 내부 분할: 각 fold의 나머지 두 fold를 component 단위로 fit / calibration(클래스별 약 25%)으로 나눈다. split1 inner seed 20261109, split2 20261110
  (실제 RNG seed = inner seed + fold). 두 split은 fit/calibration 역할만 다르고 outer 행은 같다.
- 이 스크립트는 7개 모델의 점수를 (seed, fold, stage, row_id)로 맞춘 뒤 누락·중복이 없음을 확인하고(assert), outer 행 수가 위와 같음을 확인한다.

## 5. Calibration과 Outer의 역할

| 구분 | 용도 | 이 분석에서 |
|---|---|---|
| fit | 모델 학습 | 사용하지 않음 (저장 점수만 사용) |
| calibration | 임계값 결정 | 목표 FPR 1/3/5% 임계값을 **여기서만** 구함. fold당 정상 306~308행 |
| outer | 평가 | calibration 임계값을 그대로 적용해 TP/FP 등을 계산. 임계값이나 가중치를 outer로 고르지 않음 |

split별 결과는 outer 3 fold를 합산한 값이다. fold마다 모델과 임계값이 다르므로, 합산 값은 "fold별 정책을 적용한 결과의 합"이다.

## 6. 목표 FPR 임계값 계산 (PR #13 스냅샷 `calibrate(..., mode="ML")`)

fold마다, 모델마다, 목표 t ∈ {0.01, 0.03, 0.05}에 대해:

1. calibration 정상 행 수 n (무작위 정상 + Hard benign)
2. FP 예산 `budget = floor(n·t + 1e-12)` → n=306~308에서 1%: 3, 3%: 9, 5%: 15
3. 정상 점수를 큰 순서로 정렬하고 `budget`번째 다음(0부터 세면 index = budget)의 점수를 경계값 b로 둔다
4. 임계값 = `nextafter(b, +inf)` (b보다 아주 조금 큰 수). **점수 ≥ 임계값이면 양성**
5. 정상 수가 예산 이하이면 임계값 = −inf (이번 데이터에서는 발생하지 않음)
6. calibration에서 실제 FP가 예산을 넘지 않는지 스냅샷이 확인한다

고정 임계값 0.5는 참고용이다(PR #13 표시 지점, 운영 기준 아님).

### 동점 처리

- 경계값 b와 **같은 점수의 정상은 모두 음성**이 된다(임계값이 b보다 크므로). 그래서 동점이 있으면 실제 calibration FP는 예산보다 작아진다(보수적).
- 확인: 대부분의 모델·fold에서 경계 동점은 1건(경계 행 자신)이고 calibration FP = 예산(FPR 0.97%·2.92%·4.87%)이다.
  동점이 2건 이상인 경우는 `base7`의 4건뿐이다: split1 fold0 3%(동점 2, FP 9), split2 fold1 1%(동점 2, FP 3), split2 fold1 5%(동점 3, FP 15),
  **split2 fold0 5%(동점 4, FP 13 = 4.23%, 예산 15에 못 미침)**. 7개 Feature만 쓰는 base7은 점수 종류가 적어 동점이 생긴다.
- calibration FPR을 정확히 맞추기 어려운 이유: 정상 표본이 fold당 약 307개라 예산이 정수(3/9/15)로만 움직이고, 정상 3건의 순위로 1% 임계값이 정해진다.
  그래서 같은 목표에서도 outer 실제 FPR이 목표와 다르다(예: full29 split2 목표 1% → outer 1.63%, 목표 5% → 7.01%).

## 7. 파일과 컬럼

### `fair_comparison.csv` (56행 = 운영점 4 × 모델 7 × split 2)

| 컬럼 | 의미 |
|---|---|
| `op` | `calFPR1%`, `calFPR3%`, `calFPR5%` (calibration 목표 FPR 임계값), `0.5` (고정 임계값, 참고) |
| `variant` | 모델 이름 (2절) |
| `split` | `split1` (inner seed 20261109) / `split2` (20261110) |
| `TP`, `FN`, `FP` | outer 3 fold 합산. 악성 928, 정상 1,839 기준 |
| `HardFP` | FP 중 Hard benign 행 수 (Hard benign 239 중) |
| `Recall` | TP / 928 |
| `Precision` | TP / (선택된 행 수). 선택 0이면 분모 1 |
| `F1` | 2·Recall·Precision / (Recall + Precision) |
| `outerFPR` | FP / 1,839 (무작위 정상 + Hard benign) |
| `CampMacro` | 캠페인 평균 Recall: outer 악성을 `campaign`(splitGroup, individuals_case는 하나로 묶임)별로 Recall을 구해 단순 평균 |

### `calibration_attainment.csv` (126행 = 모델 7 × split 2 × fold 3 × 목표 3)

| 컬럼 | 의미 |
|---|---|
| `variant`, `split`, `fold` | 모델, split, outer fold (이 fold의 calibration 데이터) |
| `target` | 목표 FPR 0.01 / 0.03 / 0.05 |
| `cal_normals` | calibration 정상 수 n (306~308) |
| `budget` | floor(n·target) |
| `cal_fp` | 그 임계값에서 calibration 정상 중 양성 수 |
| `achieved_cal_fpr` | cal_fp / cal_normals |
| `boundary_ties` | 경계값 b와 같은 점수의 정상 수 (6절) |
| `threshold` | outer에 적용한 임계값 (확률 점수) |

임계값 범위(6개 split·fold의 최솟값~최댓값, 확인): full29 1% 5.47e-05~0.0479, 3% 1.02e-05~0.00684, 5% 1.63e-06~0.000881;
A2 1% 4.42e-05~0.138; base7 1% 0.0558~0.998. fold마다 임계값이 수십~수천 배 차이 난다.

### `ranking.csv` (14행 = 모델 7 × split 2)

| 컬럼 | 의미 |
|---|---|
| `ROC_AUC_fold_mean` | outer fold별 ROC-AUC(scikit-learn `roc_auc_score`)의 3-fold 평균 |
| `PR_AUC_fold_mean` | outer fold별 PR-AUC(`average_precision_score`)의 3-fold 평균 |

임계값과 무관한 진단 지표다. fold마다 모델이 달라 행을 합쳐 계산하지 않고 fold별로 구한 뒤 평균했다.

### `diagnostic_matched_outer_fpr.csv` (42행 = FPR 3 × 모델 7 × split 2) — **진단 전용**

| 컬럼 | 의미 |
|---|---|
| `outerFPR_budget` | 0.01 / 0.03 / 0.05 |
| `variant`, `split` | 모델, split |
| `TP`, `FP` | outer fold마다 **outer 정상 점수로** 6절과 같은 방식의 임계값을 만들어 적용한 결과의 3-fold 합. FP는 floor(613·x)×3 = 18 / 54 / 90 |

### `fair.py`

위 4개 CSV를 만든다. 추가로 화면에 E06·E09 CV01 OOF 참고 지표를 출력한다(파일로 저장하지 않음).

## 8. 실제 운영점 평가와 진단용 Oracle 비교의 차이

- **운영점 평가** (`fair_comparison.csv`): 임계값을 calibration에서만 정한다. 실제로 쓸 수 있는 절차이며, outer FPR은 목표와 어긋날 수 있다.
  그래서 모델마다 실제 오탐 수준이 다르다.
- **Oracle 비교** (`diagnostic_matched_outer_fpr.csv`): outer 정답을 보고 모든 모델의 FP를 같게 맞춘다. "같은 오탐에서 몇 개를 잡는가"를 직접 보여 주지만
  실제로는 불가능한 절차다. 모델·임계값·가중치 선택에 쓰지 않았고, 쓰면 안 된다.

## 9. 결과

### 9.1 운영점 (calibration 목표 FPR) — 확인

#### 목표 FPR 1%

| 모델 | split | TP | FN | FP | Hard FP | Recall | Precision | F1 | outer FPR | 캠페인 평균 Recall |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| base7 | split1 | 479 | 449 | 35 | 23 | 0.516 | 0.932 | 0.664 | 1.90% | 0.302 |
| base7 | split2 | 516 | 412 | 26 | 16 | 0.556 | 0.952 | 0.702 | 1.41% | 0.276 |
| full29 | split1 | 735 | 193 | 14 | 5 | 0.792 | 0.981 | 0.877 | 0.76% | 0.498 |
| full29 | split2 | 779 | 149 | 30 | 13 | 0.839 | 0.963 | 0.897 | 1.63% | 0.592 |
| no_interval28 | split1 | 711 | 217 | 14 | 4 | 0.766 | 0.981 | 0.860 | 0.76% | 0.494 |
| no_interval28 | split2 | 580 | 348 | 24 | 8 | 0.625 | 0.960 | 0.757 | 1.31% | 0.370 |
| full35 | split1 | 772 | 156 | 20 | 8 | 0.832 | 0.975 | 0.898 | 1.09% | 0.597 |
| full35 | split2 | 813 | 115 | 30 | 16 | 0.876 | 0.964 | 0.918 | 1.63% | 0.607 |
| A1 | split1 | 752 | 176 | 13 | 5 | 0.810 | 0.983 | 0.888 | 0.71% | 0.506 |
| A1 | split2 | 824 | 104 | 31 | 13 | 0.888 | 0.964 | 0.924 | 1.69% | 0.637 |
| A2 | split1 | 760 | 168 | 13 | 4 | 0.819 | 0.983 | 0.894 | 0.71% | 0.509 |
| A2 | split2 | 825 | 103 | 29 | 11 | 0.889 | 0.966 | 0.926 | 1.58% | 0.637 |
| A3 | split1 | 762 | 166 | 13 | 4 | 0.821 | 0.983 | 0.895 | 0.71% | 0.509 |
| A3 | split2 | 827 | 101 | 27 | 9 | 0.891 | 0.968 | 0.928 | 1.47% | 0.644 |

#### 목표 FPR 3%

| 모델 | split | TP | FN | FP | Hard FP | Recall | Precision | F1 | outer FPR | 캠페인 평균 Recall |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| base7 | split1 | 594 | 334 | 75 | 43 | 0.640 | 0.888 | 0.744 | 4.08% | 0.399 |
| base7 | split2 | 587 | 341 | 69 | 29 | 0.633 | 0.895 | 0.741 | 3.75% | 0.362 |
| full29 | split1 | 782 | 146 | 32 | 12 | 0.843 | 0.961 | 0.898 | 1.74% | 0.549 |
| full29 | split2 | 830 | 98 | 75 | 27 | 0.894 | 0.917 | 0.906 | 4.08% | 0.700 |
| no_interval28 | split1 | 796 | 132 | 51 | 19 | 0.858 | 0.940 | 0.897 | 2.77% | 0.556 |
| no_interval28 | split2 | 730 | 198 | 53 | 17 | 0.787 | 0.932 | 0.853 | 2.88% | 0.610 |
| full35 | split1 | 841 | 87 | 66 | 31 | 0.906 | 0.927 | 0.917 | 3.59% | 0.673 |
| full35 | split2 | 860 | 68 | 70 | 26 | 0.927 | 0.925 | 0.926 | 3.81% | 0.718 |
| A1 | split1 | 797 | 131 | 34 | 12 | 0.859 | 0.959 | 0.906 | 1.85% | 0.556 |
| A1 | split2 | 867 | 61 | 86 | 34 | 0.934 | 0.910 | 0.922 | 4.68% | 0.743 |
| A2 | split1 | 803 | 125 | 37 | 14 | 0.865 | 0.956 | 0.908 | 2.01% | 0.587 |
| A2 | split2 | 871 | 57 | 80 | 32 | 0.939 | 0.916 | 0.927 | 4.35% | 0.754 |
| A3 | split1 | 804 | 124 | 38 | 14 | 0.866 | 0.955 | 0.908 | 2.07% | 0.593 |
| A3 | split2 | 878 | 50 | 75 | 32 | 0.946 | 0.921 | 0.934 | 4.08% | 0.743 |

#### 목표 FPR 5%

| 모델 | split | TP | FN | FP | Hard FP | Recall | Precision | F1 | outer FPR | 캠페인 평균 Recall |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| base7 | split1 | 618 | 310 | 111 | 54 | 0.666 | 0.848 | 0.746 | 6.04% | 0.411 |
| base7 | split2 | 621 | 307 | 112 | 34 | 0.669 | 0.847 | 0.748 | 6.09% | 0.409 |
| full29 | split1 | 797 | 131 | 87 | 31 | 0.859 | 0.902 | 0.880 | 4.73% | 0.557 |
| full29 | split2 | 857 | 71 | 129 | 39 | 0.923 | 0.869 | 0.896 | 7.01% | 0.762 |
| no_interval28 | split1 | 811 | 117 | 86 | 29 | 0.874 | 0.904 | 0.889 | 4.68% | 0.562 |
| no_interval28 | split2 | 794 | 134 | 77 | 29 | 0.856 | 0.912 | 0.883 | 4.19% | 0.649 |
| full35 | split1 | 854 | 74 | 106 | 50 | 0.920 | 0.890 | 0.905 | 5.76% | 0.698 |
| full35 | split2 | 876 | 52 | 117 | 43 | 0.944 | 0.882 | 0.912 | 6.36% | 0.759 |
| A1 | split1 | 823 | 105 | 76 | 32 | 0.887 | 0.915 | 0.901 | 4.13% | 0.614 |
| A1 | split2 | 890 | 38 | 122 | 43 | 0.959 | 0.879 | 0.918 | 6.63% | 0.801 |
| A2 | split1 | 832 | 96 | 75 | 31 | 0.897 | 0.917 | 0.907 | 4.08% | 0.678 |
| A2 | split2 | 891 | 37 | 121 | 46 | 0.960 | 0.880 | 0.919 | 6.58% | 0.799 |
| A3 | split1 | 835 | 93 | 78 | 33 | 0.900 | 0.915 | 0.907 | 4.24% | 0.679 |
| A3 | split2 | 891 | 37 | 107 | 42 | 0.960 | 0.893 | 0.925 | 5.82% | 0.799 |

#### 고정 임계값 0.5 (참고)

| 모델 | split | TP | FN | FP | Hard FP | Recall | Precision | F1 | outer FPR | 캠페인 평균 Recall |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| base7 | split1 | 583 | 345 | 73 | 34 | 0.628 | 0.889 | 0.736 | 3.97% | 0.292 |
| base7 | split2 | 595 | 333 | 95 | 32 | 0.641 | 0.862 | 0.735 | 5.17% | 0.364 |
| full29 | split1 | 604 | 324 | 3 | 1 | 0.651 | 0.995 | 0.787 | 0.16% | 0.325 |
| full29 | split2 | 658 | 270 | 6 | 3 | 0.709 | 0.991 | 0.827 | 0.33% | 0.384 |
| no_interval28 | split1 | 513 | 415 | 8 | 2 | 0.553 | 0.985 | 0.708 | 0.44% | 0.291 |
| no_interval28 | split2 | 548 | 380 | 14 | 7 | 0.591 | 0.975 | 0.736 | 0.76% | 0.316 |
| full35 | split1 | 655 | 273 | 3 | 2 | 0.706 | 0.995 | 0.826 | 0.16% | 0.335 |
| full35 | split2 | 673 | 255 | 3 | 3 | 0.725 | 0.996 | 0.839 | 0.16% | 0.324 |
| A1 | split1 | 604 | 324 | 3 | 1 | 0.651 | 0.995 | 0.787 | 0.16% | 0.324 |
| A1 | split2 | 658 | 270 | 5 | 2 | 0.709 | 0.992 | 0.827 | 0.27% | 0.384 |
| A2 | split1 | 607 | 321 | 3 | 1 | 0.654 | 0.995 | 0.789 | 0.16% | 0.325 |
| A2 | split2 | 659 | 269 | 5 | 2 | 0.710 | 0.992 | 0.828 | 0.27% | 0.382 |
| A3 | split1 | 607 | 321 | 2 | 1 | 0.654 | 0.997 | 0.790 | 0.11% | 0.320 |
| A3 | split2 | 657 | 271 | 5 | 2 | 0.708 | 0.992 | 0.826 | 0.27% | 0.376 |

### 9.2 순위 지표 (임계값 무관, fold 평균) — 확인

| 모델 | ROC-AUC split1 | ROC-AUC split2 | PR-AUC split1 | PR-AUC split2 |
|---|---:|---:|---:|---:|
| base7 | 0.9067 | 0.8975 | 0.8622 | 0.8515 |
| full29 | 0.9647 | 0.9702 | 0.9466 | 0.9607 |
| no_interval28 | 0.9548 | 0.9599 | 0.9277 | 0.9340 |
| full35 | 0.9666 | 0.9762 | 0.9584 | 0.9694 |
| A1 | 0.9678 | 0.9771 | 0.9550 | 0.9716 |
| A2 | 0.9680 | 0.9781 | 0.9564 | 0.9730 |
| A3 | 0.9684 | 0.9788 | 0.9573 | 0.9738 |

### 9.3 진단용 Oracle: outer FP를 맞췄을 때 TP / FP — 확인 (선택에 쓰지 않음)

| 모델 | 1% s1 | 1% s2 | 3% s1 | 3% s2 | 5% s1 | 5% s2 |
|---|---|---|---|---|---|---|
| base7 | 479 / 18 | 490 / 18 | 562 / 54 | 567 / 54 | 599 / 90 | 599 / 88 |
| full29 | 737 / 18 | 748 / 18 | 784 / 54 | 807 / 54 | 800 / 90 | 834 / 90 |
| no_interval28 | 602 / 18 | 579 / 18 | 775 / 54 | 747 / 54 | 795 / 90 | 807 / 90 |
| full35 | 758 / 18 | 769 / 18 | 824 / 54 | 841 / 54 | 844 / 90 | 865 / 90 |
| A1 | 757 / 18 | 789 / 18 | 797 / 54 | 841 / 54 | 822 / 90 | 866 / 90 |
| A2 | 768 / 18 | 798 / 18 | 803 / 54 | 839 / 54 | 826 / 90 | 872 / 90 |
| A3 | 777 / 18 | 798 / 18 | 804 / 54 | 840 / 54 | 828 / 90 | 875 / 90 |

base7 5% split2의 FP 88은 경계 동점 때문에 FP 예산(90)을 다 채우지 못한 것이다.

### 9.4 해석 (검증되지 않은 판단 포함)

- 확인: 같은 calibration 정책에서 base7(E06 Feature 세트) 대비 A2의 TP는 목표 1%에서 +281 / +309, 3%에서 +209 / +284, 5%에서 +214 / +270이며,
  FP는 세 목표 모두 split1에서 A2가 적고(1%: 35 → 13, 3%: 75 → 37, 5%: 111 → 75) split2에서 A2가 조금 많다(26 → 29, 69 → 80, 112 → 121).
  Hard FP는 1%에서 두 split 모두 A2가 적고(23 → 4, 16 → 11), 3%·5% split2에서는 A2가 많다(29 → 32, 34 → 46). Oracle 비교에서도 같은 FP에서 A2가
  base7보다 289~308개(1%) 더 잡는다. ROC-AUC·PR-AUC도 모든 split에서 base7이 가장 낮다.
- 확인: 고정 0.5에서는 base7 Recall(0.628 / 0.641)이 full29(0.651 / 0.709)와 비슷하지만 FP는 73 / 95로 full29(3 / 6)의 10배 이상이다.
  모델마다 점수 척도가 달라 고정 0.5는 같은 오탐 수준의 비교가 아니다.
- 해석: 예전의 "E06(60.8%)이 E00(16.1%)보다 낫다"는 인상은 Test에서 0.5 고정 임계값으로 비교한 영향일 가능성이 크다.
  E00·E06의 Test 점수를 이번에 보지 않았으므로 확인하지 않았다.
- 확인: A와 full35의 비교는 split과 운영점에 따라 다르다. 목표 1% split1에서는 full35의 TP가 더 많지만(772 vs A1~A3 752~762) FP도 많다(20 vs 13).
  목표 1% split2에서는 A1~A3의 TP가 더 많고(824~827 vs 813) FP는 비슷하다(27~31 vs 30). 목표 3%·5%의 split1에서는 full35가 TP가 많지만 FP도 많다
  (3%: 841·66 vs A2 803·37). Oracle(같은 FP)에서는 1%에서 A2가 많고(768 / 798 vs 758 / 769), 3%·5% split1에서는 full35가 많다(824, 844 vs A2 803, 826).
- 확인: no_interval28은 split2에서 크게 떨어진다(목표 1% TP 580 vs full29 779). split1과 split2의 차이가 커서 updateInterval 제거의 효과는 불안정하다.
- 해석: 결합 가중치 사이(A1~A3)의 차이는 작다. 이 결과로 가중치를 고르지 않는다.

## 10. 한계

- D06 outer는 원인 분석과 A 설계에 이미 쓰였다. 개발 결과이며 최종 일반화 성능이 아니다.
- outer fold 3개가 각각 큰 캠페인 하나에 지배된다(fold 0 sha1-hulud 332, fold 1 mini-shai-hulud 198, fold 2 shai-hulud-original 186).
- split1과 split2는 같은 outer 행을 쓰므로 독립 관측이 아니다.
- calibration 정상이 fold당 약 307개라 1% 임계값은 정상 3건의 순위로 정해지고, outer FPR이 목표에서 벗어난다(6절). 임계값 분산(신뢰구간)은 계산하지 않았다.
- 정상 1,839건 중 Hard benign이 239건(13%)이다. 실제 배포에서의 정상 구성·악성 비율과 다르므로 Precision과 FPR을 그대로 기대할 수 없다.
- E06·E09 자체는 같은 조건의 점수가 없어 비교하지 못했다. PR #13 `M_base_weighted` 점수는 저장되지 않았다.
- 캠페인별 Recall 표는 이 폴더에 없다(캠페인 평균만 있음). 캠페인별 결과는 아래 11절 자료로 다시 계산해야 한다.

### 참고 출력 (파일 저장 안 함, 위 표와 차이를 계산하지 않음)

| 자료 | 조건 | 결과 |
|---|---|---|
| D06-E06 | Test 677, 0.5 (`results/experiments.csv`) | Recall 0.608, Precision 0.886, F1 0.721, PR-AUC 0.869 |
| D06-E09 | Test 677, 0.5 | Recall 0.710, Precision 0.798, F1 0.751, PR-AUC 0.814 |
| D06-E00 | Test 677, 0.5 | Recall 0.161, Precision 0.921, F1 0.275, PR-AUC 0.701 |
| E06 CV01 OOF | 2,767행, 0.5 (`fair.py` 출력) | TP 508, FP 47, Recall 0.547, PR-AUC fold 평균 0.847, ROC-AUC 0.896 |
| E09 CV01 OOF | 〃 | TP 664, FP 183, Recall 0.716, PR-AUC 0.852, ROC-AUC 0.902 |

D06 Test 677은 이전 실험들에서 여러 번 확인된 자료이므로 독립 평가로 볼 수 없다. CV01 OOF는 fold 구성이 다르고 calibration이 없으며
평가 fold로 early stopping을 했다.

## 11. 이후 분석에 재사용할 수 있는 자료

| 자료 | 위치 (이 브랜치) | 내용 |
|---|---|---|
| 7개 모델 목표 FPR 1/3/5% 임계값 | `calibration_attainment.csv` | fold별 임계값, 예산, 동점 |
| base7·full29·no_interval28 점수 | `../d06_feature_comparison_18/scores/saved_scores.csv` | calibration·outer, 2 split × 3 fold |
| full35 점수 | `../d06_full35_compare/run/scores.csv` | 〃 |
| A1~A3 outer 행별 점수·선택(FPR 1%, 0.05, 0.5)·fold 안 순위·캠페인·component | `../d06_x1_blend_a/blend_outer_rows.csv` | FPR 3·5% 선택 여부는 없음 → 점수와 위 임계값으로 재계산 가능 |
| A1~A3 FPR 1% fold별 임계값·TP·FP | `../d06_x1_blend_a/blend_fold_cal1.csv` | |
| 캠페인별 TP(FPR 1%·0.05·0.5), TreeSHAP 등 | `../d06_x1_cause_analysis/out/` | |

A1~A3의 calibration 단계 결합 점수는 저장돼 있지 않지만 full29·full35 저장 점수로 결정적으로 다시 만들 수 있다(이 스크립트가 그렇게 한다).

## 12. 입력, 기준 커밋, 재현

- 기준: 이 브랜치 `exp/d06-x1-fair-compare`는 `exp/d06-x1-blend-a` `a4a5280` 위에 만들었다. 그 안에 아래 입력이 모두 있다.
- 입력 파일 (저장소 상대 경로)
  - `experiments/d06_feature_comparison_18/scores/saved_scores.csv` (PR #13, main `e267281`)
  - `experiments/d06_feature_comparison_18/provenance/phase2_run1_base7_full29/executed_script_snapshot.py` (`calibrate`만 사용)
  - `experiments/d06_full35_compare/run/scores.csv`, `run/row_metadata.csv` (`03ac937`)
  - `experiments/d06_x1_extraction/analysis/d06_full35.csv` (행 메타데이터 결합용, `5a1a61e`)
  - `experiments/d06_x1_cause_analysis/common.py` (로더, `9846690`)
  - 참고 출력 전용: `results/diagnostics/d06_diag01_pair_predictions.csv`, `splits/cv_3fold_assignment.csv`
- 외부 입력: 없음. D06 `train.csv` 원본이나 데이터 저장소는 필요하지 않다(저장 점수만 사용).
- 환경: Python 3.13, lightgbm 4.7.0, pandas 3.0.6, numpy 2.5.3, scikit-learn 1.9.1. 스냅샷이 import 시 lightgbm·scikit-learn을 불러오므로 둘 다 설치돼 있어야 한다
  (학습은 하지 않는다).
- 실행: 저장소 루트에서 `python -I -B experiments/d06_x1_fair_compare/fair.py` → 이 폴더에 CSV 4개를 덮어쓴다.
- 검증: 임시 작업공간에서 처음 만든 CSV 4개와, 경로만 저장소 상대 경로로 바꾼 이 스크립트로 다시 만든 CSV 4개가 바이트 단위로 같았다.
  계산 코드는 바꾸지 않았다(바꾼 것: `sys.path`, 출력 경로, 참고용 입력 경로 3곳, 사용법 docstring).
