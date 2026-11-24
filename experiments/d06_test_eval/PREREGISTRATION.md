# D06 Test 평가 사전 등록

작성: 2026-11-24. **이 문서는 Test 예측·성능 계산 전에 작성했다.** 작성 시점까지 이 세션에서 Test 677쌍에 대해 한 일은
키·행 수·열·출처 확인과 X1 추출 준비뿐이며, 어떤 모델로도 Test를 예측하거나 성능을 계산하지 않았다.
아래 조건은 Test 결과를 본 뒤 바꾸지 않는다. 바꿔야 하면 바꾼 날짜·이유·이전 내용을 이 문서 끝 "변경 이력"에 남기고, 바꾸기 전 결과도 함께 보고한다.

## 1. 평가 데이터

| 구분 | 정의 | 용도 |
|---|---|---|
| **주 평가: Test-674** | D06 동결 Test 677쌍에서 아래 vant 3쌍을 뺀 674쌍 | 모든 주 결과 |
| 보조: Test-677 | `npm-malware-package-pairs` `be87ab4c` `derived/splits/test.csv` (SHA-256 `e8a70053ce639ebc79d7bc8d9402578d3ceaf24853ed31735b5f55c418b8bd73`, 677행: 악성 217, 무작위 정상 400, Hard benign 60) | 과거 E06·E09 수치와의 비교 |

- 제외 3쌍(키): `vant 4.9.11 → 4.9.12`, `vant 4.9.11 → 4.9.13`, `vant 4.9.11 → 4.9.14` (모두 악성).
  데이터 저장소 D07-B 커밋 `c5b4d32`("remove stale Vant rows from derived CSVs")에서 `baselines.csv`·`test.csv` 등에서 제거된 행이다.
- 확인: be87ab4c Test 677에서 이 3쌍을 뺀 674행은 현재 main `4498acd`의 `derived/splits/test.csv`(SHA-256 `604673b9…5060`)와 모든 열·순서가 같다.
- 원본 파일은 바꾸지 않는다. 674는 키 기준 필터로 만든다. 제외 3쌍은 Test-677 결과에만 포함되고, 결과 표에서 따로 표시한다.
- Test 677은 이전 실험(D04~D06-E00~E10 등)에서 여러 번 평가된 자료다. 이 평가는 "처음 보는 독립 평가"가 아니라 **이미 공개된 개발 Test에서의 사전 등록 확인 평가**로 해석한다.

## 2. 학습 데이터와 분할

- 학습: D06 Train 2,767쌍(`be87ab4c` `train.csv`, SHA-256 `22fbc875…2c23`) 전체. Test는 학습·calibration·모델 선택에 쓰지 않는다.
- component: PR #13 스냅샷 `components()`(같은 package, 실제 splitGroup, 비어 있지 않은 악성 payload 해시를 union-find). 입력은 PR #13과 같다.
- 분할: 스냅샷 `inner_split(train_all, seed)`로 Train 전체를 component 단위 fit / calibration(클래스별 약 25%)으로 나눈다. `check_disjoint`로 겹침 0 확인.
  - **주 평가 seed 20261109**, 보조 seed 20261110. (outer fold가 없으므로 seed + fold 보정은 하지 않고 seed 값을 그대로 쓴다.)
- Train과 Test의 분리(확인): 키 0, 패키지 0, 비어 있지 않은 payload 해시(`largestChangedJsSha1`, `changedJsSetSha1`) 0, 실제 캠페인 0 겹침.
  `individuals_case`(범용 묶음)만 양쪽에 있다(데이터 저장소 설계).

## 3. 모델 (모두 사전 고정)

공통: LightGBM 4.7.0, PR #13 파라미터 `objective=binary, metric=binary_logloss, verbosity=-1, num_threads=2, deterministic=true, force_col_wise=true, seed=20261109`,
200 rounds, early stopping 없음, 검증 세트 없음, fit 행으로만 학습, `updateType` 범주형 `[major, minor, patch]`, 결측 NaN, 학습 코드는 PR #13 스냅샷을 수정 없이 import.

| 모델 | Feature | 가중치 | 비고 |
|---|---|---|---|
| `base7` | package.json 7개 | 없음 | E06과 같은 Feature |
| `base7_w` | package.json 7개 | E09 방식: 악성 행에 `1/sqrt(캠페인 크기)`, 캠페인 = 실제 splitGroup, 범용 묶음(`individual-compromise*`, `individuals_case`)은 행마다 크기 1, 악성 가중치 합 = fit 악성 수로 정규화, 정상·Hard benign 1. 크기는 fit 행 안에서 센다 | `train_model.py` `compute_sample_weights` 및 W1 `weights_splitgroup`과 같은 정의 |
| `full29` | 기존 29개 | 없음 | |
| `full35` | 29개 + X1 6개 | 없음 | X1은 `depbee-analyzer` `d56738c`. bool 1.0/0.0, 빈 칸 NaN, 변환 없음 |
| `A1`, `A2`, `A3` | `(1-w)·full29 + w·full35`, w = 0.1 / 0.2 / 0.3 | — | 확률 공간 결합. 세 가중치 모두 보고하며 Test로 고르지 않는다 |

## 4. 임계값과 운영점

- 임계값은 **calibration에서만** 구한다: PR #13 스냅샷 `calibrate(scores, labels, rule=all False, mode="ML", target)`, target ∈ {0.01, 0.03, 0.05}.
  (FP 예산 floor(n·target), 경계값 다음 실수, 점수 ≥ 임계값이면 양성, 동점은 음성 쪽)
- A1~A3는 calibration 행에도 같은 결합을 적용해 임계값을 구한다.
- 고정 임계값 0.5는 참고용으로만 보고한다.
- Test 결과로 임계값·목표 FPR·가중치·모델을 다시 고르지 않는다.

## 5. 보고할 지표 (Test-674 주, Test-677 보조, seed별)

- 운영점별: TP, FN, FP, 무작위 정상 FP, Hard benign FP, Recall, Precision, F1, Test FPR, 캠페인 평균 Recall
- calibration FPR과 Test FPR의 차이
- 임계값 무관(진단): ROC-AUC, PR-AUC
- full29 대비 새로 잡은 악성 / 새로 놓친 악성, 캠페인별 TP
- 두 seed의 결과를 각각 보고하고 합치지 않는다(같은 Test 행을 다시 쓴다).

## 6. 참고: 기존 E06·E09 모델 재현 (본 비교 아님)

- `models/D06_E06_package_json_only.txt`, `models/D06_E09_package_json_only_campaign_weight.txt`를 그대로 불러와(`best_iteration` 사용 여부는 저장 모델 기준)
  Test-677에 임계값 0.5를 적용하고, `results/experiments.csv`의 기록(E06 Recall 0.6083 / Precision 0.8859 / F1 0.7213 / PR-AUC 0.8688,
  E09 0.7097 / 0.7979 / 0.7512 / 0.8143)과 같은지 확인한다. 같지 않으면 차이와 원인을 보고하고, 본 비교 결과는 바꾸지 않는다.
- E06·E09는 calibration 데이터가 없어(validation 555행은 early stopping에 사용) 같은 FPR 정책을 적용하지 않는다.

## 7. Test X1 추출 (이 단계에서 수행)

- 추출기: `26-Capstone-Project-Team01/depbee-analyzer` `d56738c234aae239d82729f964b7dd35f304fa93`, `code_context` extractor.
- 절차: `../d06_x1_extraction/extract_x1.py`와 같은 함수(쌍 단위 정적 추출, registry tarball은 sha512/sha1 검증 후 `tarfile` `filter="data"`로 임시 해제,
  악성 archive는 데이터 저장소 `be87ab4c` 별도 부분 사본에서 60쌍씩 sparse checkout). 입력 목록만 Test로 바꾼다(`extract_x1_test.py`).
- 패키지 코드·설치 스크립트를 실행하지 않는다. 추출 실패는 0으로 채우거나 지우지 않고 status=error와 사유를 남기며, 6개 값은 빈 칸(NaN)으로 둔다.
- 병합: Test `test.csv`의 행 순서를 유지하고 키(package, old_version, new_version)로 X1을 붙인 `d06_test_full35.csv`(677행).
  Test-674는 같은 파일에서 제외 3쌍을 키로 걸러 만든다.

## 8. 해석 원칙

- D06 Train outer 결과는 이미 개발에 쓰였다. Test 결과가 outer와 다르면 그 차이를 그대로 보고하고 모델을 바꾸지 않는다.
- Test 악성은 Train에 없는 캠페인(예: mastra-easy-day-js, canisterworm, debug-chalk-duckdb, rspack-vant, @emilgroup/*)으로 구성돼 있어
  "새 캠페인에서의 성능"에 가깝지만, 정상 400 + Hard benign 60으로 표본이 작다. FPR 1%는 Test 정상 기준 약 4~5건이다.

## 변경 이력

(없음)
