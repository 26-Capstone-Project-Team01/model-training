# D06 미탐(False Negative) 분석과 다음 실험 제안 (Train campaign 3-fold CV OOF)

- 범위: 기존 저장 OOF 예측만 분석. 모델 재학습·feature 추출 코드 수정·데이터셋 변경 없음. Train 2,767쌍 밖의 데이터와 그 지표는 읽지도 참조하지도 않음. 모델 비교·제안 근거는 Train campaign CV OOF만 사용.
- 데이터: `be87ab4cf:derived/splits/train.csv` Train 2,767쌍(악성 928 / 정상 1,839 = 무작위 정상 1,600 + hard benign 239)의 campaign 단위 3-fold CV out-of-fold 예측. 공격 흔적 열은 같은 고정 커밋의 `derived/pairs/malicious_pair_groups.csv`(git show).
- 모델: E06(package.json feature 7개), E09(E06 + campaign 가중치 1/√size), E10 α=0.25·0.75(가중치 1/size^α). E10 α=0·0.5는 E06·E09와 pair별 pred·fold가 일치해(스크립트에서 확인) 0.5 고정 성능 CSV에만 남기고 비교에서는 뺐다. 네 모델 모두 난독화 feature 22개는 쓰지 않는다.
- 유형: A = installScriptAdded OR scriptEntryAdded / B = A 아님 AND newDependencyAdded / C = 나머지 (악성 A 734 · B 52 · C 142).
- 운영점: `default_0.5` = 기존 pred(proba ≥ 0.5). 모델마다 FPR이 달라 모델 비교 기준으로 쓰지 않는다. `fpr_1pct`·`fpr_5pct` = `scripts/eval_d06_type_fpr_matched.py`와 같은 규약: 정상 1,839쌍의 OOF 점수를 3 fold 합쳐(pooled) 허용 FP k = floor(목표 FPR × 1,839)(1% → 18, 5% → 91), 임계값 t = (k+1)번째로 높은 정상 점수, 판정 proba > t(동점은 음성).
- 결론(0·4·5절) 기준 운영점: **FPR 5%**. 네 모델의 전체 FP가 같은 상한(≤ 91) 아래에 있어 비교할 수 있고, FPR 1%에서는 네 모델 모두 B·C 악성을 하나도 잡지 못해 B·C의 탐지/미탐 차이를 볼 수 없다. 0.5 고정과 FPR 1% 결과는 1~3절 표와 CSV에 함께 남겼다.

## 0. 요약

- 0.5 고정에서 E09는 E06보다 TP가 156쌍 많지만 전체 FP도 183 vs 47(FPR 10.0% vs 2.6%)로 운영점이 다르다. 같은 FPR 5%에서는 TP 차이가 9쌍(E06 612, E09 621)이다.
- FPR 5%에서 TP가 가장 많은 모델은 E09(621/928, Recall 66.9%), 캠페인 평균 Recall이 가장 높은 모델은 E06(43.9%)다.
- FPR 1%에서 유형 B·C 악성 TP 합: E06 0, E09 0, E10_a0.25 0, E10_a0.75 0. FPR 1%의 탐지는 모두 A 유형에서 나온다.
- FPR 5%의 FP 구성(무작위 정상 / hard benign): E06 39(2.4%) / 49(20.5%), E09 55(3.4%) / 35(14.6%), E10_a0.25 40(2.5%) / 47(19.7%), E10_a0.75 70(4.4%) / 21(8.8%). 같은 전체 FPR이라도 hard benign 비중이 모델마다 다르다.
- FPR 5%에서 E06·E09 공통 미탐은 296쌍(A 124 · B 44 · C 128)이다. 원인과 제안은 4·5절.

## 1. 운영점별 성능 (CV 전체 합산)

| 운영점 | 모델 | 판정 | TP | FN | Recall | 전체 FP (FPR) | 무작위 정상 FP (FPR, /1,600) | hard benign FP (FPR, /239) | 캠페인 평균 Recall |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0.5 고정 | E06 | proba ≥ 0.5000 | 508 | 420 | 54.7% | 47 (2.6%) | 15 (0.9%) | 32 (13.4%) | 29.9% |
| 0.5 고정 | E09 | proba ≥ 0.5000 | 664 | 264 | 71.6% | 183 (10.0%) | 123 (7.7%) | 60 (25.1%) | 42.7% |
| 0.5 고정 | E10_a0.25 | proba ≥ 0.5000 | 630 | 298 | 67.9% | 136 (7.4%) | 76 (4.8%) | 60 (25.1%) | 40.4% |
| 0.5 고정 | E10_a0.75 | proba ≥ 0.5000 | 636 | 292 | 68.5% | 170 (9.2%) | 129 (8.1%) | 41 (17.2%) | 51.0% |
| FPR 1% | E06 | proba > 0.7386 | 222 | 706 | 23.9% | 16 (0.9%) | 0 (0.0%) | 16 (6.7%) | 20.9% |
| FPR 1% | E09 | proba > 0.7945 | 399 | 529 | 43.0% | 18 (1.0%) | 6 (0.4%) | 12 (5.0%) | 24.5% |
| FPR 1% | E10_a0.25 | proba > 0.7902 | 517 | 411 | 55.7% | 17 (0.9%) | 1 (0.1%) | 16 (6.7%) | 24.7% |
| FPR 1% | E10_a0.75 | proba > 0.8684 | 267 | 661 | 28.8% | 17 (0.9%) | 12 (0.8%) | 5 (2.1%) | 4.2% |
| FPR 5% | E06 | proba > 0.4133 | 612 | 316 | 65.9% | 88 (4.8%) | 39 (2.4%) | 49 (20.5%) | 43.9% |
| FPR 5% | E09 | proba > 0.5996 | 621 | 307 | 66.9% | 90 (4.9%) | 55 (3.4%) | 35 (14.6%) | 39.9% |
| FPR 5% | E10_a0.25 | proba > 0.5593 | 611 | 317 | 65.8% | 87 (4.7%) | 40 (2.5%) | 47 (19.7%) | 36.8% |
| FPR 5% | E10_a0.75 | proba > 0.6523 | 513 | 415 | 55.3% | 91 (4.9%) | 70 (4.4%) | 21 (8.8%) | 27.8% |

- 검증: 모든 모델 x 운영점(0.5 고정, FPR 1%, FPR 5%)의 임계값·판정식·TP·FP·무작위 정상 FP·hard benign FP·유형별 TP·캠페인별 탐지 수가 `results/type_fpr/d06_type_fpr_matched.csv`·`d06_type_fpr_matched_campaign_recall.csv`와 같음. 0.5 고정의 fold별 TP·FN·FP·TN은 기존 fold 집계(`results/cv`, `results/e10`)와 같다.
- 캠페인 평균 Recall은 악성 campaign(splitGroup) 19개의 캠페인별 Recall 단순 평균이다.
- fold별 값·fold 평균·Precision은 `d06_fn_performance_cv.csv`에 있다. fold 구성: fold 0 = sha1-hulud-second-coming_2025-11; fold 1 = 10개 캠페인; fold 2 = 9개 캠페인. fold 0은 `sha1-hulud-second-coming_2025-11` 한 캠페인(332쌍)뿐이다.
- FPR 운영점의 임계값은 평가에 쓴 정상 1,839쌍으로 직접 정했으므로 달성 FPR은 그 표본에서의 값이다(별도 검증셋 아님).

## 2. 유형별·캠페인별 Recall

### 2-1. 유형별 Recall (FN)

| 운영점 | 유형 | n | E06 | E09 | E10_a0.25 | E10_a0.75 |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 0.5 고정 | A | 734 | 68.9% (228) | 84.1% (117) | 83.2% (123) | 79.4% (151) |
| 0.5 고정 | B | 52 | 0.0% (52) | 25.0% (39) | 3.8% (50) | 34.6% (34) |
| 0.5 고정 | C | 142 | 1.4% (140) | 23.9% (108) | 12.0% (125) | 24.6% (107) |
| FPR 1% | A | 734 | 30.2% (512) | 54.4% (335) | 70.4% (217) | 36.4% (467) |
| FPR 1% | B | 52 | 0.0% (52) | 0.0% (52) | 0.0% (52) | 0.0% (52) |
| FPR 1% | C | 142 | 0.0% (142) | 0.0% (142) | 0.0% (142) | 0.0% (142) |
| FPR 5% | A | 734 | 82.2% (131) | 82.4% (129) | 82.7% (127) | 65.4% (254) |
| FPR 5% | B | 52 | 11.5% (46) | 5.8% (49) | 0.0% (52) | 25.0% (39) |
| FPR 5% | C | 142 | 2.1% (139) | 9.2% (129) | 2.8% (138) | 14.1% (122) |

### 2-2. 캠페인별 Recall (FN), 0.5 고정

| 캠페인 | n | fold | E06 | E09 | E10_a0.25 | E10_a0.75 |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| sha1-hulud-second-coming_2025-11 | 332 | 0 | 69.3% (102) | 98.2% (6) | 98.2% (6) | 91.3% (29) |
| mini-shai-hulud_2026-05 | 198 | 1 | 48.5% (102) | 56.6% (86) | 49.5% (100) | 51.0% (97) |
| shai-hulud-original_2025-09 | 186 | 2 | 71.5% (53) | 74.2% (48) | 71.5% (53) | 75.3% (46) |
| individuals_case | 50 | 1,2 | 6.0% (47) | 52.0% (24) | 28.0% (36) | 66.0% (17) |
| autotel-node-env-resolver_2026-06 | 29 | 2 | 6.9% (27) | 13.8% (25) | 6.9% (27) | 13.8% (25) |
| miasma_2026-06 | 26 | 2 | 0.0% (26) | 3.8% (25) | 0.0% (26) | 3.8% (25) |
| chaindrop_2026-08 | 25 | 1 | 96.0% (1) | 96.0% (1) | 96.0% (1) | 92.0% (2) |
| react-native-aria-gluestack_2025-06 | 17 | 1 | 0.0% (17) | 17.6% (14) | 17.6% (14) | 17.6% (14) |
| injective_2026-07 | 12 | 1 | 0.0% (12) | 0.0% (12) | 0.0% (12) | 0.0% (12) |
| pgserve-automagik-openwebconcept_2026-04 | 10 | 2 | 20.0% (8) | 20.0% (8) | 20.0% (8) | 20.0% (8) |
| toptal-xene_2025-07 | 10 | 1 | 50.0% (5) | 80.0% (2) | 80.0% (2) | 50.0% (5) |
| js-metrics_2018 | 9 | 2 | 0.0% (9) | 0.0% (9) | 0.0% (9) | 0.0% (9) |
| node-gyp-dll_2025-07 | 9 | 1 | 100.0% (0) | 100.0% (0) | 100.0% (0) | 88.9% (1) |
| nx-s1ngularity_2025-08 | 7 | 2 | 0.0% (7) | 100.0% (0) | 100.0% (0) | 100.0% (0) |
| sap-maintainer-compromise | 4 | 1 | 100.0% (0) | 100.0% (0) | 100.0% (0) | 100.0% (0) |
| axios_2026-03 | 1 | 2 | 0.0% (1) | 0.0% (1) | 0.0% (1) | 100.0% (0) |
| bitwarden-cli_2026-04 | 1 | 1 | 0.0% (1) | 0.0% (1) | 0.0% (1) | 0.0% (1) |
| miasma-leoplatform_2026-06 | 1 | 2 | 0.0% (1) | 0.0% (1) | 0.0% (1) | 100.0% (0) |
| solana-web3js_2024-12 | 1 | 1 | 0.0% (1) | 0.0% (1) | 0.0% (1) | 0.0% (1) |

### 2-2. 캠페인별 Recall (FN), FPR 1%

| 캠페인 | n | fold | E06 | E09 | E10_a0.25 | E10_a0.75 |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| sha1-hulud-second-coming_2025-11 | 332 | 0 | 0.0% (332) | 84.9% (50) | 92.8% (24) | 80.4% (65) |
| mini-shai-hulud_2026-05 | 198 | 1 | 48.0% (103) | 37.4% (124) | 44.4% (110) | 0.0% (198) |
| shai-hulud-original_2025-09 | 186 | 2 | 46.8% (99) | 0.0% (186) | 44.6% (103) | 0.0% (186) |
| individuals_case | 50 | 1,2 | 6.0% (47) | 4.0% (48) | 6.0% (47) | 0.0% (50) |
| autotel-node-env-resolver_2026-06 | 29 | 2 | 0.0% (29) | 0.0% (29) | 0.0% (29) | 0.0% (29) |
| miasma_2026-06 | 26 | 2 | 0.0% (26) | 0.0% (26) | 0.0% (26) | 0.0% (26) |
| chaindrop_2026-08 | 25 | 1 | 96.0% (1) | 92.0% (2) | 92.0% (2) | 0.0% (25) |
| react-native-aria-gluestack_2025-06 | 17 | 1 | 0.0% (17) | 0.0% (17) | 0.0% (17) | 0.0% (17) |
| injective_2026-07 | 12 | 1 | 0.0% (12) | 0.0% (12) | 0.0% (12) | 0.0% (12) |
| pgserve-automagik-openwebconcept_2026-04 | 10 | 2 | 0.0% (10) | 0.0% (10) | 0.0% (10) | 0.0% (10) |
| toptal-xene_2025-07 | 10 | 1 | 0.0% (10) | 70.0% (3) | 0.0% (10) | 0.0% (10) |
| js-metrics_2018 | 9 | 2 | 0.0% (9) | 0.0% (9) | 0.0% (9) | 0.0% (9) |
| node-gyp-dll_2025-07 | 9 | 1 | 100.0% (0) | 77.8% (2) | 88.9% (1) | 0.0% (9) |
| nx-s1ngularity_2025-08 | 7 | 2 | 0.0% (7) | 0.0% (7) | 0.0% (7) | 0.0% (7) |
| sap-maintainer-compromise | 4 | 1 | 100.0% (0) | 100.0% (0) | 100.0% (0) | 0.0% (4) |
| axios_2026-03 | 1 | 2 | 0.0% (1) | 0.0% (1) | 0.0% (1) | 0.0% (1) |
| bitwarden-cli_2026-04 | 1 | 1 | 0.0% (1) | 0.0% (1) | 0.0% (1) | 0.0% (1) |
| miasma-leoplatform_2026-06 | 1 | 2 | 0.0% (1) | 0.0% (1) | 0.0% (1) | 0.0% (1) |
| solana-web3js_2024-12 | 1 | 1 | 0.0% (1) | 0.0% (1) | 0.0% (1) | 0.0% (1) |

pooled 기준, 임계값 방식에 민감하다(6절: fold별 임계값이면 FPR 1% TP와 캠페인별 Recall이 크게 달라진다).

### 2-2. 캠페인별 Recall (FN), FPR 5%

| 캠페인 | n | fold | E06 | E09 | E10_a0.25 | E10_a0.75 |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| sha1-hulud-second-coming_2025-11 | 332 | 0 | 97.6% (8) | 97.6% (8) | 98.2% (6) | 88.3% (39) |
| mini-shai-hulud_2026-05 | 198 | 1 | 49.0% (101) | 49.5% (100) | 48.0% (103) | 36.9% (125) |
| shai-hulud-original_2025-09 | 186 | 2 | 71.5% (53) | 69.4% (57) | 71.5% (53) | 51.1% (91) |
| individuals_case | 50 | 1,2 | 14.0% (43) | 22.0% (39) | 8.0% (46) | 38.0% (31) |
| autotel-node-env-resolver_2026-06 | 29 | 2 | 6.9% (27) | 6.9% (27) | 6.9% (27) | 6.9% (27) |
| miasma_2026-06 | 26 | 2 | 0.0% (26) | 0.0% (26) | 0.0% (26) | 0.0% (26) |
| chaindrop_2026-08 | 25 | 1 | 96.0% (1) | 96.0% (1) | 96.0% (1) | 32.0% (17) |
| react-native-aria-gluestack_2025-06 | 17 | 1 | 0.0% (17) | 17.6% (14) | 0.0% (17) | 17.6% (14) |
| injective_2026-07 | 12 | 1 | 0.0% (12) | 0.0% (12) | 0.0% (12) | 0.0% (12) |
| pgserve-automagik-openwebconcept_2026-04 | 10 | 2 | 20.0% (8) | 20.0% (8) | 20.0% (8) | 20.0% (8) |
| toptal-xene_2025-07 | 10 | 1 | 80.0% (2) | 80.0% (2) | 50.0% (5) | 50.0% (5) |
| js-metrics_2018 | 9 | 2 | 0.0% (9) | 0.0% (9) | 0.0% (9) | 0.0% (9) |
| node-gyp-dll_2025-07 | 9 | 1 | 100.0% (0) | 100.0% (0) | 100.0% (0) | 66.7% (3) |
| nx-s1ngularity_2025-08 | 7 | 2 | 0.0% (7) | 100.0% (0) | 100.0% (0) | 71.4% (2) |
| sap-maintainer-compromise | 4 | 1 | 100.0% (0) | 100.0% (0) | 100.0% (0) | 50.0% (2) |
| axios_2026-03 | 1 | 2 | 100.0% (0) | 0.0% (1) | 0.0% (1) | 0.0% (1) |
| bitwarden-cli_2026-04 | 1 | 1 | 0.0% (1) | 0.0% (1) | 0.0% (1) | 0.0% (1) |
| miasma-leoplatform_2026-06 | 1 | 2 | 100.0% (0) | 0.0% (1) | 0.0% (1) | 0.0% (1) |
| solana-web3js_2024-12 | 1 | 1 | 0.0% (1) | 0.0% (1) | 0.0% (1) | 0.0% (1) |

캠페인×유형·fold별 분해는 `d06_fn_summary_by_type_campaign.csv`에 있다.

## 3. 미탐 악성 비교

| 구분 | 0.5 고정 | FPR 1% | FPR 5% |
| --- | ---: | ---: | ---: |
| E06 미탐 전체 | 420 | 706 | 316 |
| E09 미탐 전체 | 264 | 529 | 307 |
| E06·E09 공통 미탐 | 264 | 417 | 296 |
| E06 미탐 · E09 탐지 | 156 | 289 | 20 |
| E06 탐지 · E09 미탐 | 0 | 112 | 11 |

0.5 고정의 공통 미탐 264쌍·E09 추가 탐지 156쌍은 이전 보고와 같다(스크립트에서 확인). 0.5 고정에서는 E09의 미탐이 E06 미탐의 부분집합이다. 같은 FPR에서는 두 모델이 서로 다른 pair를 놓친다(E06 탐지 · E09 미탐 행).

| 운영점 | E10 | 미탐 | 그중 E06·E09 공통 미탐 | 공통 미탐 중 새로 탐지 | E09가 잡았는데 놓침 |
| --- | --- | ---: | ---: | ---: | ---: |
| 0.5 고정 | E10_a0.25 | 298 | 263 | 1 | 35 |
| 0.5 고정 | E10_a0.75 | 292 | 251 | 13 | 41 |
| FPR 1% | E10_a0.25 | 411 | 391 | 26 | 7 |
| FPR 1% | E10_a0.75 | 661 | 417 | 0 | 132 |
| FPR 5% | E10_a0.25 | 317 | 294 | 2 | 17 |
| FPR 5% | E10_a0.75 | 415 | 275 | 21 | 129 |

pair별 목록(운영점별, 모델별 확률·판정, feature, 공격 흔적)은 `d06_fn_samples.csv`에 있다.

## 4. 미탐 원인 (FPR 5% 기준)

### 4-1. 데이터로 확인된 사실

- 공통 미탐 296쌍의 유형: A 124 · B 44 · C 128. 유형별 Recall(E06 / E09): A 82.2% / 82.4%, B 11.5% / 5.8%, C 2.1% / 9.2%(2-1).
- **package.json feature만으로는 구별 정보가 부족한 pair가 전부다.** 공통 미탐 296쌍 중 296쌍은 이산 package.json feature 6개(설치 스크립트 3종, 새 의존성 여부·개수, updateType)가 완전히 같은 정상 pair가 있다. 남은 구별 수단은 updateInterval뿐인데, 같은 값의 정상 중 updateInterval이 그 악성 이상인 비율의 중앙값이 A 0.40, B 0.64, C 0.16이다. 즉 updateInterval 임계값으로 이 악성을 잡으려 하면 같은 모양의 정상도 그만큼 함께 걸린다.
- **A 유형**: 두 모델이 모두 잡은 A의 updateInterval 중앙값은 222일, patch 비율 98.7%, 새 의존성 비율 0.0%다. 함께 놓친 A는 updateInterval 중앙값 13.5일, patch 58.1%, 새 의존성 41.1%이고, A 유형 hard benign은 중앙값 5.0일, patch 56.1%, 새 의존성 29.5%다.
- **B 유형**: 놓친 B는 patch 95.5%, 새 의존성 평균 1.00개, updateInterval 중앙값 5.9일이고, B 유형 무작위 정상은 patch 46.8%, 평균 1.65개, 중앙값 29.8일이다.
- **C 유형**: 놓친 C는 설치 스크립트·새 의존성 변화가 없고 patch 99.2%, updateInterval 중앙값 74.4일이다. 한 모델이라도 잡은 C의 수와 updateInterval 중앙값: malicious_detected_both 2쌍(88일), malicious_E09_only 11쌍(598일), malicious_E06_only 1쌍(190일).
- **모델 설정(코드로 확인)**: 기본 LightGBM(`objective=binary`), 클래스 가중치 없음(E06), 학습·기존 보고의 판정 임계값 0.5, early stopping을 평가 fold 자체로 수행(`scripts/run_cv_e06_e09.py` docstring의 'Approach A' 주의). 저장된 feature importance는 split 횟수이며 E06·E09 모두 updateInterval이 압도적 1위다(`results/feature_importance/`). fold별 best_iteration은 E06 3/25/11, E09 23/20/11, E10_a0.25 30/22/12, E10_a0.75 78/16/10.
- **캠페인 집중**: 공통 미탐의 캠페인 상위는 `mini-shai-hulud_2026-05` 99, `shai-hulud-original_2025-09` 53, `individuals_case` 35, `autotel-node-env-resolver_2026-06` 27, `miasma_2026-06` 26, `react-native-aria-gluestack_2025-06` 14이다. CV가 campaign 단위라 공유 공격 캠페인은 fold 사이에서 분리되고, 학습에 한 번도 쓰이지 않은 fold에서 평가된다(새 캠페인 일반화 문제). 예외로 `individuals_case`(fold 1,2)는 독립 사건을 모은 보고용 묶음이라 여러 fold에 걸친다(`scripts/run_cv_e06_e09.py`의 `is_shared_attack_split_group` 참고). 따라서 이 묶음의 Recall은 leave-campaign-out 검증 결과로 읽지 않는다.
- **모델이 쓰는 feature 중 AUC를 잰 수치형 2개(updateInterval, newDependencyCount)는 이 미탐들을 약하게만 구별한다.** 공통 미탐 vs 같은 유형 정상의 단변량 AUC(0.5 = 구별 불가, 범위 0.39~0.66): A: `newDependencyCount` 0.58, `updateInterval` 0.51; B: `updateInterval` 0.39, `newDependencyCount` 0.40; C: `updateInterval` 0.66, `newDependencyCount` 0.50.
- **쓰지 않은 난독화 feature에는 구별 정보가 있다.** E06·E09·E10은 난독화 feature 22개를 쓰지 않는다. 같은 비교의 AUC 상위는 A: `obfWhitespaceRatioChangedCode` 0.05(캠페인 균등 0.06), `obfBracketAccessRatioChangedCode` 0.93(캠페인 균등 0.82), `obfWhitespaceRatioNew` 0.07(캠페인 균등 0.10); B: `obfBracketAccessRatioChangedCode` 0.98(캠페인 균등 1.00), `obfHexIdentRatioChangedCode` 0.98(캠페인 균등 0.99), `obfHexNumberRatioChangedCode` 0.97(캠페인 균등 0.99); C: `obfWhitespaceRatioNew` 0.19(캠페인 균등 0.23), `obfWhitespaceRatioChangedCode` 0.20(캠페인 균등 0.22), `obfMeanIdentLengthChangedCode` 0.20(캠페인 균등 0.31). 상위 8개의 평균 |AUC−0.5|는 pooled→캠페인 균등으로 A 0.40→0.35, B 0.46→0.47, C 0.28→0.24다. 캠페인 균등 값은 미탐이 3쌍 이상인 캠페인 A 4개, B 1개, C 7개로만 계산했다.
- **변경 JS가 있는지 자체도 다르다.** 변경 JS가 없어 ChangedCode feature가 결측인 비율은 같은 유형 정상 A 18.5%, B 14.4%, C 40.6%, 공통 미탐 A 2.4%, B 4.5%, C 9.4%이다.
- **난독화 feature를 모두 넣은 모델의 일반화는 근거 없음(미검증).** 29개 feature를 모두 쓴 D06-E00은 Train campaign CV 결과가 없다(`results/cv`·`results/e10`에는 E06·E09·E10만 있다). 이 분석에서는 E00의 일반화 여부를 판단하지 않는다.
- **공격 흔적(데이터 저장소 `derived/pairs/malicious_pair_groups.csv`, 고정 커밋)**:
  - `mini-shai-hulud_2026-05`(악성 198쌍, fold 1): E09가 놓친 pair의 추가 install hook은 `preinstall=bun run index.js` 46, `preinstall=node setup.mjs` 11, 잡은 pair는 `preinstall=node setup.mjs` 78, `preinstall=node index.js` 16, `preinstall=node opensearch.mjs` 1이다. 모델은 hook이 추가됐는지(bool)만 보고 명령 내용은 보지 않는다.
  - 공통 미탐 A 124쌍의 추가 install hook 상위: `preinstall=bun run index.js` 46, `postinstall=node bundle.js` 33.
  - E09가 놓친 B 유형 49쌍의 추가 의존성: `@tanstack/setup` 40, `@opensearch/setup` 2, `@antv/setup` 1. 모델은 의존성 추가 여부·개수만 보고 이름·출처·새로 생긴 패키지인지는 보지 않는다.
  - `injective_2026-07` 12쌍 중 11쌍은 변경된 JS 파일이 없다(그중 E09 미탐 11쌍).
  - 공통 미탐 C 128쌍 중 변경 JS 파일이 1개인 비율은 70.3%이고, 상위 캠페인에서 `largestChangedJsSha1`(가장 큰 변경 JS 파일 전체의 해시) 고유값 수는 `individuals_case` 34/35, `autotel-node-env-resolver_2026-06` 27/27, `miasma_2026-06` 26/26로, 이 열의 파일 전체 해시는 대부분 pair마다 다르다. 주입된 payload 자체나 다른 변경 파일의 해시가 재사용되는지는 이 열만으로 알 수 없어 미검증이다.

### 4-2. 추정(검증되지 않은 원인 가설)

아래는 4-1의 사실에서 귀납적으로 추론한 가설이며, 확인하려면 4-1 밖의 실험이 필요하다.

- **H1. 모델이 '설치 스크립트 추가 + 긴 배포 간격'이라는 지름길을 학습했다.** 근거: 4-1의 A 유형 프로필(잡힌 A와 놓친 A의 updateInterval 차이)과 split importance의 updateInterval 독주. baseline 규칙 설계도 updateInterval을 통한 label 누수를 경계한다(`be87ab4cf:derived/pairs/baseline_rule.py` L21-24: 악성 직전 후보를 날짜 경계로 일괄 제외하면 정상 hotfix까지 빠져 악성 baseline만 체계적으로 오래되고 updateInterval로 label이 누수되므로, 일괄 제외 대신 clean 검증을 쓴다). worm처럼 짧은 간격으로 연속 배포하는 공격은 이 지름길에서 벗어나 미탐될 것으로 추정한다.
- **H2. E06·E09·E10의 미탐은 주로 입력 정보 부족 때문이다(7개 package.json feature 기준).** 근거: 공통 미탐 대부분이 이산 feature가 같은 정상 pair를 갖고, 모델이 쓰는 feature 중 AUC를 잰 수치형 2개(updateInterval, newDependencyCount)의 AUC가 0.39~0.66으로 약하다. 이 경우 가중치·임계값 조정만으로는 같은 모양의 정상을 함께 오탐하지 않고 Recall을 크게 올리기 어렵다. 0.5 고정에서 E09가 더 잡은 pair 상당수가 같은 FPR에서는 차이로 남지 않는 것(0절: TP 차이 156 → 9)도 이와 맞는다.
- **H3. 필요한 정보의 일부는 이미 train.csv에 있다(난독화 feature).** 근거: 캠페인 균등으로 봐도 분리도가 남고 변경 JS 유무도 다르다. 모두 넣었을 때 캠페인별 값에 과적합하는지는 campaign CV 근거가 없어 미검증이다. 이를 가르려면 일부 feature만 campaign CV로 넣어 보는 실험이 필요하다.
- **H4. CV 수치의 변동은 fold 구성과 운영점에 크게 좌우된다.** fold 0이 단일 캠페인(`sha1-hulud-second-coming_2025-11`)이라 fold 평균에서 이 캠페인이 1/3 비중을 갖는다. E09가 E06보다 더 잡은 pair 중 이 캠페인은 0.5 고정에서 96/156쌍, FPR 5%에서 0/20쌍이다. early stopping이 평가 fold를 보므로 CV 수치는 낙관적일 수 있다.
- **H5. 공격의 실체 정보(hook이 실행하는 파일의 내용, 추가된 의존성의 정체, 주입된 코드의 동작)는 현재 어떤 feature에도 직접 없다.** 근거: 4-1의 공격 흔적. 난독화 비율은 코드의 '모양'만 보므로, 난독화하지 않은 악성 코드에는 신호가 약할 것으로 추정한다.

## 5. 다음 실험 제안(같은 FPR에서 Recall↑ · FN↓ 우선)

근거 수치는 모두 Train campaign CV OOF, FPR 5% 기준이다. 기대 효과는 방향만 적었고 개선 폭은 예측하지 않는다. 효과 확인도 같은 CV·같은 FPR(1%, 5%)·유형별·캠페인별 Recall과 무작위 정상/hard benign FPR 분리로 한다.

| 우선순위 | 개선 방법 | 해결하려는 미탐 문제 | 기대 효과 | 근거 |
| --- | --- | --- | --- | --- |
| 1 | **기존 난독화 feature 일부를 package.json 모델에 다시 넣고 campaign CV로 평가**: 변경 JS 유무(obfChangedFileCount>0)와 분리도가 캠페인 균등으로도 남은 ChangedCode 비율 몇 개(공백·대괄호 접근·짧은 식별자·16진수). feature 추출 변경 없이 바로 가능 | A·B·C 전반, 특히 package.json 값이 정상과 같은 공통 미탐 | 모델 입력에 미탐을 구별할 정보를 처음으로 넣음 | 4-1의 AUC (AUC를 잰 수치형 2개(updateInterval, newDependencyCount) 0.39~0.66 vs 난독화 feature 상위), 변경 JS 결측 비율 차이. 29개 전부 넣은 E00은 campaign CV 근거 없음(미검증) |
| 2 | **변경·추가된 JS 코드의 행위(API) feature 추가**: 새로 생긴 `child_process`·`eval`/`Function`·네트워크(`http(s)`, `fetch`, `dns`)·환경변수/자격증명 파일 접근·base64 디코드, 그리고 install hook이 이번에 추가·변경된 파일을 실행하는지 | C 유형 미탐(공통 128: hook·의존성 없이 JS에 코드 주입)과 A 유형 미탐(공통 124) | 난독화 여부와 상관없이 악성 '행위'에 직접 신호 | 공통 미탐 C의 변경 JS 1개 비율 70.3%, 가장 큰 변경 JS 파일 전체 해시가 대부분 pair마다 다름(payload 자체 해시 재사용은 미검증), 공통 미탐 A의 hook 상위 `preinstall=bun run index.js`, `postinstall=node bundle.js` |
| 3 | **추가된 의존성 정체 feature 추가**: 새 의존성 패키지가 업데이트 직전에 처음 publish됐는지, 그 의존성의 install script 여부, 버전 지정이 URL/git/tarball인지 | B 유형 미탐(E09 기준 49)과 의존성을 동반한 A 미탐 | 의존성 추가 '여부'가 같은 정상 B와 구별 | E09가 놓친 B의 추가 의존성 상위: `@tanstack/setup` 40 |
| 4 | **LightGBM 학습 방식 보완**: early stopping을 학습 fold 내부 검증으로 분리, `scale_pos_weight`/class weight로 Recall 우선, Recall 목표 임계값을 학습 fold에서 정함 | 전반 | CV 수치의 낙관 편향 제거, Recall 우선 운영점 | 4-1 모델 설정, best_iteration 3~78 |
| 5 | **updateInterval 의존 점검(E04를 같은 CV로)**: updateInterval 제거·구간화 | 지름길 학습으로 짧은 간격 공격을 놓치는 문제 | 1~3의 feature가 실제로 쓰이는지 보는 기준선 | H1. D06-E04는 campaign CV 결과가 없다 |
| 6 | **유형·캠페인 가중치**: E10 α를 유형 단위로 확장(B·C 악성 가중 ↑) | B·C 미탐 | 소수 유형의 학습 신호 확대 | FPR 5%에서 α=0/0.25/0.5/0.75의 B TP 6/0/3/13, C TP 3/4/13/20, `sha1-hulud-second-coming_2025-11` FN 8/6/8/39(2-1, 2-2). pooled 기준, 임계값 방식에 민감(6절) |
| 7 | **캠페인 편향 대응**: 단일 캠페인 fold가 생기지 않게 fold 구성, 캠페인 평균 Recall 병기 | 평가 편향 | 개선 여부 판단의 신뢰도 | fold 0 = 단일 캠페인(H4) |

1은 기존 feature만 쓰므로 이번 제약(feature 추출 변경 없음) 안에서 다음 실험으로 바로 할 수 있다. 2·3은 feature 추출 코드 변경이 필요하다. H2가 맞다면 4~7만으로는 개선 폭이 제한될 수 있다.

## 6. 한계

- 모든 수치는 Train campaign CV OOF 기준이다. 최종 일반화 성능 추정이 아니다.
- FPR 운영점의 임계값은 3 fold의 OOF 점수를 합쳐 하나로 정했고, 같은 정상 1,839쌍에서 달성 FPR을 쟀다. 결과는 임계값 방식에 민감하다. fold별로 같은 규약의 임계값을 쓰면 FPR 1% TP가 E06 222→534, E09 399→506, E10_a0.25 517→543, E10_a0.75 267→365로 달라지고(E06 fold 0 sha1-hulud 0→324), FPR 5% 전체 TP 순서는 같지만 B·C TP는 바뀐다(예: E10_a0.75 B 13→3). 이 수치는 Revy 검증 값으로, 저장 OOF로 별도 계산했으며 이 스크립트는 계산하지 않는다.
- CV는 early stopping에 평가 fold를 쓰므로 수치가 낙관적일 수 있다(`scripts/run_cv_e06_e09.py`).
- 단변량 AUC는 feature 하나씩 본 값이라, 모델에 넣었을 때의 효과를 보장하지 않는다.
- 공격 흔적 열은 데이터 저장소의 `malicious_pair_groups.csv`(고정 커밋)에서 가져왔다.
- 4-2의 원인과 5의 효과는 가설이며, 실험으로 확인해야 한다.

## 출력 파일

- `results/fn_analysis/d06_fn_performance_cv.csv`
- `results/fn_analysis/d06_fn_samples.csv`
- `results/fn_analysis/d06_fn_summary_by_type_campaign.csv`
- `results/fn_analysis/d06_fn_feature_profile.csv`
- `results/fn_analysis/d06_fn_feature_separability.csv`

재현: `python scripts/analyze_d06_false_negatives.py --data-clone <npm-malware-package-pairs 클론 경로>`
