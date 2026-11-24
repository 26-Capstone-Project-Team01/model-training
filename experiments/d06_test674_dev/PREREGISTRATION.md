# D06 Test-674 개발 평가 사전 등록 (2026-11-24, 실행 전 작성)

**성격: 개발 평가(development evaluation).** Test-674는 이전에 여러 번 분석했다(Test 평가, 원인 분석, ES, X2 검토, X4 값 진단).
따라서 이 결과는 독립적인 최종 일반화 성능이 아니다. 결과를 보고 후보·Feature·임계값·가중치를 바꾸거나 다시 고르지 않는다.

## 1. 학습·결정 프로토콜 (기존 `../d06_test_eval` 그대로)

- Train 2,767쌍 → PR #13 `inner_split(data, seed)`로 fit / calibration (seed 20261109, 20261110 두 개, 둘 다 보고).
  fit·calibration 행 집합은 `../d06_test_eval/run/splits.csv`와 같아야 한다(검사).
- 모델은 fit에서만 학습. LightGBM은 PR #13 파라미터, 200 rounds, early stopping·가중치 없음.
- 임계값: calibration 점수로 PR #13 `calibrate`(ML 정책), 목표 FPR 1%, 3%, 5%.
- 블렌드 가중치: calibration 행에서만 고른다. 후보·규칙은 Train 개발 평가(`../d06_alt_models/blend.py`, `../d06_x4_rel_update/blend_x4.py`)와 같다:
  척도 prob|logit, 2모델 0.1 간격, 3모델 0.1 단체 격자, calibration PR-AUC 최대, 동률이면 기준 모델 가중치가 큰 쪽 → prob.
- Test-674 = Test-677에서 vant 4.9.11→4.9.12/13/14 3쌍 제외(기존과 같음). 점수는 677쌍에 계산하되 지표는 674쌍만 보고한다.
- 패키지 코드는 실행하지 않는다. 새 Feature 추출은 없다(이미 확보한 Feature만).

## 2. 후보 (고정)

| 후보 | Feature | 모델 | 처리 |
|---|---|---|---|
| full35 | 35 | LightGBM | 기존 Test 점수 재사용(`../d06_test_eval/run/scores.csv`), 같은 코드 재학습으로 재현 가드 |
| base7_x1 | base7 + X1 (13) | LightGBM | 신규 학습 |
| full35_lr / full35_rf / full35_mlp | 35 | LR / RF / MLP | 신규 학습, 하이퍼파라미터·전처리는 `../d06_alt_models/alt_models.py` 그대로 |
| gs24 | base7 + obfChange + obfChangedCode + x1Calls (24) | LightGBM | 신규 학습 (Train calibration 조합 탐색에서 고른 묶음 그대로) |
| B1 / B2 / B3 | full35 + LR / + MLP / + LR + MLP | 블렌드 | 이 프로토콜의 calibration에서 가중치 선택 |
| full35_x4 | 35 + X4 (37) | LightGBM | 신규 학습 |
| full34_x4 | 35 − updateInterval + X4 (36) | LightGBM | 신규 학습 |
| B3x_full35_x4, B3x_full34_x4 | X4 모델 + LR + MLP | 블렌드 | calibration에서 가중치 선택. 둘 다 보고하고, calibration PR-AUC가 높은 X4 기준 모델 쪽을 "X4 블렌드 대표"로 표시 |

X4 값: Train `../d06_x4_rel_update/run/d06_x4.csv`, Test `../d06_x4_rel_update/test_diag/test674_x4.csv`(같은 `x4.py` 정의, registry time 맵).
Test vant 3쌍은 X4가 없어 NaN으로 두며 지표에 포함되지 않는다.

## 3. 지표 (Test-674, seed별, 목표 FPR 1/3/5%)

전체 Recall, mastra(`mastra-easy-day-js_2026-06`, 119쌍) Recall, mastra 제외 Recall, 전체 FPR, Hard benign FPR, PR-AUC(임계값 무관), 캠페인별 Recall.
보조: TP·FP·HB FP 수, calibration FPR 대비 Test FPR 차이.

## 4. 해석 규칙

- X4가 mastra 미탐을 개선했다고 말하려면, 두 seed 모두에서 full35_x4 또는 full34_x4의 mastra Recall이 full35보다 높아야 한다(같은 목표 FPR).
- 한 seed에서만 좋아지면 "근거 부족"으로 쓴다. Test 결과로 최종 후보(B3)를 바꾸지 않는다. 바꾸려면 새 독립 데이터나 새 사전 등록이 필요하다.
