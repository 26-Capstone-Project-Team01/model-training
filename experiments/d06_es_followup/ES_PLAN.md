# Early stopping 실험 계획 (실행 전 기록)

작성: 2026-11-24, 실행 전. **이미 평가한 D06 Test를 다시 쓰는 사후 개발 실험이다**(사전 등록 평가 아님). Test 결과로 트리 수·조건을 고르지 않는다.

## 대상과 고정 조건
- 모델: `base7`(package.json 7개), `full35`(29개 + X1 6개). 가중치 없음.
- Fit / Calibration: `../d06_test_eval/run/splits.csv`의 seed20261109·seed20261110 배정을 그대로 쓴다(실행 시 일치 검사).
- LightGBM: PR #13 파라미터(`objective=binary, metric=binary_logloss, verbosity=-1, num_threads=2, deterministic=true, force_col_wise=true, seed=20261109`).

## Validation 분할 (Fit 안에서만)
- PR #13 스냅샷 `inner_split(fit, seed)`를 Fit 행에만 적용해 component 단위 Sub-fit / Validation(클래스별 약 25%)으로 나눈다. seed는 각 split의 seed 값(20261109 / 20261110)을 그대로 쓴다.
- `check_disjoint(sub_fit, validation)`으로 component·package·payload 해시·실제 캠페인 겹침 0 확인. Calibration·Test 행은 쓰지 않는다.
- Validation 구성(클래스·캠페인)을 기록한다.

## Early stopping
- Sub-fit으로 학습, Validation `binary_logloss` 감시, 최대 200 rounds, `early_stopping(stopping_rounds=50, first_metric_only=True)`.
- 결정 트리 수 B = `best_iteration`(Validation logloss가 가장 낮은 반복). B가 0이면(개선 없음) 1로 둔다.
- 재학습: 같은 파라미터로 **Fit 전체**에서 `num_boost_round = B`, early stopping 없음.

## 평가
- 임계값: 기존 Calibration에서 목표 FPR 5%(주), 1%·3%(보조), 0.5(참고). PR #13 `calibrate`(ML).
- Test-674(주)·Test-677(보조): Recall, TP, FP, Test FPR, Hard benign FP, PR-AUC, ROC-AUC, 캠페인별 Recall.
- 비교 대상: `../d06_test_eval`의 200 rounds base7·full35(저장 점수), 그리고 같은 B의 트리 prefix 진단값(`../d06_test_followup/run/prefix_metrics.csv`에 B가 없으면 비교하지 않음).
