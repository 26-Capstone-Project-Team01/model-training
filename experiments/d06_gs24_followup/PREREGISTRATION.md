# D06 gs24 후속 탐색 실험 사전 등록 (2026-11-24, 실행 전 작성)

**성격: Test-674 개발 평가(`../d06_test674_dev/RESULTS.md`)의 관찰을 바탕으로 제안한 후속 탐색 실험.**
gs24가 Test-674에서 높게 나온 것을 보고 시작했으므로, 이 실험의 Test-674 결과는 그 관찰에 대해 독립적이지 않다. 최종 성능은 독립 데이터로 검증해야 한다.
Test 결과에 맞춰 가중치·임계값·후보를 조정하지 않는다. 설계 판단은 Train 외부 평가로 한다.

## 1. 두 평가 프로토콜 (둘 다 기존 그대로)

- **Train 외부(설계 근거)**: PR #13 component 외부 3-fold × 2 split, 내부 `inner_split(seed+fold)` fit/calibration (`../d06_full35_compare/run_full35.py`).
- **Test-674(개발 관찰)**: Train 전체 `inner_split(seed)` fit/calibration, seed 20261109·20261110 (`../d06_test_eval`, `../d06_test674_dev`).
- LightGBM: PR #13 파라미터, 200 rounds, 가중치·early stopping 없음. 임계값: calibration 점수로 PR #13 `calibrate`(ML), 목표 FPR 1·3·5%.
- 조합 가중치·선택은 **calibration 행에서만** 한다.

## 2. 원인 확인 조합 (LightGBM)

| 이름 | Feature | 처리 |
|---|---|---|
| full35 | 35 | 재사용 (Train 외부: `../d06_full35_compare/run`, Test: `../d06_test_eval/run`) |
| full28_noObfNew | full35 − obfNew 7 | 신규 학습 (두 프로토콜) |
| full31_noHook | full35 − X1 설치 훅 4 (installHookNewProgramCount, installHookArgsChanged, installHookRefFileChanged, installHookNewExternalExecCount) | 신규 학습 (두 프로토콜) |
| gs24 | full35 − obfNew 7 − X1 설치 훅 4 | 재사용 (Train 외부: `../d06_alt_models/run_gs`, Test: `../d06_test674_dev/run`) |

## 3. full35 + gs24 결합 방법 (모두 고정)

점수 척도 변환 `rank`: 같은 calibration 집합의 정상 점수 분포 기준 백분위 r(s) = (#정상 < s + 0.5 × #정상 = s) / #정상. 평가 행에도 그 calibration 정상 분포를 그대로 쓴다.

| 이름 | 방법 | 선택 |
|---|---|---|
| C1_prob | (1−w)·full35 + w·gs24 (확률) | w ∈ {0, 0.1, …, 1}, calibration PR-AUC 최대 |
| C2_logit | logit 가중 평균 | 같음 |
| C3_rank | rank 가중 평균 | 같음 |
| C4_route_noJS | rank 척도에서 JS 변경 없음(obfChangedFileCount = 0 또는 결측) → gs24, 나머지 → full35 | 선택 없음 |
| C5_route_mastraType | rank 척도에서 JS 변경 없음 & 새 의존성 & 설치 스크립트 추가 없음 → gs24, 나머지 → full35 | 선택 없음 |
| C6_typewise_rank | rank 가중 평균, JS 변경 쌍의 w_js와 JS 변경 없음 쌍의 w_nojs를 따로 (각 0~1, 0.1 간격, 121조합) | 전체 calibration PR-AUC 최대 |
| C7_or_maxrank | max(r_full35, r_gs24) — 두 모델 중 하나라도 높으면 탐지(보완적 OR) | 선택 없음 |
| C8_and_minrank | min(r_full35, r_gs24) — 두 모델이 모두 높을 때만 (오탐 감소 방향, 참고) | 선택 없음 |

동률 규칙: PR-AUC 같으면 full35 가중치가 큰 쪽(w 작은 쪽). 선택은 Train 외부는 split별(3 fold calibration 평균), Test 프로토콜은 seed별.
모든 결합 점수의 임계값은 결합 점수의 calibration 분포로 정한다.

## 4. 지표

목표 FPR 1·3·5%에서: 전체 Recall, 실제 FPR, Hard benign FPR, PR-AUC, 캠페인별 Recall, 공격 유형별 Recall(A: 설치 스크립트·스크립트 항목 추가, B: 새 의존성, C: 그 외 — PR #13 정의를 Test에도 같은 식으로 적용),
full35 대비 신규 탐지·기존 탐지 손실·오탐 제거·신규 오탐, gs24 대비 같은 항목. Test에서는 mastra Recall·mastra 제외 Recall을 추가로 보고한다.

## 5. 판단 규칙 (Train 외부 기준)

"gs24의 탐지와 full35의 탐지를 결합하면서 오탐도 줄인다" = 목표 FPR 5%와 1%에서 두 split 모두 full35보다 TP가 같거나 높고 FP가 같거나 낮으며, 최소 한 쪽은 엄격히 나음.
Test-674 결과는 이 판단에 쓰지 않고 별도로 보고한다.
