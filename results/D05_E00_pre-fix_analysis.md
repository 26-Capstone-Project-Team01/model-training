# D05-E00_pre-fix Analysis (superseded)

> **superseded**: 이 문서는 `D05-E00`의 이전 기록이다. `assign_components()`가 `individual-compromise-4th`처럼 서로 무관한 개별 침해 사례를 묶는 범용 수집-라운드 버킷 이름만으로 campaign처럼 하나의 component로 합치던 grouping/split 정책으로 생성됐다. 이 정책을 수정해 재학습한 결과가 새로운 `D05-E00`(`results/D05_E00_analysis.md`, `models/D05_E00_baseline.txt`, `results/plots/D05_E00/`)으로 이 기록을 대체한다. 아래 내용은 원본 그대로 보존한다.

데이터 버전 D05, 실험 `baseline` (상세 수치: `results/experiments.csv`의 `D05-E00_pre-fix` 행, 모델: `models/D05_E00_pre-fix_baseline.txt`, 그림: `results/plots/D05_E00_pre-fix/`)의 결과를 D04-E00과 비교해 정리한다.

## 0. D05에서 바뀐 것과 바뀌지 않은 것
- 데이터: npm-malware-package-pairs `d6e6d0425`(PR #17). D04(`4ee5c7357`)에 4차 수집 중 NPMStudy 출처 30쌍(2016~2021 사건)을 더했다. 이 30쌍은 meta.json 키 문제로 D04에 빠져 있었다.
- 30쌍은 모두 `individual-compromise-4th` splitGroup이라 Train으로 갔다. Train 악성 757 → 787, Test 650행은 D04와 바이트 단위로 같다.
- feature 정의, feature-extractor 로직, LightGBM 파라미터, threshold 0.5, grouping/split 정책, validation 분할 방식과 seed는 D04와 같다. `train_model.py`는 `DATA_VERSION`과 실험 메모만 바꿨다.
- 같은 환경에서 D04-E00을 다시 돌려 지표·best iteration·트리가 모두 같음을 먼저 확인했다(파일 차이는 줄바꿈뿐).
- Validation 구성은 D04와 같다(악성 164 중 163이 `shai-hulud-original`, 1이 `axios`). Validation 안의 학습용 Train 악성은 593 → 623.

## 1. 지표
| 지표 | D04-E00 | D05-E00 |
| --- | ---: | ---: |
| Val Recall | 0.8841 | 0.8780 |
| Val Precision | 1.0000 | 1.0000 |
| Val F1 | 0.9385 | 0.9351 |
| Val PR-AUC | 0.9994 | 0.9974 |
| Test Recall | 0.1158 | 0.1684 |
| Test Precision | 1.0000 | 0.9697 |
| Test F1 | 0.2075 | 0.2870 |
| Test PR-AUC | 0.6995 | 0.6377 |
| best iteration | 275 | 125 |

## 2. Confusion Matrix (Test)
- D04: TP 22 / FP 0 / TN 460 / FN 168
- D05: TP 32 / FP 1 / TN 459 / FN 158
- D04에서 잡은 악성은 D05에서도 모두 잡았고(새로 놓친 것 0), 10개를 새로 잡았다.
- 새 FP 1건: 무작위 benign `sprintf-js` 1.1.2 → 1.1.3(점수 0.70).

## 3. Test splitGroup별 Recall
| splitGroup | D04 | D05 | 평균 점수 D04 → D05 |
| --- | ---: | ---: | --- |
| `mastra-easy-day-js_2026-06` | 1/119 | 2/119 | 0.016 → 0.019 |
| `canisterworm_2026-03` | 2/48 | 10/48 | 0.038 → 0.231 |
| `debug-chalk-duckdb_2025-09` | 16/17 | 17/17 | 0.939 → 0.998 |
| `individual-compromise-3rd` | 1/3 | 1/3 | 0.333 → 0.332 |
| `rspack-vant_2024-12` | 2/3 | 2/3 | 0.661 → 0.742 |

- 늘어난 10개는 canisterworm 8, `@duckdb/duckdb-wasm` 1, `@mastra/twilio` 1이다.
- mastra(Test 악성의 63%, 의존성 한 줄 주입)는 여전히 거의 못 잡는다. 지금 feature로는 정상의 의존성 추가와 구분할 근거가 없다.

## 4. Prediction Probability
- Test FN 중 점수 0.01 미만: D04 154/168 → D05 124/158
- 0.4~0.5 구간 FN: 0 → 2
- 여전히 threshold 문제라기보다 모델이 대부분의 Test 악성을 정상으로 확신하는 상태다.

## 5. 무엇이 성능을 바꿨나 (SHAP, pred_contrib)
- 새로 잡힌 canisterworm: D04에서는 "추가·수정된 JS 파일 수가 적음"(`obfChangedFileCount`, -2.9~-3.4)이 정상 쪽으로 작용해 배포 간격·설치 스크립트 추가 신호를 상쇄했다. D05에서는 이 상쇄가 사라지고 `updateInterval`(+3~+4)과 `installScriptAdded`(+1.5~+1.9)가 이긴다. NPMStudy 공격 대부분이 파일 1~2개만 바꾸는 사례라 "변경 파일이 적으면 정상"이라는 패턴이 약해진 것으로 보인다.
- 새 FP `sprintf-js` 1.1.3: 이전 버전과 1,737일(약 4.8년) 간격의 정상 업데이트다. `updateInterval` 기여가 +3.69 → +6.71로 커져 악성으로 판정됐다.
- `updateInterval` 중앙값: D04 Train 악성 119일, `individual-compromise-4th` 37쌍 288일, Train 정상 9일. NPMStudy 30쌍의 배포 간격은 185~1,258일이다. "배포 간격이 길면 악성"이라는 지름길이 강해졌다.
- Split importance 1위는 계속 `updateInterval`(566 → 594)이다. SHAP 평균 절댓값 상위는 `obfWhitespaceRatioChangedCode`, `obfHexIdentRatioNew`, `updateInterval` 순으로 D04와 비슷하지만 값은 전반적으로 작아졌다.

## 6. ChangedCode Missingness
- Test FN 중 ChangedCode 결측: D04 112 → D05 112. 결측인 Test 악성(113개)은 D05에서도 거의 전부 놓친다.

## 7. 정리
- 새 데이터 30쌍만으로 Test Recall은 0.116 → 0.168, F1은 0.208 → 0.287로 올랐다. 다만 늘어난 탐지 대부분이 canisterworm이고, 그 주된 근거가 배포 간격이다.
- PR-AUC가 0.700 → 0.638로 내려갔다. 배포 간격이 긴 정상 업데이트(sprintf-js)가 높은 점수를 받아 순위가 흐트러진 영향으로 보인다.
- 30쌍은 2016~2021년 사건인데 같은 시기 정상 pair는 넣지 않았다(D04 조건 유지). 시기와 배포 간격이 함께 학습됐을 수 있다.
- Validation이 D04와 같은 구성(shai-hulud-original 위주)이라 early stopping 기준은 그대로 편향돼 있다.

다음 실험에서 확인할 것:
- `updateInterval` 제거(E04)로 D05 향상분 중 배포 간격 의존이 얼마인지
- ChangedCode 결측 처리(E01)
- 같은 시기 정상 pair를 넣었을 때 NPMStudy 30쌍의 효과가 유지되는지
