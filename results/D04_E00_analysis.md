# D04-E00 Analysis

데이터 버전 D04, 실험 `baseline` (상세 수치: `results/experiments.csv`, 모델: `models/D04_E00_baseline.txt`, 그림: `results/plots/D04_E00/`)에 대한 분석 결과를 정리한다.

## 1. Confusion Matrix
- Validation: TP 145 / FP 0 / TN 368 / FN 19
- Test: TP 22 / FP 0 / TN 460 / FN 168
- Test malicious 190개 중 168개를 놓침

## 2. Prediction Probability
- Validation malicious는 대부분 1에 가까움
- Test malicious는 대부분 0에 가까움
- Test FN 168개 중 154개(91.7%)가 probability 0.01 미만
- 0.4~0.5 구간 FN은 0개
- 따라서 threshold 0.5 문제로 보기 어려움

## 3. Feature Distribution
Train/Validation malicious와 Test malicious의 주요 feature 값이 크게 달랐음.
특히:
- installScriptAdded
- ChangedCode 계열 결측
- obfWhitespaceRatioNew
- obfShortIdentRatioNew
- updateInterval
- obfChangedFileCount

updateType은 상대적으로 비슷한 패턴 유지.

## 4. Campaign / splitGroup
- Train/Validation/Test 간 동일 splitGroup 겹침 없음
- campaign 단위 leakage 없음
- Validation malicious 164개 중 163개가 shai-hulud-original
- Train에도 Shai-Hulud 관련 campaign 비중이 큼
- Test는 mastra-easy-day-js, canisterworm, debug-chalk-duckdb 등 다른 campaign 중심
- 단, 이름이 비슷하다고 같은 attack family라고 확정하지는 말 것

## 5. ChangedCode Missingness
- Train malicious 결측률 2.5%
- Validation malicious 결측률 0.6%
- Test malicious 결측률 59.5%
- Test malicious 중 ChangedCode 결측 113개
- 그중 112개가 FN
- 다만 ChangedCode 존재 77개 중에서도 56개가 FN
- 따라서 중요한 원인 후보지만 단독 원인은 아님

## 6. SHAP
- Test FN에서 obfWhitespaceRatioChangedCode가 가장 강하게 benign 쪽으로 작용
- obfHexIdentRatioNew, obfWhitespaceRatioNew, obfShortIdentRatioNew도 FN에서 주로 benign 쪽으로 작용
- updateInterval은 TP에서는 malicious 판단에 도움을 주지만 FN에서는 영향이 약해짐
- installScriptAdded는 FN 전체에서 단순히 benign 쪽으로 작용한 것은 아님
- 단일 feature보다 여러 feature 조합이 실패에 영향을 준 것으로 보임

## 7. Main Hypothesis

가장 유력한 가설:
Test malicious가 Train/Validation malicious와 feature 특성이 크게 달라,
모델이 Train/Validation에서 학습한 악성 패턴을 Test에 잘 일반화하지 못한 것으로 보임.

보조 원인:
- ChangedCode 결측
- Validation campaign 구성 편향 가능성

원인이 아닌 것으로 보이는 것:
- threshold 문제
- splitGroup leakage

아직 확정할 수 없는 것:
- Shai-Hulud 관련 campaign들이 실제 동일한 공격 패턴을 공유하는지
- feature 분포 차이의 근본 원인이 공격 유형인지, 수집 방식/시점인지
- ChangedCode 결측이 독립 원인인지 특정 campaign 특성의 결과인지
