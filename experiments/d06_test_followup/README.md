# D06 Test 후속 개발 실험: W1·W1+X1, 트리 수 진단, 성능 하락 원인 분석

**성격: 이미 평가한 D06 Test를 다시 쓰는 사후(post-hoc) 개발 실험이다.** 사전 등록 평가(`../d06_test_eval`, `d3c0c0d`)가 아니며,
이 폴더의 결과는 독립 성능이 아니다. 여기서 본 Test 결과를 근거로 모델·임계값·트리 수를 고르면 Test가 개발 데이터가 된다.
최종 모델은 정하지 않았다. 주 비교 운영점은 calibration 목표 FPR 5%이고, 1%·3%·0.5도 함께 기록했다.

## 1. 조건

- 분할·seed·파라미터: `../d06_test_eval`과 같다(PR #13 스냅샷, component 단위 fit/calibration, seed 20261109·20261110, 200 rounds, early stopping 없음).
  실행 시 fit/calibration 행이 `../d06_test_eval/run/splits.csv`와 같은지 검사한다.
- 새로 학습한 모델은 4개뿐이다: `full29_w1`, `full35_w1` × 2 seed. 가중치는 W1 정의(`exp/d06-w1-component-weight` `run_w1.py` `weights_component`):
  악성 행 1/√n (n = 같은 component의 fit 악성 수), 악성 가중치 합 = fit 악성 수, 정상·Hard benign 1. fit 악성 component 34 / 42개, 가중치 0.43~7.83 / 0.41~7.43.
- 재사용: base7, base7_w, full29, full35는 `../d06_test_eval/run/models`·`scores.csv`(저장 모델로 다시 예측해 저장 점수와 최대 차 < 1e-12 확인), A1~A3는 저장 점수.
  E06·E09는 저장 모델(`models/D06_E0{6,9}_*.txt`)로 Test를 예측(0.5와 순위 지표만, calibration 없음).
- 트리 수 진단: 200-round 모델의 앞 k개 트리(k = 6, 7, 10, 20, 50, 100, 200)로 추론만 했다(재학습 없음). k마다 임계값은 calibration에서만 구했다. Test로 k를 고르지 않는다.
- 확인: 저장 모델의 지표가 `../d06_test_eval/run/metrics.csv`와 112행 모두 같다.

## 2. 결과: Test-674, calibration 목표 FPR 5% (각 칸 seed20261109 / seed20261110, `run/metrics.csv`)

| 모델 | TP | FP | Hard FP | Recall | Precision | F1 | Test FPR | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|---|---|---|
| base7 | 80 / 145 | 25 / 19 | 12 / 13 | .374 / .678 | .762 / .884 | .502 / .767 | 5.4 / 4.1% | .833 / .935 | .714 / .860 |
| base7_w | 78 / 133 | 27 / 21 | 11 / 10 | .364 / .621 | .743 / .864 | .489 / .723 | 5.9 / 4.6% | .823 / .923 | .697 / .850 |
| full29 | 64 / 66 | 25 / 22 | 5 / 3 | .299 / .308 | .719 / .750 | .422 / .437 | 5.4 / 4.8% | .761 / .884 | .631 / .738 |
| **full29_w1** | 64 / 67 | 25 / 23 | 4 / 4 | .299 / .313 | .719 / .744 | .422 / .441 | 5.4 / 5.0% | .782 / .892 | .647 / .752 |
| full35 | 104 / 121 | 34 / 20 | 9 / 4 | .486 / .565 | .754 / .858 | .591 / .682 | 7.4 / 4.3% | .879 / .948 | .789 / .881 |
| **full35_w1** | 103 / 115 | 36 / 16 | 8 / 5 | .481 / .537 | .741 / .878 | .584 / .667 | 7.8 / 3.5% | .883 / .945 | .795 / .879 |
| A1 | 99 / 96 | 23 / 24 | 4 / 5 | .463 / .449 | .811 / .800 | .589 / .575 | 5.0 / 5.2% | .798 / .913 | .714 / .799 |
| A2 | 99 / 112 | 22 / 21 | 4 / 4 | .463 / .523 | .818 / .842 | .591 / .646 | 4.8 / 4.6% | .811 / .918 | .726 / .809 |
| A3 | 100 / 113 | 24 / 21 | 5 / 4 | .467 / .528 | .806 / .843 | .592 / .649 | 5.2 / 4.6% | .820 / .920 | .732 / .817 |
| E06 (저장, 0.5) | 132 | 17 | 14 | .617 | .886 | .727 | 3.7% | .940 | .874 |
| E09 (저장, 0.5) | 154 | 39 | 14 | .720 | .798 | .757 | 8.5% | .922 | .816 |

- E06·E09는 calibration 정책이 없어 0.5 결과만 있다. 오탐 수준이 다르므로(E06 Test FPR 3.7%, E09 8.5%) 위 행들과 같은 조건의 비교가 아니다.
- FPR 1%·3%·0.5와 Test-677 결과는 `run/metrics.csv`. W1(full29_w1·full35_w1)은 full29·full35와 비교해 일관된 개선이 없다(5% TP: full29_w1 +0 / +1, full35_w1 −1 / −6. FPR 1%에서는 full35_w1 seed20261110만 103 vs 83으로 많다).

## 3. 트리 수 진단 (`run/prefix_metrics.csv`, `run/prefix_thresholds_calrank.csv`, Test-674 FPR 5% TP/FP)

| 모델 | seed | k=6 | 7 | 10 | 20 | 50 | 100 | 200 |
|---|---|---|---|---|---|---|---|---|
| base7 | 09 | 89/34 | 89/33 | 85/29 | 84/26 | 79/23 | 84/31 | 80/25 |
| base7 | 10 | 169/27 | 169/27 | 170/28 | 170/27 | 150/24 | 141/20 | 145/19 |
| full29 | 09 | 41/23 | 41/21 | 47/21 | 66/22 | 69/35 | 62/28 | 64/25 |
| full29 | 10 | 14/13 | 14/11 | 14/11 | 21/13 | 54/20 | 69/21 | 66/22 |
| full35 | 09 | 91/19 | 95/18 | 95/22 | 98/22 | 101/39 | 103/37 | 104/34 |
| full35 | 10 | 77/9 | 76/9 | 90/12 | 96/17 | 115/21 | 116/17 | 121/20 |

- base7는 트리가 적을 때 TP가 조금 많다(seed10: 6~20트리 169~170 vs 200트리 145, FP 27 vs 19). full29·full35는 트리가 적을수록 TP가 줄거나 같다.
- calibration ROC-AUC도 full29는 트리가 많을수록 높다(seed10 6트리 .836 → 200트리 .977). 200트리 학습이 성능 하락의 주원인이라는 근거는 없다.

## 4. 원인 분석 (`cause/`)

### 4.1 학습 데이터 구성 (`cause/training_composition.csv`)

| 학습 집합 | 악성 | 설치 훅 없음 + 새 의존성 악성 | 같은 조건의 정상 | P(악성 \| 훅 없음+새 의존성) | 주요 악성 캠페인 |
|---|---:|---:|---:|---:|---|
| E06·E09 학습 (2,212) | 741 | 51 (mini-shai-hulud 46) | 76 | .402 | sha1-hulud 332, mini-shai 198, individuals 50, autotel 29, miasma 26, chaindrop 25 |
| fit seed20261109 | 624 | **4** | 71 | **.053** | sha1-hulud 332, **shai-hulud-original 186**, individuals 27, chaindrop 25 (**mini-shai 없음**) |
| fit seed20261110 | 692 | 51 (mini-shai 46) | 69 | .425 | sha1-hulud 332, mini-shai 198, individuals 36, autotel 29 |

### 4.2 Feature 분포 (`cause/feature_profiles.csv`)

| 집단 | n | 설치 스크립트 추가 | 새 의존성 | 훅 없음+새 의존성 | 변경 JS 없음 | Hex 식별자>0 | RefFile | Proc>0 | Net>0 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Train 악성 | 928 | .772 | .111 | .056 | .033 | .577 | .765 | .556 | .830 |
| Train 무작위 정상 | 1,600 | .001 | .058 | .049 | .371 | .002 | .002 | .007 | .016 |
| Train Hard benign | 239 | .477 | .218 | .046 | .314 | .008 | .159 | .109 | .180 |
| Test mastra | 119 | **0** | **1.000** | **.958** | **.950** | 0 | 0 | .008 | .017 |
| Test canisterworm | 68 | **1.000** | 0 | 0 | 0 | **0** | 1.000 | 1.000 | 1.000 |
| Test 무작위 정상 | 400 | .003 | .058 | .050 | .415 | 0 | .010 | .010 | .010 |
| Test Hard benign | 60 | .600 | .133 | 0 | .333 | .017 | .250 | .050 | .067 |

- mastra: 설치 스크립트 0/119, 새 의존성 119/119, 변경 JS 없음 113/119(난독화 ChangedCode 계열 결측). Train에서 이와 같은 모양의 악성은 mini-shai-hulud B유형 46쌍이 거의 전부다.
- canisterworm: 설치 훅·RefFile·Proc·Net이 모두 있지만 난독화 신호(HexIdent>0)가 없다.

### 4.3 점수 분포 (`cause/score_by_group_test674.csv`, 중앙값 [FPR 5% 임계값 이상 비율])

| 모델 | seed | mastra | canisterworm | Test 정상 | Test Hard benign | 임계값 |
|---|---|---|---|---|---|---|
| E06 | 저장 | 0.492 [.49] | 0.567 [.97] | 0.184 [.01] | 0.274 [.23] | 0.5 |
| E09 | 저장 | 0.566 [.56] | 0.550 [1.0] | 0.178 [.06] | 0.222 [.23] | 0.5 |
| base7 | 09 / 10 | 0.026 [.03] / 0.978 [.60] | 0.963 / 0.982 [1.0] | | | 0.413 / 0.585 |
| full29 | 09 / 10 | 1.4e-07 [.04] / 9.6e-06 [.15] | 2.0e-04 [.50] / 2.8e-05 [.34] | | | 2.2e-04 / 1.6e-03 |
| full35 | 09 / 10 | 6.3e-07 [.08] / 6.4e-05 [.23] | 0.975 [1.0] / 0.078 [1.0] | | | 2.0e-05 / 3.1e-04 |
| A2 | 09 / 10 | 2.6e-07 [.04] / 2.1e-05 [.16] | 0.195 [1.0] / 0.016 [1.0] | | | 3.6e-04 / 2.1e-03 |

같은 쌍의 모델별 점수는 `cause/focus_pair_scores.csv`.

### 4.4 TreeSHAP (mastra 평균, log-odds, `cause/treeshap_focus_groups.csv`)

| 모델 | seed | 합계 | 기여 큰 Feature |
|---|---|---|---|
| E06 | 저장 | +0.03 | newDependencyAdded +0.70, installScriptAdded −0.32, updateType +0.24 |
| base7 | 09 | −5.35 | installScriptAdded −1.46, newDependencyAdded +1.24, installScriptPresent −0.94 |
| base7 | 10 | +1.36 | newDependencyAdded +2.94, installScriptAdded −1.69, updateType +1.39 |
| full29 | 09 | −14.78 | obfBracketAccessRatioChange −1.72, newDependencyAdded +1.24, obfBracketAccessRatioChangedCode −1.18 |
| full29 | 10 | −9.87 | newDependencyAdded +3.50, obfWhitespaceRatioChangedCode −1.38, obfHexNumberRatioChange −1.26 |
| full35 | 09 | −13.54 | addedNetworkCallCount −3.21, installHookRefFileChanged −1.75, newDependencyAdded +1.39 |
| full35 | 10 | −8.46 | newDependencyAdded +3.88, obfWhitespaceRatioChangedCode −1.63, obfWhitespaceRatioNew −1.48 |

canisterworm: full29 합계 −7.0 / −7.5(installScriptAdded +2.4 / +3.9, 난독화 Feature 음수), full35 +4.3 / −0.5(Net +6.3 / +3.3, RefFile +4.4 / +4.6), base7 +5.1 / +6.0.

### 4.5 원인 구분 (확인된 사실 / 해석)

| 후보 | 확인된 사실 | 해석 |
|---|---|---|
| 학습 데이터 구성 | mastra 같은 "훅 없음+새 의존성" 악성이 seed09 fit에 4쌍(P=.053), seed10·E06 학습에 51쌍(P≈.41). base7의 mastra 중앙 점수 0.026 vs 0.978, FPR 5% TP 4 vs 71 | **base7 계열의 mastra 탐지는 mini-shai-hulud가 fit에 있느냐로 거의 정해진다** |
| Feature 부족 | mastra는 설치 훅·변경 JS가 없어 X1·난독화 Feature가 모두 0/결측. full29·full35는 seed10에서도 newDependencyAdded +3.5~3.9를 난독화·X1 음수 기여가 상쇄해 합계 −8~−10 | **29/35개 모델은 악성을 "코드 변화 신호"로 학습했고, 코드 변화 없는 의존성 추가형을 표현할 Feature가 newDependencyAdded 하나뿐이다** |
| 과적합(트리 수) | base7은 트리가 적을 때 TP가 조금 많고, full29·full35는 적을수록 적다 | 주원인 아님. base7에서 일부 영향 |
| 임계값 | Test FPR이 목표 근처(4.1~7.8%). mastra 점수는 임계값보다 1~3자리 낮다(full29) | 임계값보다 **순위** 문제. 단, E06·E09의 0.5는 점수가 0.5 근처에 몰린 얕은 모델(6·7트리)이라 mastra 중앙값 0.49~0.57이 경계에 걸려 절반가량 통과한 것 |
| canisterworm | 훅·X1 신호가 있으나 난독화 없음. full29는 난독화 음수 기여로 놓치고, X1이 있는 full35는 잡는다 | full29의 판단이 sha1-hulud 같은 난독화 페이로드에 치우침 |

## 5. 한계

- 사후 개발 실험이며 Test는 이미 여러 번 봤다. 여기서 나온 개선 아이디어는 새 독립 자료에서 검증해야 한다.
- Test 악성의 56%(119/214)가 mastra 한 캠페인이다.
- 두 seed의 차이 자체가 원인 분석의 핵심 근거다(fit 구성 차이). seed가 두 개뿐이다.
- TreeSHAP은 상관을 보여 줄 뿐 인과를 확정하지 않는다.

## 6. 파일과 재현

```text
followup_eval.py    W1 4개 학습, 저장 모델·점수 재사용, E06·E09 Test 점수, 트리 prefix 진단
cause_analysis.py   학습 구성, Feature 분포, 점수 분포, 같은 쌍 점수, importance, TreeSHAP (추론만)
run/                models/ (W1 4개), training_w1.csv, scores_w1.csv, thresholds.csv, metrics.csv,
                    prefix_metrics.csv, prefix_thresholds_calrank.csv, e06_e09_test.csv, e06_e09_test_scores.csv, manifest.json
cause/              manifest.json (cause 결과·입력 SHA-256), training_composition.csv, feature_profiles.csv, score_by_group_test674.csv, focus_pair_scores.csv,
                    feature_importance.csv, treeshap_focus_groups.csv
```

실행(lightgbm 4.7.0, pandas 3.0.6, numpy 2.5.3, scikit-learn 1.9.1):
`python -I -B followup_eval.py --workspace <ws> --groups <be87ab4c malicious_pair_groups.csv> --out run` 후
`python -I -B cause_analysis.py --workspace <ws> --groups <...> --out cause`. `<ws>`는 `../d06_test_eval/README.md` 7절과 같다.
