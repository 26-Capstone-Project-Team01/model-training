# D06 최종 후보 종합 비교

새 학습·새 Feature 없음. 저장 점수만 사용했다. 판단 기준은 Recall, 전체 FPR, Hard benign FPR, mastra Recall, mastra 제외 Recall, Split/seed 간 안정성이다.

**Recall 90% 목표는 Test 일반화 기준이다.** 아래 Test-674 수치는 개발 평가다(이미 반복 분석했다). 임계값 출처를 두 종류로 구분한다.
- **Train 선택**: 운영 calibration 목표를 Train MGV(`../d06_mgv_hpo` 8절, eval 라벨로 정한 Train 내부 규칙)에서 정하고, 임계값은 Test 프로토콜의 Train calibration에서 계산. Test-674 라벨을 쓰지 않는다.
- **Test 선택 (독립 검증 아님)**: seed별로 Test-674 점수에서 Test FPR ≤ 5%를 만족하며 Recall이 가장 높은 임계값. 상한 참고용이다.

검사: full35·gs24·full28의 Train 선택 5% TP·FP·mastra TP가 `../d06_gs24_followup/eval`과 같다(assert).

## 1. Train 내부 (MGV 7그룹, 운영점 = 실제 FPR ≤ 5%인 가장 높은 calibration 목표)

| 후보 | 운영 목표 | Recall 최소 / 평균 | FPR 최대 | HB FPR 평균 |
|---|---|---|---|---|
| B3 | 3% | .893 / .919 | .045 | .103 |
| full35 | 3% | .844 / .896 | .043 | .108 |
| C5 라우팅 | 3% | .844 / .896 | .041 | .107 |
| gs24 | 4% | .839 / .897 | .046 | .124 |
| full28_noObfNew | 3% | .847 / .891 | .043 | .108 |

## 2. Test-674 개발 평가 — Train 선택 운영점 (seed 20261109 / 20261110)

| 후보 (운영 목표) | Recall | FPR | HB FPR | mastra Recall | mastra 제외 Recall | seed 간 Recall 차 |
|---|---|---|---|---|---|---|
| full35 (3%) | .472 / .505 | .037 / .015 | .083 / .067 | .059 / .151 | .989 / .947 | .033 |
| B3 (3%) | .453 / .425 | .033 / .037 | .067 / .067 | .059 / .193 | .947 / .716 | .028 |
| C5 라우팅 (3%) | .453 / .645 | .039 / .017 | .083 / .067 | .025 / .403 | .989 / .947 | .192 |
| gs24 (4%) | .706 / .799 | .037 / .033 | .050 / .100 | .513 / .941 | .947 / .621 | .093 |
| **full28_noObfNew (3%)** | **.720 / .949** | **.020 / .020** | .033 / .083 | .513 / .941 | .979 / .958 | .229 |

목표 5%(Train calibration): full35 .486/.565, B3 .481/.542, C5 .757/.972, gs24 .752/.818, full28 .729/.953. 1%·전체 표: `run/test674_final_compare.csv`, `run/test674_stability.csv`.

## 3. Test-674 — Test 선택 임계값 (독립 검증 아님, FPR ≤ 5%에서 최대 Recall)

| 후보 | Recall | HB FPR | mastra Recall | mastra 제외 Recall |
|---|---|---|---|---|
| full35 | .481 / .570 | .117 / .117 | .076 / .235 | .989 / .989 |
| B3 | .477 / .505 | .067 / .100 | .084 / .269 | .968 / .800 |
| C5 라우팅 | .724 / .972 | .100 / .100 | .513 / .958 | .989 / .989 |
| gs24 | .757 / .977 | .067 / .150 | .571 / .958 | .989 / 1.000 |
| full28_noObfNew | .724 / .953 | .067 / .150 | .513 / .950 | .989 / .958 |

## 4. 판단

1. **어느 후보도 Test-674에서 두 seed 모두 Recall 90%에 이르지 못했다**(Train 선택 운영점). 가장 가까운 것은 full28_noObfNew(.720 / .949, FPR .020 / .020)다.
   Test 선택 임계값을 써도(독립 아님) 최고가 C5 .724 / .972, gs24 .757 / .977로 seed 09에서 90% 미만이다.
2. **병목은 mastra다.** mastra 제외 Recall은 full35·C5·full28 모두 .95~.99로 이미 높다. 전체 Recall은 mastra Recall(119/214쌍)에 거의 결정된다.
3. **obfNew 제거가 mastra를 여는 유일한 레버다**(full28·gs24·C5). 그러나 seed 09에서는 mastra Recall이 .51에 머문다 — fit에 mini-shai-hulud B가 들어가느냐에 따라 달라지는 기존 원인과 같다.
   seed 간 Recall 차가 .19~.23으로 크다(full35·B3는 .03 수준으로 안정적이지만 Recall이 낮다).
4. **Train과 Test의 순위가 뒤집힌다.** Train에서 가장 좋은 B3가 Test에서 가장 낮고(.453/.425), Train에서 가장 낮은 full28이 Test에서 가장 높다. Train에 mastra 유형이 6쌍뿐이라 Train 기준으로는 이 차이를 볼 수 없다.
5. Hard benign FPR은 Train 운영점에서 모든 후보가 .03~.10 수준으로 비슷하다(Test HB 60쌍이라 1쌍 = .017).
6. X3+D(full35+X3+D)는 Train에서 조건부 개선(5%·3%)을 보였지만 Test X3/D Feature가 없어 이 비교에 넣지 못했다.

## 5. Freeze를 위한 결론

- 현재 D06 Train으로는 "Test에서 두 seed 모두 Recall 90%, FPR ≤ 5%"를 보장하는 후보가 없다. 남은 결손은 Feature·알고리즘보다 **학습 데이터에 mastra 유형(의존성 추가형) 악성이 거의 없는 것**에서 온다.
- Freeze 후보를 고른다면 목적에 따라 둘 중 하나다.
  - Test 일반화(mastra 포함) 우선: **full28_noObfNew(운영 calibration 3%)** 또는 **C5 라우팅**. FPR이 낮고(.020/.020, .039/.017) mastra 제외 Recall도 유지된다. 단 seed 의존성이 크다.
  - Train 내부 안정성 우선: **B3(3%)**. Train 7그룹 Recall 최소 .893으로 가장 안정적이지만 Test mastra를 거의 못 잡는다.
- 이 선택은 Test-674를 본 뒤의 판단이므로 독립 데이터(`../d06_mgv_hpo/README.md` 6절 조건)로 검증해야 한다.

## 6. 파일

`final_compare.py`, `run/test674_final_compare.csv`(모든 후보·seed·임계값 출처·목표), `run/test674_stability.csv`(seed 간 비교), `run/manifest.json`
