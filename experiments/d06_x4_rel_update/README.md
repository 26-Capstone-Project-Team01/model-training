# D06 X4: 상대적 업데이트 이상도 Feature 구현·실험

X3/D 추출과 병행(nice 19). registry packument `time` 맵만 읽었다(tarball·manifest·패키지 코드 없음).
PR #13 분할(component 외부 3-fold, 내부 seed+fold)과 calibration 정책(PR #13 `calibrate`, ML, 목표 FPR 1·3·5%)을 그대로 썼다.
기존 결과(full35, LR, MLP, B3 블렌드)는 저장 점수를 재사용했고, 새로 학습한 것은 LightGBM 2개 변형(각 6모델)뿐이다.
Test는 모델 평가에 쓰지 않았다(5절의 Feature 값 진단만).

## 1. 정의 (`x4.py`, 추출 전에 고정, `test_x4.py` 6개 테스트 통과)

- 입력: packument `time` 맵. `created`·`modified`와 npm 보안 대체 버전(`*-security`)은 뺀다.
- **과거 이력은 old 버전 배포 시점까지만**: H = T_old 이하의 모든 배포 시각(T_old 포함), 그중 최근 11개 → 최대 10개 간격.
- `x4RelUpdateIntervalRatio` = (T_new − T_old) ÷ max(간격 중앙값, 60초). 60초 하한은 모노레포 동시 배포 때문에 분모가 0에 가까워지는 것을 막는다.
- `x4HistoryGapCount` = 쓴 간격 수(0~10).
- **이력 부족**: 간격이 2개 미만(old가 1·2번째 배포)이면 비율 = NaN(`history_short`), 간격 수는 그대로 둔다.
  registry 실패·버전 없음·new가 old보다 먼저 배포된 경우는 둘 다 NaN(상태로 구분, 상태는 Feature 아님).
- 삭제된 악성 버전도 `time` 항목은 남아 있어 계산된다. manifest 기반 값은 악성 94%가 결측이라 쓰지 않았다(`../d06_rel_update_feasibility`).

## 2. 추출 결과 (Train 2,767쌍, `run/`, `analysis/`)

| 상태 | 정상 | Hard benign | 악성 |
|---|---:|---:|---:|
| ok | 1,317 | 169 | 777 |
| history_short | 283 | 69 | 151 |
| registry 404 | 0 | 1 | 0 |
| 비율 결측률 | 17.7% | 29.3% | 16.3% |

비율 분포:

| 클래스 | 10% | 중앙값 | 90% | >10 | >100 |
|---|---:|---:|---:|---:|---:|
| 정상 | 0.03 | 1.63 | 39.5 | 16.3% | 5.9% |
| Hard benign | 0.02 | 2.41 | 89.7 | 18.4% | 7.1% |
| 악성 | 0.31 | 15.5 | 8,590 | 45.2% | 27.2% |

- 캠페인별(`analysis/by_class_campaign.csv`): sha1-hulud 중앙값 167, shai-hulud-original 11.5, mini-shai 5.8, individuals_case 50.0. 낮은 캠페인: chaindrop 2.9, injective 1.8, pgserve 3.4.
  결측률은 sha1-hulud 24%, mini-shai 16%이고, 결측이 악성 쪽으로 몰리는 패턴은 없다(악성 16.3% < 정상 17.7% < HB 29.3%).
- **updateInterval과의 관계**: 비율의 분자(time 맵 간격)는 기존 `updateInterval`과 99.96% 쌍에서 1초 이내로 같다(같은 출처).
  비율 대 updateInterval Spearman 0.70(정상 0.61, HB 0.69, 악성 0.73). 단일 Feature AUC: 전체 0.726 vs updateInterval 0.705,
  HB 대 악성 0.691 vs 0.725 — **Hard benign과의 구분에서는 오히려 updateInterval이 낫다.**

## 3. 모델 비교 (Train 외부, calibration 목표 FPR, split1 / split2)

학습 경로 검증: full35를 같은 코드로 다시 학습해 저장 점수와 비트 단위로 같음을 확인한 뒤(8,548행) 새 변형을 학습했다.

| 모델 | 5% TP | 5% FP | 5% HB 오탐 | 1% TP | 1% FP | PR-AUC |
|---|---|---|---|---|---|---|
| full35 | 854 / 876 | 106 / 117 | 50 / 43 | 772 / 813 | 20 / 30 | .958 / .969 |
| full35 + X4 | 850 / 864 | 114 / 120 | 47 / 50 | 782 / 817 | 21 / 28 | .959 / .971 |
| full35 − updateInterval + X4 (full34_x4) | 859 / 870 | 104 / 90 | 52 / 38 | 802 / 829 | 25 / 34 | .963 / .961 |
| B3 (full35+LR/MLP, 최종 후보) | 846 / 880 | 90 / 103 | 31 / 35 | 823 / 838 | 29 / 36 | .964 / .976 |
| B3x (full34_x4 + LR/MLP) | 852 / 876 | 91 / 103 | 34 / 35 | 826 / 842 | 34 / 35 | .965 / .975 |
| B3x (full35_x4 + LR/MLP) | 841 / 873 | 89 / 112 | 31 / 34 | 817 / 830 | 27 / 23 | .963 / .976 |

- full35 대비 변화(5%): full35+X4 신규 탐지 5/3·손실 9/15, full34_x4 신규 6/9·손실 1/15(오탐 제거 28/57·신규 26/30).
- 동일 외부 FPR 1%(진단): full35 758/769, full35+X4 754/778, B3 807/807, B3x(full34_x4) 799/824.
- 동일 Recall(진단, full35 5% TP에 맞춤) HB 오탐: full35 32/29, full35+X4 31/33, B3 20/21, B3x(full34_x4) 21/23.
- 블렌드 기준 모델 선택(사전 규칙: calibration PR-AUC): full35_x4 .9175 > full34_x4 .9121. 둘 다 full35 자체(.9182, `../d06_alt_models/run_gs`)보다 높지 않다.
  블렌드 가중치는 B3와 같은 절차(사전 후보, calibration 선택)이고 LR/MLP는 재학습하지 않았다(full35 Feature 그대로).

## 4. 판단

- **X4는 Train 내부 기준으로 채택 근거가 없다.** full35+X4는 5%에서 두 split 모두 TP가 줄었고, full34_x4는 split마다 방향이 다르다(split1 TP +5, split2 −6; FP는 둘 다 감소).
  1%에서는 두 변형 모두 TP가 늘지만(full34_x4 +30/+16) FP·HB 오탐도 늘었다. calibration 기준으로도 full35보다 낫지 않다.
- B3x는 B3와 사실상 같다(5% TP 852/876 vs 846/880, HB 오탐 34/35 vs 31/35). **최종 후보는 B3 유지.**
- 원인: X4의 분자가 `updateInterval`과 같아 트리가 이미 쓰는 정보와 겹치고, Train의 HB 대 악성 구분에는 오히려 약하다.

## 5. mastra(의존성 추가형) 미탐과의 관계 — 진단만 (`test_diag/`)

Test-674 쌍의 X4 **값만** 계산했다(모델 점수 계산·선택 없음).

| 그룹 | n | 결측 | 중앙값 | >10 |
|---|---:|---:|---:|---:|
| Test 정상 | 400 | 15.5% | 1.72 | 17.0% |
| Test Hard benign | 60 | 18.3% | 1.74 | 13.3% |
| mastra-easy-day-js | 119 | 5.0% | 56.3 | **94.1%** |
| canisterworm | 68 | 4.4% | 14.3 | 50.0% |

- mastra 쌍은 X4가 매우 크다(평소보다 훨씬 오래 쉬었다가 배포). 그러나 Train에는 "JS 변경 없음·새 의존성·훅 추가 없음" 악성이 6쌍뿐이라,
  Train으로 학습한 모델이 이 영역에서 X4를 쓰도록 배울 근거가 거의 없다. Train 외부 결과가 개선되지 않은 것과 모순되지 않는다.
- 이 값으로 모델·임계값을 고르지 않았다. Test에서 X4 모델의 mastra 탐지를 보려면 별도 사전 등록 후 평가해야 한다.

## 6. 파일

```text
x4.py, test_x4.py                  정의·단위 테스트
extract_x4.py                      registry time 맵 수집(4스레드) → run/d06_x4.csv, d06_x4_status.csv, packuments.jsonl.gz(시각 포함, --from-log로 재계산)
analyze_x4.py → analysis/          상태·분포·캠페인별·상관·단일 AUC
train_x4.py → run_models/          full35_x4, full34_x4 (full35 재현 가드 포함)
blend_x4.py → run_blend_x4/        X4 변형 + LR/MLP 블렌드 (B3와 같은 절차)
eval_models/                       ../d06_alt_models/evaluate.py 결과 (full35·LR·MLP·RF·B1~B3 포함)
matched/                           ../d06_alt_models/matched.py 진단 (동일 Recall·동일 외부 FPR·추가 탐지/손실)
test_diag_x4.py → test_diag/       Test-674 X4 값 진단(모델 평가 아님)
```
