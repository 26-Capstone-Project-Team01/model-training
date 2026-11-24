# D06 기존 Feature만으로 한 병행 실험: Feature 묶음 조합 탐색, LR / RF / MLP

X3/D 추출과 병행해 실행했다(nice 19, 1스레드). 기존 35개 Feature만 쓴다. PR #13 분할(component 외부 3-fold, 내부 분할 seed+fold),
보정(calibration) 임계값 정책(PR #13 `calibrate`, ML, 목표 FPR 1·3·5%)을 그대로 쓴다. Test는 읽지 않았고 패키지 코드는 실행하지 않았다.
데이터 로딩·분할·정렬 검사·X1 인코딩은 `../d06_full35_compare/run_full35.py`를 경로로 불러 그대로 썼다.
평가는 `evaluate.py`(= `exp/d06-x3-design`의 `d06_x3_models/evaluate.py` 사본, sha256 1c6517d9…)로 했고,
base7·full29·full35 수치가 `../d06_x1_fair_compare/fair_comparison.csv`와 같음을 assert로 확인했다.

중복 방지: 이미 학습한 base7, full29, no_interval28, full35, full32, full29_ref/proc/net, base7_x1은 다시 학습하지 않고 저장 점수를 썼다.

## 1. Feature 묶음 조합 탐색 (LightGBM, `run_gs/`)

- base7은 항상 포함. 선택 묶음: obfNew(7), obfChange(7), obfChangedCode(7 + obfChangedFileCount), x1Hook(4), x1Calls(2) → 32조합.
- **선택 기준은 내부 calibration 행의 PR-AUC 평균(2 split × 3 fold)뿐**이다. 외부(outer) 라벨은 선택에 쓰지 않았다. 동률이면 Feature가 적은 쪽.
- 선택: `gs_obfChange+obfChangedCode+x1Calls` (24개, obfNew 7개와 X1 설치 훅 4개를 뺀 것). 선택된 조합만 외부 점수를 만들었다.
- **주의**: 상위 조합 간 calibration PR-AUC 차이는 0.004 이내(선택 0.9218, full29 0.9185, full35 0.9182)이고 셀 간 표준편차는 0.11~0.13이다.
  선택은 잡음 수준의 차이로 이루어졌다.

## 2. LR / RF / MLP (full35 Feature, `run_alt/`)

하이퍼파라미터는 실행 전에 고정했다(탐색 없음). 전처리는 fit 행으로만 맞췄다: updateType one-hot, 결측 → fit 중앙값 + 결측 지시 열,
LR·MLP는 추가로 sign·log1p 후 표준화. LR C=1, RF 500 trees·min_samples_leaf 2, MLP (64, 32)·alpha 1e-3·max_iter 500. 수렴 경고 없음.

## 3. 결과 (Train 외부, 보정 목표 FPR 5%, split1 / split2) — `eval_alt/`

| 모델 | TP | Recall | FP | 실제 FPR | HB 오탐 | HB FPR | PR-AUC(fold 평균) |
|---|---|---|---|---|---|---|---|
| full35 (기준) | 854 / 876 | .920 / .944 | 106 / 117 | .058 / .064 | 50 / 43 | .209 / .180 | .958 / .969 |
| full29 | 797 / 857 | .859 / .924 | 87 / 129 | .047 / .070 | 31 / 39 | .130 / .163 | .947 / .961 |
| base7 | 618 / 621 | .666 / .669 | 111 / 112 | .060 / .061 | 54 / 34 | .226 / .142 | .862 / .852 |
| LR | 837 / 861 | .902 / .928 | 89 / 125 | .048 / .068 | 27 / 38 | .113 / .159 | .957 / .967 |
| RF | 850 / 866 | .916 / .933 | 115 / 106 | .063 / .058 | 54 / 53 | .226 / .222 | .950 / .963 |
| MLP | 807 / 847 | .870 / .913 | 105 / 127 | .057 / .069 | 27 / 20 | .113 / .084 | .947 / .958 |
| 선택 조합(24) | 838 / 868 | .903 / .935 | 98 / 106 | .053 / .058 | 43 / 43 | .180 / .180 | .956 / .968 |

full35 대비 변화(5%): LR 신규 탐지 20/19·손실 37/34, 오탐 제거 67/79·신규 50/87, HB 오탐 제거 35/21·신규 12/16.
MLP 신규 23/17·손실 70/46, HB 오탐 제거 33/26·신규 10/3. RF 신규 11/11·손실 15/21, HB 오탐 신규 14/18.
선택 조합 신규 2/6·손실 18/14.

목표 FPR 1%: full35 TP 772/813(FP 20/30). LR 803/818(FP 32/38), RF 807/790(34/20), MLP 762/804(25/33), 선택 조합 735/801(22/23).

공격 유형별 TP(5%, A/B/C): full35 708·42·104 / 731·43·102, LR 712·41·84 / 721·41·99, MLP 687·41·79 / 714·43·90, RF 706·42·102 / 715·42·109.

## 4. 해석

- **PR-AUC는 full35 LightGBM과 LR이 사실상 같고(차이 ≤ .002) RF·MLP는 낮다.** 어느 모델도 full35보다 두 split 모두에서 TP가 높지 않다.
- LR·MLP는 HB 오탐이 크게 줄었다(5%: LR 27/38, MLP 27/20 vs 50/43). 그 대가로 TP가 줄었다(LR −17/−15, MLP −47/−29). 운영점 이동과 섞여 있어
  "같은 TP에서 HB 오탐이 적다"고 말할 수는 없다. 1%에서는 LR이 TP가 더 많고 FP도 더 많다.
- 조합 탐색으로 고른 24개 묶음은 full35와 거의 같은 수준이고(5% TP −16/−8, FP −8/−11), 선택 근거 자체가 잡음 수준이다. **채택 근거 부족.**
- 판단: 기존 Feature만으로 모델 종류나 묶음을 바꿔서 full35를 두 split 모두에서 넘는 결과는 없다. LR/MLP의 HB 오탐 감소는 후속(X3 결과와 함께)
  같은 TP 기준 비교로 확인할 가치가 있다.

## 5. 파일

```text
alt_models.py     groupsearch / altmodels 단계
evaluate.py       d06_x3_models/evaluate.py 사본
run_gs/           groupsearch_calibration.csv(32조합×6셀), groupsearch_ranking.csv, selection.json, scores.csv(선택 조합), manifest.json
run_alt/          scores.csv, training.csv(입력 수·반복 수), manifest.json
eval_alt/         metrics.csv, thresholds.csv, campaign_recall.csv, type_recall.csv, change_vs_full35.csv, change_vs_full35_cases_fpr5.csv, manifest.json
```

## 6. full35 · LR · MLP 블렌딩 (`blend.py`, `run_blend/`, `eval_blend/`, `matched/`)

저장 점수만 썼다(재학습 없음). 후보는 결과를 보기 전에 고정했다.
- 척도 2종: 확률 가중 평균(`prob`), logit 가중 평균(`logit`, p를 1e-6~1-1e-6로 자른 뒤).
- 가중치: B1 full35+LR, B2 full35+MLP는 다른 모델 가중치 0.0~1.0(0.1 간격), B3 full35+LR+MLP는 0.1 간격 단체 격자 66점.
- 선택: split마다 calibration PR-AUC의 3-fold 평균이 가장 높은 (척도, 가중치). 동률이면 full35 가중치가 큰 쪽, 그다음 `prob`. 외부 라벨은 선택에 쓰지 않았다.
- 임계값은 다른 모델과 같은 PR #13 calibration 정책.

### 6.1 점수 척도 (`run_blend/score_scale_calibration.csv`)

calibration 행 기준 full35(LightGBM)는 극단으로 몰린다: 정상의 99.4%·Hard benign의 95.4%가 0.01 미만, 악성의 55%가 0.99 초과, 21%가 0.01 미만.
LR은 훨씬 완만하다(정상 0.01 미만 66.9%, 95분위 0.128). MLP는 full35와 비슷하게 몰린다(정상 0.01 미만 96.1%).
순위 상관(Spearman): full35~LR .785, full35~MLP .808, LR~MLP .788. 확률 평균에서는 LR의 완만한 점수가 저점수 영역 순위를 주로 바꾼다.

### 6.2 선택된 블렌드 (`run_blend/manifest.json`)

| 블렌드 | split1 | split2 |
|---|---|---|
| B1 full35+LR | prob, 0.9/0.1 | logit, 0.9/0.1 |
| B2 full35+MLP | prob, 0.9/0.1 | logit, 0.8/0.2 |
| B3 full35+LR+MLP | prob, 0.9/0.1/0.0 (= B1) | logit, 0.8/0.0/0.2 (= B2) |

B3는 두 split 모두 2모델 블렌드와 같은 점으로 수렴했다(3모델 결합의 추가 이득 없음). split1 calibration PR-AUC는 full35 단독 .840 → B1 .919로 크게 올랐고, split2는 .996 → .997로 거의 같다.

### 6.3 동일 FPR (calibration 목표 FPR, split1 / split2)

| 모델 | 5% TP | 5% FP | 5% HB 오탐 | 1% TP | 1% FP | 1% HB 오탐 | PR-AUC |
|---|---|---|---|---|---|---|---|
| full35 | 854 / 876 | 106 / 117 | 50 / 43 | 772 / 813 | 20 / 30 | 8 / 16 | .958 / .969 |
| LR | 837 / 861 | 89 / 125 | 27 / 38 | 803 / 818 | 32 / 38 | 15 / 24 | .957 / .967 |
| MLP | 807 / 847 | 105 / 127 | 27 / 20 | 762 / 804 | 25 / 33 | 9 / 10 | .947 / .958 |
| B1 | 846 / 880 | 90 / 116 | 31 / 43 | 823 / 820 | 29 / 30 | 13 / 16 | .964 / .974 |
| B2 | 830 / 880 | 95 / 103 | 29 / 35 | 780 / 838 | 19 / 36 | 9 / 20 | .963 / .976 |
| B3 | 846 / 880 | 90 / 103 | 31 / 35 | 823 / 838 | 29 / 36 | 13 / 20 | .964 / .976 |

진단(외부 라벨로 맞춘 동일 외부 FPR, `matched/same_outer_fpr.csv`): 외부 FPR 1%에서 TP full35 758/769, B1 807/777, B3 807/807, LR 794/806;
5%에서 full35 844/865, B3 846/877. HB 오탐(5%) full35 44/36, B3 33/36, MLP 26/17.

### 6.4 동일 Recall (진단, `matched/same_recall_as_full35_fpr5.csv`)

각 fold에서 full35가 calibration 5% 임계값으로 잡은 TP(854/876)를 같게 맞추는 가장 높은 임계값을 썼다(외부 라벨 사용 → 선택에 쓰지 않음).

| 모델 | FP s1 / s2 | HB 오탐 s1 / s2 | 일반 정상 오탐 s1 / s2 |
|---|---|---|---|
| full35 | 74 / 87 | 32 / 29 | 42 / 58 |
| LR | 310 / 101 | 36 / 20 | 274 / 81 |
| MLP | 229 / 306 | 21 / 30 | 208 / 276 |
| B1 | 92 / 75 | 20 / 25 | 72 / 50 |
| B2 | 108 / 73 | 22 / 21 | 86 / 52 |
| B3 | 92 / 73 | 20 / 21 | 72 / 52 |

- **같은 Recall에서 HB 오탐은 블렌드에서 두 split 모두 줄었다**(B3 20/21 vs 32/29). 그러나 split1에서는 일반 정상 오탐이 늘어 전체 FP가 74 → 92로 늘었다. split2는 전체 FP도 87 → 73으로 줄었다.
- LR·MLP 단독은 full35의 높은 Recall 구간까지 끌어올리면 FP가 크게 는다(LR s1 310, MLP 229/306). 단독 모델의 HB 오탐 감소(6.3)는 운영점이 낮은 Recall로 옮겨간 효과가 컸다.

### 6.5 full35가 놓친 악성의 추가 탐지와 손실 (calibration 5%, `matched/gain_loss_vs_full35_fpr5.csv`)

full35가 놓친 악성: split1 74, split2 52.

| 모델 | 추가 탐지 s1 / s2 | 기존 탐지 손실 s1 / s2 |
|---|---|---|
| LR | 20 / 19 | 37 / 34 |
| MLP | 23 / 17 | 70 / 46 |
| RF | 11 / 11 | 15 / 21 |
| B1 | 20 / 4 | 28 / 0 |
| B2 | 22 / 13 | 46 / 9 |
| B3 | 20 / 13 | 28 / 9 |
| LR 또는 MLP(합집합, 참고) | 28 / 21 | — |

추가 탐지는 node-gyp-dll(8), individuals_case, react-native-aria-gluestack(split2 10~14), miasma에 몰려 있다.
손실은 split1에서 react-native-aria-gluestack·pgserve·individuals_case(B1·B3), shai-hulud-original 25(B2)에 몰린다.

### 6.6 판단

- B3(= split별로 B1 또는 B2)는 calibration 5%에서 full35보다 FP·HB 오탐이 적고(90/103 vs 106/117, 31/35 vs 50/43) TP는 비슷하다(846/880 vs 854/876).
  PR-AUC가 두 split 모두 올랐고(.964/.976 vs .958/.969), 1%에서 TP가 늘었다(823/838 vs 772/813, FP 29/36 vs 20/30).
- 다만 split1은 선택 가중치에서 LR/MLP 비중이 0.1뿐인데도 손실 28이 생겼고, 동일 Recall에서 일반 정상 오탐이 늘었다. 두 split의 선택 척도도 다르다(prob vs logit).
- **잠정 결론**: full35 + 소량(0.1~0.2) LR/MLP 블렌드는 HB 오탐 감소와 1% 운영점 개선 방향이 두 split에서 같다. X3 결과와 함께 최종 비교한다.
  Test로 가중치를 고르지 않는다.
