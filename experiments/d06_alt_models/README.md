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
