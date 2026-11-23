# D06-A: full29 + full35 저장 점수 Blending (진단)

상태: D06 개발자료 진단. **모델 학습 없음**(저장 점수 결합만). Test 677 미사용. 가중치는 실행 전에 정한 세 값이며
D06 outer 결과로 고르거나 최종 선택하지 않는다. D06은 이미 X1 설계·원인 분석에 쓰인 자료라 독립 검증이 필요하다.

## 1. 조건

| 항목 | 값 |
|---|---|
| 입력 점수 | full29 = PR #13 `d06_feature_comparison_18/scores/saved_scores.csv`(model=full29), full35 = `d06_full35_compare/run/scores.csv` |
| 결합 | 확률 공간 선형 결합 `s = (1-w)·full29 + w·full35`. A1 w=0.1, A2 w=0.2, A3 w=0.3 (사전 고정) |
| 대응 | (split, seed, fold, stage, row_id) 1:1 outer join, 누락·중복 시 중단. 8,548행(split1 calibration 1,434 / outer 2,767, split2 1,580 / 2,767) |
| 분할 | PR #13 outer 3fold × split1(20261109)·split2(20261110), fit/calibration/outer 그대로 |
| 운영점 | PR #13 phase2 정책: 스냅샷 `calibrate()`(ML), calibration 정상 FP 예산 floor(n·0.01), 결합 방식·split·fold별로 산출해 outer에 적용 |
| 진단 임계값 | 0.05, 0.5 (PR #13 표시 지점, 운영 기준 아님) |
| 진단 순위 지표 | fold별 ROC-AUC, PR-AUC, Hard benign 대비 ROC-AUC, shai-hulud-original 제외 PR-AUC (정책 아님) |

재실행: `python -I -B blend_eval.py` (같은 브랜치의 `../d06_x1_cause_analysis/common.py` 로더 사용, 라이브러리는 PR #13과 동일 버전).
이 폴더의 CSV는 임시 작업공간 실행 결과와 바이트 단위로 같음을 확인했다.

## 2. 결과 (outer 합산, calibration FPR 1% 운영점)

| | split1 TP/FN/FP (Hard FP) | split2 TP/FN/FP (Hard FP) | 캠페인 평균 Recall s1/s2 | shai-orig 제외 TP s1/s2 |
|---|---|---|---|---|
| full29 | 735/193/14 (5) | 779/149/30 (13) | 0.498 / 0.592 | 603 / 649 |
| full35 | 772/156/20 (8) | 813/115/30 (16) | 0.597 / 0.607 | 613 / 637 |
| A1 | 752/176/13 (5) | 824/104/31 (13) | 0.506 / 0.637 | 607 / 663 |
| A2 | 760/168/13 (4) | 825/103/29 (11) | 0.509 / 0.637 | 608 / 663 |
| A3 | 762/166/13 (4) | 827/101/27 (9) | 0.509 / 0.644 | 608 / 665 |

- full29 대비 새로 놓친 악성: full35 14 / 36, A1~A3 0 / 1. 새로 잡은 악성: full35 51 / 70, A1 17 / 46, A2 25 / 47, A3 27 / 49.
- full35가 놓친 악성 복구: 14/14, 35/36(A1~A3). full35의 새 탐지 유지: s1 17~27/51, s2 46~49/70.
- autotel·miasma·chaindrop TP는 A1~A3 모두 full29와 같다(s1 18/16/25, s2 27/22/25). full35는 s2 autotel 10, miasma 9.
- shai-hulud-original TP: full29 132/130 → A1~A3 145~154 / 161~162 (full35 159/176).
- fold별: A1~A3 TP는 6개 fold 모두 full29 이상. FP는 split2 fold2 +2~3, split1 fold1 +1(A2·A3), 나머지 같거나 감소.
- 0.05: 새로 놓친 악성 A1 0/2, A2·A3 0/6 (full35 14/46). **0.5에서는 A ≈ full29**(shai-orig 66/81 → A3 71/83, full35 113/140).
- mini-shai-hulud B유형 40쌍(@tanstack/*, split2 fold1) 중앙 점수: full29 0.97, full35 0.23, A1 0.89, A2 0.82, A3 0.74. 0.5 기준 40/40 유지.
- 순위(진단): fold1 ROC가 full29 수준으로 회복(s1 0.929~0.931, s2 0.950~0.952), fold2는 개선(s1 0.973~0.976, s2 0.982~0.985).
  shai-orig 제외 fold2 PR-AUC s1 0.736 → 0.772~0.790, s2 0.854 → 0.881~0.886(full35 0.851/0.820).

## 3. 해석과 한계

- 확률 공간 선형 결합은 비대칭이다. full35 점수가 높으면 w·s35만큼 더해져 낮은 임계값을 넘고(이득 유지),
  full35 점수가 0이면 full29 점수가 (1-w)배로만 줄어 손실이 거의 없다. 따라서 낮은 임계값(운영점 약 4e-5~0.2, 0.05)에서는
  "둘 중 하나가 높으면 통과"에 가깝고, 0.5에서는 full29와 거의 같다. 효과가 임계값에 따라 달라진다.
- 세 가중치 사이 차이는 작고 단조적이다(w↑: shai-orig 유지↑, mini40 점수↓). 이 결과로 가중치를 고르지 않는다.
- 결합은 학습이 없어 누수는 없지만, D06 outer를 본 진단이다. 채택 판단은 독립 자료에서 해야 한다.

## 4. 파일

```text
blend_eval.py          결합·평가 코드
blend_summary.csv      운영점(cal1)·0.05·0.5별 split 합산: TP/FN/FP, Hard FP, Precision, 캠페인 평균 Recall,
                       shai-orig 제외 TP, full29 대비 새 탐지·새 누락, 복구·유지 수, 집중 캠페인 TP
blend_fold_cal1.csv    운영점 fold별 임계값·TP·FP
blend_ranking.csv      fold별 ROC-AUC·PR-AUC(진단)
blend_outer_rows.csv   outer 행별 full29·full35·A1~A3 점수, 선택 여부, fold 안 순위
```
