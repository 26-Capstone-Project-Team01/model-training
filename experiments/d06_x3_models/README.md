# D06 신규 Feature 조합 모델 (PR #13 프로토콜, Train 외부)

`train_variants.py`: 데이터·분할·파라미터는 `../d06_full35_compare/run_full35.py`를 그대로 불러 쓰고 Feature 열만 바꾼다. 200 rounds, 가중치·early stopping 없음.
`evaluate.py`: calibration(PR #13 `calibrate`, ML) 목표 FPR 1·3·5% 임계값, base7·full29·full35 수치가 `../d06_x1_fair_compare/fair_comparison.csv`와 같음을 assert.

## 완료: 학습 경로 검증 (`run_verify/`)
같은 코드로 full35를 다시 학습 → 저장된 full35 점수와 8,548행 모두 같음(CSV 왕복 후 비교).

## 완료: base7 + X1 (13개, `run_x1/`, `eval_x1/`)

| 모델 (calibration 5%) | TP s1 / s2 | FP | HB 오탐 | PR-AUC |
|---|---|---|---|---|
| base7 | 618 / 621 | 111 / 112 | 54 / 34 | .862 / .852 |
| full29 | 797 / 857 | 87 / 129 | 31 / 39 | .947 / .961 |
| full35 | 854 / 876 | 106 / 117 | 50 / 43 | .958 / .969 |
| base7 + X1 | 763 / 717 | 115 / 85 | 44 / 20 | .929 / .910 |

1%: base7+X1 702/652(FP 27/21) vs full35 772/813(20/30). full35 대비(5%) 신규 탐지 13/8, 손실 104/167. 공격 유형 C(JS 변경) 36/48 vs full35 104/102.
판단: 난독화 22개를 빼면 탐지가 크게 준다. 채택하지 않음.

## 예정: X3·D 조합 (full35+X3, base7+X1+X3, full35+D, full35+X3+D, base7+X1+X3+D)
전체 추출 완료 후 `train_variants.py --stage x3d`.
