# D06 범위 축소 후보의 다중 Group Validation · 제한적 하이퍼파라미터 탐색 (준비)

**상태: 코드 준비와 dry run 완료. 전체 실행은 X3/D 추출이 끝난 뒤(같은 CPU를 쓰므로).** 새 Feature·새 알고리즘은 추가하지 않는다.
Train만 쓴다. Test-674는 이미 반복 분석했으므로 이 단계에서도 읽지 않는다.

## 1. 대상 (축소된 후보)

| 후보 | 구성 |
|---|---|
| full35 | LightGBM, 35 Feature |
| gs24 | LightGBM, full35 − obfNew 7 − X1 설치 훅 4 |
| full28_noObfNew | LightGBM, full35 − obfNew 7 |
| B3 | full35 + LR + MLP 블렌드(가중치 calibration 선택, `../d06_alt_models/blend.py` 규칙) |
| C5 라우팅 | rank 척도, JS 변경 없음 & 새 의존성 & 설치 스크립트 추가 없음 → gs24, 나머지 → full35 |

## 2. 다중 Group Validation (`mgv_hpo.py`)

모든 분할은 PR #13 component 단위(같은 패키지·캠페인·payload hash가 train/eval에 걸치지 않음), 내부 fit/calibration은 snapshot `inner_split`.

| 계열 | 셀 | 내용 |
|---|---|---|
| pr13 | 2 split × 3 fold | 기존 프로토콜. 기본 설정 full35가 저장 점수를 재현해야 함(가드, dry run에서 통과) |
| rgk3_s1..s5 | 5 × 3 fold | 무작위 탐욕 component 3-fold: 악성 component를 섞어 악성 행이 가장 적은 fold에, 정상 component는 해당 클래스 행이 가장 적은 fold에 |
| loco | 6 | 악성 행 ≥ 18인 component 하나씩 제외(eval = 그 component + PR #13 fold 0 정상), 보지 못한 캠페인 일반화 |

주의: 악성 component 3개(332·198·186행)가 전체 악성의 77%라 3-fold 분할은 이 셋을 거의 항상 서로 다른 fold에 둔다. rgk3의 다양성은 주로 나머지 캠페인과 정상 배치에서 온다.

## 3. 제한적 하이퍼파라미터 탐색

- 격자 12개: num_leaves {15, 31, 63} × min_data_in_leaf {20, 50} × rounds {100, 200}. 나머지 PR #13 파라미터 고정. 기본값 (31, 20, 200) = PR #13.
- 선택: 계열(pr13 split별, rgk3 반복별, loco)마다 Feature 묶음별로 calibration PR-AUC 평균이 가장 높은 설정. 외부(eval) 라벨은 선택에 쓰지 않는다.
- 보고: 기본 설정과 선택 설정 모두, 목표 calibration FPR 1·2·3·4·5%.
- 규모: 27셀 × (3 묶음 × 12 설정 + LR + MLP). dry run 기준 1셀 기본 설정 약 2.5초 → 전체 약 7분(1스레드). 평가 `mgv_eval.py` 약 수 분.

## 4. 목표와 현재 위치 (기존 Train 외부 결과, 재계산 없음)

목표: **두 split 모두 Recall ≈ 90% 이상, 실제 FPR ≤ 5%.**

calibration 목표 5%는 실제 외부 FPR이 5.8~6.4%로 넘친다(calibration 집합의 정상이 300~400행 수준이라 추정 오차가 있다).
calibration 목표 3%에서는 이미 목표를 만족한다:

| 후보 (calibration 3%) | Recall split1 / split2 | 실제 FPR | HB FPR |
|---|---|---|---|
| full35 | .906 / .927 | .036 / .038 | .130 / .109 |
| C5 라우팅 | .903 / .928 | .034 / .039 | .126 / .109 |
| C4 라우팅(JS 변경 없음 → gs24) | .901 / .925 | .032 / .036 | .121 / .121 |
| B3 | .893 / .930 | .029 / .038 | .092 / .126 |
| gs24 | .888 / .912 | .032 / .035 | .109 / .134 |
| B3 (calibration 1%) | .887 / .903 | .016 / .020 | .054 / .084 |

(출처: `../d06_alt_models/eval_blend/metrics.csv`, `../d06_gs24_followup/eval/metrics.csv`)

따라서 남은 과제는 새 Feature가 아니라 **(a) 이 결과가 다른 component 분할에서도 유지되는지, (b) 운영 목표 FPR(calibration 목표)을 어떻게 정할지, (c) Hard benign FPR(9~13%)** 이다.
MGV에서 운영점 규칙을 미리 정한다: "모든 비-loco 계열에서 실제 FPR ≤ 5%를 만족하는 가장 높은 calibration 목표"를 후보별로 고르고, 그때의 최소·평균 Recall로 비교한다.

## 5. 변경 유형별 라우팅의 Hard benign FPR (기존 결과)

| calibration 목표 | full35 | C4 | C5 | B3 |
|---|---|---|---|---|
| 1% | .033 / .067 | .033 / .063 | .033 / .063 | .054 / .084 |
| 3% | .130 / .109 | .121 / .121 | .126 / .109 | .092 / .126 |
| 5% | .209 / .180 | .205 / .192 | .213 / .176 | .130 / .146 |

Test-674(개발 관찰, 5%, seed09/10): full35 .150/.067, C4 .150/.133, C5 .133/.067, B3 .133/.133.
라우팅은 Hard benign FPR을 바꾸지 않는다(라우팅 대상 영역에 HB가 거의 없음: Train 2쌍, Test 0쌍). HB FPR을 낮추는 것은 B3 쪽(LR/MLP 성분)이다.

## 6. 최종 모델의 독립 검증 조건

1. **데이터**: D06 Train·Test-674와 패키지·component·payload hash·실제 캠페인이 겹치지 않는 새 쌍. 수집·라벨 규칙은 D06과 같게, 수집 전에 고정. Test-674는 개발 평가로만 인용한다.
2. **구성**: mastra 유형(JS 변경 없음·새 의존성·훅 추가 없음) 악성을 별도 층으로 충분히(예: 서로 다른 캠페인 3개 이상) 포함해야 라우팅을 검증할 수 있다. Hard benign도 별도 층으로 둔다.
3. **동결**: 평가 전에 모델(Feature 목록, 하이퍼파라미터, 블렌드 가중치·척도, 라우팅 규칙), 학습 데이터(D06 Train 전체 또는 사전에 정한 부분), calibration 분할과 운영 목표 FPR을 커밋 해시로 고정한다.
4. **사전 등록**: 주 지표(전체 Recall, 실제 FPR, HB FPR, mastra 유형 Recall)와 판정 기준(예: Recall ≥ 0.90 & FPR ≤ 0.05), 비교 대상(full35 기준선), seed를 실행 전에 커밋.
5. **1회 평가**: 결과를 보고 모델·임계값을 바꾸지 않는다. 바꾸면 그 데이터는 개발 데이터가 되고 새 독립 데이터가 필요하다.
6. **불확실성**: 캠페인(component) 단위 부트스트랩 신뢰구간을 함께 보고한다(쌍 단위가 아님).
7. **추출 동일성**: 독립 데이터의 Feature는 같은 추출기 커밋(depbee-analyzer 브랜치 해시)과 같은 소스 처리로 만든다. 패키지 코드는 실행하지 않는다.

## 7. 파일

`mgv_hpo.py`(점수 생성), `mgv_eval.py`(선택·B3·C5·지표). dry run 출력은 저장소에 넣지 않았다(scratchpad).
