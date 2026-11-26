# D08 전체 후보 비교: D06 우수 Feature 조합 × D06/D08 학습 데이터 (G2f, clipper 6쌍 제외)

브랜치 `exp/d08-full-model-compare`(main `e267281`에서 생성). 기존 브랜치·실험 결과·데이터는 수정하지 않는다. depbee-analyzer와 DepBee의 Feature 스키마는 바꾸지 않는다.
**D08 Test는 M1~M4-r 평가로 이미 본 데이터이므로 이 폴더의 Test 수치는 모두 개발 평가다.** 임계값은 calibration에서만 정한다.

## 1. Feature 추출 (`extraction/`)
- 대상: D06 Train·Test-677 추출에 없는 D08 pair 2,587쌍 중 clipper 6쌍을 뺀 **2,581쌍**(Train 2,571 + Test 10, 모두 악성).
  D06 행(Train 2,767, Test 674)은 저장된 D06 추출값을 그대로 쓴다.
- 추출기: depbee-analyzer `e45cb4d`(D06 X3/D와 같음, X1 코드는 D06 X1의 `d56738c`와 동일). 추출 스크립트는 D06 것을 그대로 가져와(`vendor/`)
  데이터 commit만 D08 `2c48bd83`으로, 행 목록만 바꿔 실행한다(`extraction/extract_d08_x3d.py`). 정적 분석만 하고 패키지 코드·설치 스크립트는 실행하지 않는다.
- 일치 검증: D06 표본 109쌍(악성 캠페인별·benign·HB·Test 포함)을 D08 commit으로 다시 추출 → X1·X3·D 값이 저장값과 모두 같다.
  기본 Feature는 hard benign `midi` 1쌍 3값(registry 메타데이터와 tarball package.json의 scripts 차이)만 다르며 D06 추출 때 이미 기록된 출처 차이다.
- 일관성: D06 행의 baseline 출처는 D06·D08 `baselines.csv`에서 모두 같고, D06·D08 두 데이터 commit에 공통인 raw 디렉터리 2,288개의 tree가 모두 같다.
- 결과: `extraction/results/` (features_x1x3d_d08.csv, coverage, 결측·오류 목록, parity, provenance).

## 2. 비교 실험 (`run_compare.py` → `eval_compare.py`)
- Feature 세트(정의·열 순서는 D06 코드 그대로): no_interval28, full29, full35, full28_noObfNew, gs24, base7_x1, full28_x3_d, full35_x3_d, B3(full35 LightGBM+LR+MLP), C5(full35/gs24 라우팅).
- 학습 데이터: 모든 세트 D06(fit 중 D06 행) / D08(fit 전체). full35·full28_noObfNew·gs24(와 no_interval28)는 M4·M2-r 가중치도. C5는 full35·gs24가 있는 모든 조건.
- 조건: G2f 5-fold CV(Validation) + 최종 학습(Train 전체, 정상 전용 calibration 460쌍), calibration seed 20261109/20261110, 목표 FPR 1·3·5%, PR #13 LightGBM 파라미터 200 rounds.
- B3 가중치 선택(프로토콜 적용): G2f calibration에 악성이 없으므로 CV fold f는 같은 seed의 나머지 4개 fold OOF PR-AUC로, 최종 모델은 5개 fold OOF PR-AUC로 고른다(Train 라벨만 사용).
- 재현 가드: no_interval28의 D06/D08/M4/M2-r 점수가 기존 G2f 60-run(M1/M2/M4/M2-r)과 최종 12모델과 비트 단위로 같아야 진행한다.
