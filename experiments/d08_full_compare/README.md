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

## 3. 실행 기록
- stage A(`stageA/`): lock.json sha256 `1c7897da…`, Test 미접근. 재현 가드 8개 모두 통과(no_interval28 D06/D08/M4/M2-r = 기존 M1/M2/M4/M2-r, CV·최종 점수 비트 일치).
  LightGBM 모델 48개 포함. sklearn LR·MLP pickle 8개는 넣지 않고 해시만 lock에 기록(같은 코드·seed로 재생성 가능).
- stage B(`stageB/`): 1차 실행은 Test를 읽은 뒤 sklearn pickle 역직렬화 모듈 경로 오류로 지표 산출 전에 중단됐다(출력 없음).
  `--alt` 인자를 추가해 다시 실행했다. 임계값·모델은 stage A 그대로이며, no_interval28의 Test 결과가 이전 최종 12모델 결과와 같음을 확인했다.
- B3 가중치: D06 학습은 두 seed 모두 full35 단독(1.0/0/0)이 선택되어 B3|D06 = full35|D06과 같다. D08은 logit 결합(0.9/0/0.1, 0.7/0/0.3).

## 4. 결과 요약 (Test-684 개발 평가, seed 20261109/20261110; 전체 `stageB/metrics_by_seed.csv`, `summary_test684_validation.csv`)
| 모델 | 3% Recall | 3% 실제 FPR | 3% HB FPR | 5% Recall | 5% 실제 FPR | 1% Recall | 1% 실제 FPR |
|---|---|---|---|---|---|---|---|
| no_interval28 D06 (=M1) | .250/.295 | .035/.028 | .083/.050 | .371/.411 | .043/.052 | .165/.228 | .009/.015 |
| full35 D06 | .589/.540 | .026/.017 | .050/.017 | .768/.576 | .063/.054 | .567/.496 | .022/.004 |
| full28_noObfNew D06 | .942/.973 | .030/.035 | .050/.100 | .973/.978 | .052/.065 | .763/.531 | .004/.004 |
| full28_noObfNew M2-r | .969/.946 | .054/.033 | .200/.133 | .978/.964 | .076/.052 | .750/.656 | .011/.017 |
| gs24 D08 | .955/.942 | .043/.033 | .183/.133 | .978/.969 | .063/.043 | .719/.580 | .015/.017 |
| C5 D06 | .982/.683 | .026/.020 | .050/.017 | .982/.960 | .057/.057 | .920/.634 | .022/.004 |
| C5 D08 | .973/.942 | .048/.024 | .117/.067 | .982/.969 | .061/.074 | .866/.629 | .024/.007 |
| full28_x3_d D06 | .902/.777 | .046/.015 | .117/.033 | .978/.915 | .072/.039 | .741/.674 | .009/.011 |
