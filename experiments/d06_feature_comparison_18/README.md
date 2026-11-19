# D06 특징 세트 비교 18모델 인계 묶음

D06 개발자료 2,767쌍으로 이미 학습한 LightGBM 모델 18개와 그 분할, 저장 점수, 저장 점수 진단 결과를 한곳에 모았다.
18개는 특징 세트 3개(7개, 29개, 28개) x 내부 분할 2개(split1, split2) x outer 3fold 조합이다.
이 묶음을 만들면서 모델을 다시 학습하거나 추론하지 않았고, 모델 파일은 원 실행 결과의 바이트 그대로다.
같은 개발자료를 반복 평가한 탐색 결과이며 제품 채택, 최종 모델 승인, 운영 임계값 결정을 뜻하지 않는다.

## 1. 시작 순서

1. 묶음이 온전한지 확인한다(모델 로드·추론·학습 없이 표준 라이브러리만 쓴다).

   ```bash
   python -I -B -X utf8 experiments/d06_feature_comparison_18/verify_bundle.py
   ```

   기본 실행은 묶음 무결성만 확인하며 종료 코드 0은 그 통과를 뜻한다. 학습 특징 CSV는 `--train-csv`를 줄 때(5절), class 파일은 이 저장소 안에서 실행할 때만 확인한다. 확인하지 못한 외부 입력은 마지막에 "외부 입력 검증 미완료"로 표시되므로 전체 입력 해시가 통과한 것으로 읽지 않는다.

2. `model_index.csv`(또는 `model_index.json`)에서 18개 모델의 특징 순서, 분할, fold, 원 실행, 해시, 학습 횟수를 확인한다.
3. 3절의 규칙으로 `splits/split1.csv`·`splits/split2.csv`와 `scores/saved_scores.csv`를 모델에 연결한다.
4. `evaluation/summary.md`에서 임계값별 Recall/FN, 검토 후보 수, fold 안 순위, 낮은 점수 악성, 확률 해석 진단을 본다.
5. 학습 조건을 다시 확인하거나 재현하려면 4절과 5절을 본다.

## 2. 18개 조합

| feature_set | 특징 수 | 구성 | 원 variant | split1 원 scenario | split2 원 scenario |
|---|---:|---|---|---|---|
| base7 | 7 | package.json 특징 7개(D06-E06과 같은 7개) | M_base | primary | calibration_seed |
| full29 | 29 | base7 + 난독화 특징 22개 | M_full | primary | calibration_seed |
| no_interval28 | 28 | full29에서 `updateInterval`만 뺌 | M_full_no_interval | posthoc | posthoc_calibration_seed |

모델 이름은 `<feature_set>_<split>_fold<k>`이고 파일은 `models/<모델 이름>.txt`다.
특징 순서는 `model_index.json`의 `feature_sets`와 각 모델 파일의 `feature_names=` 줄에 있다.

실제 트리 수(요청은 모두 200회):

| feature_set | split | fold0 | fold1 | fold2 |
|---|---|---:|---:|---:|
| base7 | split1 | 200 | 200 | 200 |
| base7 | split2 | 200 | 200 | 200 |
| full29 | split1 | 200 | 149 | 200 |
| full29 | split2 | 200 | 200 | 200 |
| no_interval28 | split1 | 200 | 151 | 200 |
| no_interval28 | split2 | 200 | 200 | 200 |

149·151은 요청 횟수 전에 학습이 끝난 모델이며 원 학습 기록(`training.csv`의 `trained_rounds`)과 모델 파일의 트리 수가 같다.
학습 로그는 남지 않았다(`verbosity=-1`). 학습 코드에 검증 세트·callback이 없고 early stopping을 쓰지 않으므로 LightGBM이 더 나눌 분할을 찾지 못해 멈춘 것으로 해석했다(로그 확인이 아니라 코드에 근거한 해석).
early stopping과 outer 자료는 학습 횟수 결정에 쓰지 않았다.

## 3. 분할 정의와 파일 연결

- `row_id`는 입력 `train.csv`의 데이터 행 순서(0부터 2,766까지)다. `scores/row_metadata.csv`에 row_id별 package, old_version, new_version, label, class, campaign, component, outer_fold가 있다.
- `component`는 package, 실제 campaign(개별 사례 묶음인 `individual-compromise*`, `individuals_case`는 제외), 비어 있지 않은 악성 payload 해시(`largestChangedJsSha1`, `changedJsSetSha1`)를 하나라도 공유하면 묶은 연결 그룹이다. 전체 1,893개이고 악성을 포함한 그룹은 56개다.
- outer fold 0/1/2는 component 단위 3fold이고 세 특징 세트와 두 split이 모두 같은 배정을 쓴다. 행 수는 945/911/911, 악성은 332/298/298이다.
- 각 outer fold의 나머지 두 fold(학습 부분)를 component 단위로 다시 fit과 calibration으로 나눈 것이 내부 분할이다. class별로 약 25%를 calibration에 두도록 seed를 쓴 greedy 배정이다.
- split1은 내부 seed 20261109(기본), split2는 내부 seed 20261110(대체)이다. split2는 fit/calibration 배정만 바꾼 것이며 outer fold2와 무관하다.
- 실제 RNG seed는 `inner_seed + outer_fold`다. fold k의 내부 분할은 정렬한 component 목록을 `numpy.random.default_rng(inner_seed + k)`로 섞은 순서로 greedy 배정한다. 이 fold 더하기는 실행 명세의 `inner` 설명에는 없고 두 학습 스냅샷의 코드(`inner_split(..., seed + fold)`)에 있다. 그래서 split1 fold1과 split2 fold0은 같은 RNG seed 20261110을 쓰지만 나누는 행 집합이 다르다.
- stage의 의미: `fit`은 모델 학습, `calibration`은 임계값 같은 기준 조정, `outer`는 평가에만 쓴 행이다. 모델·split·fold마다 세 stage가 2,767행을 중복 없이 나누고 component도 stage 사이에 겹치지 않는다.

| split | fold | fit 행(악성) | calibration 행(악성) | outer 행 |
|---|---:|---:|---:|---:|
| split1 | 0 | 1,365 (447) | 457 (149) | 945 |
| split1 | 1 | 1,437 (518) | 419 (112) | 911 |
| split1 | 2 | 1,298 (379) | 558 (251) | 911 |
| split2 | 0 | 1,292 (373) | 530 (223) | 945 |
| split2 | 1 | 1,332 (412) | 524 (218) | 911 |
| split2 | 2 | 1,330 (411) | 526 (219) | 911 |

`splits/split1.csv`와 `splits/split2.csv`의 열은 `scenario,seed,rounds,fold,stage,row_id,component,model`이다.
같은 split·fold의 배정은 세 특징 세트에서 같지만 원 저장 형식대로 `model`별로 반복 기록해 파일마다 24,903행(3 x 3 x 2,767)이다.
두 파일은 원 저장 점수 진단의 `saved_splits.csv` 49,806행을 seed로 나눈 것이며, `verify_bundle.py`가 두 파일로 원 파일을 바이트 단위로 다시 만들어 SHA-256을 대조한다.

모델과 다른 파일의 연결은 `model_index.csv`의 열로 찾는다.

- 분할: `split_file`에서 `split_filter`(model, seed, fold)가 같은 행.
- 점수: `scores/saved_scores.csv`에서 `score_filter`(model, seed, fold)가 같은 행. stage는 calibration과 outer만 있다.
- 평가 결과: `evaluation/*.csv`에서 `evaluation_key`(model, variant, source_scenario, seed, fold)가 같은 행. fold가 -1인 행은 세 outer fold를 합친 값이다.
- `evaluation/low_by_group.csv`에는 fold=-1 합산 행만 있어 fold별 key로는 행이 나오지 않으므로 model, variant, source_scenario, seed와 fold=-1로 찾는다. `evaluation/cohorts.csv`에는 fold별 행만 있다.

## 4. 입력, 환경, 학습 조건

입력(악성 코드 원본은 포함하지 않는다):

| 입력 | 위치 | SHA-256 |
|---|---|---|
| 학습 특징 CSV | 데이터 저장소 `26-Capstone-Project-Team01/npm-malware-package-pairs` 커밋 `be87ab4cff66fff1980c4a71be8032b6b47225ba`의 `derived/splits/train.csv`(git blob `dc9f3db9df58d0d20295e7226ce5b77b12a7c37a`, 857,767 bytes) | `22fbc8752fff5fff90e40b911f6bf7d187769b4566db957d65a37a16be7d2c23` |
| 악성 payload 그룹 | `provenance/inputs/train_malicious_groups.csv` | `4f894621f8315e386757ac8c89525a1c40636931c5acc8d8c9835802173894a2` |
| class·campaign | 이 저장소의 `results/diagnostics/d06_diag01_pair_predictions.csv` | `877de58c82120e1dcd71dbd934e3349bca79e6d575f4d07594d626f850316c6b` |

- 학습 특징 CSV는 `data/SOURCE.json`이 고정한 것과 같은 커밋의 Train 2,767쌍(악성 928, 정상 1,839 = 무작위 정상 1,600 + 어려운 정상 239)이다. Test 677쌍은 읽지 않았다.
- 악성 payload 그룹 파일은 같은 커밋의 `derived/pairs/malicious_pair_groups.csv`(SHA-256 `b05c9dfd869dde5b9a488d830bebec998c9673a388e835ec1b52c253153d7a7b`)에서 Train 악성 928쌍의 `splitGroup`, `largestChangedJsSha1`, `changedJsSetSha1`만 골라 만든 것이다. 해시 값만 있고 코드는 없다.
- 특징 인코딩: `updateType`은 범주 순서 `[major, minor, patch]`인 pandas Categorical(LightGBM 범주형 특징)이고, 나머지는 float64(불리언은 1.0/0.0)이며 결측은 NaN 그대로다. 모델 파일 끝의 `pandas_categorical` 줄에 범주 순서가 저장돼 있다.
- 실행 환경: Python 3.13.5, lightgbm 4.7.0, pandas 3.0.6, numpy 2.5.3, scikit-learn 1.9.1(원 실행 manifest 기록).
- LightGBM 파라미터: `objective=binary`, `metric=binary_logloss`, `verbosity=-1`, `num_threads=2`, `deterministic=true`, `force_col_wise=true`, `seed=20261109`. `num_boost_round=200`, 검증 세트와 early stopping 없음, sample weight 없음.
- 점수는 `model.predict(X, num_threads=2)` 값이다. 보정하지 않은 위험 점수이며 악성 확률로 해석하지 않는다.

## 5. 원 실행 코드와 복원 경로

| 대상 | 실행 코드 스냅샷 | 실행 명세 |
|---|---|---|
| base7, full29 (12개) | `provenance/phase2_run1_base7_full29/executed_script_snapshot.py` (SHA-256 `049bf00c...`) | `provenance/phase2_run1_base7_full29/evaluation_spec.json` |
| no_interval28 (6개) | `provenance/phase2_run2_no_interval28/executed_script_snapshot.py` (SHA-256 `2a1e060d...`) | `provenance/phase2_run2_no_interval28/executed_spec.json` |

- 두 스냅샷의 SHA-256은 각 실행 manifest가 실행 시작 때 기록한 `script_sha256`과 같다. run2 스냅샷은 실행 중인 모듈이 자기 파일을 복사했고, run1 스냅샷은 실행 직후 같은 해시의 원 스크립트를 복사했다.
- 두 스냅샷은 같은 학습 모듈의 서로 다른 시점 버전이므로 모델마다 `model_index.csv`의 `source_script_snapshot`을 따른다.
- no_interval28 실행은 이 모듈의 `run()`을 부르는 얇은 진입 스크립트(`--prepared-spec` 인자)로 시작했고 그 진입 스크립트의 스냅샷은 남아 있지 않다. 남아 있는 진입 스크립트 기준으로 이 호출은 스냅샷의 `--spec <executed_spec.json>` 실행과 같다(context 입력 없음).
- 두 실행은 명세에 있는 다른 비교 모델도 함께 학습한다(45개, 30개). 이 묶음에는 그중 18개만 넣었다. `provenance/*/training.csv`, `feature_sets.json`, `manifest.public.json`은 원 실행 전체의 기록이다.
- `provenance/phase2_decision_criteria.json`은 실행 전에 등록돼 있어야 하는 판단 보조 기준 파일이다(학습 값에는 쓰이지 않는다). 팀 운영 기준이나 배포 승인이 아니다.

스냅샷은 `--workspace <작업공간>` 아래의 다음 상대 경로를 읽고, 출력은 `<작업공간>/temp/detection-feasibility/phase2/runs/` 아래 새 폴더에 쓴다.

| 스냅샷이 읽는 작업공간 상대 경로 | 가져올 곳 |
|---|---|
| `temp/detection-feasibility/phase1/run_20261108T141426Z_d8b14252/inputs/train.csv` | 데이터 저장소 고정 커밋의 `derived/splits/train.csv` |
| `temp/detection-feasibility/phase1/run_20261108T141426Z_d8b14252/inputs/train_malicious_groups.csv` | `provenance/inputs/train_malicious_groups.csv` |
| `model-training/results/diagnostics/d06_diag01_pair_predictions.csv` | 이 저장소의 같은 경로 |
| `temp/detection-feasibility/phase2/decision_criteria.json` | `provenance/phase2_decision_criteria.json` |
| `temp/detection-feasibility/phase2/evaluation_spec.json`(run1 기본 명세) | `provenance/phase2_run1_base7_full29/evaluation_spec.json` |

학습 특징 CSV는 데이터 저장소 체크아웃에서 bash(Git Bash 포함)로 꺼낸 뒤 해시를 확인한다.
PowerShell의 `>` 리디렉션은 줄바꿈과 인코딩을 바꿀 수 있으므로 쓰지 않는다.

```bash
git -C <npm-malware-package-pairs 체크아웃> show be87ab4cff66fff1980c4a71be8032b6b47225ba:derived/splits/train.csv > train.csv
python -I -B -X utf8 experiments/d06_feature_comparison_18/verify_bundle.py --train-csv train.csv
```

이 묶음을 만들 때 학습 스크립트를 실행하지 않았으므로 재학습 결과가 같은 바이트로 나오는지는 확인하지 않았다.
재현할 때는 4절의 패키지 버전을 맞추고 결과 모델의 SHA-256을 `model_index.csv`의 `model_sha256`과 비교한다.

## 6. 저장 점수와 평가 결과

- `scores/saved_scores.csv`: 18개 모델의 calibration과 outer 점수 25,644행이다(모델·split마다 outer 2,767행). fit 행 점수는 없다. 점수는 원 학습 실행의 `predictions.csv` 값과 같다.
- `scores/row_metadata.csv`: row_id별 쌍 정보와 outer_fold다.
- `evaluation/`: 저장 점수만 다시 읽어 계산한 진단이다(새 학습, 추론, 확률 보정 0회). 계산 명세는 `provenance/phase7_score_eval/executed_spec.public.json`이다.
- 진단 계산 코드(`executed_script.py`, `evaluator_snapshot.py`, `fusion_helper_snapshot.py`, `tests_snapshot.py`)는 이 묶음에 넣지 않았고 경로와 SHA-256만 `provenance/phase7_score_eval/manifest.public.json`에 있다. 따라서 `evaluation/` 수치를 같은 코드로 다시 계산하는 기능은 이 묶음에 없으며, 다시 계산하려면 저장 점수와 계산 명세로 따로 구현해야 한다.

| 파일 | 내용 |
|---|---|
| `summary.md` | 결과 요약(한국어) |
| `thresholds.csv` | 사전 고정 임계값 14개의 TP/FN/FP/TN, 검토 후보 수, 무작위 정상·어려운 정상, campaign·component 단위 값 |
| `ranking.csv` | fold 안 상위 비율 6개의 악성 포함 범위와 동점 처리 |
| `low_scores.csv`, `low_by_group.csv` | 점수 0.01/0.05/0.1 이하에 남은 악성 수와 campaign·component별 분포 |
| `probability_diagnostics.csv`, `reliability_bins.csv`, `score_bins.csv` | Brier, log loss, ECE와 점수 구간별 실제 악성 비율 |
| `recall_examples.csv` | calibration에서 Recall 90%/95%를 맞춘 임계값을 outer에 그대로 적용한 예시 |
| `cohorts.csv` | 모델·fold·stage별 행 수와 악성 비율 |
| `verification.json` | 진단 실행의 자체 검증 결과 |

임계값별 결과와 예시는 운영 기준으로 채택한 값이 아니다. 높은 FPR만으로 후보를 탈락시키지 않으며, 검토 후보에 든 악성은 사람이 확인한 탐지 성공을 뜻하지 않는다.

## 7. 이전 D06-CV01과의 차이

저장소의 D06-CV01(`scripts/run_cv_e06_e09.py`, `results/cv/`)은 이 묶음과 절차가 달라 숫자를 직접 비교하거나 이 18개 중 일부로 대체하지 않는다.

| 항목 | D06-CV01 | 이 묶음 |
|---|---|---|
| 특징 | E06(7개), E09(같은 7개 + 캠페인 가중치) | 7개, 29개, 28개, 가중치 없음 |
| 분할 | `splits/cv_3fold_assignment.csv` | component 3fold + fold마다 fit/calibration 내부 분할 2개 |
| 학습 횟수 | 최대 500회, outer 평가 fold를 early stopping 검증 세트로 사용 | 200회 요청 고정, early stopping 없음, outer는 평가에만 사용 |
| 기준 조정 자료 | 없음 | calibration stage |

팀 기록에서 "추가 18모델"로 부르는 phase3 residual 실행(규칙 적중 행 제외 학습)과도 다른 묶음이다. 그 실행의 모델(29개 특징 전체 학습 6, R_obf 적중 행을 fit에서 뺀 6, R2_and_obf 적중 행을 fit에서 뺀 6)은 이 묶음에 들어 있지 않고, 이 묶음의 모델은 규칙 적중 행을 빼지 않았다.

## 8. 해석 한계

- no_interval28은 run1 결과를 본 뒤 추가한 사후(posthoc) 비교다. 사전에 정한 주 비교가 아니다.
- 2,767쌍은 이미 특징 선택에 쓰인 개발자료이고, 두 split은 같은 행을 다시 쓰므로 독립 관측으로 합치지 않는다.
- outer fold는 3개뿐이고 악성 928쌍 중 716쌍(77%)이 가장 큰 component 3개에 있다. 시간 순서 holdout이나 미래 성능 추정이 아니다.
- 모델·fold마다 점수 척도가 다를 수 있어 서로 다른 모델의 점수를 합쳐 순위를 매기지 않는다. 낮은 점수는 안전 판정이 아니다.
- 이 묶음은 기존 결과의 인계 자료다. 배포 모델 선정, 제품 정책, 임계값 결정은 별도 팀 결정으로 남는다.

## 9. 파일 구성

```text
experiments/d06_feature_comparison_18/
  README.md                 이 안내
  verify_bundle.py          묶음 검증(표준 라이브러리)
  SHA256SUMS                나머지 모든 파일의 SHA-256
  .gitattributes            줄바꿈 변환 금지(바이트 보존)
  model_index.csv / .json   18개 모델 색인과 공통 조건
  models/                   LightGBM native 텍스트 모델 18개(원 바이트)
  splits/                   split1.csv, split2.csv
  scores/                   saved_scores.csv, row_metadata.csv
  evaluation/               저장 점수 진단 결과
  provenance/
    inputs/train_malicious_groups.csv
    phase2_decision_criteria.json
    phase2_run1_base7_full29/     실행 코드 스냅샷, 명세, feature_sets, training, manifest.public
    phase2_run2_no_interval28/    실행 코드 스냅샷, 명세, feature_sets, training, manifest.public
    phase7_score_eval/            진단 명세와 manifest(공개용 사본)
    public_copies.json            원 바이트 사본과 공개용 사본의 원본 해시
```

`*.public.json`은 원 기록의 로컬 절대 경로만 작업공간 상대 경로로 바꾼 사본이다.
원본 파일의 SHA-256과 바이트 수, 바꾼 방법은 `provenance/public_copies.json`에 따로 있다.
모델 txt에는 CRLF 줄이 섞여 있고 일부 원본 JSON·md는 CRLF라서 `.gitattributes`로 줄바꿈 변환을 막았다.

## 10. 검증 범위

`verify_bundle.py`는 다음을 확인하고 하나라도 어긋나면 종료 코드 1로 끝난다.

- `SHA256SUMS`의 모든 파일 해시와 목록 밖 파일 유무
- 18개 선택 key(3 x 2 x 3), 모델 해시와 원 실행 manifest 기록의 일치, 실행 코드 스냅샷 해시
- 모델 파일의 `feature_names` 순서와 색인·원 `feature_sets.json`의 일치, 트리 수와 실제 학습 횟수
- split1/split2의 seed, 모델·fold마다 row_id 2,767개 완전성, fit/calibration/outer 비중복, component 비중복, outer와 `row_metadata`의 일치, 원 `saved_splits.csv` 바이트 재구성
- 점수 행과 분할 calibration/outer row_id의 1:1 대응, 점수 범위, 메타데이터 일치
- 입력 해시: 묶음 안 그룹 파일은 항상 확인한다. 저장소 안 class 파일은 이 저장소에서 실행할 때, 학습 특징 CSV(해시·행 순서·특징 열 순서)는 `--train-csv`를 줄 때만 확인한다. 확인하지 못한 외부 입력은 종료 코드가 0이어도 마지막에 "외부 입력 검증 미완료"로 표시된다.

`sha256sum -c SHA256SUMS`는 묶음 폴더 안에서 실행한다(Linux, Git Bash).
SHA256SUMS는 README.md와 verify_bundle.py까지 포함하므로 묶음 안 파일을 하나라도 고치면 묶음 폴더 안에서 SHA256SUMS를 다시 만들고 `verify_bundle.py --train-csv`를 다시 실행한다.

```bash
cd experiments/d06_feature_comparison_18
sha256sum -c SHA256SUMS
# 파일을 고친 뒤 재생성
find . -type f ! -name SHA256SUMS ! -path '*/__pycache__/*' -printf '%P\n' | LC_ALL=C sort | xargs sha256sum > SHA256SUMS
```
