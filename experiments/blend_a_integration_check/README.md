# full29+full35 결합(Blend A)의 depbee 연동 가능성 확인 (EXP-BLEND-01)

full29와 full35 두 LightGBM 모델의 점수를 가중 합산하는 결합(A1~A3)과 X1 추출기를 depbee에 연동할 수 있는지, 처리비용과 배포 방식이 어떤지를 확인한 작업의 정리다.
재학습과 모델 fit을 하지 않았고 `test.csv`와 Test 677을 읽지 않았으며 추출기를 실행하지 않았다.
저장된 fold 모델과 저장 점수만 썼고 새 모델 파일을 만들지 않았다.
이 문서는 최종 모델, 비율, 임계값을 고르지 않는다.
전체 보고서는 `temp/exp-blend-01/report.md`(저장소 밖)이고 이 문서는 그 요약이다.
아래 수치는 모두 그 보고서와 `results/blend_a_integration_check/`의 값이다.

## 1. 결론: 조건부 가능

두 모델의 점수를 가중 합산해 점수 하나와 임계값 하나로 판정하는 구조는 depbee의 예측기 계약 안에서 구현할 수 있다.
지금 바로 연동할 수는 없다. 배포할 모델과 임계값이 없고, X1 추출기가 Draft PR이며, X1의 설치 훅 입력이 학습 때와 depbee에서 서로 다른 출처에서 온다.

가능하다고 본 근거는 다음과 같다.

- 예측기를 바꿔 끼우는 지점이 좁다. depbee의 `pipeline.scan()`은 예측기의 `predict()`, `threshold`, `model_id`, `feature_schema`와 선택 속성 `explain`, `identity`만 쓴다.
- 기지 악성 우선 판정은 점수 계산 뒤의 별도 분기라서 결합 예측기를 넣어도 건드릴 이유가 없다.
- 저장된 fold 모델이 depbee와 같은 입력 인코딩으로 저장 점수와 같은 점수를 내고, 저장 점수 결합이 원래 수치를 재현한다(3절).
- X1 추출기는 표준 라이브러리만 쓰는 정적 분석이고 분석기 패키지 안의 선택형 extractor다.
- 모델을 2개 쓸 때 늘어나는 로드와 추론 비용이 작다(3절).

## 2. 연동 전에 풀어야 하는 조건

| 번호 | 조건 | 보고서 절 |
|---|---|---|
| C1 | 배포할 full29, full35 모델이 없다. 저장소와 로컬에는 fold 모델만 있다 | 3.1, 3.2 |
| C2 | 임계값을 정하는 규칙이 없고, 정한 임계값을 검증할 독립 보정 데이터도 없다. A2의 fold별 운영점은 fold에 따라 3,118.685배까지 다르고 정상 점수 4번째 값 하나로 정해진다. 공유 임계값 안(T1, T2)의 보정 행은 다른 fold의 outer 평가 행과 겹쳐서(정상 행 기준 split1 806개, split2 804개) 지금의 outer 지표로는 배포용 공유 임계값을 검증할 수 없다 | 3.4 |
| C3 | X1 추출기가 depbee-analyzer Draft PR #17이고 depbee의 분석기 고정 커밋에 없다 | 4.1, 4.3 |
| C4 | X1 설치 훅 feature의 입력이 학습 때는 tarball의 `package.json`, depbee에서는 registry 메타데이터다. 값이 달라질 수 있고 크기는 확인하지 못했다 | 4.6 |
| C5 | X1 결측(NaN) 정책이 없다. 저장된 full35 fold 모델은 split에 따라 NaN을 다르게 처리한다 | 4.4 |
| C6 | 모델 묶음 형식과 출력 계약이 단일 모델 전제다. 지금 설명(SHAP) 계약은 확률 결합 점수에서 성립하지 않는다 | 2.6, 5 |
| C7 | A1~A3 수치는 이미 여러 번 본 D06 개발자료의 진단이다. 독립 검증과 Test 677 1회 평가는 최종 모델을 정한 뒤의 일이다 | 3.4, 7 |

## 3. 재현 결과와 핵심 수치

결합 점수는 `(1 - w) * full29 + w * full35`이고 w는 A1 0.1, A2 0.2, A3 0.3이다. 점수 행은 `(seed, fold, stage, row_id)`로 1:1 대응하는 8,548행이다.
아래는 모두 D06 개발자료의 fold 모델과 저장 점수로 낸 진단이고 배포 모델의 값이 아니다.

| 항목 | 값 |
|---|---|
| 원래 수치 재현 | `a4a5280`의 full29, full35, A1, A2, A3 값 190개(요약 100, fold 90)가 부동소수 값까지 모두 같았다. A2는 38개 비교가 모두 일치한다(`repro_vs_a4a5280.csv`) |
| A2, calibration FPR 1% 운영점(outer) | TP / FN / FP가 split1 760 / 168 / 13, split2 825 / 103 / 29로 원래 값과 같다 |
| 점수 일치 | fold 모델 12개로 저장 점수 17,096개를 batch 예측으로 다시 냈고, 단일 행 예측의 A2 표본 1,200개 비교까지 합친 최대 차이가 2.2e-16이다. 단일 행 비교의 기준은 저장된 A2 점수 열이 아니라 저장된 구성 모델 점수 두 열로 재구성한 A2다. 표본 1,200개는 모두 악성 행이다 |
| 임계값 배율 | A2의 fold별 운영점 임계값 여섯 개의 최소와 최대가 3,118.685배 다르다. calibration 정상 행은 fold마다 306~308개이고 1% 예산이 3이라 임계값이 정상 점수 4번째 값 하나로 정해진다 |
| 공유 임계값 안의 겹침 | T1(평균)과 T2(중앙값)의 보정 정상 행이 평가 행과 겹친다(split1 806개, split2 804개, 자기 fold 안에서는 0개) |
| 학습 CSV 대조 | 저장된 35개 feature CSV(2,767행)의 키 3열, 29개 feature, `label`이 D06 `train.csv`와 문자 단위로 같다(다른 칸 0개, `feature_csv_checks.json`) |

모델을 1개에서 2개로 늘릴 때의 비용이다(Windows 11 PC 한 대, Python 3.13.5, LightGBM 4.7.0, fold 쌍 6개의 중앙값).

| 측정 | 모델 1개(full29) | 모델 2개(full29+full35) | 차이 |
|---|---:|---:|---:|
| 로드, 프로세스의 첫 예측 전 | 135.4 ms | 260.5 ms | +125.2 ms |
| 로드, 예측을 한 번이라도 한 뒤 | 85.8 ms | 171.2 ms | +85.5 ms |
| 예측, 행 하나씩 | 36.1 µs/행 | 76.7 µs/행 | +40.7 µs |
| 설명(`pred_contrib`), 행 하나씩 | 716.6 µs/행 | 1,477.6 µs/행 | +761.0 µs |

X1 추출이 depbee 안에서 더하는 시간은 재지 않았다. 학습용 X1 추출의 과거 기록(2,767쌍, 소스 준비 시간 포함)은 중앙값 0.71초, 최대 285.79초이고 300초를 넘은 것은 0건이다.

## 4. 남은 결정

팀이 정해야 하고 이 작업은 고르지 않았다.

1. 출력 계약 버전. 보고서의 계약안은 필드를 더하기만 하고(`provenance.model_bundle`, `score_components`) `schema_version` 1 유지를 제안하지만 유지 여부는 팀 결정이다. depbee 계약 문서는 필드를 바꿀 때 팀 합의 후 `schema_version`을 올린다고 정한다. 결합 실행에서는 `provenance.model`이 null이라 그 값만 읽는 옛 소비자가 모델 출처를 잃으므로, 구현 전에 버전 결정과 묶음용 재현 규칙을 depbee의 두 계약 문서에 적어야 한다.
2. 독립 보정 데이터. 배포할 모델 쌍의 학습에 쓰지 않았고 임계값을 검증하는 평가 행과도 겹치지 않는 자료가 필요하다(C2).
3. 모델, 비율, 임계값. 배포할 full29, full35 모델 쌍(C1), 비율(A1 0.1, A2 0.2, A3 0.3), 임계값 규칙(보고서 3.4절의 선택지 T1~T7)이고 2026-11-27 팀 결정으로 남아 있다.
4. 그 밖에 X1 PR #17 병합과 분석기 고정 커밋(C3), X1 설치 훅 입력 차이의 확인(C4), NaN 정책(C5), 결합 점수의 설명 필드 안(C6)이 남아 있다.

## 5. 미검증 항목

보고서 8절의 19개 항목을 묶어 적는다. 프로토타입은 depbee의 코드를 바꾸지 않았고 depbee의 클래스 자체를 실행하지 않았다.

- depbee 경로로 뽑은 X1 값이 학습 CSV와 같은지, registry 메타데이터의 `scripts`와 tarball `package.json`의 `scripts`가 다른 빈도와 원인. 추출기를 실행해야 안다.
- D06 `train.csv`의 29개 feature를 만든 분석기 커밋과 명령.
- depbee 안에서 X1이 더하는 추출 시간, 변경당 300초 예산을 넘는 패키지의 비율, symlink가 든 npm tarball의 빈도.
- 배포 모델의 크기, 로드 시간, 추론 시간, 점수 분포. 배포 모델이 없어 fold 모델로 쟀고 Linux와 GitHub Actions 러너에서는 재지 않았다.
- depbee-analyzer PR #17의 테스트 통과 여부, CI 결과, 리뷰 승인 상태.
- 결합 묶음을 넣은 depbee의 실제 동작(CLI, Actions, Docker, MCP, 대시보드)과 `score_components` 안 설명 필드에 대한 MCP 문자열 규칙.
- 임계값의 독립 보정과 선택 근거. fold별 운영점과 T1~T3은 모두 같은 개발자료 안에서 계산했다.
- 과거 실험의 Test 집계 지표가 작업 중 출력된 일의 영향. Test 행 자료는 읽지 않았고 그 지표를 계산에 쓰지 않았지만 이후 판단에 준 영향은 확인할 수 없다.
- 정상 행의 단일 행 예측 시간과 점수 일치. timing 표본 1,200개가 전부 악성 행이다.
- 재지 않은 서빙 비용. 디스크와 manifest 읽기, depbee의 feature 인코딩, 기여도 순위 정리, 출력 렌더링, 요청 하나의 전체 시간이다.
- 부수 timing 시행(`dump_model()` 비중, 스레드 수 상태별 로드 시간)의 관측값. 커밋한 결과 파일에 없어 감사할 수 없다.
- 실행하지 않은 호환성 검사 네 가지. 실제 v1 소비자의 결합 보고서 출처 검증, 구성 모델 하나가 실패한 항목에서 기지 악성 우선 유지, `feature_schema` 불일치 때의 요청 전체 중단, 분석기 고정 커밋을 올리기 전과 후의 캐시 동작이다.
- 팀원 기기에 개발 데이터 전체로 학습한 모델이 있는지, 배경 문서(Notion) 원문, 원인 분석과 W1 실험의 결과. 확인하지 않았고 근거로 쓰지 않았다.

## 6. 산출물

프로토타입은 `scripts/blend_a_prototype.py`이고 모드가 넷이다.
입력은 `--train-csv`로 주는 파일을 빼면 모두 이 저장소의 git 객체에서 두 고정 커밋(`e267281`, `a4a5280`)으로 읽으므로 두 커밋이 로컬 저장소에 있어야 한다.
checkout을 바꾸지 않고 모델 파일을 쓰지 않으며, 모드마다 검사가 하나라도 실패하면 종료 코드 1로 끝난다. `nan`과 `timing`은 LightGBM이 필요하다.

```bash
python -I -B scripts/blend_a_prototype.py repro      # 저장 점수로 a4a5280의 A1~A3 수치를 다시 내고 원래 값과 비교
python -I -B scripts/blend_a_prototype.py profile --train-csv <D06 train.csv>   # 35개 feature CSV의 열 순서, 자료형, 결측 패턴
python -I -B scripts/blend_a_prototype.py nan        # X1이 결측(NaN)이거나 full35 점수가 없을 때의 결합 판정
python -I -B scripts/blend_a_prototype.py timing     # 모델 1개와 2개의 로드, 단일 행 예측, 설명 시간
```

`--train-csv`는 선택이고 저장소 밖의 D06 `train.csv`를 받는다. SHA-256이 스크립트의 고정값과 다르면 바로 끝나고, 같으면 키 3열, 29개 feature, `label`의 열 목록과 셀을 비교해 다르면 종료 코드가 1이다.

결과는 `results/blend_a_integration_check/`에 있다(UTF-8, LF). `timing.json`은 실행마다 값이 달라지고 나머지 9개는 다시 실행해도 바이트가 같았다.

| 파일 | 모드 | 내용 |
|---|---|---|
| `repro_summary.csv` | repro | 방식(full29, full35, A1~A3), split, 운영점(cal1, cal5)별 outer 요약 지표 |
| `repro_folds.csv` | repro | fold별 임계값, calibration 정상 수와 예산, TP / FN / FP |
| `repro_campaign_recall.csv` | repro | 캠페인별 TP와 Recall |
| `repro_vs_a4a5280.csv` | repro | 원래 값과 재현 값 190개의 비교(`match` 열) |
| `repro_checks.json` | repro | 대응 행 수, 데이터 커밋 일치, 비교한 값과 불일치 수 |
| `threshold_options.csv` | repro | fold별 운영점(참고)과 공유 임계값 안 T1~T3을 적용한 개발자료 진단 |
| `feature_csv_profile.csv` | profile | CSV 39개 열(키 3, feature 35, `label` 1)의 위치, 자료형, class별 빈 칸 수, 값 범위 |
| `feature_csv_checks.json` | profile | 열 순서 검사와 Train 비교 결과 |
| `nan_policy.csv` | nan | X1 결측과 full35 미산출 경우별 TP / FN / FP, 저장 점수 판정 대비 변화 |
| `timing.json` | timing | 측정 환경, fold 쌍별과 전체 중앙값, 저장 점수와의 최대 차이 |

## 7. 근거 기준

| 표기 | 저장소 | 커밋 |
|---|---|---|
| MT | model-training main | `e2672817428f4107bbf41f40cbe78496083b5ab5` |
| MT-A | model-training `origin/exp/d06-x1-blend-a` | `a4a5280ed256924090d8a2b8b1e165324b42eddd` |
| DB | depbee main(작업 시점) | `759cc6880452b178566fe0d3294dadaf1a249d2c` |
| DA | depbee-analyzer `feat/x1-code-context`(Draft PR #17 head) | `d56738c234aae239d82729f964b7dd35f304fa93` |
| DA-main | depbee-analyzer main | `871b26f6bd059a76c5377a78a35b2f0e99824fe3` |

- 보고서의 depbee 인용(파일:줄)은 모두 커밋 `759cc68` 기준이고 depbee-analyzer 인용은 PR #17 head `d56738c` 기준이다.
- depbee main은 이후 `0a68fed`로 바뀌었다. R2 검토서는 `759cc68`과 `d56738c`를 기준으로 확인했고, 두 검토서(R1, R2) 모두 `0a68fed`와의 차이를 다루지 않는다. `0a68fed` 기준 줄 번호는 확인하지 않았다.
- 점수의 데이터 커밋이 `data/SOURCE.json`의 고정 커밋과 같음을 `repro`가 실행 때 확인한다(`repro_checks.json`).

## 8. 검증

구현과 분석은 Claude Code(`claude-fable-5-2`)가 했고 독립 검토는 Revy(Codex `gpt-6.2-astra`, effort `ultra`)가 두 번 했다. 검토서는 저장소 밖에 있고 아래 해시로 식별한다.

| 검토 | 판정 | 지적과 반영 | 검토서 SHA-256 |
|---|---|---|---|
| R1 | '조건부 가능'에 동의 | major 3, minor 3, nit 1건과 추가 기재 요청을 반영 기록 9건으로 반영했다. 저장소에서 바뀐 것은 커밋 `1692620`의 `scripts/blend_a_prototype.py`(profile 종료 검사에 Train 비교를 넣음)이고 나머지는 보고서 수정이다 | `db599ca7ade32df87d90cc5ade88eb07301c4018d1a5f46e48d9def02e05c0f9` |
| R2 | 통과. R1 반영이 '조건부 가능' 결론에 대해 수용 가능하고 새 blocker와 major가 없다 | 새 minor 4건을 보고서에 반영했다. 스크립트와 결과 파일은 바꾸지 않았다 | `050c1553348716cd890e9cf38acc395ce6e7088576039ee350fa535f35de299c` |

R2의 minor 4건과 반영 내용은 다음과 같다.

1. `schema_version` 1 유지는 제안이고 유지 여부는 팀 결정이 필요하다고 명시했다(4절 1번).
2. 단일 행 예측의 비교 기준을 '저장된 A2 점수'에서 '저장된 구성 모델 점수 두 열로 재구성한 A2'로 바로잡았다(3절).
3. 범주형 feature에 문자열이 아닌 값이 오면 `inference_failed`가 아니라 `out_of_training_scope` 경로라고 고쳤다.
4. 단일 모델 보고서의 바이트 동일 요구는 같은 입력, 같은 모델과 분석기 identity, 통제한 측정 필드에서만 성립한다고 범위를 정했다. 분석기 고정 커밋을 올리면 `provenance.feature_extractor`와 `cache_hit`가 바뀔 수 있으므로 그 전후에는 v1 feature 값과 판정의 일치를 따로 요구한다.

R2는 저장된 개발 기록, git 객체, 문서 diff, 정적 코드 읽기로 했고 프로토타입을 다시 실행하지 않았다. R2 minor 반영에 대한 재검토는 받지 않았다.
