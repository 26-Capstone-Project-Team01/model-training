# D06 후속 개발 실험: Early stopping (base7·full35) + Dependency Feature 조사

**성격: 이미 평가한 D06 Test를 다시 쓰는 사후 개발 실험이다**(사전 등록 평가 아님). 조건은 실행 전에 `ES_PLAN.md`로 기록했다.
Test 결과로 트리 수·조건·모델을 고르지 않았고, 최종 모델은 정하지 않았다. Dependency Feature는 조사만 했고 구현·추출하지 않았다.

## 1. Early stopping

### 1.1 절차 (`ES_PLAN.md`, `es_eval.py`)
- Fit/Calibration은 `../d06_test_eval` 배정 그대로(실행 시 일치 검사). Fit 안에서만 스냅샷 `inner_split(fit, seed)`로 component 단위 Sub-fit / Validation(클래스별 약 25%), `check_disjoint` 통과.
- Sub-fit 학습, Validation `binary_logloss` 감시, 최대 200 rounds, `early_stopping(50, first_metric_only=True)` → B = `best_iteration`.
- 같은 파라미터로 Fit 전체에서 B rounds 재학습. 임계값은 기존 Calibration(목표 FPR 5% 주, 1·3% 보조, 0.5 참고).

### 1.2 결정된 트리 수 (`run/early_stopping.csv`)

| seed | 모델 | B | Validation 악성 (주요 캠페인) | Validation logloss 1회 → 최저 |
|---|---|---:|---|---|
| 20261109 | base7_es | 20 | 242 (shai-hulud-original 186, react-native-aria 17, individuals 13) | 0.656 → 0.426 |
| 20261109 | full35_es | 19 | 〃 | 0.653 → 0.335 |
| 20261110 | base7_es | 37 | 335 (sha1-hulud 332, individuals 3) | 0.689 → 0.139 |
| 20261110 | full35_es | 190 | 〃 | 0.676 → 0.0006 |

Validation 악성이 seed마다 캠페인 하나(shai-hulud-original 또는 sha1-hulud)에 거의 전부 몰린다. seed20261110의 full35는 Validation이 거의 완벽히 분리돼 200에 가까운 B가 나왔다.

### 1.3 Test-674, calibration 목표 FPR 5% (`run/metrics.csv`, 각 칸 seed20261109 / seed20261110)

| 모델 | 트리 | TP | FP | Hard FP | Recall | Test FPR | PR-AUC | ROC-AUC |
|---|---|---|---|---|---|---|---|---|
| base7 (200) | 200 / 200 | 80 / 145 | 25 / 19 | 12 / 13 | .374 / .678 | 5.43 / 4.13% | .714 / .860 | .833 / .935 |
| base7_es | 20 / 37 | 84 / 146 | 26 / 22 | 15 / 14 | .393 / .682 | 5.65 / 4.78% | .700 / .873 | .833 / .945 |
| full35 (200) | 200 / 200 | 104 / 121 | 34 / 20 | 9 / 4 | .486 / .565 | 7.39 / 4.35% | .789 / .881 | .879 / .948 |
| full35_es | 19 / 190 | 98 / 121 | 21 / 22 | 11 / 6 | .458 / .565 | 4.57 / 4.78% | .733 / .879 | .786 / .948 |

캠페인별 TP (Test-674, 5%, `run/campaign_recall.csv`):

| 캠페인 (n) | base7 | base7_es | full35 | full35_es |
|---|---|---|---|---|
| canisterworm (68) | 68 / 68 | 68 / 68 | 68 / 68 | 68 / 68 |
| mastra-easy-day-js (119) | 4 / 71 | 7 / 69 | 10 / 27 | 5 / 27 |
| debug-chalk-duckdb (17) | 2 / 0 | 1 / 1 | 17 / 17 | 17 / 17 |
| rspack-vant (7) | 5 / 5 | 7 / 7 | 7 / 7 | 7 / 7 |
| individuals_case (3) | 1 / 1 | 1 / 1 | 2 / 2 | 1 / 2 |

1%·3%·0.5와 Test-677은 `run/metrics.csv`, `run/campaign_recall.csv`.

### 1.4 관찰 (확인된 사실)
- Early stopping은 TP를 크게 바꾸지 않았다(5%에서 base7 +4 / +1, full35 −6 / 0). FP·Hard FP는 base7에서 조금 늘었다.
- mastra 탐지는 early stopping 후에도 seed에 따라 4~7 vs 69~71(base7)로 갈린다. 트리 수가 아니라 fit 구성(4.1절, `../d06_test_followup` 4.1)이 좌우한다.
- full35_es seed20261109(19트리)는 PR-AUC·ROC-AUC가 200트리보다 낮다(.733 vs .789, .786 vs .879).
- Validation이 단일 캠페인에 지배돼 B가 seed마다 19~190으로 크게 다르다. 이 데이터 구성에서는 Validation 기반 트리 수 결정 자체가 불안정하다.

## 2. Dependency Feature 조사 (구현 안 함)

### 2.1 현재 기능
- **depbee-analyzer `d56738c`** `extractors/package_json.py`:
  `newDependencyAdded` = new의 의존성 이름 집합 − old의 의존성 이름 집합이 비어 있지 않음, `newDependencyCount` = 그 개수.
  대상 필드는 `dependencies`, `optionalDependencies`만(`devDependencies`·`peerDependencies` 제외). 이름만 비교하며, 버전 범위 변경·추이 의존성·의존성의 내용은 보지 않는다.
- **depbee** (`origin/main` `863efe6`, 로컬 사본은 `7681386`으로 뒤처짐):
  - `analysis/extractor.py`: 같은 이름 차집합으로 "새 의존성 N개: 이름…" 근거 문구(최대 5개 이름)를 보고서에 남긴다. 모델 Feature는 위 2개뿐.
  - `inputs/npm.py`: lockfile 모드에서는 바뀐 lockfile 항목마다 분석하며, **새로 추가된 의존성 항목도 분석 대상**이다(그 패키지의 registry 직전 버전과 비교). 기지 악성 색인은 lockfile 항목별로 확인한다.
  - 단일 패키지 검사 모드와 학습 데이터(버전 쌍)에서는 추가된 의존성 자체를 분석하지 않는다.

### 2.2 신규 의존성의 당시 버전·메타데이터
- new 버전의 `package.json`에서 의존성 이름과 버전 범위(예 `^1.11.21`)를 얻는다. tarball에는 lockfile이 없어 실제 설치 버전은 모른다.
- registry packument의 `versions`·`time`으로 **new 버전 publish 시각 T 이전에 publish된 버전 중 범위를 만족하는 최고 버전**을 "당시 버전"으로 근사할 수 있다(설치 시각은 T 이후일 수 있으므로 근사다).
- 확인(사례 조사, Feature 아님): Test mastra 3쌍은 모두 의존성 1개를 새로 추가했고 범위는 `^1.11.21`, 그 의존성 패키지는 registry에 1개 버전만 있으며 생성 시각이 mastra 새 버전 publish 18.6~18.7시간 전이다. 그 버전 manifest의 scripts에 설치 훅(preinstall/install/postinstall)은 없다.

### 2.3 추출 가능한 후보 신호 (모두 의존성 패키지 일반 속성, 이름 자체는 쓰지 않음)

| 후보 | 얻는 방법 | 비용 | 비고 |
|---|---|---|---|
| 의존성 나이: T − 의존성 패키지 최초 publish 시각, T − 당시 버전 publish 시각 | packument `time` | 의존성당 packument 1회 | mastra 사례에서 18.6시간 |
| T 시점 의존성 버전 수, 유지 기간 | packument `time`을 T로 자름 | 같음 | |
| 당시 버전의 설치 훅 존재 | packument `versions[v].scripts` | 같음(tarball 불필요) | mastra 사례에서는 없음 |
| 당시 버전 코드의 정적 신호(난독화, X1 실행·통신 호출) | 의존성 tarball 다운로드 후 기존 추출기 적용 | tarball 다운로드 + 추출기 적용 방식 설계 필요(현재 추출기는 old/new 쌍 비교용) | 패키지 코드는 실행하지 않음 |
| 기존 의존성의 범위 변경 | old/new `package.json` | 없음 | 현재 Feature에 없음 |

### 2.4 중복
- `newDependencyAdded`·`newDependencyCount`와는 "추가 여부/개수"가 겹친다. 위 후보는 추가된 의존성의 **성질**이라 겹치지 않는다.
- 운영 depbee의 lockfile 모드는 추가 의존성을 별도 항목으로 분석하므로, 같은 정보를 서비스에서 이중으로 볼 수 있다. 모델 Feature로 넣을지, 서비스의 별도 판정으로 둘지 결정이 필요하다.

### 2.5 정상·Hard benign 적용
- 새 의존성이 있는 쌍: Train 무작위 정상 92/1,600, Hard benign 52/239, 악성 103/928. Test 무작위 정상 23/400, Hard benign 8/60, 악성 124/217.
- 정상·Hard benign의 의존성도 registry 패키지이므로 같은 절차로 추출할 수 있다. 의존성이 없는 쌍은 "해당 없음"으로 결측 처리해야 한다(0으로 채우면 "나이 0"과 섞인다).

### 2.6 누수·사후 정보 위험
- **T 이후 정보 금지**: 현재 다운로드 수, 현재 버전 수, deprecated 표시, `0.0.1-security` 같은 보안 대체 버전, 이후의 OSV·GitHub 권고, 현재 maintainer는 쓰면 안 된다. packument `time`을 T로 잘라 쓴다.
- **삭제·비공개된 의존성**: 악성 의존성이 나중에 registry에서 지워졌다면 메타데이터를 못 얻는다. "가져오기 실패"가 악성과 상관돼 결측 자체가 정답을 흘릴 수 있다. 실패 비율을 클래스별로 기록하고, 결측 지시 변수는 Feature로 쓰지 않는 것을 권한다. (loader docstring에 따르면 registry는 unpublish 후에도 `time` 항목은 남기는 것으로 관찰됐지만 공식 계약이 아니다.)
- **캠페인 지문화**: 같은 캠페인 쌍들이 같은 의존성을 공유한다(mastra 3쌍 모두 같은 의존성). 의존성 나이 같은 값은 캠페인 안에서 거의 상수라, 학습 캠페인 하나를 외우는 Feature가 될 수 있다. 캠페인·component 단위 분할 평가가 필수다.
- **데이터 저장소 스냅샷 시점**: 추출을 지금 하면 registry 상태가 학습 데이터 수집 시점과 다를 수 있다. 조회 시각을 manifest에 남겨야 한다.
- 특정 의존성 이름(예: 사례의 의존성 이름)이나 알려진 악성 목록 일치 여부를 Feature로 쓰지 않는다.

## 3. 파일과 재현

```text
ES_PLAN.md                     실행 전 조건 기록
es_eval.py                     Sub-fit/Validation 분할, early stopping, Fit 재학습, 평가
run/early_stopping.csv         모델·seed별 B, Validation logloss, Sub-fit/Validation 구성
run/subfit_validation_split.csv
run/models/                    base7_es·full35_es × 2 seed (Fit 전체, B rounds)
run/scores_es.csv              calibration·Test 점수
run/thresholds.csv, metrics.csv, campaign_recall.csv
run/manifest.json              입력·출력 해시, ES_PLAN 해시
```

실행: `python -I -B es_eval.py --workspace <ws> --groups <be87ab4c malicious_pair_groups.csv> --out run` (`<ws>`는 `../d06_test_eval/README.md` 7절과 같다).
