# D06 X2(신규 의존성) Feature 추출 타당성 조사 — D06 Train 247쌍

**조사만 했다.** X2 추출기 구현, Test 추출, 모델 학습은 하지 않았다. 패키지 코드·설치 스크립트는 실행하지 않았고
registry JSON 메타데이터와 `package.json`만 읽었다. 기존 데이터·실험 결과는 수정하지 않았다.

## 1. 검토 대상 정의 (InstallHookCount는 보류)

- T = parent new 버전의 registry publish 시각 (`packument.time[new_version]`)
- 신규 의존성 = new의 (`dependencies` ∪ `optionalDependencies`) 이름 − old의 이름 (기존 `newDependencyAdded`와 같은 정의). manifest는 출처가 archive면 데이터 저장소 `be87ab4c` archive의 `package.json`, registry면 packument의 해당 버전 manifest.
- `newDependencyMinAgeHours` = min over d (T − `time[d].created`) / 3600
- `newDependencyMinVersionCount` = min over d #{v : `time[d][v]` ≤ T} — **현재 `versions` 목록이 아니라 `time` 맵 기준**(나중에 지워진 버전도 time 항목이 남아 있으면 센다)
- 쌍 상태(Feature 아님): `ok` / `dep_lookup_failed_all` / `dep_lookup_failed_partial`(일부만 성공 — **최솟값을 계산하지 않고 NaN**) / `created_after_T` / `no_new_dependency`(조사 대상 밖)
- 의존성 상태: `ok` / `http_<code>` / `no_time_map` / `no_created` / `created_after_T`

## 2. 결과 (`analysis/`)

### 2.1 확보율 (`coverage.json`)

| 항목 | 값 |
|---|---|
| 대상 쌍 | 247 (악성 103, 무작위 정상 92, Hard benign 52) |
| 계산한 신규 의존성 수 = Train `newDependencyCount` | 247/247 일치 |
| 고유 신규 의존성 / 쌍-의존성 연결 | 321 / 477 |
| parent T 확보 | 247/247 |
| 의존성 선언 형식(고유) | registry 범위 313, git/URL 4, file·link·workspace 4 |
| registry 조회 200 / 404 (고유) | 311 / 10 (404 중 8개는 git/URL·file 형식 선언, 2개는 범위 `*`로 선언됐지만 registry에 없는 패키지(Hard benign)) |
| time 맵 확보 (고유) | 311/321 |
| **두 Feature 모두 계산 가능한 쌍** | **153/247 (61.9%)** |
| Feature가 NaN인 쌍 | **94/247** = 조회 실패 92(전부 실패 67 + 일부 실패 25) + `created_after_T` 2 |

### 2.2 클래스·캠페인별 실패 (`status_by_class.csv`, `status_by_campaign.csv`, `dep_status_by_spec_type.csv`)

| 클래스 | ok | 전부 실패 | 일부 실패 | created_after_T | 실패율 |
|---|---:|---:|---:|---:|---:|
| 무작위 정상 | 92 | 0 | 0 | 0 | 0% |
| Hard benign | 49 | 0 | 3 | 0 | 5.8% |
| 악성 | 12 | 67 | 22 | 2 | **88.3%** |

- 집계 단위: 아래 "실패"는 Feature가 NaN인 쌍(`ok`가 아닌 쌍)이다. 클래스별 합계는 Hard benign 3 + 악성 91 = 94. 이 중 조회 실패(전부·일부)는 92쌍이고, 나머지 2쌍은 `created_after_T`(악성)다.
- 악성 NaN 91쌍(전부 실패 67, 일부 실패 22, created_after_T 2) 중 89쌍이 mini-shai-hulud(92쌍 중 89)다. 이 캠페인의 신규 의존성은 **registry 버전이 아니라 GitHub 커밋을 가리키는 git 선언**
  (`github:<org>/<repo>#<commit>`, 고유 2개, 47쌍·40쌍이 공유)이라 registry에 없다. 삭제로 인한 조회 실패가 아니라 정의상 registry Feature가 없는 경우다.
- Hard benign 실패 3쌍은 `file:` 경로·git 선언, 그리고 registry에 없는 `*` 범위 의존성(모노레포 내부 패키지로 보임, 확인 안 함)이다.
- `created_after_T` 2쌍(axios_2026-03 1, individuals_case 1): 의존성이 나중에 보안 대체 패키지(`0.0.1-security`)로 바뀌면서 `created`가 T 이후로 다시 쓰였다.
  한 의존성은 당시 설치 범위(`^0.1.0`)에 해당하는 버전의 time 항목조차 남아 있지 않다(`dependency_time_integrity.csv`).

### 2.3 Feature 분포 (계산 가능한 153쌍, `feature_distribution_by_class.csv`)

| 클래스 | n | MinAgeHours 중앙값 | 24시간 미만 | 7일 미만 | 30일 미만 | MinVersionCount 중앙값 | ≤1 | ≤3 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 무작위 정상 | 92 | 22,695 (≈2.6년) | 4% | 8% | 9% | 15 | 8% | 17% |
| Hard benign | 49 | 24,756 (≈2.8년) | 8% | 12% | 20% | 15 | 10% | 22% |
| 악성 | 12 | 80,201 (≈9.2년) | 0% | 8% | 8% | 97 | 0% | 17% |

- **D06 Train에서는 "생성된 지 얼마 안 된 의존성"이 악성보다 정상·Hard benign에 더 많다.** 계산 가능한 악성 12쌍의 MinAgeHours 중앙값은 약 9.2년으로, 대부분 오래된 일반 패키지를 추가했다.
  Test의 mastra 같은 "새로 만든 의존성" 악성 사례가 Train에는 사실상 없어, 이 Feature를 넣어도 Train에서 "새 의존성 = 악성"을 학습할 근거가 거의 없다.

### 2.4 같은 의존성을 공유하는 그룹 (`shared_dependencies.csv`)

- 2쌍 이상이 공유하는 의존성 36개. 상위: git 선언 2개(47쌍·40쌍, mini-shai 단일 component), 런타임 패키지 1개(26쌍, mini-shai·miasma-leoplatform 2 component).
- 클래스를 넘어 공유되는 의존성 11개(대부분 정상·Hard benign이 함께 쓰는 일반 라이브러리, 1개는 Hard benign·악성).
- 캠페인 안에서 같은 의존성을 공유하면 X2 값이 캠페인 안에서 거의 상수가 된다. component 단위 분할 없이 평가하면 캠페인 암기가 성능처럼 보일 수 있다.

### 2.5 최근 생성된 정상 의존성 (`young_dependencies_non_malicious.csv`)

- 집계 단위: 파일의 21행은 **쌍-의존성 연결** 단위(T 기준 나이 30일 미만)이며, 고유 의존성도 21개다. 이 연결이 속한 **쌍**은 18개(무작위 정상 8, Hard benign 10)다.
  한 쌍이 여러 개를 가진 경우: 무작위 정상 1쌍에 2개, Hard benign 1쌍에 3개(플랫폼별 하위 패키지).
- 2.3절 표의 "30일 미만" 비율은 쌍 단위 최솟값 기준이다(무작위 정상 8/92 ≈ 9%, Hard benign 10/49 ≈ 20%).

- 플랫폼별 바이너리 하위 패키지(나이 0.0005~0.009시간, 버전 1개), 같은 조직의 형제 패키지(0.04~0.27시간), 새 유틸리티(0.06시간) 등.
- Test mastra 사례(생성 18.6~19.0시간, 당시 버전 2개)와 값이 겹친다. 이 Feature 하나로는 정상 모노레포 릴리스와 구분되지 않는다.

### 2.6 NaN이 악성 신호가 될 위험 (`nan_signal_risk.csv`)

| 신규 의존성이 있는 247쌍 | 무작위 정상 | Hard benign | 악성 | P(악성) |
|---|---:|---:|---:|---:|
| Feature 계산됨 | 92 | 49 | 12 | 0.078 |
| Feature NaN (조회 실패 92 + created_after_T 2 = 94쌍) | 0 | 3 | 91 | **0.968** |

- LightGBM은 NaN을 별도 분기로 학습하므로, `newDependencyAdded=True`이면서 X2=NaN이면 거의 확실히 악성이라는 규칙을 배울 수 있다.
  그 내용은 실제로는 "mini-shai-hulud의 git 의존성 선언"(한 캠페인)과 "보안 대체 패키지로 바뀐 의존성"(사후 정보)이다.
- 따라서 X2를 이대로 넣으면 (a) 캠페인 지문, (b) 사후 삭제 정보가 NaN을 통해 누수된다.

## 3. 판단

**결정(2026-11-24): 현재 정의의 X2 Feature(`newDependencyMinAgeHours`, `newDependencyMinVersionCount`)는 채택 보류.** InstallHookCount는 과거 버전 원본 확보 전까지 보류.


- `newDependencyMinAgeHours`·`newDependencyMinVersionCount`는 registry 범위 선언 의존성에 대해서는 time 맵으로 대부분 계산된다(정상 100%, Hard benign 94%).
- 그러나 (1) 악성의 88%가 NaN이고 그 대부분이 registry 밖 git 선언이며, (2) Train에는 "새로 만든 registry 의존성" 악성이 거의 없고, (3) 정상 모노레포 릴리스가 같은 값 범위를 가진다.
  지금 형태로는 Train에서 의미 있는 신호를 배우기 어렵고, NaN 누수 위험이 크다.
- 검토할 만한 방향(미구현): 의존성 선언 형식(registry 범위 / git·URL / file·workspace)을 별도 정보로 분리해 NaN과 섞지 않기,
  `created` 대신 T 이전 첫 버전 time을 쓰는지 비교, 보안 대체 패키지 여부 같은 사후 정보는 계산에서 제외하고 해당 쌍을 명시적으로 기록.
  이런 변경도 새 Feature 정의이므로 사전 기록 후 진행해야 한다.

## 4. 파일

```text
review/X2_REVIEW.md                         Test mastra 3쌍 조사 메모 (조회 시각·출처 포함)
review/easy-day-js.packument.2026-11-24.json 그 조사의 registry 응답 사본
review/CORRECTION_es_followup_README.md     ../d06_es_followup/README.md 2.2절 정정
x2_feasibility.py                           247쌍 조사 (registry 메타데이터·package.json만 읽음)
x2_analysis.py                              요약 (네트워크 없음)
run/pairs.csv                               쌍별 상태·신규 의존성 수·T·두 Feature
run/pair_dependencies.csv                   쌍-의존성별 선언 범위·조회 상태·나이·T까지 버전 수
run/registry_query_log.jsonl                registry 조회 기록 556건 (URL, 조회 시각, HTTP 상태, time 맵, 당시 versions 목록)
run/manifest.json
analysis/*.csv, coverage.json, manifest.json
```

주의: 패키지 이름 `nan`이 실제로 존재해 pandas 기본 읽기에서 결측으로 바뀐다. `x2_analysis.py`는 `keep_default_na=False`로 읽는다.
실행: `python -I -B x2_feasibility.py --train <be87 train.csv> --baselines <be87 baselines.csv> --archive-repo <be87 부분 사본> --out run` 후 `python -I -B x2_analysis.py --run run --out analysis`.
registry 상태가 바뀌므로 다시 실행하면 결과가 달라질 수 있다. 조회 시각은 `run/registry_query_log.jsonl`에 있다.
