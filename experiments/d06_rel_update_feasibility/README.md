# 상대적 업데이트 이상도 Feature 구현 가능성 검토 (조사만)

패키지 자신의 과거 배포 이력에 비해 이번 업데이트가 얼마나 이례적인지를 나타내는 Feature를 검토했다. 구현·추출·학습은 하지 않았다.
registry packument JSON만 읽었고(tarball 없음, 코드 실행 없음), D06 Train에서 클래스별 50쌍(고정 seed 20261124)만 조사했다.

## 1. 후보와 입력

| 후보 | 정의 | 입력 |
|---|---|---|
| `relIntervalRatio` | (T_new − T_old) ÷ T_old 이전 최대 10개 배포 간격의 중앙값 | packument `time` 맵 |
| `oldGapRatio` | T_old 직전 간격 ÷ 그 이전 간격 중앙값 | `time` 맵 |
| `priorReleaseCount` | T_new 이전 배포 수 | `time` 맵 |
| `releasesIn24hBeforeNew` | T_new 이전 24시간 안의 배포 수 | `time` 맵 |
| `unpackedSizeLogRatio` | log(new dist.unpackedSize ÷ old) | 버전 manifest |

## 2. 결과 (`probe/`)

| 클래스 | registry 200 | new·old가 time 맵에 있음 | new manifest 있음 | time 기반 계산 가능 | 크기 계산 가능 |
|---|---:|---:|---:|---:|---:|
| 정상 | 100% | 100% | 100% | 90% | 72% |
| Hard benign | 100% | 100% | 100% | 70% | 94% |
| 악성 | 100% | 100% | **6%** | 88% | **6%** |

- **time 맵 기반 후보는 악성도 계산된다.** 삭제된 악성 버전도 time 항목이 남아 있다(X2 조사와 같은 관찰). 결측은 이전 배포 간격이 2개 미만인 신규 패키지에서만 생긴다(정상 10%, HB 30%, 악성 12%) — 결측이 악성 신호가 되는 패턴은 표본에서 보이지 않았다.
- **manifest 기반(unpackedSize 등)은 악성 94%가 결측**이다. 악성 버전 manifest가 지워졌기 때문이다. X2와 같은 결측 누수 위험이라 registry manifest로는 쓰지 않는다.
  크기 변화가 필요하면 이미 받은 tarball·archive 파일에서 직접 계산해야 하고, 과거 버전 크기 이력은 별도 다운로드가 필요하다.

`relIntervalRatio` 분포(표본):

| 클래스 | 10% | 중앙값 | 90% | >10 비율 |
|---|---:|---:|---:|---:|
| 정상 | 0.09 | 1.41 | 713 | 22% |
| Hard benign | 0.01 | 1.51 | 92 | 20% |
| 악성 | 1.81 | **26.1** | 823 | **60%** |

악성 캠페인별 중앙값: shai-hulud-original 31.6, sha1-hulud 48.5, mini-shai 14.9, individuals_case 42.5, react-native-aria 280, chaindrop 1.3, injective 1.8.
"오래 조용하던 패키지가 갑자기 새 버전을 낸다"는 탈취형 공격 패턴과 맞는다. `releasesIn24hBeforeNew`, `priorReleaseCount`는 클래스 차이가 작다.

## 3. 판단과 위험

- 우선 후보: `relIntervalRatio`(+ `oldGapRatio`). time 맵만 쓰므로 manifest 삭제의 영향을 받지 않고, 표본에서 클래스 차이가 크다.
- 위험
  1. 기존 `updateInterval`과 겹친다(분자가 같다). 패키지별 기준으로 나눈 것이 새 정보다. 추출 후 상관·조건부 효과를 확인해야 한다.
  2. 같은 캠페인의 쌍은 같은 날 배포돼 값이 비슷하다 → component 단위 평가 필수(기존 분할이 그렇다).
  3. time 맵은 조회 시점 상태다. 보안 대체 버전(`0.0.1-security`)은 계산에서 빼야 하고, T 이후 항목은 쓰지 않는다(이 조사 코드는 T 이전만 쓴다).
  4. 정상 패키지도 오래 쉬었다 배포하면 값이 크다(정상 90분위 713) → 단독 규칙이 아니라 모델 입력으로만.
  5. 표본 150쌍이다. 전체 2,767쌍 추출 후 분포를 다시 봐야 한다.
- 비용: 패키지별 packument 1회(Train 고유 패키지 수만큼). 이미 X3 추출과 별도로 가능하다.

## 4. 파일

`probe.py`, `probe/probe_pairs.csv`, `probe/coverage_by_class.csv`, `probe/distribution_by_class.csv`, `probe/registry_log.jsonl`, `probe/manifest.json`
