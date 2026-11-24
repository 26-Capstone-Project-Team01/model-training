# D06 이후 추가된 악성 pair(D07/D07-B, D08)의 공격 유형 조사

목적: D06 실험에서 미탐이 많았던 **mastra 유사 유형(JS 변경 없이 새 dependency만 추가)** 악성이 새 데이터에 얼마나 있는지 확인한다.
조사만 했다. 데이터 저장소는 git 객체 읽기(`ls-tree`, `cat-file`, `show`)로만 접근했고 lazy fetch를 껐다(`GIT_NO_LAZY_FETCH=1`, 없는 객체는 받지 않고 실패).
패키지 코드는 압축 해제·실행하지 않았고 `package.json` blob과 tree의 blob id만 읽었다.
실행 전후 데이터 저장소의 HEAD(4498acd)와 `git status` 항목 수(1,555,691, 이 clone이 파일을 체크아웃하지 않아 생기는 staged deletion)가 같음을 확인했다.

## 1. 조사 대상 데이터 커밋

| 역할 | 커밋 |
|---|---|
| D06 Train/Test 기준 | `be87ab4cff66fff1980c4a71be8032b6b47225ba` (`derived/splits/train.csv` sha256 22fbc875…, `test.csv` e8a70053…) |
| D07-B 배치 반영(PR #22 직전 main) | `c5b4d32051354299454a4e57f2a08282b10394fb` ("D07-B - add verified pairs and remove erroneous pairs") |
| D08 반영 후 main | `4498acddcf72c7bd6cb91486e59bb92fdf1824fa` (PR #22 merge, Test-674 `test.csv` 604673b9…) |

대상 = `pairs/<campaign>/<pair_dir>/meta.json`이 4498acd에는 있고 be87ab4c에는 없는 pair 2,695개. `pairs/_excluded/`는 깊이가 달라 포함하지 않았다.
D08(PR #22)은 이 중 2개이고(c5b4d32에 없던 것), 나머지 2,693개는 D07/D07-B 배치(collection_round 5)다. be87ab4c의 pair 디렉터리 중 23개는 4498acd에서 사라졌다(오류 pair 삭제).

**주의**: 이 pair들은 아직 Feature 추출·`baselines.csv`·split 반영 전이다(PR #22 본문, 저장소 README). 아래 분류는 정식 Feature가 아니라 근사다.

## 2. 분포 (`run/by_*.csv`, `run/summary.json`)

| 배치 | 차수 | 상태 | pair | A(설치·스크립트 추가) | B(새 의존성) | C(그 외) | mastra 유사 | JS 변경 없음 | 새 의존성 있음 |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| D07/D07-B | 5 | needs_review | 1,168 | 1,144 | 21 | 3 | **1** | 1 | 202 |
| D07/D07-B | 5 | ok | 1,525 | 1,430 | 18 | 77 | **0** | 73 | 65 |
| D08 (PR #22) | 6 | ok | 2 | 2 | 0 | 0 | **0** | 0 | 0 |

캠페인별(`by_campaign_status.csv`): chaindrop 1,719(전부 A), sha1-hulud-second-coming 466(A), mini-shai-hulud 293(A 292), individuals_case 103(A 35·B 8·C 60),
weavedb 34, toptal 24, miasma 23(B 14·C 9), miasma-leoplatform 16(B), shai-hulud-original 6, canisterworm 6, nx 4, bkc_group_4 1.

D08 2쌍: `@subql/common` 5.8.2 → 5.8.3, `@ethersphere/bee-js` 13.2.0 → 13.3.0 — 둘 다 postinstall 추가 + JS 변경(A).

## 3. mastra 유사 유형 분류 기준과 한계

- 기준: 변경 JS 0개 & 새 의존성 1개 이상 & 설치 스크립트(preinstall/install/postinstall) 추가 없음. D06 실험의 C5 라우팅·mastra 유형 정의와 같다.
- 결과: **2,695쌍 중 1쌍** — `@cap-js/openapi` 1.4.0 → 1.4.1(mini-shai-hulud, 새 의존성 `@sap/setup`, `needs_review`). mastra(easy-day-js) 같은 별도 캠페인이 아니라 mini-shai-hulud 변형으로 보인다.
- 한계
  1. JS 변경은 `.js/.mjs/.cjs`만, 파일 경로·git blob id 비교로 판단했다(`.ts`·`.json`·바이너리 변경, 경로 이동은 반영하지 않음). D06 `obfChangedFileCount`(추출기)와 정확히 같지 않다.
  2. 패키지 루트는 node_modules 밖의 가장 얕은 `package.json`이다. archive 구조가 다르면 어긋날 수 있다.
  3. 의존성은 `dependencies`∪`optionalDependencies`만(D06 `newDependencyAdded`와 같음). dev·peer, lockfile, git URL 선언의 실제 대상은 보지 않았다.
  4. `needs_review` 1,168쌍은 악성 판정 또는 baseline 검토가 끝나지 않았다. 최종 학습셋에서 빠질 수 있다.
  5. baseline은 `meta.json`의 `normal_version` 그대로다. 정식 반영 때 `select_baselines.py`로 바뀌면 유형이 바뀔 수 있다.

## 4. 기존 D06 Train/Test와의 중복 (`run/overlap_with_d06.json`)

| 검사 | Train | Test-677 | Test-674 |
|---|---:|---:|---:|
| 같은 (package, old, new) | 0 | 0 | 0 |
| 같은 패키지 이름 | 2쌍(`shell-exec`) | 3쌍(`vant`) | 3쌍(`vant`) |
| 변경 JS blob 공유(같은 payload 파일) | 2,460쌍 | 10쌍 | — |

- payload 공유는 같은 캠페인의 추가 쌍이다. Train 쪽 2,460: chaindrop 1,719, sha1-hulud 466, mini-shai-hulud 270, individuals_case 4, nx 1. Test 쪽 10: canisterworm 6, individuals_case 4. 양쪽 모두와 공유하는 쌍은 없다.
- Test와 공유하는 10쌍: canisterworm 새 6쌍(Test 캠페인), `vant` 4.9.10 → 4.9.12/13/14 3쌍(Test-677에서 빠진 오류 `vant` 4.9.11 → 4.9.12/13/14의 교체 pair), `react-native-international-phone-number` 1쌍.
- 함의: 새 데이터를 추가할 때 이 pair들은 같은 payload를 가진 기존 split에 넣어야 누수가 없다(PR #13 component 규칙으로 자동 처리되는지 반영 시 확인 필요).

## 5. 결론

- D07/D07-B/D08을 합쳐도 mastra 유사 유형은 1쌍(검토 대기)뿐이다. **새 데이터로 Train의 mastra 유형 부족(6쌍)은 해결되지 않는다.**
- 추가분의 대부분(2,576/2,695)은 설치 스크립트 추가형(A)이고, 그중 다수가 이미 Train에 있는 캠페인과 같은 payload다.
- 이 유형을 학습·검증하려면 의존성 추가형 공격(서로 다른 캠페인 여러 개)을 별도로 수집해야 한다.

## 6. 파일

```text
survey.py                     조사 스크립트 (읽기 전용, lazy fetch 차단)
run/pairs.csv                 pair별 경로·배치·차수·상태·유형·새 의존성 이름·변경 JS 수·D06 중복 여부·변경 JS blob id
run/by_batch_round_status.csv, by_campaign_status.csv, by_batch_attack_type.csv
run/overlap_with_d06.json     key·패키지·payload 중복
run/summary.json, run/manifest.json
```
실행: `python3 -I -B survey.py --data-repo <npm-malware-package-pairs clone> --out <new dir>` (필요한 객체가 로컬에 있어야 함).
