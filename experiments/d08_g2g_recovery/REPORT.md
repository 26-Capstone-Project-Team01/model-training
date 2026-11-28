# D08 G2g 그룹 복구 보고서 (G2f → G2g)

작성 2026-11-28. 이전 작업 환경에서 유실된 G2g 매핑을 실제 코드 관련성 분석으로 다시 만들었다.
데이터: npm-malware-package-pairs D08 `2c48bd83` (Train 5,344 − clipper 6 = 5,338쌍). 기준: G2f(`exp/d08-g2f-group-leakage`의 `merge_G2f.json`).
모델 학습·Test 평가는 하지 않았다. 패키지 코드는 실행·설치·복호화하지 않고 텍스트로만 읽었다. 이 폴더에는 악성 코드 원문, IOC 문자열, raw 파일이 없다(해시·개수·표지 플래그만 있음).

## 1. 결과 요약
| 항목 | 이전 기록 | 이번 복구 | 판정 |
|---|---|---|---|
| Skimmer 계열 | 27쌍 | 27쌍 (D06 27) | 일치 |
| 강한 공통 코드 패턴 | 24쌍, G2f Fold 3: 6 / Fold 4: 18, 모두 D06 | 24쌍, Fold 3: 6 / Fold 4: 18, 모두 D06 | 일치 |
| 정규화 일치 줄 수 | 25~33줄 | 25~35줄 (N3, 아래 2절) | 정규화 방식 차이로 상한만 다름 |
| Hidden-loader 계열 | 45쌍 (D06 18 / 신규 27) | **46쌍 (D06 18 / 신규 28), 확정** | **1쌍 차이** (4절), Fold 영향 없음 |
| syncraft 3쌍 | Hidden-loader 포함, payload 동일 | 포함, 숨겨진 텍스트 해시 3쌍 동일 | 일치 |
| 두 계열 중복 | 없음 | 없음 | 일치 |
| group_merge | 9 | 9 | 일치 |
| row_override | 59 | **60** | 4절의 1쌍 |
| 신규 individuals override | 41 | **42** | 4절의 1쌍 |
| Fold 이동 | 32쌍 (3→4 16, 4→3 16) | 32쌍 (3→4 16, 4→3 16) | 일치 |
| Fold별 악성 | 1694/795/591/210/209 | 1694/795/591/210/209 | 일치 |
| 일반 정상 / Hard benign | 320×5 / 48,48,48,47,48 | 같음 | 일치 |
| 공격 그룹 수(individuals 제외) | 14 | 14 | 일치 |
| 두 계열의 Fold | 모두 Fold 4 | Skimmer 27 → Fold 4, Hidden-loader 46 → Fold 4 | 일치 |
| Train/Test 배정 | 변경 없음 | 변경 없음 (5,338행 모두 Train, Test 행 없음) | 일치 |

## 2. Skimmer 계열 (27쌍)
- seed: G2f 그룹 `js-metrics_2018`(10쌍)과 `apt-js-skimmer[from-individuals]`(4쌍).
- 방법(`decide_families.py`): 각 쌍의 diff에서 추가된 줄을 세 가지로 정규화해 seed와 공유하는 서로 다른 줄 수를 센다.
  N1(공백 무시), N2(+문자열·숫자 → 자리표시), N3(+일반 식별자 → `i`, 구조만). 다른 G2f 그룹 3개 이상에 나오는 줄은 일반 코드로 보고 뺀다.
- N1·N2에서는 변형끼리(식별자 이름이 다른 변형)만 63~65줄을 공유하고 변형 사이는 15~17줄로, 관련 없는 쌍(10~14줄)과 구분되지 않았다.
  N3에서 변형 사이 구조가 같아져 **24쌍이 seed와 25~35줄을 공유**하고, 그 다음 점수는 6줄(eslint-config-airbnb-standard)·6줄(@everreal, sha1-hulud) 이하로 간격이 분명하다. 기준 20줄.
- 24쌍: seed 11쌍(js-metrics 7 + apt-js 4) + individuals 13쌍. G2f Fold 3의 6쌍은 angular-location-update, leaflet-gpx, scroool, radic-util, stream-combine, nginxbeautifier로 이전 기록과 같다.
- 나머지 3쌍(motiv.scss, precode.js, ng-ui-library)은 데이터셋 원래 캠페인 `js-metrics_2018`에 속해 계열에 남지만 N3 공유는 기준 미만이다(`basis`에 "seed label only"로 표시).
- 근거: `evidence/evidence_skimmer.csv`(쌍별 N1/N2/N3 최대 공유 줄 수, 가장 가까운 seed 패키지).

## 3. Hidden-loader 계열 (46쌍)
- seed: G2f 그룹 `react-native-aria-gluestack_2025-06`(17쌍).
- 방법(`scan_hidden_raw.py` → `decide_families.py`): 각 쌍 `malicious_raw/`에서 normal_raw와 바이트가 다른 텍스트 파일만 읽어, 100자 이상 공백 뒤에 이어지는 코드를 찾는다.
  숨겨진 코드에 로더 표지(버전 태그 대입 `global['x']='<n>-…'` 또는 `globalThis.x="<A>n-…"`, `global['_V']`, `global['r']=require`, `_$_xxxx` 문자열 섞기 배열)가 있으면 계열로 본다.
- `diff.txt`만으로는 부족했다: 글꼴 이름을 단 텍스트 파일(`fa-solid-*.woff2`, `.llf`, `.lfk`)과 `diff.txt`에 본문이 빠진 파일이 있어 raw 파일을 직접 읽었다.
- 구성: D06 18쌍(react-native-aria 17 + @gluestack-ui/utils 0.1.17, seed와 숨겨진 텍스트 해시 동일),
  신규 28쌍(html-to-gutenberg 13, fetch-page-assets 6, rand-user-agent 3, @syncraft-labs core/react/vue 3, @kolbo/mcp 1, @lambda-platform/lambda-vue 1, revine 1).
- 구조 군집(`skeleton_clusters`, 숨겨진 코드 앞 300자 구조 해시)이 패키지를 서로 잇는다: 예) `39b74cdb` = @kolbo/mcp + fetch-page-assets + html-to-gutenberg, `d8b6e4ac` = lambda-vue + fetch-page-assets 1.2.9 + html-to-gutenberg 4.2.11.
- syncraft 3쌍은 숨겨진 텍스트 해시가 서로 같고 `globalThis` 형태의 버전 태그를 쓴다.
- 공백 뒤 코드가 있지만 표지가 없어 제외한 쌍: eslint-config-airbnb-standard(번들된 node_modules), pm-controls(번들 파일), @everreal/react-charts 2쌍(sha1-hulud의 pnpm store).
- 근거: `evidence/evidence_hidden.csv`(쌍별 표지 플래그, 파일 이름, 구조 군집·숨겨진 텍스트 해시 앞 8자).

## 4. 이전 기록과의 차이: Hidden-loader 46쌍 (이전 45쌍)
- 추가로 잡힌 1쌍은 rand-user-agent 1.0.109→1.0.110으로 판단한다. 이 쌍의 `diff.txt`는 `src/index.js`를 modified로 나열하지만 hunk 본문이 없어(파일 24줄), diff만 보는 방법으로는 숨겨진 코드가 보이지 않는다.
  raw 파일에는 같은 패키지 2.0.83/2.0.84와 같은 구조 군집(`09f634d3`)과 표지(`global['_V']`, `global['r']=require`, 버전 태그)가 있어 계열에서 빼지 않았다.
- **결정(2026-11-28): Hidden-loader 계열은 rand-user-agent 1.0.110을 포함한 46쌍으로 확정한다.**
  이전 분석이 어느 쌍을 빠뜨렸는지는 기록이 없어 확정할 수 없다. 신규 27쌍이라는 이전 수치와 이 쌍 하나 차이가 정확히 맞는다는 점이 근거다.
- 영향: 이 쌍은 같은 패키지의 나머지 2쌍과 이미 같은 component(패키지 단위 결합)라 **fold와 component 배정은 넣든 빼든 같다**(확인함). 차이는 그룹 이름 1행(row_override 60 vs 59)뿐이다.
- 따라서 이 1쌍은 Fold 이동 수·Fold별 개수·학습 데이터에 영향이 없고, 캠페인 단위 지표(Hidden-loader 계열 크기)에만 1쌍 차이가 난다.

## 5. G2g 매핑과 Fold 재구성
- `mappings/merge_G2g.json` = G2f + group_merge 2개(`js-metrics_2018` → skimmer 계열, `react-native-aria-gluestack_2025-06` → hidden-loader 계열)
  + G2f row_override 18개(apt-js 4쌍·individuals→js-metrics 1쌍은 skimmer 계열로 대상 이름만 변경) + 신규 individuals override 42개.
- Fold: PR #13 `components()`와 `run_m1m4.greedy_folds()`를 그대로 써서 다시 계산(`build_folds.py`). G2f 설정으로 돌리면 저장된 G2f `fold_assignment.csv`와 바이트 단위로 같다(가드 통과).
  G2g 결과도 재실행 시 같은 파일이 나온다.
- Fold 이동 32쌍(모두 악성): 3→4 16쌍 = 계열 9쌍(skimmer 6, hidden-loader 3: lambda-vue, syncraft/react, revine) + individuals 7쌍,
  4→3 16쌍 = individuals 15쌍 + solana-web3js 1쌍. 계열 행이 Fold 4로 모이며 생긴 부하를 탐욕 배정이 다른 작은 component로 맞춘 결과이고, Fold별 개수는 G2f와 같다.
- 쌍별 변경: `compare/pair_group_changes.csv`(그룹 변경 73행 = 계열 73쌍 중 G2f 이름이 바뀐 행, fold 이동 32행). Fold별 개수: `compare/fold_counts.csv`.
- individuals_case 악성 행: G2f 90 → G2g 48.

## 6. 재현
`run_g2g.sh <작업공간> <데이터 체크아웃> <출력 폴더>`. 작업공간 구성과 입력 해시는 `README.md`.
스캔 중간 산출물(줄 해시 18MB, 숨겨진 구간 목록)은 다시 만들 수 있어 넣지 않았다.
