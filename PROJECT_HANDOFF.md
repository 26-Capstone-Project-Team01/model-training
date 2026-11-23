# depbee 모델링 인수인계 문서 (W1 · X1 → full29 vs full35 실험)

작성 기준: 2026-11-23. 이 문서는 이전 대화 없이 이 작업을 처음 이어받는 사람(또는 Claude)이 읽는다는 전제로 쓴다.
각 항목은 **확인한 사실**과 **검토 중인 가설·미확정 사항**을 구분한다. 확인하지 못한 내용은 "미확인"으로 적었다.

담당: 솔(GitHub `ssol22`) — 9차 회의(11/20) 기준 W1·X1과 모델 실험 담당. 다른 팀원: 하람(`1unaram`, 18모델 인계·리뷰·merge),
소은(규칙 스캐너 `rules/diff_scan.py` 작성. 해당 커밋의 작성자 표기는 `lacroix`).

---

## 0. 먼저 지킬 것 (변경 금지 사항)

1. **데이터 분할을 바꾸지 않는다.** 모든 비교는 PR #13의 component 기반 outer 3fold와 split1(inner seed 20261109)·split2(20261110)를 그대로 쓴다.
   새 fold를 만들거나, 기존 `splits/cv_3fold_assignment.csv`(D06-CV01용, 다른 분할)와 섞지 않는다.
2. **D06 데이터 버전을 바꾸지 않는다.** 데이터 저장소 커밋 `be87ab4c`의 Train 2,767쌍만 쓴다. D07·D08·Tracky 자료는 동결 여부를 팀이 정하기 전까지 학습·모델 선택에 쓰지 않는다.
3. **Test 677쌍으로 임계값·모델·feature를 고르지 않고, 독립 일반화 성능이라고 주장하지 않는다.** 이미 여러 번 확인한 자료다.
4. **X1 feature 정의를 실험 중에 바꾸지 않는다.** 정의는 depbee-analyzer `feat/x1-code-context` 커밋 `d56738c`로 고정이다. 바꾸면 D06 전체를 다시 추출하고 새 커밋으로 기록한다.
5. **결측을 0으로 채우지 않는다.** X1 추출 실패·분석 불가는 빈 칸(NaN)이며 LightGBM 기본 결측 처리에 맡긴다.
6. **outer 평가 결과를 보고 feature·임계값·모델을 고르지 않는다.** 비교할 변형은 실행 전에 고정한다(10절).
7. **규칙 적중 샘플을 학습 데이터에서 빼지 않는다.** 규칙의 최종 hit/no_hit을 X1 feature로 쓰지 않는다.
8. **분석 대상 npm 패키지를 설치하거나 lifecycle script를 실행하지 않는다.** 정적 분석만 한다.
9. **기존 코드·결과·모델 파일을 덮어쓰지 않는다.** 새 결과는 새 실험 ID 폴더에 둔다.
10. `main`에 직접 commit하지 않고, merge는 팀 검토 후 사람이 한다.
11. 데이터 저장소를 내용 없이(blobless, no-checkout) 받은 사본은 `git status`에 파일이 대량으로 "삭제됨"으로 보인다. **그 사본에서 commit·push·복구를 하지 않는다.**

---

## 1. 프로젝트 목표와 저장소

목표: npm 패키지의 **버전 업데이트(old → new)** 가 악성 업데이트인지 판단을 돕는 도구(depbee). 기지 악성 목록, 정적 규칙, ML 위험 점수를
함께 보여 주고 사람이 판단한다. ML 점수는 확률이 아니라 **위험 점수(risk score)** 로 다룬다.

| 저장소 | 역할 |
|---|---|
| `26-Capstone-Project-Team01/npm-malware-package-pairs` | 악성·정상 버전 쌍 원본(archive)과 파생 자료(`derived/`: feature CSV, baseline 선정, 그룹, train/test 분할) |
| `26-Capstone-Project-Team01/depbee-analyzer` | feature 추출기(개발·데이터셋 생성용). **옛 이름 `feature-extractor`** (GitHub가 새 이름으로 리다이렉트). Python 모듈 `depbee_analyzer` |
| `26-Capstone-Project-Team01/model-training` | LightGBM 학습·평가 실험 |
| `26-Capstone-Project-Team01/depbee` | 최종 사용자 CLI·서비스. 분석기를 `depbee-analyzer@917ba903…`로 고정. 설치본 기본 모델 ID는 `D04-E00` |

파이프라인: (데이터 저장소) 버전 쌍 → (depbee-analyzer) feature 추출 → (model-training) LightGBM 학습·평가 → native `model.txt` + 모델 manifest →
(depbee) 추론·보고.

depbee 모델 계약(`depbee/docs/contracts.md`, 확인함): 모델 폴더에 `model.txt`(Booster.save_model)와 manifest
(`model_id`, `model_sha256`, `feature_schema: depbee-features-v1`, `feature_names`(모델 순서와 정확히 같아야 함), `boolean_features`,
`categorical_features`(updateType 순서), `nullable_features`). depbee 내장 분석기는 `resolve_extractors(None)`(기본 extractor 전체)을 쓴다
(`depbee/src/depbee/analysis/extractor.py:148`).

---

## 2. 데이터

### 2.1 이력 (확인한 범위)

- D04 → D05(NPMStudy 30쌍 추가) → **D06(4-B 데이터 반영, 데이터 커밋 `be87ab4c`)** → D07(Backstabber's Knife Collection, 11/11 커밋) →
  D08(Tracky 2쌍, 데이터 저장소 PR #22, 11/23 merge). D07·D08을 학습에 쓸지(동결 여부)는 **미확인/미결정**.
- baseline(old) 선정 규칙: 같은 release line의 직전 stable(`derived/pairs/baseline_rule.py`). 악성은 24시간 안 후보에 payload 흔적이 없는지 확인.
- Hard benign: 겉모습이 악성 업데이트와 비슷한 정상 업데이트. `install_script_added`(설치 스크립트가 새로 생김) 또는
  `bundle_growth`(압축 해제 크기 3배 이상, 1MB 이상)로 고름. 무작위 정상만으로는 "설치 스크립트 추가 = 악성"이라는 지름길을 학습하기 때문이다.

### 2.2 D06 구성

- `derived/splits/train.csv`(SHA-256 `22fbc875…2c23`): **2,767쌍 = 악성 928 + 무작위 정상(benign) 1,600 + Hard benign 239**. 열: `package, old_version, new_version` + 29개 feature + `label`.
- `derived/splits/test.csv`: 677쌍. 사용 금지(0절 3).
- `derived/pairs/baselines.csv`: 쌍별 `class`, `old_source`, `new_source`(`registry` 또는 `archive:<경로>`).
  D06 Train: 정상·Hard benign은 old/new 모두 registry. 악성 883쌍은 old/new 모두 archive, 45쌍은 old만 registry.
- `derived/pairs/malicious_pair_groups.csv`: 악성 쌍의 `splitGroup`, `largestChangedJsSha1`, `changedJsSetSha1`.

### 2.3 용어

- **splitGroup**: 데이터 저장소가 악성 쌍에 붙인 캠페인 이름(예: `sha1-hulud-second-coming_2025-11`). `individual-compromise*`, `individuals_case`는
  실제 공격 묶음이 아닌 개별 사례 모음(범용 묶음)이라 그룹 기준에서 뺀다.
- **component(연결그룹)**: PR #13 학습 코드의 `components()`. 같은 package, 같은 실제 splitGroup, 같은 비어 있지 않은 악성 payload 해시
  (`largestChangedJsSha1`, `changedJsSetSha1`) 중 하나라도 공유하면 union-find로 묶는다. D06 전체 1,893개, 악성 포함 56개.
  악성 928쌍 중 716쌍(77%)이 가장 큰 component 3개(sha1-hulud 332, mini-shai-hulud 198, shai-hulud-original 186)에 있다.
- **row_id**: `train.csv` 데이터 행 순서(0~2,766).

### 2.4 분할과 누수 방지 (PR #13, 확인함)

- 코드: `experiments/d06_feature_comparison_18/provenance/phase2_run1_base7_full29/executed_script_snapshot.py`
  (`components` 61–88줄, `check_disjoint` 90–99, `outer_folds` 105–124, `inner_split` 126–142, 일정 402–404, fold 루프 412–417).
- **outer 3fold**: component 단위. 악성 component를 큰 것부터 악성이 적은 fold에 넣고, 정상 component는 class 균형으로 배정. seed 없음(결정적).
  행 945/911/911, 악성 332/298/298. **split1과 split2에서 같다.** Fold 0의 악성은 sha1-hulud 하나뿐이다.
- **내부 분할(split1·split2)**: 각 fold의 나머지 두 fold를 component 단위로 fit(학습)과 calibration(기준 조정, 클래스별 약 25%)으로 나눈다.
  seed를 쓴 greedy 배정이고 실제 RNG seed는 `inner_seed + fold`. split1 = 20261109, split2 = 20261110. 두 split 사이에 학습 부분 행의 37.1%(2,054/5,534)의 역할이 다르다.
- 누수 방지: `check_disjoint`가 component·package·두 해시·실제 splitGroup이 fit/calibration/outer 사이에 겹치면 실행을 멈춘다.
  파일로도 18가지 조합(split 2 × fold 3 × 구간 쌍 3) 모두 겹침 0을 확인했다.
- 파일: `splits/split1.csv`, `splits/split2.csv`(열 `scenario,seed,rounds,fold,stage,row_id,component,model`, 세 feature 세트에서 같은 배정),
  `scores/row_metadata.csv`(row_id별 package·버전·label·class·campaign·component·outer_fold).
- 주의: 예전 `splits/cv_3fold_assignment.csv`(PR #7, D06-CV01, early stopping에 outer 사용)는 **다른 분할**이다(fold 번호 일치 54%). 섞지 않는다.

---

## 3. 기존 29개 feature와 학습·평가 방식

- package.json 7개: `installScriptPresent`, `installScriptAdded`, `scriptEntryAdded`, `newDependencyAdded`, `newDependencyCount`,
  `updateType`(범주 major/minor/patch), `updateInterval`(초). 설치 훅은 preinstall/install/postinstall.
- 난독화 22개: `obfChangedFileCount` + 지표 7개(HexIdentRatio, HexNumberRatio, BracketAccessRatio, EscapeDensity, ShortIdentRatio,
  MeanIdentLength, WhitespaceRatio) × (`New` 새 버전 전체, `Change` 이전 대비 변화, `ChangedCode` 바뀐 코드).
- PR #13 학습: LightGBM 4.7.0, `objective=binary, metric=binary_logloss, verbosity=-1, num_threads=2, deterministic=true, force_col_wise=true, seed=20261109`,
  **200 rounds 고정, early stopping 없음, 검증 세트 없음**, `updateType`은 pandas Categorical `[major, minor, patch]`, 나머지 float64, 결측 NaN.
  fit으로만 학습하고 calibration·outer 점수를 저장. outer는 평가에만 쓴다.
- 평가(PR #13 phase7, 저장 점수만 사용): 사전 고정 임계값 14개(0, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.2, 0.3, 0.5, 0.7, 0.9, 0.99, 1)의
  TP/FN/FP/검토 후보·무작위 정상/Hard benign 오탐·campaign/component 평균 Recall, fold 안 상위 비율 순위(동점 범위), 낮은 점수(≤0.01/0.05/0.1) 악성,
  calibration Recall 90/95% 예시. **phase7 코드는 묶음에 없다**(해시만). W1에서 같은 정의를 `evaluate_w1.py`로 다시 구현했고 PR #13 수치를 정확히 재현함을 확인했다.

---

## 4. PR #13 기준선과 W1

### 4.1 PR #13 (merged, main `e267281`)

- `experiments/d06_feature_comparison_18/`: 7개(base7)/29개(full29)/28개(no_interval28, updateInterval 제외, **사후 추가**) × split 2 × fold 3 = 18 모델,
  분할, 저장 점수(calibration·outer 25,644행), 평가 결과. `verify_bundle.py --train-csv <D06 train>` 통과 확인.
- full29 outer 합산(임계값 0.05): split1 TP 685 / FN 243 / FP 9, split2 708 / 220 / 16.

### 4.2 W1 (PR #14, Open, 채택 보류)

- 목적: 큰 연결그룹이 학습을 지배하는 효과를 줄이기 위해 fit 안 악성에 1/√n(n = 같은 component의 fit 악성 수), 악성 가중치 합 = 악성 수로 정규화, 정상 1.
- 방법: PR #13 스냅샷을 수정 없이 import, 가중치만 다름. 가중치 없는 full29 6개를 재학습해 PR #13과 모델 내용(CR 줄바꿈 제외)·점수(최대 차 1.1e-16) 동일 확인.
- 결과: split에 따라 방향이 엇갈림(0.05: split1 686/242/9, split2 724/204/18; 0.5: split1 566/362/4, split2 643/285/4). B유형(52쌍)이 0.5에서 크게 하락
  (split1 41→1). split1 fold1은 fit 악성 component가 2개뿐이라 가중치가 거의 균등(0.89/1.19)한데도 mini-shai-hulud 순위가 크게 바뀜.
  **결론: 일관된 개선 근거 없음 → 채택 보류**(PR #14 본문에 기록).
- 위치: 브랜치 `exp/d06-w1-component-weight` 커밋 `e8c5847`, `experiments/d06_w1_component_weight/`(`run_w1.py`, `evaluate_w1.py`, W1 모델 12개, 점수, 평가).

---

## 5. X1 도입 배경과 규칙 스캐너

- 9차 회의 결정(사용자 전달 내용): 모델 작업 순서 ① PR #13 ML 점수와 6개 규칙 결과 비교 ② full29와 W1·X1을 각각 비교 ③ feature 동결 및 독립 데이터 검증.
  X1은 A유형(설치 훅의 실행 프로그램·인자 변경, 훅이 직접 참조하는 파일)과 C유형(변경 JS에서 실제 추가된 프로세스 실행·외부 통신 호출)에 집중하고,
  B유형(새 의존성의 당시 버전 분석)은 별도 실험. 규칙의 최종 hit를 feature로 쓰지 않는다. 분석 불가는 결측.
- 규칙 스캐너: depbee-analyzer `src/depbee_analyzer/rules/diff_scan.py`(`RULESET_VERSION 2026-11-16.1`, main 커밋 `e1c84e2`, PR 없이 main 반영).
  6개 규칙: `R_download_exec`(검토), `R_secret_send`(강한 근거), `R_ci_secret_send`, `R_install_root_wipe`, `R_remote_admin_auth_override`(검토), `R_diff_obfuscation`(검토).
  모델 feature가 아니다. 파일 8MB 초과 시 4개 규칙이 `unknown`.
- **① 규칙·ML 비교는 미실행**: 회의에서 언급된 `handoffs/rule-model-comparison/`을 model-training·depbee-analyzer·데이터 저장소·depbee의 main·브랜치·PR에서
  찾지 못했다. D06 규칙 결과도 어디에도 저장돼 있지 않다. 필요하면 하람·소은에게 위치를 물어야 한다.
- 규칙과 X1 비교(합성 19사례, 코드 수준): `R_download_exec`는 `curl | sh`, `sh -c "…"`, 기존 다운로드·실행 훅의 URL 변경을 놓친다(X1은 반응).
  `R_ci_secret_send`·`R_remote_admin_auth_override`·`R_diff_obfuscation`(eval 페이로드) 사례는 X1이 0. 보완 관계로 판단해 X1 유지(사용자 결정).
  D06 악성 928쌍의 package.json만으로 돌리면 `R_download_exec` 0건, `R_install_root_wipe` 10건(toptal).

---

## 6. X1 feature 6개 (정의 고정: depbee-analyzer `d56738c`)

코드: `src/depbee_analyzer/extractors/code_context.py`. 문서: `docs/x1-code-context-features.md`. 테스트: `tests/extractors/test_code_context.py`(전체 170개 통과).
**선택형 extractor**: `OPTIONAL_EXTRACTOR_REGISTRY["code_context"]`에만 등록. `--extractors ...,code_context`로만 실행되며 기본 실행(29개)과 depbee 출력은 그대로다
(depbee가 기본 목록을 쓰기 때문에 기본 registry에 넣지 않았다). 기본 29개 출력이 main `871b26f`와 같음을 확인.

| feature | 타입 | 계산 | 결측 |
|---|---|---|---|
| `installHookNewProgramCount` | int | new 설치 훅(preinstall/install/postinstall)의 실행 프로그램 집합 − old 집합의 크기 | 훅 명령 해석 실패, scripts 형식 오류 |
| `installHookArgsChanged` | bool | 양쪽에 있는 같은 훅에서 프로그램 구성은 같고 명령만 바뀜 | 위와 같음 |
| `installHookRefFileChanged` | bool | 훅이 실행하는 **패키지 내부** 파일이 old에 없거나 내용이 다름 | 바뀐 내부 파일이 없고 내부 실행 대상 일부를 확인할 수 없음 |
| `installHookNewExternalExecCount` | int | new 훅에만 있는 **외부 실행 대상** 수(`path:` 패키지 밖·`~`·`$VAR/` 경로, `download:` 같은 훅에서 curl -o/wget -O/>로 받은 파일, `pipe:` curl … \| sh) | 훅 해석 실패 |
| `addedProcExecCallCount` | int | 바뀐 JS 파일마다 new 호출 서명 multiset − old 같은 경로 multiset의 크기 합. 대상 `child_process` exec/execSync/execFile/execFileSync/spawn/spawnSync/fork | 소스 수집 실패 |
| `addedNetworkCallCount` | int | 같은 방식. http/https/http2/net/tls/dgram/dns, axios·node-fetch·got·undici·ws 등, 전역 fetch, `new WebSocket/XMLHttpRequest/EventSource`, `navigator.sendBeacon` | 소스 수집 실패 |

설계 핵심:
- 실행 대상은 명령 위치의 경로와 인터프리터의 첫 파일 인자만(`cp /tmp/a b`의 `/tmp/a`는 아님). `sh -c "…"`는 한 단계 펼침.
- **호출 서명** = (API 이름, 인자의 문자열 리터럴, 숫자 리터럴). 줄 단위 diff를 쓰지 않는 이유: minified 번들은 한 줄이 파일 전체.
  변수 이름은 서명에 넣지 않음(빌드마다 바뀜) → `exec(cmd)`→`exec(cmd2)`는 구분 못 함(한계). 비교 중인 old·new 버전 문자열은 같은 토큰으로 바꿔 비교.
- 주석·문자열·정규식 리터럴 안은 세지 않음(`lex_js`). 모듈에 묶인 이름의 호출만 셈(`RegExp.exec` 오탐 방지).

구현 이력(depbee-analyzer `feat/x1-code-context`, Draft PR #17):
1. `0defc95`: 첫 구현 5개. 리뷰 과정에서 C유형을 "호출 수 차이"에서 "호출 서명 multiset 차이"로 바꿈(호출 수가 같은 대상 변경을 놓쳐서), 자기 버전 문자열 정규화 추가(esbuild 오탐).
2. `83d33bc`: 외부 경로 실행이 `installHookRefFileChanged`를 결측으로 만들던 문제 → 내부 파일만 보도록 하고 `installHookNewExternalExecCount` 신설(6개).
3. `d56738c`: 실제 악성 검증 반영(7절).

---

## 7. 실제 악성 20쌍 검증 (정적, 18개 캠페인)

발견 → 해결(`d56738c`):
- `bun run index.js`의 `run`을 파일로 해석 → D06 46쌍 `installHookRefFileChanged` 결측. **해결**: `bun run`/`deno run` 다음 파일(확장자·`/`)만 실행 대상, 스크립트 이름이면 참조 없음. 46쌍 모두 True로 확인.
- `$NODE lint.js`를 외부 경로로 오분류(928쌍 중 유일한 외부 실행 1건). **해결**: 단독 변수 명령은 인터프리터, 외부는 `$VAR/…`만.
- `|| true`의 `true`, `sudo`를 프로그램으로 셈. **해결**: 셸 내장(true/false/:/exit/cd/export/set/unset) 제외, sudo·doas·time 래퍼.
- C유형 누락: `require('chi'+'ld_pro'+'cess')`, `createRequire`, `x = require('child_process').spawn` 후 호출, 리터럴 대괄호 `["sp"+"awn"](`. **해결**(리터럴 범위만).
- 해결하지 않은 한계: eval 페이로드(autotel, miasma), 난독화 래퍼에 함수 전달(chaindrop setup.mjs), 재사용 변수 require, webpack 모듈 번호(shai-hulud-original 실행), 공백 뒤 숨긴 코드(gluestack).
- 설계 후보(미구현): `npm install -g`, `npx`, `bunx` 등 원격 패키지 실행을 외부 실행으로 볼지(`cline` 사례). 정상 데이터와 함께 측정 후 결정.

---

## 8. D06 전체 X1 추출 결과 (`experiments/d06_x1_extraction/`)

- 추출: **2,765 성공, 2 실패**(Hard benign: `nestjs-grpc` 1.3.11 registry 메타데이터에 없음, `@camstack/addon-decoder-ffmpeg` 404). 실패 쌍 X1은 빈 칸.
  성공 쌍 결측은 `installHookRefFileChanged` 11건(악성 4: `coa`, `@automagik/genie`×3; 정상 1: `djlint`; Hard benign 6).
- 소스: registry tarball 3,719개를 sha512로 검증 후 `filter="data"`로 임시 해제. 악성은 데이터 저장소 부분 사본에서 60쌍씩 sparse checkout(정적 읽기).
- `analysis/d06_full35.csv`: 2,767행 × 39열(키 3 + 29 + X1 6 + label). 29개 값·label은 `train.csv`와 동일, **행 순서·label이 PR #13 row_id와 동일**.
- 비영(True) 비율 악성/정상/Hard benign과 단일 AUC(vs 정상 / vs Hard benign, 결측 제외):

| feature | 악성 | 정상 | Hard benign | AUC |
|---|---:|---:|---:|---|
| installHookNewProgramCount | 76.8% | 0.06% | 43.5% | 0.884 / 0.663 |
| installHookArgsChanged | 0.8% | 0.06% | 0% | 0.503 / 0.504 |
| installHookRefFileChanged | 76.8% | 0.2% | 16.5% | 0.883 / 0.802 |
| installHookNewExternalExecCount | 0% | 0% | 0% | 0.5 / 0.5 |
| addedProcExecCallCount | 55.6% | 0.7% | 11.0% | 0.776 / 0.740 |
| addedNetworkCallCount | 83.0% | 1.6% | 18.1% | 0.912 / 0.878 |

- 중복성: `installHookNewProgramCount`–`installScriptAdded` Spearman 0.977. `installScriptAdded=True` 층에서 악성 vs Hard benign:
  RefFile 98.3% vs 34.6%, Net>0 92.7% vs 10.6%, Proc>0 70.8% vs 12.4%. `installScriptAdded=False` 층: Net 50% vs 25%(정상 1.6%), Proc 4.2% vs 9.7%.
  `addedProcExecCallCount`–`obfHexIdentRatio*` Spearman 약 0.88(sha1-hulud 공통 페이로드 영향일 가능성, 미검증 가설).
- 캠페인 집중: 악성 비영 값의 43~64%가 sha1-hulud. 캠페인 동일 비중 비영 비율: NewProgram 47.1%, RefFile 44.6%, Proc 38.6%, Net 52.5%.
- 극단값: 정상 `klaviyo-api` 12.0.1 통신 226(생성된 API 클라이언트).

---

## 9. feature별 현재 평가 (모델 실험 전, 미확정)

| feature | 현재 의견 | 확정 여부 |
|---|---|---|
| addedNetworkCallCount | 유지 후보(단일 분리도 최고, 훅 없는 악성에도 신호) | 미확정. 극단값 처리(상한·로그) 미결정 |
| installHookRefFileChanged | 유지 후보(훅 층 안에서 Hard benign과 분리) | 미확정 |
| addedProcExecCallCount | 유지 후보(주의: 캠페인 집중, 훅 없는 층 신호 없음) | 미확정 |
| installHookNewProgramCount | 제거 검토(installScriptAdded와 사실상 중복) | 미확정. 사용자가 "정상 데이터 비교 후 결정"으로 보류 |
| installHookArgsChanged | 제거·보류 검토(8건) | 미확정 |
| installHookNewExternalExecCount | D06 학습 입력 제외 검토(전부 0). 추출기에는 유지 | 미확정 |

---

## 10. 다음 실험: full29 vs full35 (제안된 계획, 미실행)

고정 조건:
- 데이터 D06 `be87ab4c` Train 2,767쌍, X1 = `analysis/d06_full35.csv`(추출기 `d56738c`). 입력 해시는 `experiments/d06_x1_extraction/run_manifest.json`.
- 분할: PR #13 split1·split2 × outer fold 0~2(`splits/split1.csv`, `split2.csv`의 fit/calibration/outer row_id).
- 학습: PR #13과 같은 LightGBM 파라미터·200 rounds·early stopping 없음·sample weight 없음. X1 bool은 1.0/0.0, 빈 칸은 NaN. `updateType` 범주 순서 유지.
- PR #13 스냅샷은 Train CSV가 정확히 29개 feature여야 통과하므로 **스냅샷을 고치지 말고**, W1의 `run_w1.py`처럼 스냅샷을 import해
  `load_data`·`inner_split`·`feature_matrix`를 쓰고 row_id로 X1 열을 붙이는 별도 스크립트를 만든다. 실행 시 fit/calibration/outer row_id가
  PR #13 split 파일과 같은지 검사한다(`run_w1.py` 참고).
- 기준선: PR #13 full29 저장 점수 재사용(같은 코드로 재학습하면 동일함이 W1에서 확인됨).
- 비교 변형(실행 전에 고정, 결과를 보고 추가·삭제하지 않음): full35, full32(full29 + RefFile·Proc·Net), full29 + 각 1개(3개).
- 평가: W1 `evaluate_w1.py`와 같은 정의(PR #13 phase7 재현 확인됨): 고정 임계값별 TP/FN/FP·검토 후보·무작위 정상/Hard benign 오탐,
  fold 안 상위 비율 순위, 낮은 점수 악성, calibration Recall 예시, 공격 유형(A/B/C, feature 기반 대리 분류)·캠페인·component별 Recall, full29 대비 행 단위 증감.
  split·fold별로도 본다. 두 split은 같은 행을 다시 쓰므로 독립 관측으로 합치지 않는다.
- 해석 주의: 가중치·feature가 바뀌면 점수 척도가 바뀌므로 고정 임계값 비교와 순위 지표를 함께 본다. 캠페인 집중이 크므로 캠페인 동일 비중 지표를 함께 본다.
  D06은 이미 feature 선택에 쓰인 개발자료다.
- 결과 저장: 새 실험 폴더(예: `experiments/d06_full35_compare/`), 새 브랜치. 기존 폴더·모델을 덮어쓰지 않는다.

이후 단계(9차 회의 순서, 미착수): feature 동결과 독립 데이터 검증, 최종 모델 인계(`model.txt` + manifest, feature 순서, 데이터·추출기 커밋, split, 임계값 근거).
depbee 연동 시 바꿀 항목(미착수): 분석기 고정 커밋, 내장 분석기에 `code_context` 명시, 스키마 이름(`depbee-features-v1` 유지 여부), manifest의 `boolean_features`·`nullable_features`.

---

## 11. 저장소·브랜치·PR·커밋·경로

| 대상 | 값 |
|---|---|
| model-training main | `e267281` (PR #13 merge) |
| PR #13 | merged. `experiments/d06_feature_comparison_18/` |
| PR #14 (W1) | Open, 채택 보류. 브랜치 `exp/d06-w1-component-weight` `e8c5847`. `experiments/d06_w1_component_weight/` |
| X1 결과 브랜치 | `exp/d06-x1-extraction` (main 기반, PR 없음). `experiments/d06_x1_extraction/`, 이 문서 `PROJECT_HANDOFF.md` |
| depbee-analyzer main | `871b26f` (feature-extractor에서 이름 변경, PR #16) |
| depbee-analyzer X1 | 브랜치 `feat/x1-code-context` `d56738c`, Draft PR #17(본문의 테스트 수 154는 이전 값, 현재 170) |
| 규칙 스캐너 | `src/depbee_analyzer/rules/diff_scan.py` (`e1c84e2`에서 추가. 이후 이름 변경으로 경로만 `feature_extractor/` → `depbee_analyzer/`, 내용 변경 없음) |
| 데이터 | `npm-malware-package-pairs` D06 `be87ab4c`, 현재 main `4498acd`(D08 포함) |
| depbee | 분석기 고정 `917ba903…`, 열린 PR #39(다른 팀원) |
| 그 외 | model-training `claude/busy-heisenberg-u3j88n`(D05-E00 재실험 보존용, main에 없는 파일 있음) — 삭제 전 확인 필요 |

주요 파일:
- `experiments/d06_x1_extraction/analysis/d06_full35.csv`, `d06_full35_schema.json`, `d06_x1_status.csv`, `run_manifest.json`, `README.md`
- `experiments/d06_feature_comparison_18/splits/split1.csv`, `split2.csv`, `scores/row_metadata.csv`, `scores/saved_scores.csv`, `model_index.csv`
- W1: `experiments/d06_w1_component_weight/run_w1.py`, `evaluate_w1.py` (W1 브랜치에만 있음)

---

## 12. 확정한 결정과 검토 중인 가설

확정(사용자 결정 또는 실행으로 확인):
- 분할·데이터 버전·Test 사용 금지 원칙(0절).
- W1은 일관된 개선 근거가 없어 채택 보류(PR #14).
- X1은 기본 실행에 넣지 않는 선택형 extractor. 규칙 hit를 feature로 쓰지 않음. 결측 ≠ 0.
- X1 6개 유지(규칙과 보완 관계), `npm install -g`/`npx`/`bunx`는 별도 설계 후보로만 문서화.
- `installHookNewProgramCount`는 지금 제거하지 않음(정상 데이터 비교 후 결정).
- D06 전체 X1 추출·병합 완료(2,765/2,767), full35 데이터는 PR #13 row_id와 정렬됨.

검토 중(미확정 가설):
- X1(특히 통신·참조 파일)이 full29에 추가 정보를 준다 — 단일 분석·층별 분석 근거만 있고 모델 실험은 안 함.
- `installHookNewProgramCount`·`installHookArgsChanged`·`installHookNewExternalExecCount`는 D06에서 정보가 거의 없다 — 제거 여부 미정.
- 실행 호출과 난독화 feature의 높은 상관은 캠페인 공통 페이로드 때문이다 — 미검증.
- 규칙·ML 비교(9차 ①) — 규칙 결과 자료를 찾지 못해 미실행.
- D07·D08 사용 여부와 독립 검증 데이터 — 미정.
