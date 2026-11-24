# X3 Feature 정의 (설치 훅 참조 코드 · 변경 토큰 정규화 호출 비율) 및 의존성 변경 Feature(D)

상태: **정의 확정 전 초안 → 구현·단위 테스트까지.** 전체 데이터 추출과 모델 학습은 구현 검토 후에 한다.
기존 Feature(package_json 7개·난독화 22개·X1 6개)의 정의와 코드는 바꾸지 않는다. 새 extractor 두 개를 선택 실행 목록
(`OPTIONAL_EXTRACTOR_REGISTRY`)에만 추가한다. 기본 실행 목록과 제품 출력(depbee-features-v1)은 바뀌지 않는다.

정적 분석만 한다. 대상 패키지의 코드, lifecycle script, 셸 명령을 실행하지 않는다.

배경: D06 Train Hard benign 오탐 분석(model-training `exp/d06-hb-typewise`)에서
(1) 악성 설치 훅 명령의 98%가 `node <파일>`이고 정상 플랫폼 패키지의 `node install.js`와 명령 문자열로 구분되지 않으며,
(2) 설치 훅 없이 번들에 호출이 추가된 정상 쌍과 대형 재빌드 정상 쌍에서 정규화되지 않은 호출 카운트가 오탐을 만들었다.
X3는 구분 근거를 **훅이 실행하는 코드 자체**와 **변경량 대비 호출 밀도**로 옮긴다.

## 1. 공통 용어

- **설치 훅**: new 버전 `package.json`의 `scripts.preinstall` / `install` / `postinstall` (X1·`installScriptPresent`와 같은 키).
- **훅 실행 대상**: X1 `_hook_targets`가 고른 패키지 내부 실행 대상(명령 위치의 경로, 인터프리터의 첫 파일 인자)을
  X1 `_resolve`로 패키지 루트 안 일반 파일에 해석한 것. 외부 경로·다운로드 대상은 포함하지 않는다.
  추가로 X3에서는 node 계열 인터프리터(`node`, `nodejs`, `bun`, `ts-node`, `tsx`)의 인라인 코드(`-e`/`--eval`/`-p`/`--print` 다음 인자)를
  가상의 실행 대상 1개로 본다(X1은 인라인 코드를 참조 파일 없음으로 처리했다).
- **JS 실행 대상**: 해석된 경로의 확장자가 `.js`/`.cjs`/`.mjs`이거나, 확장자 없이 node 계열 인터프리터로 실행되어 `.js` 보완으로 해석된 것, 또는 인라인 코드.
  `.sh`/`.py`/`.ts` 대상은 JS 지표를 정의할 수 없어 제외하고 진단 열에만 센다.
- **바뀐 훅 실행 표면(changed hook surface)** = 다음 중 하나를 만족하는 JS 실행 대상의 집합.
  1. 그 대상을 부르는 훅 명령이 old의 같은 키 명령과 다르거나 old에 그 키가 없다(새 훅·바뀐 훅).
  2. 훅 명령은 같지만 대상 파일 내용이 old 같은 경로와 다르거나 old에 없다(X1 `installHookRefFileChanged`와 같은 비교).
  같은 파일을 여러 훅이 부르면 한 번만 센다(상대 경로 기준).

## 2. X3 Feature (모델 입력 후보 13개)

### 2.1 설치 훅 참조 코드 (①, ②)

| 이름 | 정의 | 결측(None) |
|---|---|---|
| `installHookTargetCount` | 바뀐 훅 실행 표면의 JS 실행 대상 수(해석 성공한 것만) | 훅 해석 실패(X1과 같은 조건) |
| `installHookTargetMaxBytes` | 그 대상들 중 최대 크기(byte, 인라인은 UTF-8 길이) | 대상 0개 |
| `obfHook<지표>` ×7 | 대상 파일들에 기존 `obfuscation.file_metrics`를 적용하고 기존 `obfuscation.aggregate`(난독화 쪽 극값, 작을수록 난독화인 지표는 1KB 이상 파일 우선)로 묶은 값. 지표 7개는 기존과 같다: HexIdentRatio, HexNumberRatio, BracketAccessRatio, EscapeDensity, ShortIdentRatio, MeanIdentLength, WhitespaceRatio | 대상 0개, 또는 그 지표를 정의할 수 없는 경우(기존 규칙 그대로) |
| `installHookTargetProcExecCallCount` | 대상 코드 전체의 프로세스 실행 호출 수(기존 `call_signatures`의 proc multiset 합) | 대상 0개 |
| `installHookTargetNetworkCallCount` | 대상 코드 전체의 외부 통신 호출 수(기존 `call_signatures`의 net multiset 합) | 대상 0개 |

- 호출 수는 **대상 파일 전체**에서 센다(old와 뺀 값이 아니다). 훅이 설치 시점에 실행하는 코드가 무엇을 하는지를 보려는 것이다.
  바뀐 표면에 든 파일만 대상이므로, 훅도 대상 파일도 그대로인 쌍은 0개 → None이다.
- 대상 0개(설치 훅이 없거나, 훅이 그대로이고 대상 파일도 그대로이거나, 훅이 JS가 아닌 것만 실행)는 `installHookTargetCount=0`, 나머지 None.
  대상이 있는데 지표가 0인 경우(난독화 흔적 없음·호출 없음)와 구분하기 위해서다.

### 2.2 변경 코드 토큰 정규화 호출 비율 (③, ④)

분자는 기존 X1 `addedNetworkCallCount` / `addedProcExecCallCount`를 **그대로** 쓴다(같은 함수 `added_call_features`).

분모는 둘 중 하나로 명확히 정한다. **모델 Feature의 분모 = A (실제로 추가된 토큰 수)**. B는 진단 열로만 낸다.

- **A. `x3diagChangedCodeAddedTokenCount` (실제 변경 토큰)**: 분자와 같은 파일 집합(추가되었거나 내용이 바뀐 JS 파일)에서
  파일마다 `Counter(tokens(new)) − Counter(tokens(old 같은 경로))`(multiset 차, old가 없으면 new 전체)의 크기를 더한 값.
  분자(호출 서명 multiset 차)와 같은 방식의 차이 계산이라 "추가된 코드 1토큰당 추가된 호출 수"가 된다.
- **B. `x3diagChangedFileTokenCount` (변경 파일 전체 토큰)**: 같은 파일 집합에서 new 파일 토큰 수의 합.
  한 줄만 바뀐 대형 번들도 파일 전체가 분모에 들어가므로 "변경 파일의 크기"를 반영한다.

| 이름 | 정의 | 결측(None) |
|---|---|---|
| `addedNetworkCallPer1kAddedTokens` | 1000 × `addedNetworkCallCount` / A | 분자 None(소스 수집 실패), 또는 A = 0(바뀐 JS 없음 포함) |
| `addedProcExecCallPer1kAddedTokens` | 1000 × `addedProcExecCallCount` / A | 같음 |

**토큰 정의** (`tokens(text)`): 기존 `code_context.lex_js`로 주석을 지우고 문자열·정규식 리터럴을 분리한 뒤,
코드 부분의 단어(`[A-Za-z_$][\w$]*`, 예약어 포함)와 숫자 리터럴, 그리고 문자열 리터럴 하나당 토큰 1개(내용 기준 `S:<내용>`), 정규식 리터럴 하나당 토큰 1개.
연산자·괄호는 세지 않는다(minify 방식 차이에 민감하고 정보가 적다). 버전 문자열 정규화(`_without_versions`)는 분모에 적용하지 않는다.

### 2.3 진단 열 (모델 입력 아님)

| 이름 | 의미 |
|---|---|
| `x3diagChangedCodeAddedTokenCount` | 분모 A |
| `x3diagChangedFileTokenCount` | 분모 B (B 기준 비율이 필요하면 추출을 다시 하지 않고 계산할 수 있다) |
| `x3diagHookTargetUnresolvedCount` | 바뀐 훅 명령이 부르는 내부 실행 대상 중 파일로 해석하지 못한 수 |
| `x3diagHookTargetNonJsCount` | 바뀐 훅 실행 표면 중 JS가 아닌 대상 수(.sh 등) |

해석 실패 수는 archive 불완전성(악성 쪽 파일 누락)과 섞일 수 있어 **모델 입력으로 쓰지 않는다**(결측이 라벨 신호가 되는 X2 문제와 같은 위험).

## 3. 의존성 변경 Feature D (package.json만, 2개)

`dependencies` ∪ `optionalDependencies` (기존 `newDependencyAdded`와 같은 범위. dev·peer 제외). 두 필드에 같은 이름이 있으면 `optionalDependencies` 값이 이긴다(npm 동작).
필드가 객체가 아니면 빈 객체로 본다(기존 `_dependency_names`와 같은 관용).

| 이름 | 정의 | 결측 |
|---|---|---|
| `dependencyRangeChangedCount` | old·new 모두에 있는 이름 중 선언 문자열(`str(v).strip()`)이 다른 수 | 없음(0 이상) |
| `dependencyChangedRatio` | (추가 + 제거 + 범위 변경) / \|old 이름 ∪ new 이름\| | 합집합이 비면 None |

- **전체 정상 데이터에 같은 기준 적용**: 이 extractor는 다른 extractor와 같은 파이프라인에서 2,767쌍 전부(그리고 이후 Test)에 같은 코드로 돈다.
  `exp/d06-hb-typewise`의 의존성 집계는 정상 93쌍(설치 스크립트 추가·새 의존성 쌍)만 대상이라 정상 기준값으로 쓰지 않는다.
- 범위 변경은 선언 문자열 비교다. `^1.2.0` → `^1.3.0`과 `1.2.0` → `~1.2.0`을 모두 1로 센다. semver 해석은 하지 않는다(registry 상태에 의존하지 않기 위해).

## 4. 기존 Feature와의 중복

| X3/D | 겹치는 기존 Feature | 관계 |
|---|---|---|
| `obfHook*` | `obf*ChangedCode` | 바뀐 JS 파일이 훅 대상 하나뿐이면 같은 값. 훅 대상이 변경 파일 일부일 때만 정보가 새로 생긴다. 추출 후 상관을 확인한다 |
| `installHookTarget*CallCount` | `addedProcExecCallCount`, `addedNetworkCallCount` | 대상이 새 파일이면 그 파일의 호출은 added에도 포함된다(added ⊇ 대상의 새 호출). 대상 파일이 그대로이고 명령만 바뀐 경우는 added에 없는 정보 |
| `installHookTargetCount` | `installHookRefFileChanged`, `installHookNewProgramCount`, `installScriptAdded` | 0/양수 여부는 이들과 강하게 겹친다. 개수 자체(여러 대상)는 새 정보 |
| 비율 2개 | `addedNetworkCallCount`, `addedProcExecCallCount` | 분자가 같다. 비율은 분모로 대형 재빌드를 약하게 만든다. 둘 다 입력하면 트리가 분자·분모 조합을 쓸 수 있다 |
| `dependencyRangeChangedCount` | 없음 | `newDependencyCount`와 다른 대상(기존 이름) |
| `dependencyChangedRatio` | `newDependencyCount` | 분자에 추가 수가 들어간다. 의존성이 적은 패키지에서 신규 1개가 큰 비율이 된다 |

## 5. 정상 패키지 오탐 가능성 (Train HB 사례 기준 예상)

- 정상 플랫폼 바이너리 설치기(`node install.js`가 https로 바이너리를 내려받음): `installHookTargetNetworkCallCount` > 0, 프로세스 실행도 있을 수 있다 → 호출 지표만으로는 악성과 구분 안 됨.
  난독화 지표(hex 식별자, escape 밀도)는 낮을 것으로 예상.
- minify된 정상 설치 스크립트(번들러 출력): `obfHookWhitespaceRatio`·`obfHookMeanIdentLength`가 난독화처럼 보일 수 있다(기존 obf 지표와 같은 약점).
- 정상 wasm·API 클라이언트 번들의 `fetch` 추가: 비율 Feature에서 분모가 크면 값이 작아진다(의도). 작은 패키지가 `fetch` 1개를 추가하면 비율이 커진다 → 오탐 가능.
- 악성도 대형 payload(수 MB 번들)를 추가하면 분모 A가 커져 비율이 작아진다 → 비율만으로는 놓칠 수 있어 기존 카운트와 함께 쓴다.
- 의존성 범위 변경: 정상 유지보수 릴리스에 흔하다(악성은 적다 — Train 집계상). 모델에서 "범위 변경 = 정상" 방향 신호가 되면, 공격자가 범위 변경을 섞어 우회할 수 있다.

## 6. 계산 비용·상한

기존 상한(`MAX_FILE_BYTES` 64MB, `MAX_FILE_COUNT` 5000)과 기존 수집 함수(`collect_source_files`)를 그대로 쓴다.
토큰화는 변경 파일마다 old·new 한 번씩 추가된다(X1이 이미 같은 파일에 `lex_js`를 돌린다).
