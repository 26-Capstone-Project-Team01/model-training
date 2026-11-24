# D06 X3/D 추출 (Train 2,767쌍)

정의: depbee-analyzer `feat/x3-hook-target-context` e45cb4d `docs/x3-features.md`. 패키지 코드는 실행하지 않는다.
`extract_x3.py`는 X1 추출(`../d06_x1_extraction/extract_x1.py`)의 소스 처리(registry tarball 무결성 확인, archive sparse checkout)를 그대로 쓰고,
package_json·obfuscation·code_context(기존)와 x3_context·dependency_change(신규)를 한 번에 돌린다. 기존 35개는 검증용으로 다시 계산한다.

## 1. 시범 추출 (완료)

- 대상 81쌍(`pilot_rows.csv`: 캠페인별 악성 2쌍, HB 오탐 상위·무작위 HB, 무작위 정상, 대형 변경), 실패 0.
- 출력: `pilot_extraction/*.jsonl`, 검증: `verify_x3.py` → `pilot_verify/` (report.json, 결측 종류·분모·극단값 표)
- 결과: 기존 34개 Feature(updateInterval 제외)는 1쌍 3개를 빼고 모두 저장값과 같다. 그 1쌍(node-pngquant-native 0.0.13)은 저장값이 registry manifest(npm이 `gypfile: true`에
  `install: node-gyp rebuild`를 자동 추가) 기준이고, tarball package.json에는 scripts가 없다. 출처 차이이며 X1도 tarball 기준이라 X3와 일관된다.
  비율 산술·분자 일치 확인, 분모 0 17쌍(호출 있는데 분모 0은 0쌍), 일부 대상만 해석 가능한 쌍 0.
- 시범 실행 시점의 `extract_x3.py`에는 아래 `--reuse-x1-calls` 옵션이 없었다(옵션을 끄면 같은 코드 경로).

## 2. 속도 개선 (`speedup_equivalence/`)

- 원인: x3_context가 X1 분자(`added_call_features`)를 같은 파일에 다시 계산한다. 대형 쌍 1개 측정: obfuscation 33.3초, code_context 32.9초, x3_context 35.1초
  (그중 `added_call_features` 33.5초, X3 토큰화 2.5초).
- `--reuse-x1-calls`: 한 쌍 안에서 code_context가 계산한 결과를 x3_context가 재사용(같은 함수·같은 입력). 추출기 코드는 바꾸지 않았다.
- 동일성 검사: 이미 추출한 정상 12쌍(대형 3쌍 포함)을 옵션을 켜고 다시 추출 → 시간 외 모든 값 동일(`result.json`), 대형 쌍 1.5~2배 빨라짐.
- 전체 추출의 악성 쪽은 272쌍까지 옵션 없이, 이후는 옵션을 켜고 이어서 추출한다(기록: 전체 추출 보존 시 `malicious_rows_before_reuse_option.txt`).

## 2b. 속도 개선 2 (`speedup_equivalence_file_cache/`)

- 원인: 대형 캠페인 쌍(예: 332쌍 component)이 같은 수 MB payload 파일을 공유해 쌍마다 같은 파일을 세 extractor가 다시 분석한다.
- `--file-cache`: 작업 프로세스 안에서 파일 단위 순수 함수(`call_signatures`, `obfuscation.file_metrics`, `x3_context.js_tokens`)를 파일 텍스트 SHA-256으로 메모이즈. 추출기 코드는 바꾸지 않았다.
- 동일성: 이미 추출한 악성 23쌍(같은 payload를 공유하는 쌍 포함, 데이터 저장소 별도 worktree로 체크아웃)과 정상 12쌍을 두 옵션을 켜고 다시 추출 → 시간 외 모든 값 동일(`result.json`).
  1 worker 기준 악성 560초 → 118초, 정상 536초 → 256초.
- 악성 348쌍까지는 이 옵션 없이, 이후는 `--reuse-x1-calls --file-cache`로 이어서 추출(경계: 전체 결과 보존 시 `malicious_rows_before_file_cache_option.txt`).

## 3. 전체 추출 (완료)

- 2,767쌍: 성공 2,765(악성 928, 정상 1,600, HB 237), 실패 2(HB: nestjs-grpc old 버전이 registry 메타데이터에 없음, @camstack/addon-decoder-ffmpeg 404 — X1 추출과 같은 2쌍). 실패 행은 빈 칸으로 두고 `analysis/d06_x3d_status.csv`에 사유를 남겼다.
- 원본 결과: `full_extraction/*.jsonl`(옵션 경계 파일 포함), 모델 입력용: `analysis/d06_x3d.csv`(Train 행 순서, X3 13 + D 2 + 진단 4).
- 검증(`full_verify/`):
  - 기존 34개 Feature(updateInterval 제외): 8쌍 18값만 저장값과 다르고 모두 같은 출처 차이다. argon2·tree-sitter-typescript·png-img·midi·macos-alias·node-pngquant-native 등
    네이티브 빌드 패키지에서 저장값(registry manifest, npm이 `gypfile`에 `install: node-gyp rebuild` 자동 추가)은 설치 스크립트가 있고 tarball package.json에는 없다. X1·X3는 tarball 기준이다.
  - 비율 산술과 분자(X1 값과 동일) 확인. 분모(추가 토큰) 0: 788쌍(호출이 있는데 0인 쌍 0), 20 미만 352쌍 — 작은 변경에서 비율이 커진다(최대 정상 250).
  - 훅 상태: 악성 710/928이 분석 대상 있음, 201 훅 없음, 13 훅 있으나 바뀐 JS 대상 없음, 4 해석 실패만. HB 46/237 대상 있음, 61 바뀐 JS 대상 없음, 6 해석 실패만. 정상 4/1600 대상 있음.
    일부 대상만 해석된 쌍 1(HB ringfence).
  - 결측률(`missing_and_extremes_by_class.csv`): 훅 대상 지표 결측 = 대상 0개(정상 99.8%, HB 80.6%, 악성 23.5%) — 기존 installScriptAdded 등과 겹치는 정보다.
    비율 결측 = 추가 토큰 0(정상 42.4%, HB 32.9%, 악성 3.3%) — JS 변경 없음과 겹친다.
  - D: `dependencyRangeChangedCount` > 0 정상 25.9%, HB 20.3%, 악성 3.9%. `dependencyChangedRatio` 결측(의존성 없음) 정상 28.8%, HB 33.8%, 악성 21.9% — 결측이 악성 쪽으로 몰리지 않는다.
  - 훅 대상 프로세스 실행 호출 수 중앙값: 악성 5, HB 95분위 2.
