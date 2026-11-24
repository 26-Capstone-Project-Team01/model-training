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

## 3. 전체 추출

진행 중. 끝나면 `build_x3d.py` → `analysis/`, `verify_x3.py` 전체 검증 결과를 별도 커밋으로 보존한다.
