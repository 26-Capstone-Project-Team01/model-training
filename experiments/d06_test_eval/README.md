# D06 Test 평가 준비: Test 677쌍 X1 추출·병합 (학습·예측·성능 계산 없음)

평가 조건은 `PREREGISTRATION.md`(Test 예측 전에 작성). 이 폴더는 그 7절(Test X1 추출)까지만 수행한 결과다.

## 1. 입력

| 항목 | 값 |
|---|---|
| Test | `npm-malware-package-pairs` `be87ab4c` `derived/splits/test.csv` 677행 (SHA-256 `e8a70053…8bd73`): 악성 217, 무작위 정상 400, Hard benign 60 |
| 출처 목록 | 같은 커밋 `derived/pairs/baselines.csv` (`acc48b6a…`), `malicious_pair_groups.csv` (`b05c9dfd…`) |
| 추출기 | `depbee-analyzer` `d56738c234aae239d82729f964b7dd35f304fa93`, `code_context` |
| 비교 기준 | Train X1 `../d06_x1_extraction/analysis/d06_full35.csv`, `d06_full35_schema.json` |

## 2. 절차

- `extract_x1_test.py`: `../d06_x1_extraction/extract_x1.py`의 복사본. 바꾼 것은 입력 인자 이름(`--train` → `--pairs`), 행 수 검사(2,767 → 677), docstring뿐이다.
  쌍 단위 추출(`extract_pair`), tarball 검증, archive sparse checkout은 같다.
- 출처: 정상·Hard benign 460쌍과 악성 112쌍의 old는 registry tarball(전부 sha512 검증 후 `filter="data"`로 임시 해제),
  악성 217쌍의 new와 105쌍의 old는 데이터 저장소 `be87ab4c`의 새 부분 사본(blob 없음, symlink·hook 끔)에서 60쌍씩 sparse checkout.
- **패키지 코드·설치 스크립트는 실행하지 않았다.** npm install도 하지 않았다.
- `merge_x1_test.py`: `../d06_x1_extraction/analyze_x1.py`의 병합 부분과 같은 형식으로 `test.csv`에 X1을 키로 붙이고 검증한다.
  pandas 3에서 Test의 bool X1 열에 결측이 없으면 dtype이 bool이 되어 실패 행 비우기가 오류를 내므로, X1 열을 object로 바꾼 뒤 처리한다(출력 형식은 같다).

## 3. 결과와 검증 (`analysis/validation.json`)

| 항목 | 결과 |
|---|---|
| 추출 상태 | 677/677 ok, 실패 0 |
| 키 | Test 677 키와 X1 결과 1:1, 중복 0, 누락 0, Test 밖 키 0 |
| label·class | label = 1 ⇔ class = malicious, class 400/217/60 |
| 행 순서·29개 Feature·label | `test.csv`와 완전히 같음 |
| 열 | Train `d06_full35.csv`와 열 이름·순서 같음 (키 3 + 29 + X1 6 + label = 39열), schema 열 목록도 같음 |
| X1 형식 | bool 2개는 `True`/`False`/빈 칸, 개수 4개는 정수 문자열. `run_full35.py`와 같은 인코딩으로 읽으면 Train과 dtype이 같다 |
| 성공 쌍의 X1 결측 | `installHookRefFileChanged` 7건(악성 6, Hard benign 1, 정의상 결측: 내부 실행 파일 확인 불가 등). 나머지 5개 0건. 0으로 채우지 않았다 |
| 출처 검증 | old: sha512 572 / archive 105, new: sha512 460 / archive 217 |
| 개수 X1 범위 | NewProgram 0~2, NewExternalExec 0~0, Proc 0~6, Net 0~35 |
| 환경 재현 | 같은 환경에서 원래 Train 스크립트로 Train 정상 12쌍을 다시 추출 → 저장된 Train 결과와 X1·status 12/12 같음 |

## 4. Test-674

- 제외 3쌍: `vant 4.9.11 → 4.9.12 / 4.9.13 / 4.9.14`. `analysis/d06_test_x1_status.csv`의 `excluded_in_test674=True`로 표시했다. 원본 파일과 행은 바꾸지 않았다.
- `d06_test_full35.csv`에서 이 키 3개를 거르면 674행(악성 214, 정상 400, Hard benign 60)이 되고, 33개 원래 열이 main `4498acd`의 `test.csv`와 완전히 같다.

## 5. 파일

```text
PREREGISTRATION.md              평가 조건 사전 등록 (Test 예측 전 작성)
extract_x1_test.py              Test X1 추출 (Train 스크립트 복사본)
merge_x1_test.py                병합·검증
run_manifest.json               입력·출력 해시, 추출기 커밋, 환경, 결과 요약
raw/malicious.jsonl             악성 217쌍 쌍별 결과(status, 검증 방식, X1 6개, 소요 시간)
raw/benign.jsonl                정상·Hard benign 460쌍
analysis/d06_test_full35.csv    677행 × 39열 (Train d06_full35.csv와 같은 형식)
analysis/d06_test_full35_schema.json   열·자료형 (Train schema와 같음)
analysis/d06_test_x1_status.csv 쌍별 class, splitGroup, status, 출처 검증, excluded_in_test674
analysis/validation.json        위 3절 검증 전체
```

포함하지 않은 것: 패키지 원본, tarball 캐시, 데이터 저장소 부분 사본, 인증 정보.

## 6. 재현

```bash
# 입력 (고정 커밋): test.csv, baselines.csv, malicious_pair_groups.csv  ← git show be87ab4c:<path>
# 악성 원본용 부분 사본
git -c core.hooksPath=/dev/null clone --filter=blob:none --no-checkout --depth 1 https://github.com/26-Capstone-Project-Team01/npm-malware-package-pairs archive
git -C archive config core.symlinks false && git -C archive config core.hooksPath /dev/null
git -C archive fetch --filter=blob:none --depth=1 origin be87ab4cff66fff1980c4a71be8032b6b47225ba
# 추출 (depbee-analyzer d56738c의 src, Python 3.13 + requests, semver)
python -I -B extract_x1_test.py --analyzer-src <depbee-analyzer>/src --pairs in/test.csv --baselines in/baselines.csv \
  --archive-repo archive --cache-dir cache --out raw/malicious.jsonl --part malicious --workers 2
python -I -B extract_x1_test.py ... --out raw/benign.jsonl --part benign --workers 3
# 병합·검증
python -I -B merge_x1_test.py --test in/test.csv --test-main <main test.csv> --baselines in/baselines.csv \
  --groups in/malicious_pair_groups.csv --x1 raw/malicious.jsonl raw/benign.jsonl \
  --train-full35 ../d06_x1_extraction/analysis/d06_full35.csv --train-schema ../d06_x1_extraction/analysis/d06_full35_schema.json --out analysis
```
