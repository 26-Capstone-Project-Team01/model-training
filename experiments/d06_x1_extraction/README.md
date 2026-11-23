# D06 X1(코드 문맥) feature 전체 추출과 분석

상태: D06 Train 2,767쌍에 X1 6개를 정적으로 추출하고 기존 29개 feature와 병합·분석했다. **LightGBM 학습은 하지 않았다.**
Test 677은 사용하지 않았다. 개발자료 분석이며 feature 유용성은 모델 실험 전이라 확정하지 않는다.

## 1. 버전

| 항목 | 값 |
|---|---|
| 데이터 | D06, `26-Capstone-Project-Team01/npm-malware-package-pairs` 커밋 `be87ab4cff66fff1980c4a71be8032b6b47225ba` |
| 입력 SHA-256 | `derived/splits/train.csv` `22fbc875…2c23`, `derived/pairs/baselines.csv` `acc48b6a…93d2`, `derived/pairs/malicious_pair_groups.csv` `b05c9dfd…7a7b` (전체 값은 `run_manifest.json`) |
| 쌍 | 2,767 = 악성 928 + 무작위 정상 1,600 + Hard benign 239 |
| 추출기 | `26-Capstone-Project-Team01/depbee-analyzer` `feat/x1-code-context` 커밋 `d56738c234aae239d82729f964b7dd35f304fa93` (Draft PR #17), extractor `code_context` |
| 분할 | 이 저장소 main의 `experiments/d06_feature_comparison_18/` (PR #13). 이 폴더는 분할을 바꾸지 않는다 |
| 환경 | Python 3.13.18, pandas 3.0.6, numpy 2.5.3, requests 2.34.2 (학습 시 lightgbm 4.7.0, PR #13과 동일) |

## 2. PR #13 Fold·Split 재사용

- `analysis/d06_full35.csv`의 i번째 데이터 행 = D06 `train.csv`의 i번째 행 = PR #13 `scores/row_metadata.csv`의 `row_id == i`.
  키(`package`, `old_version`, `new_version`)와 label이 모두 같음을 확인했다.
- 따라서 PR #13 `splits/split1.csv`·`split2.csv`의 `row_id`(stage: fit/calibration/outer, fold 0~2)를 그대로 쓴다.
- 확인 방법:

```python
import pandas as pd
K = ["package", "old_version", "new_version"]
f = pd.read_csv("experiments/d06_x1_extraction/analysis/d06_full35.csv", keep_default_na=False, dtype=str)
m = pd.read_csv("experiments/d06_feature_comparison_18/scores/row_metadata.csv", keep_default_na=False, dtype=str)
m = m.assign(row_id=m.row_id.astype(int)).sort_values("row_id")
assert (f[K].to_numpy() == m[K].to_numpy()).all() and (f.label.to_numpy() == m.label.to_numpy()).all()
```

- PR #13 학습 스냅샷(`load_data`)은 Train CSV가 정확히 29개 feature일 때만 통과한다. full35 학습은 스냅샷을 고치지 말고
  W1(`exp/d06-w1-component-weight`, PR #14)처럼 별도 스크립트에서 `load_data` 결과에 row_id로 X1 열을 붙인다.

## 3. X1 feature와 자료형

| 열 | 자료형 | 결측 |
|---|---|---|
| `installHookNewProgramCount` | nullable int | 훅 해석 실패 |
| `installHookArgsChanged` | nullable bool (`True`/`False`/빈 칸) | 훅 해석 실패 |
| `installHookRefFileChanged` | nullable bool | 내부 실행 파일 확인 불가, 훅 해석 실패 |
| `installHookNewExternalExecCount` | nullable int | 훅 해석 실패 |
| `addedProcExecCallCount` | nullable int | 소스 수집 실패 |
| `addedNetworkCallCount` | nullable int | 소스 수집 실패 |

정의는 depbee-analyzer `docs/x1-code-context-features.md`(커밋 `d56738c`). 추출 실패 쌍은 6개 모두 빈 칸이며 0으로 채우지 않았다.
열 순서·자료형은 `analysis/d06_full35_schema.json`.

## 4. 실행 방법 (재현)

패키지 코드·설치 스크립트를 실행하지 않는다. 악성 원본은 데이터 저장소의 별도 부분 사본에서 정적으로 읽는다.

```bash
# 입력 CSV (고정 커밋)
git -C <npm-malware-package-pairs> show be87ab4c:derived/splits/train.csv > in/train.csv
git -C <npm-malware-package-pairs> show be87ab4c:derived/pairs/baselines.csv > in/baselines.csv
git -C <npm-malware-package-pairs> show be87ab4c:derived/pairs/malicious_pair_groups.csv > in/malicious_pair_groups.csv

# 악성 원본용 부분 사본(blob 없음, symlink·hook 끔). 추출 스크립트가 60쌍씩 sparse checkout한다
git -c core.hooksPath=/dev/null clone --filter=blob:none --no-checkout --depth 1 https://github.com/26-Capstone-Project-Team01/npm-malware-package-pairs archive
git -C archive config core.symlinks false && git -C archive config core.hooksPath /dev/null
git -C archive fetch --filter=blob:none --depth=1 origin be87ab4cff66fff1980c4a71be8032b6b47225ba

# 추출(재시작 가능: 출력 JSONL에 이미 있는 키는 건너뜀). --analyzer-src는 depbee-analyzer d56738c의 src
python -I -B extract_x1.py --analyzer-src <depbee-analyzer>/src --train in/train.csv --baselines in/baselines.csv \
  --archive-repo archive --cache-dir cache --out raw/malicious.jsonl --part malicious --workers 2
python -I -B extract_x1.py ... --out raw/benign.jsonl --part benign --workers 3

# 병합·분석
python -I -B analyze_x1.py --train in/train.csv --baselines in/baselines.csv --groups in/malicious_pair_groups.csv \
  --x1 raw/malicious.jsonl raw/benign.jsonl --out analysis
```

- registry tarball은 `dist.integrity`(sha512) 또는 `dist.shasum`으로 검증한 뒤 `tarfile` `filter="data"`로 임시 해제한다(3,719개, 전부 sha512).
- 악성 쪽이 가장 오래 걸린다(sha1-hulud는 10MB 페이로드 때문에 쌍당 약 24초). tarball 캐시는 약 3.8GB였다(이 브랜치에 없음).
- 평가 코드 `evaluate_w1.py`는 W1 브랜치(`exp/d06-w1-component-weight`, PR #14)에 있다. main에는 아직 없다.

## 5. 결과 파일

```text
experiments/d06_x1_extraction/
  README.md, run_manifest.json   버전·입력 해시·환경·실패 목록
  extract_x1.py, analyze_x1.py   추출·분석 코드
  raw/malicious.jsonl            악성 928쌍 쌍별 추출 결과(상태, 검증 방식, X1 6개, 소요 시간)
  raw/benign.jsonl               정상·Hard benign 1,839쌍
  analysis/d06_full35.csv        2,767행 × (키 3 + 29 + X1 6 + label)
  analysis/d06_full35_schema.json
  analysis/d06_x1_status.csv     쌍별 class, campaign(splitGroup), 성공/실패, 실패 사유
  analysis/x1_distribution.csv   클래스별 결측·비영 비율·값 분포
  analysis/single_feature_auc.csv      단일 feature AUC(악성 vs 정상 / vs Hard benign, 결측 제외)
  analysis/x1_vs_full29_spearman.csv   X1 × 29개 Spearman
  analysis/x1_within_installScriptAdded.csv   installScriptAdded 층별 비영 비율
  analysis/x1_vs_changed_js.csv
  analysis/analysis_report.json  검증, 대표 사례, 캠페인 집중도
```

포함하지 않은 것: 악성 패키지 원본, registry tarball·캐시, 부분 사본, 인증 정보.

## 6. 결과 요약

- 추출: 2,765 성공, 2 실패(Hard benign, registry에서 삭제: `nestjs-grpc` 1.3.11, `@camstack/addon-decoder-ffmpeg` 404).
  성공 쌍 결측은 `installHookRefFileChanged` 11건뿐(악성 4, 정상 1, Hard benign 6).
- 비영(True) 비율, 악성 / 정상 / Hard benign:

| feature | 악성 | 정상 | Hard benign | 단일 AUC vs 정상 / vs Hard benign |
|---|---:|---:|---:|---|
| `installHookNewProgramCount` | 76.8% | 0.06% | 43.5% | 0.884 / 0.663 |
| `installHookArgsChanged` | 0.8% | 0.06% | 0% | 0.503 / 0.504 |
| `installHookRefFileChanged` | 76.8% | 0.2% | 16.5% | 0.883 / 0.802 |
| `installHookNewExternalExecCount` | 0% | 0% | 0% | 0.5 / 0.5 |
| `addedProcExecCallCount` | 55.6% | 0.7% | 11.0% | 0.776 / 0.740 |
| `addedNetworkCallCount` | 83.0% | 1.6% | 18.1% | 0.912 / 0.878 |

- 중복성: `installHookNewProgramCount`는 `installScriptAdded`와 Spearman 0.977(사실상 중복).
  `installScriptAdded=True` 층 안에서 악성 vs Hard benign: `installHookRefFileChanged` 98.3% vs 34.6%,
  `addedNetworkCallCount`>0 92.7% vs 10.6%, `addedProcExecCallCount`>0 70.8% vs 12.4%.
  `installScriptAdded=False` 층: 통신 50% vs 25%(정상 1.6%), 실행 4.2% vs 9.7%.
- 캠페인 집중: 악성 비영 값의 43~64%가 sha1-hulud 한 캠페인. 캠페인 동일 비중 비영 비율은 전체 비율보다 낮다(예: 통신 83% → 52.5%).
- 검토 의견(미확정): 유지 = 통신·참조 파일·실행(주의), 제거 검토 = `installHookNewProgramCount`(중복),
  `installHookArgsChanged`(8건), `installHookNewExternalExecCount`(전부 0).
- 한계: `eval` 페이로드(autotel, miasma), 숨긴 코드(gluestack), webpack 모듈 번호(shai-hulud-original 실행 호출)는 X1이 0.
  정상 `klaviyo-api` 12.0.1의 통신 226은 생성된 API 클라이언트에 의한 극단값.

## 7. 다음 실험(제안, 미실행)

- 고정: D06 `be87ab4c`, 추출기 `d56738c`, PR #13 component outer 3fold와 split1·split2, LightGBM 파라미터·200 rounds·early stopping 없음,
  결측 NaN 그대로, Test 677 미사용.
- 기준선: PR #13 full29 저장 점수(같은 코드로 재학습 시 모델 내용·점수 일치가 W1에서 확인됨).
- 변형(결과를 보기 전에 고정): full35, full29+{RefFile, Proc, Net}(full32), full29+각 1개.
- 평가: W1의 `evaluate_w1.py`와 같은 정의(PR #13 phase7 재현 확인됨). 고정 임계값 Recall/FN·검토 후보·정상/Hard benign 오탐,
  fold 안 순위, 낮은 점수 악성, 캠페인·component 평균 Recall. outer 결과로 feature·임계값을 고르지 않는다.
