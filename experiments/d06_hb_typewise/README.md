# D06 Hard benign 오탐 분석 · 변경 유형별 모델 검토 · 추가 Feature 설계 검토

**분석만 했다.** 새 모델 학습, 신규 Feature 전체 추출, 기존 데이터·모델·결과 수정은 하지 않았다. 패키지 코드는 실행하지 않았고
`package.json`(데이터 저장소 `be87ab4c` archive)과 registry packument JSON만 읽었다.

- 설계 근거 = D06 Train 외부 fold(PR #13 분할, split1/split2), 임계값 = `../d06_x1_fair_compare/calibration_attainment.csv`의 목표 FPR 5%.
  점수는 PR #13 저장 점수(base7, full29)와 `../d06_full35_compare` 점수(full35), A1~A3 = (1-w)·full29 + w·full35 (w=0.1/0.2/0.3).
  분리 결과가 `fair_comparison.csv`(calFPR5%)의 TP/FP와 모두 일치하는지 assert로 확인했다.
- 진단 전용 = D06 Test-674(`../d06_test_eval`, `../d06_es_followup`의 full35_es). Test 결과로 정한 것은 없다.
- 라우팅 규칙 2개는 평가 전에 고정했고 Train 외부 fold에서만 계산했다(설계 점검). 합성 점수의 임계값은 같은 fold의 calibration 합성 점수로 다시 정했다.

## 1. Hard benign 오탐 (Train 외부, FPR 5%) — `out/`

| 모델 | split1 HB 오탐 | split2 HB 오탐 | 이 모델만의 오탐 (s1/s2) |
|---|---:|---:|---:|
| base7 | 54 | 34 | 40 / 22 |
| full29 | 31 | 39 | 0 / 3 |
| full35 | 50 | 43 | 12 / 12 |
| A1 | 32 | 43 | 0 / 0 |
| A2 | 31 | 46 | 0 / 0 |
| A3 | 33 | 42 | 0 / 0 |

Hard benign 239쌍. 6개 모델 공통 오탐은 split마다 3쌍뿐이다. base7 오탐은 거의 전부 `installScriptAdded` 쌍(52/114, split1)이고,
full29/full35/A 계열 오탐은 설치 스크립트 추가 쌍과 **설치 스크립트 없이 JS 번들에 네트워크·프로세스 호출이 추가된 쌍**(wasm·ffmpeg·CLI 래퍼 등)으로 나뉜다.

Test-674 진단(seed 09/10): base7 12/13, full29 5/3, full35 9/4, full35_ES 11/6, A2 4/4. 거의 모두 `installScriptAdded` 쌍이다. ES는 HB 오탐을 줄이지 않았다.

### 1.1 Feature 분포 (`train_feature_profiles.csv`, HB 오탐 = full29·full35·A2 중 하나라도 오탐)

| 비율(값>0) | HB 오탐 s1 | HB 정탐 s1 | 악성 | 무작위 정상 |
|---|---:|---:|---:|---:|
| installScriptAdded | .57 | .45 | .77 | .001 |
| newDependencyAdded | .41 | .16 | .11 | .06 |
| obfChangedFileCount | .98 | .60 | .97 | .63 |
| obfHexIdentRatioNew | .04 | .00 | .58 | .002 |
| obfEscapeDensityChangedCode | .45 | .17 | .81 | .08 |
| installHookRefFileChanged | .32 | .11 | .77 | .002 |
| addedNetworkCallCount | .46 | .09 | .83 | .02 |
| addedProcExecCallCount | .25 | .07 | .56 | .007 |

HB 오탐은 "설치 훅 + 새 의존성 + 네트워크 호출 추가"라는 구조적 신호는 악성과 닮았고, 난독화 신호(hex 식별자, escape 밀도)는 악성보다 훨씬 약하다.

### 1.2 TreeSHAP (`train_treeshap_hb_vs_malicious.csv`, 평균 기여)

- base7: HB 오탐을 올리는 것은 `installScriptAdded`(+3.77), `installScriptPresent`(+2.60), `scriptEntryAdded`(+1.99) — 악성 TP와 같은 Feature, 같은 크기. base7은 구조적으로 구분 불가.
- full35: HB 오탐을 올리는 상위 = `installHookRefFileChanged`(+0.55), `addedNetworkCallCount`(+0.52), `newDependencyAdded`(+0.50), `installHookNewProgramCount`(+0.48).
  `obfChangedFileCount`(−1.93)가 반대로 끌어내리지만 부족한 경우가 오탐이 된다.

### 1.3 설치 훅 명령 (`analysis/hook_*`, Train, 새로 추가·변경된 preinstall/install/postinstall)

| 명령 유형 | HB 오탐 (56) | HB 정탐 (57) | 악성 (716) |
|---|---:|---:|---:|
| `node <파일>` 형태 | 52% | 35% | **98%** |
| 빌드·설정 도구(patch-package, husky, playwright/puppeteer 설치 등) | 13% | 18% | 0% |
| 네이티브 빌드(node-gyp 등) | 7% | 7% | 0% |
| 기타(npm run, npx only-allow, tsc, lerna 등) | 25% | 37% | 0.3% |
| 다운로드 도구(curl 등) | 0% | 0% | 1.4% |

- 악성 훅은 거의 전부 `node <파일>` / `bun run <파일>`이고, 정상 플랫폼 바이너리 패키지(`@napi-rs/*-linux-x64`, esbuild 계열)의 `node install.js`와 **명령 문자열이 같다.**
  따라서 명령 문자열 Feature로 둘을 가르기는 어렵고, 구분은 **참조 파일의 내용**에서 나와야 한다.
- `node <파일>`이 아닌 훅(빌드·설정 도구, npm run 등; HB 오탐 45%, HB 정탐 61%)은 악성에 거의 없다(1.8%, 대부분 curl 다운로드). 그러나 이 신호는 HB 정탐 쪽에 더 많아 오탐 감소 효과는 제한적이고, 허용 목록 방식이라 우회 위험이 있다.

### 1.4 대표 사례 (`out/train_hard_fp_cases.csv`, `out/test_hard_fp_cases.csv`)

- 설치 훅 추가 + 바이너리/브라우저 설치: ghost-cursor-playwright, cypress-accessibility-checker, @cityssm/pdf-puppeteer(`npx puppeteer browsers install || exit 0`), Test의 onnxruntime-node, puppeteer.
- 네이티브 플랫폼 패키지 `node install.js`: @napi-rs/*-linux-*, esbuild-experimental-optdeps, easy-ffmpeg.
- 훅 없이 번들에 네트워크 호출 추가: @ffmpeg/core-mt(4), @gapi/federation(8), zsign-wasm(13), byterover-cli(6), @postgres-language-server/wasm(4) — wasm 로딩·API 클라이언트용 `fetch`.
- 대형 재빌드: resolve-url-loader(변경 파일 1,977), @mongez/huskier(948, 프로세스 호출 10) — 변경량이 큰데 정규화되지 않은 카운트가 커진다.

## 2. 변경 유형별 성능과 라우팅 (`out/strata_performance.csv`, `out/train_routing_design_check.csv`)

Train 외부 악성 928 중 JS 변경 없음은 **31쌍뿐**이고, Test mastra와 같은 "JS 변경 없음 & 새 의존성 & 설치 훅 추가 없음" 악성은 **6쌍**이다(Test-674에서는 113쌍).

| 규칙 (Train 외부, FPR 5%) | TP s1/s2 | FP s1/s2 | HB 오탐 s1/s2 |
|---|---:|---:|---:|
| full35 | 854 / 876 | 106 / 117 | 50 / 43 |
| base7 | 618 / 621 | 111 / 112 | 54 / 34 |
| JS 변경 없음 → base7, 나머지 full35 | 770 / 811 | 82 / 92 | 33 / 18 |
| JS 변경 없음 & 새 의존성 & 훅 추가 없음 → base7 | 853 / 880 | 98 / 115 | 48 / 43 |

- 두 번째 라우팅은 full35와 사실상 같다. 해당 유형의 Train 악성이 6쌍이라 Train에서 이 라우팅의 이득을 확인할 근거가 없다.
  Test에서 base7이 이 유형을 잡은 것(seed10 68/113)은 seed10 학습에 mini-shai B가 들어간 결과로 이미 확인했고(`../d06_test_followup/cause`), Train 설계 근거로 쓸 수 없다.
- JS 변경 없음 전체를 base7로 보내면 FP는 줄지만 TP가 84/65 줄어 득이 없다. 합성 점수에서 calibration 임계값이 JS 변경 쌍 쪽으로 다시 정해지기 때문이다.
- 유형별 블렌딩 가중치도 같은 이유(대상 유형의 Train 악성 부족)로 Train에서 추정할 수 없다. 이전 C(제한 보정, NO-GO)와 같은 문제이고,
  B(feature_contri)처럼 특정 Feature 묶음의 영향을 조정하는 방식은 유형 라우팅과 목적이 겹친다. 둘 다 **신호가 Train에 없는 문제를 모델 구조로 풀 수 없다**는 결론은 같다.

## 3. 추가 Feature 설계 검토

| 후보 | 현재 추출기로 가능? | 계산 방법 | Train 관찰 | 한계 |
|---|---|---|---|---|
| 변경 코드 토큰 수 대비 추가 네트워크·프로세스 호출 비율 | **아니오** | `obfuscation._file_stats`가 파일별 identifier·number 토큰을 만들지만 집계·출력하지 않는다. 변경 파일 토큰 합을 내보내는 수정 필요. `code_context.added_call_features`의 카운트를 그 합으로 나눈다 | 대형 재빌드 HB 오탐(1.4절)의 큰 카운트를 낮출 것으로 기대 | 악성도 대형 번들(수 MB payload)이면 비율이 낮아져 신호가 희석될 수 있음. 분모 0 처리 정의 필요 |
| 기존 의존성 버전 범위 변경 수 | 예 (package.json) | 이름이 같고 선언 문자열이 다른 `dependencies`∪`optionalDependencies` 수 | 범위 변경 >0: 악성 3.9%, HB 19.6%(HB 오탐 21%) | 악성 중 injective(12/12)·pgserve(6/10)·chaindrop(9/25)에 몰림. 정상 쪽 기준값은 일부 정상(93쌍)만 수집해 **미확인** — 전체 정상 1,600쌍 수집 필요 |
| 전체 의존성 대비 변경(추가+범위 변경) 비율 | 예 | (추가 + 범위 변경) / new 의존성 수 | 중앙값 악성 0, HB 0.1, HB 오탐 0.17 | 의존성 0개면 NaN(HB 45%, 악성 22%) — NaN 처리 사전 결정 필요. mini-shai 신규 git 의존성 쌍이 악성 쪽 값을 대부분 만든다 |
| 신규 의존성 선언 형식(git/URL/file) | 예 | 추가 의존성 중 registry 범위가 아닌 선언 수 | >0: 악성 9.6%(거의 mini-shai), HB 1%, 정상 0% | 단일 캠페인 지문 위험(X2 검토와 같은 결론) |
| 설치 훅 참조 파일의 난독화 지표 | 아니오(조합 필요) | `code_context._hook_targets`로 찾은 파일에 `obfuscation.file_metrics` 적용 | 1.3절: 명령 문자열은 같고 참조 파일 내용이 달라야 구분 가능 | 추출기 수정 필요. 참조 파일이 없는 경우(외부 다운로드 등) 결측 정의 필요 |
| 추가된 네트워크 호출 대상 리터럴 유형 | 아니오(조합 필요) | `call_signatures`가 이미 인자 리터럴을 가진다. 상대경로·registry·GitHub 릴리스 vs 원시 IP·웹훅 등 일반 범주만 센다 | wasm·API 클라이언트 HB 오탐의 `fetch`는 상대 경로·자체 API가 많아 보임(미집계) | 특정 도메인 이름을 Feature로 쓰면 캠페인 지문이 됨 — 일반 범주로만 |
| 플랫폼 바이너리 패키지 여부(`os`/`cpu`/`binary` 필드) | 예 (package.json) | 필드 존재 여부 | 이번 수집에 `os`/`cpu`를 넣지 않아 **미확인** | 악성이 같은 필드를 넣으면 우회 가능 |

검토 결과 우선순위(제안, 아직 구현 안 함):
1. 훅 참조 파일 난독화 지표 + 변경 코드 토큰 정규화 호출 비율 — HB 오탐의 두 유형(훅 추가, 번들 호출 추가)을 직접 겨냥하고, 추출기 내부에 이미 있는 계산을 조합하면 된다.
2. 기존 의존성 범위 변경 수 / 변경 의존성 비율 — 계산은 쉽지만 정상 전체 기준값 확인과 NaN 정의가 먼저다.
3. 신규 의존성 선언 형식 — 캠페인 지문 위험으로 보류 권장.

## 4. 파일

```text
hb_typewise.py                 1·2절 (저장 모델·점수만 사용, 학습 없음)
out/hard_fp_overlap.csv        모델별 HB 오탐 수, 공통·단독 오탐 (Train, Test 진단)
out/strata_performance.csv     유형별 클래스별 선택 수 (Train, Test 진단)
out/train_routing_design_check.csv
out/train_treeshap_hb_vs_malicious.csv
out/train_feature_profiles.csv
out/train_hard_fp_cases.csv, out/test_hard_fp_cases.csv
out/manifest.json
hook_commands.py               Train 쌍 package.json(archive/registry) 수집: 정상은 설치 스크립트 추가·새 의존성 쌍(93)만
hookfam.py                     훅 명령 유형·파생 값 계산 (sanitize·analysis 공용)
sanitize_manifests.py          수집 원본에서 악성 행의 훅 명령 원문을 지우고 유형·URL 여부·출력 숨김 여부·토큰 수·명령 sha256만 남긴다
manifests/manifests_summary.csv  정리본 (식별 정보 + 의존성 선언 + 비악성 훅 명령 + 파생 값). 원본(sha256 1b2637a6…)은 보존하지 않음
manifests/registry_log.jsonl, manifest.json   (HB 2쌍 manifest 없음)
manifest_analysis.py           1.3절, 3절 의존성 후보 계산 (정리본만 읽는다)
analysis/*.csv, manifest.json  악성 훅은 유형 집계만 저장
```

실행: `python -I -B hb_typewise.py --out out`(PR #13 venv), `python -I -B hook_commands.py --archive-repo <be87 사본> --out <임시 폴더>`(requests 필요), `python -I -B sanitize_manifests.py --raw <임시 폴더>/manifests_summary.csv --out manifests/manifests_summary.csv`,
`python -I -B manifest_analysis.py --manifests manifests --hb out --out analysis`.

정리 전후 검증: 정리본으로 다시 계산한 `analysis/*.csv` 7개가 원본으로 계산한 결과와 바이트 단위로 같다. registry 상태가 바뀌므로 수집을 다시 하면 HB·정상 행의 값이 달라질 수 있다.
