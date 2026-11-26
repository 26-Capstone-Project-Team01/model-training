# D08 분석 · 그룹 누출 검증 · G2 실험 설계 보고서

작성 2026-11-26. 데이터: `npm-malware-package-pairs` 태그 D08 = `2c48bd83d23ceb16ba7f6c3989d7fb623dcdd554`
(Train 5,344 = 악성 3,505 / benign 1,600 / hard_benign 239, Test 684 = 224 / 400 / 60). D06 Train = `be87ab4c`(2,767행).
이 보고서는 분석 기록이며 동결 데이터·Test 결과는 수정하지 않았다. 복호화한 악성 payload는 이 폴더에 없다.

## 1. M1–M4 40-run (G0 = 원래 splitGroup, Train 내부, Test 미사용)
- 설정: no_interval28, LightGBM PR #13 파라미터(seed 20261109), 200 rounds, 탐욕 5-fold(PR #13 `components()`),
  정상 전용 calibration(fit 정상의 25%, seed 20261109/20261110), PR #13 `calibrate`(예산 floor(368×목표), 경계 동점은 음성).
- M1 = fit ∩ D06, M2 = fit 전체, M3 = D06 + 신규 악성 (package, old, P, v28)당 최저 버전 1행(+changedJsSetSha1 되살림),
  M4 = fit 전체 + 악성 w = 1/√n_P(악성 합 = 악성 수로 정규화).
- 주요 결과(seed 09/10): 1%에서 Recall M1 .948/.954(최고), Hard benign FPR M1 .042/.029(최저); 5%에서 macro(실제 캠페인 20개)
  M4 .812/.847(최고). `obfWhitespaceRatioChangedCode` gain 비중 M1–M3 ≈ .65, M4 .25. 상세: `results_m1m4_40run_G0/eval/`.

## 2. 그룹 누출 검증 (상세: `evidence/EVIDENCE_SUMMARY.csv`)
등급: A = 같은 사건(같은 IOC 또는 바이트 동일 payload), B = 같은 악성코드(공격자 작성 코드 공유), C = 로더 템플릿만 공유.
- E1 Toptal: toptal-xene(fold 3) ↔ toptal(fold 4), 동일 hook + 고유 webhook 토큰. 누출은 양방향(M1의 toptal recall도 xene 덕).
- E2 shai-hulud-original 안의 6행 = debug/chalk crypto-clipper(공격자 지갑 0x66a9…A8Af). Test debug-chalk-duckdb 17행과 동일 공격 → Train↔Test 누출.
- E3 autotel + miasma + miasma-leoplatform + individuals 7행: 동일 binding.gyp, 동일 ROT/AES 로더, 복호화 내부 payload 바이트 동일.
- E4 js-metrics ↔ ngx-context-menu: 4.6KB 동일 주입 코드. E5 apt.js 스키머 4개 패키지(individuals, fold 3/4).
- E6 (B) mini-shai-hulud(redhat 37행 포함)·SAP·bitwarden·E3 군집: `[npmoidc]`, `audience=npm:registry.npmjs.org`, `format-check.yml`, `stillsuit` 등 공격자 문자열 공유.
- E7 (C) chaindrop ↔ npmoidc 계열: bun 1.3.13 setup.mjs 템플릿만 공유, payload는 VM 패킹으로 비교 불가 → 병합하지 않음(잔여로 명시).
- 동일 공격 아님: sha1-hulud ↔ shai-hulud-original(라이브러리 문자열·trufflehog URL만), 일반 hook/의존성, SDK 상수, 번들 라이브러리.

## 3. 채택 그룹: G2f (`mappings/merge_G2f.json`)
= G2(Toptal 병합, clipper 6행 분리, npmoidc 계열 591행 병합, ngx-context-menu→js-metrics) + apt.js 4행 그룹(E5, 이번 검증에서 추가).
| fold | val 악성 | M1 fit 악성 | M2 fit 악성 | 캠페인 |
|---|---|---|---|---|
| 0 | 1,694 | 903 | 1,811 | chaindrop |
| 1 | 795 | 596 | 2,710 | sha1-hulud |
| 2 | 591 | 664 | 2,914 | npmoidc 계열 |
| 3 | 213 | 725 | 3,292 | shai-hulud-original (+individuals 22) |
| 4 | 212 | 824 | 3,293 | 12개 캠페인 (+individuals 63) |
정상: 모든 fold val benign 320 / hard_benign 48(fold 3은 47), calibration 368, fit 정상 1,103(fold 3은 1,104). 실제 캠페인 K = 16.
검증(`scripts/group_leakage/verify_g2_links.py`): A·B 등급 근거 링크 중 fold를 넘는 것은 벤더링된 FontAwesome 폰트(일반 자산)뿐.
C 등급 잔여: chaindrop(fold 0) ↔ npmoidc 계열(fold 2), 의도적으로 수용.

## 4. 이번 확인 사항
### 4.1 Train↔Test debug-chalk 누출 제거 평가 설정
- Train/Test 사이에 패키지·해시 겹침은 없다(PR #13 disjoint 검사 통과). 누출은 공격 수준(E2)만이며, 다른 Test 그룹(canisterworm, mastra, rspack-vant, individuals 4)과 Train 사이 특정 근거 공유는 없다.
- 제안(Test를 보기 전에 Train 쪽 근거만으로 고정): 최종 모델 학습 시 실험 설정의 제외 목록으로 Train clipper 6행을 뺀다(데이터 파일 수정 없음, 목록·해시를 config에 기록).
  Test 224행은 그대로 평가하고, debug-chalk-duckdb는 "처음 보는 공격"으로 남는다. 보조로 "6행 포함 모델"의 debug-chalk recall을 seen-family로 표시해 별도 보고.
- Train 내부 CV(G2f)에서는 6행을 독립 캠페인(fold 4)으로 유지한다(M1은 D06 행만 쓰므로 원래 영향 없음).
### 4.2 node-env-resolver-aws
- 쌍 폴더 11.0.1→12.0.1의 정상 baseline(npm registry 무결성 확인)에 악성 binding.gyp(34dd8151)와 ROT/AES index.js가 있다 → 11.0.1도 감염 버전, 쌍은 악성→악성.
- D08에서는 이미 `split=excluded`(`needs_metadata_review`)로 Train/Test에 없다 → 현재 데이터셋 영향 없음. baselines 행(12.0.0→12.0.1)과 폴더(11.0.1) 메타데이터가 불일치.
- 전체 악성 쌍 normal_raw 상위 파일 5,217개를 계열 서명으로 검사: 다른 오염 baseline 없음(duckdb·keytar binding.gyp는 정상 node-addon-api 패턴).
- 한계: benign/hard_benign 쌍의 baseline은 저장소에 raw 파일이 없어 검사하지 않았다.
### 4.3 Fold 불균형과 Macro Campaign Recall
- G2f에서 16개 캠페인 중 12개가 fold 4 한 모델·한 임계값으로 평가된다(macro 가중치 75%). fold 0–3은 각 1개 캠페인이고 recall ≈ 1.0으로 포화.
- G0 결과 분해: seed 간 macro 차이는 전부 fold 3·4에서 나왔다. 캠페인 크기 1인 그룹 하나가 macro를 1/16 = 6.25%p 움직인다.
  근사 이항 SE ≈ .046으로, 모델 간 macro 차이(.01–.04)와 비슷한 크기.
- fold 평균형 macro는 포화된 큰 fold에 가중을 줘 차이를 압축하므로 주지표로 부적합.
- 결론: 주지표는 캠페인 동일가중 macro(K=16)로 유지하되, 같은 fold·calibration에서 캠페인별 짝비교, n≥5 macro, 캠페인별 Wilson CI,
  fold별 분해를 함께 보고하고 모델 순위는 seed 2개 모두에서 같은 방향일 때만 결론 낸다.

## 5. 최종 60-run 계획 (G2f, 아직 실행 전)
- 모델: M1, M2, M3, M4, M2-r, M4-r × 5 fold × calibration seed 2 = 60.
  - M2-r: M2 행, 악성 가중치 균일 = (fold의 M1 fit 악성 수)/(M2 fit 악성 수), 정상 1.
  - M4-r: M4 가중치 × (M1 fit 악성 수 / M4 악성 가중치 합).
- 그 외 설정은 40-run과 동일. 같은 seed·fold에서 6개 모델이 같은 fit/calibration/validation 행을 쓴다.
- 지표: 기존 지표 + whitespace 구간별 recall(구간 경계는 fold의 fit 정상에서 p5/p95로 계산; 결측은 별도 구간) + 4.3의 macro 변형.
- 비교: M2 vs M2-r(비율 효과), M2-r vs M1(구성 효과), M4 vs M4-r, M3 vs M2.
- 출력은 새 폴더, 기존 run/eval 덮어쓰지 않음. feature ablation은 이 결과를 본 뒤 결정.

## 6. 재현
`README.md` 참조. 입력: D08 태그의 blob:none clone + `inputs/`(해시 고정). `all_blobs.tsv`(ls-tree 결과, 290MB)와
복호화 payload는 재생성 가능하므로 보존하지 않는다.

## 7. 이번 결정과 60-run (G2f, 2026-11-26)
### 7.1 결정
- G2f를 메인 그룹 분할로 채택. clipper 6쌍(`g2f_60run/config/dev_exclusion_clipper6.csv`, 근거 E2)은 60-run 개발 데이터와 최종 학습 모두에서 제외. D08 원본·Test 684쌍은 변경 없음.
- G0→G2f 통합 목록: `g2f_60run/config/group_mapping_G0_to_G2f_summary.csv`(그룹), `..._rows.csv`(행). 근거 ID는 `evidence/EVIDENCE_SUMMARY.csv`.
- 6쌍 제외 후 탐욕 fold 재계산으로 14행이 fold를 옮김(axios 1행 fold 4→3 등). 실제 캠페인 K = 15.
### 7.2 fold별 개수 (두 seed 동일)
| fold | val 악성 | val benign | val HB | cal benign/HB | fit 악성 | fit benign/HB | M1 fit 악성/정상 |
|---|---|---|---|---|---|---|---|
| 0 | 1,694 | 320 | 48 | 320/48 | 1,805 | 960/143 | 903/1,103 |
| 1 | 795 | 320 | 48 | 320/48 | 2,704 | 960/143 | 596/1,103 |
| 2 | 591 | 320 | 48 | 320/48 | 2,908 | 960/143 | 664/1,103 |
| 3 | 210 | 320 | 47 | 320/48 | 3,289 | 960/144 | 726/1,104 |
| 4 | 209 | 320 | 48 | 320/48 | 3,290 | 960/143 | 823/1,103 |
Validation 합계: 악성 3,499, benign 1,600, hard_benign 239(=48+48+48+47+48). calibration은 각 fold의 나머지 4개 fold에서 뽑으므로 fold 간 겹치며 합(240)은 분할이 아님.
### 7.3 결과 요약 (seed 09/10, 상세 `g2f_60run/eval/`)
목표 1%: Recall M1 .931/.933, M2 .454/.887, M3 .576/.895, M4 .767/.891, M2-r .859/.882, M4-r .611/.873.
실제 전체 FPR .008–.014. Hard benign FPR M1 .050/.050, M2 .050/.071, M3 .050/.059, M4 .046/.054, M2-r .054/.054, M4-r .050/.063.
Macro(K=15) M1 .386/.388, M2 .362/.463, M3 .390/.440, M4 .365/.426, M2-r .413/.414, M4-r .366/.383.
- 1% recall의 seed 간 출렁임은 fold 0 chaindrop(단일 payload 1,694행) 때문. M2–M4-r은 fit에 신규 악성이 들어가며 hard_benign 약 15행이 점수 ≥0.999로 포화되고,
  1% 임계값(calibration 정상 4번째 점수)이 그 포화 구간에 놓여 chaindrop 전체가 한꺼번에 넘고 안 넘음(0.04↔0.94). M1은 정상 꼬리가 낮아 안정.
- 포화는 M2-r(M1과 같은 클래스 비율)에서도 같은 행에 생김 → 비율이 아니라 신규 데이터 구성 효과.
- Toptal(34)은 모든 모델에서 1% recall 0 → 40-run의 Toptal 이득은 누출이었음이 확인됨. fold 4 소규모 캠페인 recall은 모든 모델에서 .22–.32(1%).

## 8. 최종 모델 후보 비교: M1 vs M2-r (기존 60-run 점수만 사용, 추가 학습 없음)
진단용 matched-FPR: fold마다 validation 정상 라벨로 실제 FPR을 목표 이하(1%: 3/368, 5%: 18/368)에 맞춘 임계값. 독립 추정이 아니며 운영 임계값으로 쓰지 않는다.
코드 `g2f_60run/diag_matched_fpr/matched_fpr.py`, 결과 `g2f_60run/diag_matched_fpr/out/`.
| 지표 (seed 09/10) | M1 1% | M2-r 1% | M1 5% | M2-r 5% |
|---|---|---|---|---|
| 실제 전체 FPR | .008/.008 | .008/.008 | .049/.049 | .049/.049 |
| Recall | .927/.933 | .858/.877 | .955/.956 | .954/.955 |
| Hard benign FPR | .033/.029 | .046/.050 | .134/.138 | .159/.151 |
| Macro Campaign (K=15) | .332/.370 | .350/.358 | .574/.584 | .517/.544 |
| Macro Payload (캠페인 내 평균) | .314/.358 | .335/.337 | .570/.598 | .515/.538 |
| Macro Payload (전체 307 payload) | .564/.590 | .572/.498 | .760/.764 | .749/.750 |
- M1−M2-r macro 차이(캠페인 짝 bootstrap 95% CI): 1% −.018 [−.143, .127] / +.013 [−.109, .171], 5% +.057 [−.062, .223] / +.039 [−.060, .194] → 유의하지 않음.
- 캠페인별: M1은 큰 캠페인(shai-hulud-original 1%에서 .87/.96 vs M2-r .05/.01, npmoidc 계열 .95 vs .90–.94)에서, M2-r은 소규모 캠페인(apt-js, js-metrics, nx, weavedb, react-native-aria)에서 앞섬.
- 통계적 한계: 실제 캠페인 15개 중 n=1이 2개(axios, solana), n<5가 1개(apt-js 4). 11개 캠페인이 fold 4 한 모델·한 임계값에 묶여 오차가 상관됨. 캠페인 하나가 macro를 1/15≈6.7%p 움직이고 CI 폭은 ±.13 안팎.
- 의견: 최종 후보는 M1. 같은 실제 FPR에서 Recall·Hard benign FPR이 더 좋고 seed 간 변동이 거의 없으며, 주지표 macro는 두 모델 차이가 불확실성 안에 있음.
  M1의 calibration 임계값이 validation에서 1.2–1.4%로 넘친 것은 368개 calibration 정상으로 상위 4번째 점수를 쓰는 추정의 표본 변동 범위(기대 ≈1.1%, 표준편차 ≈0.5%p) 안이다.
