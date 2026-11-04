# D06 미탐(False Negative) 분석과 다음 실험 제안

- 범위: 기존 결과만 분석. 모델 재학습·feature 추출 코드 수정·데이터셋 변경 없음. Test 데이터는 읽지 않음(Test는 `results/experiments.csv`에 저장된 지표만 사용).
- 판정: 기존 결과의 `pred`(proba ≥ 0.5) 그대로. FPR을 맞추지 않았고 FPR·FP·Precision은 참고 지표.
- 데이터: `be87ab4cf:derived/splits/train.csv` Train 2,767쌍(악성 928 / 정상 1,839 = 일반 1,600 + hard benign 239)의 campaign 단위 3-fold CV out-of-fold 예측.
- 모델: E06(package.json feature 7개), E09(E06 + campaign 가중치 1/√size), E10 α=0.25·0.75(가중치 1/size^α). E10 α=0·0.5는 E06·E09와 pair별 판정이 같아(스크립트에서 확인) 성능표에만 남기고 미탐 비교에서는 뺐다. 세 모델 모두 난독화 feature 22개는 쓰지 않는다.
- 유형: A = installScriptAdded OR scriptEntryAdded / B = A 아님 AND newDependencyAdded / C = 나머지 (악성 A 734 · B 52 · C 142).

## 1. 기존 성능

### 1-1. CV(Train 3-fold, campaign 단위) — fold 평균 vs 전체 합산

fold 평균은 fold별 지표의 단순 평균, 전체 합산은 세 fold의 TP·FN·FP·TN을 더한 뒤 계산한 값이다.

| 모델 | 집계 | Recall | TP | FN | Precision | FP | FPR |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| E06 | fold 평균 | 54.2% | – | – | 90.4% | – | 2.6% |
| E06 | 전체 합산 | 54.7% | 508 | 420 | 91.5% | 47 | 2.6% |
| E09 | fold 평균 | 70.5% | – | – | 77.8% | – | 9.9% |
| E09 | 전체 합산 | 71.6% | 664 | 264 | 78.4% | 183 | 10.0% |
| E10_a0.25 | fold 평균 | 66.7% | – | – | 81.6% | – | 7.4% |
| E10_a0.25 | 전체 합산 | 67.9% | 630 | 298 | 82.2% | 136 | 7.4% |
| E10_a0.75 | fold 평균 | 67.7% | – | – | 77.7% | – | 9.2% |
| E10_a0.75 | 전체 합산 | 68.5% | 636 | 292 | 78.9% | 170 | 9.2% |
| E10_a0.0 (= E06) | fold 평균 | 54.2% | – | – | 90.4% | – | 2.6% |
| E10_a0.0 (= E06) | 전체 합산 | 54.7% | 508 | 420 | 91.5% | 47 | 2.6% |
| E10_a0.5 (= E09) | fold 평균 | 70.5% | – | – | 77.8% | – | 9.9% |
| E10_a0.5 (= E09) | 전체 합산 | 71.6% | 664 | 264 | 78.4% | 183 | 10.0% |

fold별 값은 `d06_fn_performance_cv.csv`에 있다. fold 구성: fold 0 = sha1-hulud-second-coming_2025-11; fold 1 = 10개 캠페인; fold 2 = 9개 캠페인. fold 0은 `sha1-hulud-second-coming_2025-11` 한 캠페인(332쌍)뿐이라 fold 평균에서 이 캠페인 하나가 1/3의 비중을 갖는다.

### 1-2. 기존 Validation·Test(Train/Validation 분할 학습, CV와 별개)

| 모델 | 평가 | Recall | TP | FN | Precision | FP | FPR | PR-AUC |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| E06 | Validation | 71.1% | 133 | 54 | 91.7% | 12 | 3.3% | 0.907 |
| E06 | Test | 60.8% | 132 | 85 | 88.6% | 17 | 3.7% | 0.869 |
| E09 | Validation | 78.1% | 146 | 41 | 87.4% | 21 | 5.7% | 0.899 |
| E09 | Test | 71.0% | 154 | 63 | 79.8% | 39 | 8.5% | 0.814 |
| E10_a0.25 | Validation | 미평가 | – | – | – | – | – | – |
| E10_a0.25 | Test | 미평가 | – | – | – | – | – | – |
| E10_a0.75 | Validation | 미평가 | – | – | – | – | – | – |
| E10_a0.75 | Test | 미평가 | – | – | – | – | – | – |

- Recall·Precision·PR-AUC는 `results/experiments.csv` 값이다. TP·FN·FP는 Validation(악성 187·정상 368), Test(악성 217·정상 460) 건수로 역산했고 모두 정수로 떨어진다.
- pair별 Test 예측이 저장돼 있지 않아 Test는 유형·캠페인별로 나눌 수 없다. 아래 유형·캠페인 분석은 모두 CV 기준이다.
- E10은 Train/Validation 분할 학습과 Test 평가를 하지 않았다(미평가).

### 1-3. 유형별 Recall·FN(CV 전체 합산)

| 유형 | n | E06 Recall (FN) | E09 Recall (FN) | E10_a0.25 Recall (FN) | E10_a0.75 Recall (FN) |
| --- | ---: | ---: | ---: | ---: | ---: |
| A | 734 | 68.9% (228) | 84.1% (117) | 83.2% (123) | 79.4% (151) |
| B | 52 | 0.0% (52) | 25.0% (39) | 3.8% (50) | 34.6% (34) |
| C | 142 | 1.4% (140) | 23.9% (108) | 12.0% (125) | 24.6% (107) |

### 1-4. 캠페인별 FN(CV 전체 합산, E09 FN 순)

| 캠페인 | n | fold | E06 FN | E09 FN | E10_a0.25 FN | E10_a0.75 FN |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| mini-shai-hulud_2026-05 | 198 | 1 | 102 | 86 | 100 | 97 |
| shai-hulud-original_2025-09 | 186 | 2 | 53 | 48 | 53 | 46 |
| autotel-node-env-resolver_2026-06 | 29 | 2 | 27 | 25 | 27 | 25 |
| miasma_2026-06 | 26 | 2 | 26 | 25 | 26 | 25 |
| individuals_case | 50 | 1,2 | 47 | 24 | 36 | 17 |
| react-native-aria-gluestack_2025-06 | 17 | 1 | 17 | 14 | 14 | 14 |
| injective_2026-07 | 12 | 1 | 12 | 12 | 12 | 12 |
| js-metrics_2018 | 9 | 2 | 9 | 9 | 9 | 9 |
| pgserve-automagik-openwebconcept_2026-04 | 10 | 2 | 8 | 8 | 8 | 8 |
| sha1-hulud-second-coming_2025-11 | 332 | 0 | 102 | 6 | 6 | 29 |
| toptal-xene_2025-07 | 10 | 1 | 5 | 2 | 2 | 5 |
| axios_2026-03 | 1 | 2 | 1 | 1 | 1 | 0 |
| bitwarden-cli_2026-04 | 1 | 1 | 1 | 1 | 1 | 1 |
| chaindrop_2026-08 | 25 | 1 | 1 | 1 | 1 | 2 |
| miasma-leoplatform_2026-06 | 1 | 2 | 1 | 1 | 1 | 0 |
| solana-web3js_2024-12 | 1 | 1 | 1 | 1 | 1 | 1 |
| nx-s1ngularity_2025-08 | 7 | 2 | 7 | 0 | 0 | 0 |
| node-gyp-dll_2025-07 | 9 | 1 | 0 | 0 | 0 | 1 |
| sap-maintainer-compromise | 4 | 1 | 0 | 0 | 0 | 0 |

캠페인별 Recall과 캠페인×유형 분해는 `d06_fn_summary_by_type_campaign.csv`에 있다.

## 2. 미탐 악성 비교

| 구분 | 쌍 |
| --- | ---: |
| E06 미탐 전체 | 420 |
| E09 미탐 전체 | 264 |
| E06·E09 공통 미탐 | 264 |
| E06 미탐 · E09 탐지 | 156 |
| E06 탐지 · E09 미탐 | 0 |

기존 보고(공통 미탐 264쌍, E09 추가 탐지 156쌍)는 실제 파일에서 그대로 재현된다(공통 264, 추가 탐지 156). E06이 잡고 E09가 놓친 악성은 0쌍이라, E09의 미탐은 E06 미탐의 부분집합이다.

| E10 | 미탐 | 그중 E06·E09 공통 미탐 | 공통 미탐 중 새로 탐지 | E09가 잡았는데 놓침 |
| --- | ---: | ---: | ---: | ---: |
| E10_a0.25 | 298 | 263 | 1 | 35 |
| E10_a0.75 | 292 | 251 | 13 | 41 |

pair별 목록(모델별 확률·판정, feature, 공격 흔적)은 `d06_fn_samples.csv`에 있다.

## 3. 미탐 원인

### 3-1. 데이터로 확인된 사실

- 공통 미탐 264쌍의 유형: A 117 · B 39 · C 108. 유형별 Recall이 가장 낮은 것은 C·B다(1-3).
- **package.json feature만으로는 구별 정보가 부족한 pair가 대부분이다.** 공통 미탐 264쌍 중 263쌍은 이산 package.json feature 6개(설치 스크립트 3종, 새 의존성 여부·개수, updateType)가 완전히 같은 정상 pair가 있다. 남은 구별 수단은 updateInterval뿐인데, 같은 값의 정상 중 updateInterval이 그 악성 이상인 비율의 중앙값이 A 0.40, B 0.53, C 0.27이다. 즉 updateInterval 임계값으로 이 악성을 잡으려 하면 같은 모양의 정상도 그만큼 함께 걸린다.
- **A 유형**: 두 모델이 모두 잡은 A의 updateInterval 중앙값은 397일, patch 비율 99.0%, 새 의존성 비율 0.0%다. 함께 놓친 A는 updateInterval 중앙값 7.5일, patch 55.6%, 새 의존성 43.6%로, A 유형 hard benign(중앙값 5.0일, patch 56.1%, 새 의존성 29.5%)과 비슷하다.
- **B 유형**: 놓친 B는 patch 94.9%, 새 의존성 평균 1.10개, updateInterval 중앙값 15.9일이고, B 유형 일반 정상은 patch 46.8%, 평균 1.65개, 중앙값 29.8일이다.
- **C 유형**: 놓친 C는 설치 스크립트·새 의존성 변화가 없고 patch 99.1%, updateInterval 중앙값 28.3일이다. E09만 잡은 C 32쌍의 중앙값은 483일로, C 탐지는 사실상 긴 배포 간격에만 의존한다.
- **모델 설정(코드로 확인)**: 기본 LightGBM(`objective=binary`), 클래스 가중치 없음, 판정 임계값 0.5 고정, early stopping을 평가 fold 자체로 수행(`scripts/run_cv_e06_e09.py` docstring의 'Approach A' 주의). 저장된 feature importance는 split 횟수이며 E06·E09 모두 updateInterval이 압도적 1위다(`results/feature_importance/`). fold별 best_iteration은 E06 3/25/11, E09 23/20/11, E10_a0.25 30/22/12, E10_a0.75 78/16/10.
- **캠페인 집중**: 공통 미탐의 캠페인 상위는 `mini-shai-hulud_2026-05` 86, `shai-hulud-original_2025-09` 48, `autotel-node-env-resolver_2026-06` 25, `miasma_2026-06` 25, `individuals_case` 24, `react-native-aria-gluestack_2025-06` 14이다. CV가 campaign 단위라 각 캠페인은 학습에 한 번도 쓰이지 않은 fold에서 평가된다(새 캠페인 일반화 문제).
- **모델이 쓰는 feature는 이 미탐들을 거의 구별하지 못한다.** 공통 미탐 vs 같은 유형 정상의 단변량 AUC(0.5 = 구별 불가): A: `newDependencyCount` 0.60, `updateInterval` 0.50; B: `newDependencyCount` 0.41, `updateInterval` 0.44; C: `updateInterval` 0.61, `newDependencyCount` 0.50.
- **쓰지 않은 난독화 feature에는 구별 정보가 있다.** E06·E09·E10은 난독화 feature 22개를 쓰지 않는다. 같은 비교의 AUC 상위는 A: `obfWhitespaceRatioChangedCode` 0.05(캠페인 균등 0.06), `obfBracketAccessRatioChangedCode` 0.93(캠페인 균등 0.82), `obfWhitespaceRatioNew` 0.07(캠페인 균등 0.10); B: `obfHexNumberRatioChangedCode` 0.94(캠페인 균등 0.80), `obfWhitespaceRatioChangedCode` 0.06(캠페인 균등 0.19), `obfBracketAccessRatioChangedCode` 0.93(캠페인 균등 0.79); C: `obfWhitespaceRatioChangedCode` 0.18(캠페인 균등 0.22), `obfWhitespaceRatioNew` 0.18(캠페인 균등 0.23), `obfMeanIdentLengthChangedCode` 0.19(캠페인 균등 0.32). 상위 8개의 평균 |AUC−0.5|는 캠페인을 균등하게 봐도 A 0.40→0.35, B 0.43→0.29, C 0.29→0.24로 일부만 줄어든다(pooled→캠페인 균등). 다만 캠페인 균등 값은 미탐이 3쌍 이상인 캠페인 A 4개, B 2개, C 7개로만 계산했다. 방향은 일관돼, 놓친 악성의 변경 코드는 같은 유형 정상보다 공백 비율이 낮고 대괄호 접근·짧은 식별자 비율이 높다.
- **변경 JS가 있는지 자체도 다르다.** 변경 JS가 없어 ChangedCode feature가 결측인 비율은 같은 유형 정상 A 18.5%, B 14.4%, C 40.6%, 공통 미탐 A 2.6%, B 7.7%, C 11.1%이다.
- **난독화 feature를 그대로 다 넣은 기존 모델은 일반화되지 않았다.** 29개 feature를 모두 쓴 D06-E00은 Validation Recall 93.0%, Test Recall 16.1%였다(`results/experiments.csv`, Train/Validation 분할 학습).
- **공격 흔적(데이터 저장소 `derived/pairs/malicious_pair_groups.csv`, 고정 커밋)**:
  - `mini-shai-hulud_2026-05`(악성 198쌍, 모두 fold 1): E09가 놓친 pair의 추가 install hook은 `preinstall=bun run index.js` 46, `preinstall=node setup.mjs` 7, 잡은 pair는 `preinstall=node setup.mjs` 82, `preinstall=node index.js` 16, `preinstall=node opensearch.mjs` 1이다. 모델은 hook이 추가됐는지(bool)만 보고 명령 내용은 보지 않는다.
  - E09가 놓친 B 유형 39쌍의 추가 의존성: `@tanstack/setup` 31, `@antv/setup` 1, `@opensearch/setup` 1. 모델은 의존성 추가 여부·개수만 보고 이름·출처·새로 생긴 패키지인지는 보지 않는다.
  - `injective_2026-07` 12쌍 중 11쌍은 변경된 JS 파일·추가 hook·추가 의존성이 모두 없다. 현재 feature가 측정하는 범위 밖의 변경으로, 무엇이 바뀌었는지는 이 자료로 알 수 없다.
  - 공통 미탐 C 유형 상위 캠페인은 pair마다 가장 큰 변경 JS의 해시가 다르다(`autotel-node-env-resolver_2026-06` 25/25, `miasma_2026-06` 25/25, `react-native-aria-gluestack_2025-06` 14/14). 같은 payload 해시로 잡을 수 있는 구조가 아니다.

### 3-2. 추정(검증되지 않은 원인 가설)

아래는 3-1의 사실에서 귀납적으로 추론한 가설이며, 확인하려면 3-1 밖의 실험이 필요하다.

- **H1. 모델이 '설치 스크립트 추가 + 긴 배포 간격 + 새 의존성 없음'이라는 지름길을 학습했다.** 근거: 잡힌 A의 프로필(긴 간격, 새 의존성 0%)과 split importance의 updateInterval 독주. 데이터 저장소 `baseline_rule.py`도 baseline 선정이 updateInterval을 통해 label을 누설할 수 있다고 경고한다. worm처럼 짧은 간격으로 연속 배포하거나 의존성을 함께 추가하는 공격은 이 지름길에서 벗어나 미탐된다.
- **H2. E06·E09·E10의 미탐은 주로 입력 정보 부족 때문이다(7개 package.json feature 기준).** 근거: 공통 미탐 대부분이 이산 feature가 같은 정상 pair를 갖고, 모델이 쓰는 feature의 AUC가 0.41~0.61로 0.5 근처다. 이 경우 가중치·임계값 조정만으로는 같은 모양의 정상을 함께 오탐하지 않고 Recall을 크게 올리기 어렵다.
- **H3. 필요한 정보의 일부는 이미 train.csv에 있지만(난독화 feature), 모델이 일반화되는 방식으로 쓰지 못했다.** 근거: 캠페인 균등으로 봐도 분리도가 남고 변경 JS 유무도 다르다. 반면 22개를 모두 넣은 E00은 Test에서 크게 떨어졌다. 그래서 '정보 없음'이 아니라 '전부 넣으면 캠페인별 값에 과적합'일 가능성이 있다. 이를 가르려면 일부 feature만 campaign CV로 넣어 보는 실험이 필요하다.
- **H4. CV 수치의 변동은 fold 구성에 크게 좌우된다.** fold 0이 단일 캠페인이라, E09가 E06보다 더 잡은 156쌍 중 96쌍이 이 캠페인(`sha1-hulud-second-coming_2025-11`)에서 나온다(1-4). early stopping이 평가 fold를 보므로 CV 수치는 낙관적일 수 있다.
- **H5. 공격의 실체 정보(hook이 실행하는 파일의 내용, 추가된 의존성의 정체, 주입된 코드의 동작)는 현재 어떤 feature에도 직접 없다.** 근거: 3-1의 공격 흔적. 난독화 비율은 코드의 '모양'만 보므로, 난독화하지 않은 악성 코드에는 신호가 약할 것으로 추정한다.

## 4. 다음 실험 제안(Recall↑ · FN↓ 우선)

기대 효과는 방향만 적었다. 실험 전이므로 개선 폭은 예측하지 않는다.

| 우선순위 | 개선 방법 | 해결하려는 미탐 문제 | 기대 효과 | 근거 |
| --- | --- | --- | --- | --- |
| 1 | **기존 난독화 feature 일부를 package.json 모델에 다시 넣고 campaign CV로 평가**: 변경 JS 유무(obfChangedFileCount>0)와 분리도가 캠페인 균등으로도 남은 ChangedCode 비율 몇 개(공백·대괄호 접근·짧은 식별자·16진수). feature 추출 변경 없이 바로 가능 | A·B·C 전반, 특히 package.json 값이 정상과 같은 공통 미탐 | 모델 입력에 미탐을 구별할 정보를 처음으로 넣음 | 3-1의 AUC (모델 사용 feature ≈ 0.5 vs 난독화 feature), 변경 JS 결측 비율 차이, E00 Test 16.1%(전부 넣으면 일반화 실패) |
| 2 | **변경·추가된 JS 코드의 행위(API) feature 추가**: 새로 생긴 `child_process`·`eval`/`Function`·네트워크(`http(s)`, `fetch`, `dns`)·환경변수/자격증명 파일 접근·base64 디코드, 그리고 install hook이 이번에 추가·변경된 파일을 실행하는지 | C 유형 미탐(공통 108: hook·의존성 없이 JS 1개에 코드 주입)과 A 유형 미탐(공통 117: hook이 새 payload 파일 실행) | 난독화 여부와 상관없이 악성 '행위'에 직접 신호 | C 미탐의 변경 JS가 대부분 1개이고 pair마다 payload 해시가 다름, A 미탐 hook이 `bun run index.js` 등 파일 실행 |
| 3 | **추가된 의존성 정체 feature 추가**: 새 의존성 패키지가 업데이트 직전에 처음 publish됐는지, 그 의존성의 install script 여부, 버전 지정이 URL/git/tarball인지 | B 유형 미탐(E09 기준 39)과 의존성을 동반한 A 미탐 | 의존성 추가 '여부'가 같은 정상 B와 구별 | E09가 놓친 B의 31쌍이 같은 의존성(`@tanstack/setup`)을 추가 |
| 4 | **LightGBM 학습 방식 보완**: early stopping을 학습 fold 내부 검증으로 분리, `scale_pos_weight`/class weight로 Recall 우선, Recall 목표 임계값을 학습 fold에서 정함 | 전반 | CV 수치의 낙관 편향 제거, Recall 우선 운영점 | 3-1 모델 설정, best_iteration 3~78 |
| 5 | **updateInterval 의존 점검(E04를 같은 CV로)**: updateInterval 제거·구간화 | 지름길 학습으로 짧은 간격 공격을 놓치는 문제 | 1~3의 feature가 실제로 쓰이는지 보는 기준선 | H1, D06-E04는 Train/Validation 분할로만 평가됨 |
| 6 | **유형·캠페인 가중치**: E10 α를 유형 단위로 확장(B·C 악성 가중 ↑) | B·C 미탐 | 소수 유형의 학습 신호 확대 | E10에서 α↑일 때 B·C 미탐은 줄고 sha1-hulud 미탐은 늘어남(1-3, 1-4) |
| 7 | **캠페인 편향 대응**: 단일 캠페인 fold가 생기지 않게 fold 구성, 캠페인 평균 Recall 병기 | 평가 편향 | 개선 여부 판단의 신뢰도 | fold 0 = 단일 캠페인(H4) |

1은 기존 feature만 쓰므로 이번 제약(feature 추출 변경 없음) 안에서 다음 실험으로 바로 할 수 있다. 2·3은 feature 추출 코드 변경이 필요하다. H2가 맞다면 4~7만으로는 개선 폭이 제한될 수 있다.

## 5. 한계

- 모든 유형·캠페인 분석은 Train CV 기준이다. Test는 pair별 예측이 없어 나누지 못했다.
- CV는 early stopping에 평가 fold를 쓰므로 수치가 낙관적일 수 있다(`scripts/run_cv_e06_e09.py`).
- 단변량 AUC는 feature 하나씩 본 값이라, 모델에 넣었을 때의 효과를 보장하지 않는다.
- 공격 흔적 열은 데이터 저장소의 `malicious_pair_groups.csv`(고정 커밋)에서 가져왔다.
- 3-2의 원인과 4의 효과는 가설이며, 실험으로 확인해야 한다.

## 출력 파일

- `results/fn_analysis/d06_fn_performance_cv.csv`
- `results/fn_analysis/d06_fn_performance_holdout.csv`
- `results/fn_analysis/d06_fn_samples.csv`
- `results/fn_analysis/d06_fn_summary_by_type_campaign.csv`
- `results/fn_analysis/d06_fn_feature_profile.csv`
- `results/fn_analysis/d06_fn_feature_separability.csv`

재현: `python scripts/analyze_d06_false_negatives.py --data-clone <npm-malware-package-pairs 클론 경로>`
