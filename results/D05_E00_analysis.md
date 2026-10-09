# D05-E00 Analysis

데이터 버전 D05, 실험 `baseline` (상세 수치: `results/experiments.csv`, 모델: `models/D05_E00_baseline.txt`, 그림: `results/plots/D05_E00/`)의 결과를 정리한다. 이 실험은 grouping/split 정책을 수정한 뒤 재학습한 것으로, 이전 `D05-E00`(현재 `D05-E00_pre-fix`로 보존됨, `results/D05_E00_pre-fix_analysis.md`)을 대체한다.

## 0. 무엇을, 왜 고쳤나

`train_model.py`의 `assign_components()`는 malicious 행마다 `package` 노드와 `splitGroup` 노드를 union-find로 묶어, 같은 package 또는 같은 splitGroup이 train/validation에 걸쳐 쪼개지지 않게 한다. 이 중 **splitGroup 쪽 제약**이 문제였다.

- 대부분의 splitGroup(`shai-hulud-original_2025-09`, `canisterworm_2026-03`, `sap-maintainer-compromise` 등)은 실제로 같은 공격(같은 campaign, 같은 공격자, 동일 시점)을 가리키는 이름이라 "함께 분할"이 타당하다.
- 반면 `individual-compromise`, `individual-compromise-2nd`, `individual-compromise-3rd`, `individual-compromise-4th`는 이름에 날짜·공격 식별자가 없고, "N차 데이터 수집에서 개별적으로 수집된, 서로 무관한 단독 침해 사례"를 모아둔 범용 버킷이다(`individual-compromise-4th`의 실제 구성원: `cline`/`node-ipc`처럼 서로 무관한 패키지들, D05에서 추가된 NPMStudy 30쌍도 서로 다른 30개 패키지의 무관한 개별 사건). 기존 코드는 이 버킷 이름이 같다는 이유만으로 구성원 전체를 하나의 campaign처럼 취급해 통째로 같은 split에 몰아넣었다.

**수정**: `assign_components()`에서 `GENERIC_BUCKET_SPLIT_GROUP` 정규식(`^individual-compromise(-\d+(st|nd|rd|th))?$`)에 매칭되는 splitGroup은 union 대상에서 제외했다. 즉:
1. 실제 campaign(날짜·고유 식별자가 있는 splitGroup)은 기존처럼 그대로 함께 분할된다 — **원칙 1 유지**.
2. `individual-compromise[-Nth]` 버킷에 속한 행들은 이제 "같은 splitGroup"이라는 이유만으로 묶이지 않는다 — **원칙 2 반영**.
3. package 기반 union(같은 package가 train/val에 걸쳐 쪼개지지 않음)은 그대로 유지했다 — **원칙 3 유지**.
4. `splitGroup` 원본 값·upstream 데이터는 변경하지 않았고, `train_model.py`의 `assign_components()`와 관련 상수 추가 외 다른 코드는 바꾸지 않았다 — **원칙 4 유지**.

## 1. 문제 발생 범위 (D04 vs D05)

| | D04 | D05 |
| --- | ---: | ---: |
| `individual-compromise` | 2 | 2 |
| `individual-compromise-2nd` | 4 | 4 |
| `individual-compromise-4th` | 7 | 37 (+30, 전부 NPMStudy 신규) |
| 범용 버킷 합계 (Train) | 13 | 43 |

이 범용 버킷 문제는 **D04-E00 때부터 이미 존재**했다(13건이 이미 하나의 가짜 "campaign"처럼 다뤄짐). D05에서는 새로 추가된 30쌍이 모두 `individual-compromise-4th`에 들어가면서 그 버킷이 37건으로 커졌을 뿐, 문제의 구조 자체는 D05가 새로 만든 것이 아니다. (D04-E00 자체는 이번 작업 범위에 포함되지 않아 재학습하지 않았다.)

## 2. 수정 전/후 split 비교

수정 전 split(`splits/train_val_split_assignment_D05_E00_pre-fix.csv`)과 수정 후 split(현재 `splits/train_val_split_assignment.csv`)을 직접 비교했다.

**바뀐 행 (3건, 전체 2,626행 중)**:

| package | old→new version | class | splitGroup | 이전 split | 이후 split |
| --- | --- | --- | --- | --- | --- |
| `is` | 3.3.0 → 3.3.1 | malicious | `individual-compromise-2nd` | train | **validation** |
| `is` | 0.0.7 → 0.1.0 | benign | (없음) | train | **validation** |
| `stlint` | 1.0.50 → 1.0.51 | benign | (없음) | validation | **train** |

- `individual-compromise-4th`의 37건은 수정 후에도 전부 train에 남았다(버킷을 깨도 브루트포스 선택 결과가 바뀌지 않음). 즉 이번 수정의 **실제 split 변화는 `individual-compromise-2nd` 버킷이 깨지면서 생긴 3건뿐**이고, D05에서 새로 추가된 NPMStudy 30쌍 자체와는 무관하다. 실제로 D04 시점 데이터만 놓고 같은 수정을 적용해도 동일한 3건이 바뀐다(이번 작업에서 확인, D04-E00 자체는 재학습하지 않음).
- `is` 패키지는 malicious 행(`individual-compromise-2nd`)과 benign 행이 둘 다 있는데, 수정 후 `individual-compromise-2nd` union이 끊기면서 `pkg:is` component가 (campaign과 무관하게) 자체적으로 validation에 뽑혔고, package 단위 누수 방지 제약에 따라 같은 package의 benign 행도 같이 validation으로 이동했다. `stlint`는 그 결과 singleton 랜덤 채우기 몫이 줄어들며 교체되어 train으로 이동했다(class별 val 비율을 20%에 맞추는 결정론적 탐색의 부수 효과).

**누수 방지 조건 검증 (수정 후 split)**:
- package가 train/val에 걸쳐 쪼개진 경우: **0건**
- 실제 campaign(범용 버킷 제외) splitGroup이 train/val에 걸쳐 쪼개진 경우: **0건**
- `individual-compromise-2nd`만 train 3건/validation 1건으로 쪼개짐 — 이는 의도된 수정 결과(서로 무관한 개별 사례이므로 쪼개져도 됨).

## 3. 환경 재현성 확인

이 컨테이너(Linux, lightgbm 4.7.0, pandas 3.0.5, scikit-learn 1.9.1)에서 **수정 전 split을 그대로 다시 학습**해 `D05-E00_pre-fix`의 기록값(Val Recall 0.8780, best_iteration 125 등)과 **완전히 일치**함을 확인했다. 즉 아래 지표 변화는 환경 차이가 아니라 전적으로 split 변경 때문이다.

## 4. 지표 비교

| 지표 | D04-E00 | D05-E00_pre-fix | D05-E00 (신규) |
| --- | ---: | ---: | ---: |
| Train / Val / Test 샘플 수 | 2064 / 532 / 650 | 2094 / 532 / 650 | 2093 / 533 / 650 |
| best iteration | 275 | 125 | **57** |
| Val Recall | 0.8841 | 0.8780 | **0.7455** |
| Val Precision | 1.0000 | 1.0000 | 1.0000 |
| Val F1 | 0.9385 | 0.9351 | **0.8542** |
| Val PR-AUC | 0.9994 | 0.9974 | **0.9940** |
| Test Recall | 0.1158 | 0.1684 | **0.1526** |
| Test Precision | 1.0000 | 0.9697 | **0.9062** |
| Test F1 | 0.2075 | 0.2870 | **0.2613** |
| Test PR-AUC | 0.6995 | 0.6377 | **0.6200** |

Test confusion matrix: `D05-E00_pre-fix` TP 32 / FP 1 / TN 459 / FN 158 → `D05-E00` **TP 29 / FP 3 / TN 457 / FN 161**.

## 5. 왜 지표가 나빠졌나

validation에 새로 들어온 malicious 1건(`is` 3.3.0→3.3.1)의 `updateInterval`은 약 2.08×10⁸초(≈6.6년)로, 새 validation 내 malicious 분포(평균 3.7×10⁷초, 최댓값 2.62×10⁸초)에서도 극단값에 가깝다. 이 한 건이 validation loss를 흔들어 early stopping이 125라운드가 아니라 57라운드에서 멈췄고, 그만큼 덜 학습된 모델이 저장됐다. 그 결과 validation·test 지표가 전반적으로 낮아졌다(특히 best_iteration이 절반 이하로 줄며 과소적합 쪽으로 이동).

이것은 버그가 아니라 **수정된(올바른) 정책이 만들어낸 실제 split**이 우연히 early stopping에 민감한 지점을 건드린 결과다. "같은 package는 train/val에 걸쳐 쪼개지 않는다"는 제약이 `is` package를 통째로 validation으로 옮긴 것이고, 이는 이번 수정이 지키기로 한 원칙 3(package 누수 방지)의 당연한 결과다.

## 6. 결론 및 다음 실험 제안

- grouping/split 정책 수정 자체는 의도대로 동작한다: 서로 무관한 `individual-compromise[-Nth]` 사례들이 더 이상 가짜 campaign으로 묶이지 않고, package·실제 campaign 누수 방지는 그대로 유지된다.
- 다만 이번 데이터에서는 그 수정이 하필 early-stopping에 민감한 validation 구성 변화(극단적 `updateInterval` malicious 1건 추가)를 만들어 Test F1이 0.287 → 0.261로, Test Recall이 0.168 → 0.153으로 내려갔다. 데이터 품질 문제라기보다 **validation 20건 내외의 작은 규모에서 단일 샘플이 early stopping을 좌우하는 구조적 취약성**을 보여준다.
- 다음 실험에서 확인하면 좋을 것: validation 크기를 늘리거나 early stopping을 validation logloss 대신 더 안정적인 지표(예: k-fold 평균)로 바꿨을 때 이 민감도가 줄어드는지.

## 7. 변경된 파일

- `train_model.py`: `assign_components()`에 범용 버킷 제외 로직(`GENERIC_BUCKET_SPLIT_GROUP`, `is_shared_attack_split_group`) 추가. `EXPERIMENT_NOTES` 갱신. 그 외 로직 동일.
- `splits/train_val_split_assignment.csv`: 수정된 정책으로 재생성(3건 재배정).
- `splits/train_val_split_assignment_D05_E00_pre-fix.csv` (신규): 수정 전 split 보존.
- `models/D05_E00_baseline.txt` (재생성), `results/feature_importance/D05_E00_baseline.csv` (재생성), `results/plots/D05_E00/*` (재생성).
- `models/D05_E00_pre-fix_baseline.txt`, `results/feature_importance/D05_E00_pre-fix_baseline.csv`, `results/plots/D05_E00_pre-fix/*`, `results/D05_E00_pre-fix_analysis.md` (기존 D05-E00 결과 보존용 리네임).
- `results/experiments.csv`: 기존 `D05-E00` 행을 `D05-E00_pre-fix`로 변경 + superseded 메모 추가, 새 `D05-E00` 행 추가.
- `results/D05_E00_analysis.md` (본 문서): 신규 작성.
