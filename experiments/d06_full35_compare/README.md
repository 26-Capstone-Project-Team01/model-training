# D06 full29 vs full35 (X1 코드 문맥 feature) 비교

상태: D06 개발자료(Train 2,767쌍) 탐색 실험. 모델·임계값·feature 선정 결과가 아니며 독립 일반화 성능을 주장하지 않는다.
Test 677은 읽지 않았다. D06은 이미 feature 설계·선택에 쓰인 자료다.

## 0. 결론: X1 채택 보류

- **full29 대비 X1의 일관된 추가 효과는 확인되지 않았다. X1(full35·full32 및 단일 추가) 채택을 보류한다.**
- **성능 개선의 캠페인 집중 문제**: 합산 TP 증가(full35 0.05 기준 s1 +34, s2 +42)는 대부분 **shai-hulud-original 한 캠페인(186쌍,
  outer fold 2)** 에서 나왔다(full35 0.05 s1 +35, s2 +70). 이 캠페인을 빼면(악성 742쌍) X1 변형은 full29와 같거나 낮다
  (s2 0.5: full29 577 → full35 533, full32 543). 따라서 합산 Recall 증가를 X1의 일반적 효과로 해석하면 안 된다.
- 손실도 있었다: X1 값이 0인 C유형 캠페인(autotel −17, miasma −13; s2 0.05 full35), chaindrop(s1 −10),
  split2 fold1의 mini-shai-hulud B유형 40쌍(Proc 포함 변형, 0.5 기준). 캠페인 동일 비중 Recall은 full35 s2에서 0.506 → 0.436으로 낮아졌다.
- feature 의견(미확정): `addedNetworkCallCount`·`installHookRefFileChanged`는 유지 후보(효과 미확정), `addedProcExecCallCount`는 제외 검토 근거가 가장 강함,
  `installHookArgsChanged`·`installHookNewExternalExecCount`는 D06 학습에서 쓰이지 않음(gain 0). 상세 근거는 4·5절.
- 이 결과를 보고 새 feature 조합을 이 실험에 추가하지 않았다. 후속 조합은 별도로 사전 등록하고 D06이 아닌 독립 자료에서 확인해야 한다.

## 1. 고정 조건 (학습 전에 정함, `PROJECT_HANDOFF.md` 10절)

| 항목 | 값 |
|---|---|
| 데이터 | D06 `npm-malware-package-pairs` `be87ab4cff66fff1980c4a71be8032b6b47225ba` `derived/splits/train.csv` (SHA-256 `22fbc875…2c23`) |
| 그룹·class 입력 | `train_malicious_groups.csv` `4f894621…`, `results/diagnostics/d06_diag01_pair_predictions.csv` `877de58c…` (전체 값 `run/manifest.json`) |
| X1 | `experiments/d06_x1_extraction/analysis/d06_full35.csv` (추출기 depbee-analyzer `d56738c`), row_id로 붙임(키·label 일치 검사) |
| 코드 | PR #13 run1 스냅샷을 **수정 없이 import**(SHA-256 `049bf00c…`): `load_data`, component·outer 3fold, `inner_split`, `feature_matrix` |
| 분할 | PR #13 outer 3fold × split1(seed 20261109)·split2(20261110). 실행 중 fit/calibration/outer row_id가 PR #13 `splits/`와 같은지 검사 |
| LightGBM | 4.7.0, `objective=binary, metric=binary_logloss, verbosity=-1, num_threads=2, deterministic=true, force_col_wise=true, seed=20261109`, 최대 200 rounds, early stopping 없음, sample weight 없음 |
| X1 인코딩 | bool `True`/`False` → 1.0/0.0, 빈 칸 → NaN, 개수는 float. 상한·로그 등 변환 없음 |
| 변형 | `full35`(29+X1 6), `full32`(29+RefFile·Proc·Net), `full29_ref`, `full29_proc`, `full29_net`. 결과를 보고 추가·삭제하지 않음 |
| 기준선 | PR #13 저장 full29 점수(`full29_pr13`). 아래 재현 검증으로 같은 코드 재학습과 동일함을 확인 |
| 평가 | W1 `evaluate_w1.py`(e8c5847) 정의를 그대로 복사. 실행 전에 PR #13 full29 평가표 4종을 다시 계산해 정확히 일치해야 진행 |
| 환경 | Python **3.13.18** (PR #13 기록 3.13.5), lightgbm 4.7.0, pandas 3.0.6, numpy 2.5.3, scikit-learn 1.9.1(스냅샷 import용) — 별도 venv |

## 2. 재현 검증 (`repro_verification.json`)

- `run_full35.py --stage repro`로 가중치 없는 full29 6개를 재학습: 모델 내용이 PR #13과 **CR 줄바꿈만 다르고 동일(6/6)**,
  실제 rounds 동일(split1 fold1 149, 나머지 200), 점수 8,548행 최대 차 1.1e-16. Python 3.13.5 → 3.13.18 차이의 영향 없음.
- 재현 모델·점수는 PR #13과 중복이라 이 폴더에 두지 않았다(다시 실행하면 생성).
- 본 실험을 같은 입력으로 다시 실행했을 때 모델 30개·점수·학습 기록·중요도가 바이트 단위로 같았다.

## 3. 파일

```text
run_full35.py            학습 (repro / main 단계)
verify_repro.py          full29 재현 검증
evaluate_full35.py       저장 점수 평가
repro_verification.json
run/manifest.json        입력 해시, X1 해시, 라이브러리, Python, 변형별 feature 목록
                         (`argv`의 /tmp/... 경로는 실행 당시 임시 작업공간이며 저장소에 포함되지 않는다. 입력은 해시로 식별)
run/training.csv         모델별 조건, 실제 rounds, 모델 SHA-256, fit/calibration/outer 행 수
run/models/              30개 native model.txt
run/scores.csv           calibration·outer 점수
run/splits.csv, run/row_metadata.csv
run/feature_importance.csv  gain·split 횟수
run/evaluation/          thresholds(Precision 포함), ranking, low_scores, recall_examples, group_recall(유형·캠페인·component),
                         fold_consistency, paired_vs_full29, paired_cases(행 단위 증감 사례), feature_importance_summary
```

## 4. 결과 (outer 3fold 합산; 임계값은 PR #13 표시 지점이며 운영 기준이 아니다)

TP / FN / FP (정상·Hard benign 오탐), 검토 후보 수:

| split | 점수 이상 | full29 | full35 | full32 | +RefFile | +Proc | +Net |
|---|---:|---|---|---|---|---|---|
| s1 | 0.05 | 685/243/9 (5·4) 694 | 719/209/9 (3·6) 728 | 721/207/9 (4·5) 730 | 684/244/8 692 | 682/246/9 691 | 711/217/5 716 |
| s1 | 0.5 | 604/324/3 607 | 655/273/3 658 | 649/279/3 652 | 609/319/3 612 | 600/328/1 601 | 661/267/4 665 |
| s2 | 0.05 | 708/220/16 (6·10) 724 | 750/178/10 (4·6) 760 | 766/162/13 (4·9) 779 | 751/177/14 765 | 674/254/19 693 | 718/210/15 733 |
| s2 | 0.5 | 658/270/6 664 | 673/255/3 676 | 664/264/5 669 | 666/262/6 672 | 607/321/6 613 | 669/259/8 677 |

### 4.1 개선이 어디서 왔나 — 캠페인 집중

- 합산 TP 증가의 대부분은 **shai-hulud-original(186쌍, outer fold 2) 한 캠페인**이다.
  full35 기준 0.05에서 s1 +35, s2 +70; 0.5에서 s1 +47, s2 +59.
- 이 캠페인을 빼면(악성 742쌍) X1 변형은 full29와 같거나 낮다.

| shai-hulud-original 제외 TP | full29 | full35 | full32 | +Ref | +Proc | +Net |
|---|---:|---:|---:|---:|---:|---:|
| s1 0.05 | 567 | 566 | 566 | 566 | 567 | 556 |
| s2 0.05 | 619 | 591 | 611 | 611 | 592 | 614 |
| s1 0.5 | 538 | 542 | 541 | 543 | 536 | 527 |
| s2 0.5 | 577 | 533 | 543 | 566 | 537 | 577 |

- 손실 캠페인: autotel(29쌍, 0.05 s2 full35 −17), miasma(26쌍, −13), chaindrop(25쌍, s1 −10).
  autotel·miasma는 X1이 전부 0인 C유형(eval 페이로드; X1 한계로 이미 기록됨)이다. X1이 있는 모델은 "통신·실행 호출 없음 = 정상" 쪽으로
  기울어 이런 악성의 점수를 낮춘 것으로 보인다(관찰; 원인 단정은 아님).
- 캠페인 동일 비중 Recall(`campaign_macro_recall`)은 full35에서 s2가 낮아졌다(0.05: 0.506 → 0.436). component 평균은 올랐는데,
  individuals_case(50쌍)가 component 단위로는 여러 개로 나뉘어 그 증가(+6~11)가 크게 반영되기 때문이다.
- 크기 5 이상 캠페인 14개 중 full29 대비 Recall 상승/하락 수(0.05): full35 s1 5/1, s2 3/7; full32 s1 5/1, s2 5/4.

### 4.2 fold·split 일관성 (`fold_consistency.csv`)

- fold 0(sha1-hulud만)은 모든 변형에서 TP 변화 0.
- 이득은 fold 2(shai-hulud-original 포함)에 집중, fold 1은 감소 또는 0.
- **split2 fold1에서 Proc를 포함한 변형(full35·full32·+Proc)은 mini-shai-hulud B유형 40쌍(@tanstack/*)을 0.5에서 놓쳤다**
  (full29 점수 0.95 내외 → 0.13~0.28). 40쌍 모두 RefFile=False, Proc=0, Net=9. +Net·+Ref 단독은 이 손실이 없다(+Ref −9).
  W1에서 보인 B유형 불안정과 같은 fold다.
- 4개 표시 임계값 × 2 split × 3 fold = 24칸 중 TP 증가/감소: full35 9/7, full32 9/6, +Net 11/5, +Ref 9/3, +Proc 0/12.

### 4.3 행 단위 증감 (`paired_vs_full29.csv`, 상세 `paired_cases.csv`)

| 0.05 / 0.5 | s1 악성 획득·상실 | s2 악성 획득·상실 | s1 오탐 추가·제거 | s2 오탐 추가·제거 |
|---|---|---|---|---|
| full35 | 48·14 / 59·8 | 88·46 / 73·58 | 2·2 / 1·1 | 5·11 / 2·5 |
| full32 | 50·14 / 53·8 | 85·27 / 58·52 | 2·2 / 1·1 | 5·8 / 1·2 |
| +Net | 45·19 / 74·17 | 37·27 / 27·16 | 0·4 / 2·1 | 5·6 / 3·1 |
| +Ref | 0·1 / 7·2 | 56·13 / 25·17 | 2·3 / 0·0 | 2·4 / 0·0 |
| +Proc | 10·13 / 2·6 | 10·44 / 7·58 | 2·2 / 0·2 | 4·1 / 1·1 |

오탐 변화는 수 건 수준이고 Hard benign 오탐도 ±0~8건이다. 오탐 감소는 작게나마 대체로 X1 쪽이다.

### 4.4 순위 지표 (`ranking.csv`, fold 안 상위 비율에 든 악성, 동점 없음)

상위 30%: full29 s1 764 / s2 780 → full35 781 / 793, full32 778 / 797, +Net 780 / 788, +Ref 770 / 796, +Proc 759 / 777.
상위 50%: full29 896 / 907 → full35 887 / 905(소폭 감소). 상위 10%는 악성 수가 슬롯보다 많아 차이가 거의 없다.

### 4.5 Feature 중요도 (`feature_importance_summary.csv`, gain 비중)

- full35: Net·Proc·RefFile이 상위권이지만 **fold마다 하나가 집중적으로 쓰인다**:
  split1 fold1 Net 86%, split1 fold2 Proc 64%, split2 fold2 RefFile 41%. 해당 fold의 fit에 있는 큰 캠페인의 서명을 학습하는 모양이다.
- `installHookArgsChanged`, `installHookNewExternalExecCount`: 전 모델 gain 0(쓰이지 않음).
  `installHookNewProgramCount`: gain 0~3.5%(installScriptAdded와 중복).
- 실제 rounds: split1 fold1이 full35·full32·+Net 138, +Ref 157, +Proc 149, 나머지 200.

## 5. 해석

- **full29 대비 X1의 일관된 추가 효과는 확인되지 않았다.** 합산 Recall 증가는 대부분 shai-hulud-original 한 캠페인에서 왔고,
  그 캠페인을 빼면 같거나 낮다. split2에서는 C유형(X1=0) 캠페인과 mini-shai-hulud B유형에서 손실이 있었다.
- 변형별 (미확정, D06 개발자료 기준):
  - `addedNetworkCallCount`: 단독 추가 시 손실이 가장 작고 이득 칸이 가장 많다(11/5). 다만 이득도 shai-hulud-original 중심이고
    shai-hulud-original 제외 시 s1에서 −11. 유지 후보이나 효과 미확정.
  - `installHookRefFileChanged`: 손실이 작고 split2에서 이득(+43 at 0.05). 유지 후보이나 split1에선 효과 없음.
  - `addedProcExecCallCount`: 단독으로 24칸 중 증가 0, 감소 12. split2 fold1 B유형 40쌍 손실의 원인 feature. **제외 검토 근거가 가장 강함.**
  - `installHookArgsChanged`, `installHookNewExternalExecCount`: D06 학습에서 쓰이지 않음(gain 0). 학습 입력 제외 근거.
  - `installHookNewProgramCount`: 거의 쓰이지 않음(중복). 제외해도 영향 작을 것으로 보이나 이 실험에서 단독 비교는 하지 않았다.
- 이 결론으로 feature를 확정하지 않는다. outer 결과를 보고 새 변형(예: full29+Ref+Net)을 이 실험에 추가하지 않았다.
  그런 조합은 별도 실험으로 사전 등록하고, 가능하면 D06이 아닌 독립 자료에서 확인해야 한다.

## 6. 한계

- outer fold 3개가 각각 큰 캠페인 하나에 지배된다(fold 0 = sha1-hulud 332, fold 1 = mini-shai-hulud 198, fold 2 = shai-hulud-original 186).
  "캠페인 하나를 처음 볼 때"의 일반화를 본 것이며 fold 수가 적어 변동이 크다.
- split1·split2는 같은 행을 다시 쓰므로 독립 관측이 아니다. 두 split 방향이 다르면 불안정으로 본다.
- 고정 임계값 비교는 feature가 바뀌면 점수 척도가 바뀌는 영향을 받는다. 순위 지표를 함께 보았다.
- 규칙 미적중 악성에서의 효과: D06 규칙(diff_scan) 판정 결과 자료를 데이터 저장소(be87ab4c·main)와 model-training 브랜치에서
  찾지 못했다(인수인계 문서 5절과 같음). 자료가 없으므로 이 항목은 **추정하지 않았다**.
- 공격 유형 A/B/C는 feature 기반 대리 분류(PR #13 스냅샷 정의)다.

## 7. 재실행

```bash
# venv: lightgbm==4.7.0 pandas==3.0.6 numpy==2.5.3 scikit-learn==1.9.1
# <ws>/temp/detection-feasibility/phase2/evaluation_spec.json, decision_criteria.json  (PR #13 provenance 사본)
# <ws>/temp/detection-feasibility/phase1/run_20261108T141426Z_d8b14252/inputs/train.csv  (데이터 저장소 be87ab4c)
# <ws>/temp/detection-feasibility/phase1/run_20261108T141426Z_d8b14252/inputs/train_malicious_groups.csv  (PR #13 provenance/inputs)
# <ws>/model-training -> 이 저장소
python -I -B run_full35.py --workspace <ws> --stage repro --out <tmp>/repro
python -I -B verify_repro.py --run <tmp>/repro --out repro_verification.json
python -I -B run_full35.py --workspace <ws> --stage main --out run
python -I -B evaluate_full35.py --run run
```
