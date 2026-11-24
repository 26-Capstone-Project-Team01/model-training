# D06 X3 · D Feature 실험 계획 (설계 단계, 추출·학습 전)

상태: **Feature 구현·단위 테스트 완료, 전체 추출과 학습은 검토 후.** 이 문서는 학습 전에 비교 조합과 판단 기준을 고정하기 위한 것이다.

- Feature 정의: depbee-analyzer `feat/x3-hook-target-context` 브랜치 `docs/x3-features.md` (사본: `x3-features.md`)
- 구현: `extractors/x3_context.py`(X3 13개 + 진단 4열), `extractors/dependency_change.py`(D 2개), 둘 다 선택 실행 목록에만 등록
- 근거 분석: `../d06_hb_typewise/` (`exp/d06-hb-typewise` 94ee232)

## 1. Feature 묶음

| 이름 | 수 | 구성 |
|---|---:|---|
| base7 | 7 | package.json 7 |
| obf22 | 22 | 난독화 22 (full29 = base7 + obf22) |
| X1 | 6 | installHookNewProgramCount, installHookArgsChanged, installHookRefFileChanged, installHookNewExternalExecCount, addedProcExecCallCount, addedNetworkCallCount |
| X3 | 13 | installHookTargetCount, installHookTargetMaxBytes, obfHook×7, installHookTargetProcExecCallCount, installHookTargetNetworkCallCount, addedNetworkCallPer1kAddedTokens, addedProcExecCallPer1kAddedTokens |
| D | 2 | dependencyRangeChangedCount, dependencyChangedRatio |

X3 진단 열(`x3diag*`)은 모델 입력이 아니다.

## 2. 비교 조합

| 조합 | 수 | 상태 | 처리 |
|---|---:|---|---|
| base7 | 7 | **이미 있음** (PR #13 저장 모델·점수) | 재학습 안 함, 저장 점수 재사용 |
| full29 | 29 | **이미 있음** (PR #13) | 재사용 |
| full35 | 35 | **이미 있음** (`d06_full35_compare`, `exp/d06-full35-compare` 03ac937) | 재사용 |
| base7 + X1 | 13 | 신규 (기존 실험에 없음 — full32·full29_* 변형은 모두 obf22 포함) | 학습 6모델 |
| full35 + X3 | 48 | 신규 | 학습 6모델 |
| base7 + X1 + X3 | 26 | 신규 | 학습 6모델 |
| (조건부) full35 + X3 + D | 50 | D 분포 검토 후 결정 | 학습 6모델 |
| (조건부) base7 + X1 + X3 + D | 28 | 같음 | 학습 6모델 |

이미 한 실험(full32, full29_ref/proc/net, W1, ES, A1~A3 블렌딩, base7_w, E06/E09)은 다시 하지 않는다. A1~A3·ES·W1은 이번 비교의 기준선으로 저장 결과만 인용한다.
조건부 2개는 D를 전체 정상 1,600쌍에 추출해 분포를 본 뒤(학습 결과를 보기 전에) 넣을지 정한다.

## 3. 프로토콜 (기존과 동일)

- 데이터: D06 Train 2,767쌍 (be87ab4c `derived/splits/train.csv`, sha 22fbc875…). 행 정렬은 `d06_full35.csv`와 같은 row_id.
- PR #13 실행 스냅샷(`executed_script_snapshot.py`, sha 049bf00c…)을 경로로 불러 component 외부 3-fold, 내부 분할(seed 20261109/20261110), 보정(calibration) 임계값, LightGBM 파라미터를 그대로 쓴다.
  200 rounds, early stopping 없음, 가중치 없음, 값 변환 없음. 결측은 NaN 그대로.
- 새 열은 row_id와 키(package, old_version, new_version)·라벨 일치를 확인한 뒤 붙인다.
- 산출: 외부 fold 점수, 보정 FPR 1·3·5% 임계값별 TP·FP·Hard benign FP, 캠페인별 재현율, 변경 유형별 성능(`d06_hb_typewise`와 같은 층), TreeSHAP 요약.

## 4. 판단 기준 (학습 전에 고정)

Train 외부 fold(split1·split2) 결과만 쓴다. Test는 쓰지 않는다.

1. 주 지표: 보정 FPR 5%와 1%의 외부 TP 합(두 split). Hard benign FP는 함께 보고, full35보다 늘면 채택하지 않는다.
2. 두 split에서 방향이 같아야 한다(한 split만 좋아지면 "근거 부족").
3. 이득이 한두 캠페인에 몰리면(`d06_x1_candidate_analysis`의 집중도 기준과 같은 계산) 별도 표시한다.
4. X3가 목표로 한 사례(1.4절 HB 오탐: 설치 훅 추가 정상, 번들 호출 추가 정상)의 오탐 변화를 따로 보고한다.
5. base7 + X1 (+X3)는 "난독화 22개 없이 얼마나 가는가"를 보는 조합이다. full35 대비 TP가 같거나 높고 FP가 같거나 낮을 때만 대안으로 본다.

알려진 한계: mastra 유형(JS 변경 없음·새 의존성·훅 추가 없음) 악성은 Train에 6쌍뿐이라 Train으로는 그 유형의 개선을 판단할 수 없다. X3는 이 유형에 값이 거의 없다(훅·JS 변경이 없다).

## 5. 추출 계획 (검토 후 실행)

1. Train 2,767쌍 전부에 `x3_context`, `dependency_change` 추출 (기존 X1 추출과 같은 입력 처리: registry tarball 무결성 확인, archive partial clone, 코드 실행 없음).
   실패는 0으로 채우거나 지우지 않고 기록한다.
2. 추출 검증: 진단 열 분포, X3와 obf22·X1의 상관, 결측률을 클래스별로 본다(학습 전).
3. 이후 학습 → 비교 → 선택. Test(674/677) X3 추출과 진단 평가는 선택 후 별도 사전 등록으로 한다.

필요한 규모: 신규 학습 18모델(+조건부 12), 추출 2,767쌍(X1 추출과 같은 소스 다운로드량).
