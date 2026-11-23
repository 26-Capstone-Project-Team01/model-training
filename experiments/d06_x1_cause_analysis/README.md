# D06 X1 성능 변화 원인 진단 (재학습 없음)

`d06_full35_compare`의 저장 모델·점수와 PR #13 full29 저장 모델·점수만 사용했다. LightGBM 학습, 새 feature 조합, Test 677,
분할 변경, 패키지 설치·실행은 하지 않았다. TreeSHAP은 저장 모델의 `predict(pred_contrib=True)`(추론)로 계산했다.
`common.py`의 feature 인코딩으로 36개 모델(full29 6 + 변형 30)을 다시 예측해 저장 점수와 최대 차 1.1e-16을 확인했다.

- `a1_campaigns.py`: 캠페인별 TP/중앙 점수, X1·주요 29개 feature 분포, fold별 fit 악성 캠페인 구성
- `a2_shap.py`: 집중 캠페인·mini-shai 40쌍 TreeSHAP 평균 기여(log-odds)
- `a3_trees.py`: 트리 분기(feature별 split 수·gain 비중·임계값), fit/calibration/outer의 Proc·Net 분포
- `a4_ranking.py`: fold별 ROC-AUC·PR-AUC(진단), PR #13 phase2 calibration FPR 1%/5% 운영점(기존 정책), 순위 변화, 점수 분포
- `a5_features.py`: +Ref/+Proc/+Net 단독 추가 시 획득·상실 사례, fit의 feature 값-label 관계, X1 양성의 캠페인 집중
- 결과: `out/`
- 진단용 지표(ROC-AUC, PR-AUC, outer FPR 1% 기준 Recall)는 평가 정책이 아니며 임계값 선택에 쓰지 않는다.
