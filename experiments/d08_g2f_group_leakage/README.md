# D08 그룹 누출 검증 · G2f 60-run · 최종 후보 비교 (최소 보존본)
보고서: `REPORT.md`(1–8절). 데이터: npm-malware-package-pairs D08 `2c48bd83d23ceb16ba7f6c3989d7fb623dcdd554`(동결 파일은 이 묶음에 없음, 해시는 `code/run_m1m4.py`의 `EXPECTED`).

## 구성
- `evidence/`: 근거 요약(`EVIDENCE_SUMMARY.csv`), 복호화 payload의 해시 대응표(내용 없음), 계열 표지 적중 목록, 그룹 간 동일 파일 oid, baseline 오염 검사, G2f 근거 링크.
- `mappings/`: G1/G2/G2f 재매핑 설정, 개발 데이터 제외 6쌍(clipper), G0→G2f 통합 목록(그룹·행).
- `code/`: 40-run(`run_m1m4.py`, `evaluate_m1m4.py`), 60-run(`run_g2f.py`, `evaluate_g2f.py`), 진단(`matched_fpr_diagnostic.py`), 그룹 검증, D08 분석, 이 묶음 생성기.
- `results/`: 60-run(run·eval·진단), 40-run(설정·로그·임계값·fold 지표·eval). 모델 파일은 없음(sha256은 training_log).
- `results/g2f_60run/diag_matched_fpr_DIAGNOSTIC/`: validation 라벨로 맞춘 임계값 기반 진단. 운영 임계값으로 쓰지 않는다.

## 의도적으로 뺀 것
복호화 스크립트와 복호화 payload, 악성 raw 파일, 문맥 출력 스크립트, 전체 IOC 토큰 목록, 모델 파일, ls-tree 목록, 대체된 초기 diff 스캔.
`verify_g2_links.py`가 읽는 `evidence/rotpacker_decoded_payload_hashes.csv`는 해시만 담고 있으며, 복호화 단계는 재현 대상에서 제외했다.

## 정화(sanitisation)
install hook 명령 문자열과 `nojs:` payload 키는 `sha1[:16]` 태그로, webhook capability 토큰·Telegram 봇 토큰도 해시로 대체(`SANITISATION_LOG.json`).
payload 키의 묶음 관계는 1:1로 유지된다. 공격자 지갑 주소 등 공개 IOC 문자열과 SDK URL은 근거로 남아 있다.

## 재현
`run_g2f.py`는 `run_m1m4.py`(같은 폴더 위치 가정)와 PR #13 snapshot(`049bf00c…`), D08 입력 사본(`inputs/`)이 필요하다. 실행 순서: `run_g2f.py --out run` → `evaluate_g2f.py --run run --out eval` → `matched_fpr_diagnostic.py run diag`.
