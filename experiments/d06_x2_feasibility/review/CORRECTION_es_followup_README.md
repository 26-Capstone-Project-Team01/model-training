# 정정: `experiments/d06_es_followup/README.md` 2.2절 (커밋 `db941bb`)

기존 파일은 그대로 두고 이 문서로 정정한다.

## 기존 내용

> 확인(사례 조사, Feature 아님): Test mastra 3쌍은 모두 의존성 1개를 새로 추가했고 범위는 `^1.11.21`, 그 의존성 패키지는 registry에
> 1개 버전만 있으며 생성 시각이 mastra 새 버전 publish 18.6~18.7시간 전이다. 그 버전 manifest의 scripts에 설치 훅(preinstall/install/postinstall)은 없다.

## 정정 내용

- "registry에 1개 버전만 있다"와 "설치 훅이 없다"는 **조회 시점(2026-11-24)에 남아 있는 1.11.21**에 대한 사실이다.
- 같은 packument의 `time` 맵에는 `1.11.22`(2026-06-17T01:01:33.087Z)가 남아 있고, 이 버전의 manifest·tarball은 404다.
- 1.11.22는 mastra 세 new 버전보다 40.9~61.1분 먼저 publish됐으므로, 당시 `^1.11.21`은 1.11.22로 해석될 수 있었다.
  당시 설치되었을 버전의 설치 훅은 현재 registry로 확인할 수 없다.
- 따라서 "해당 의존성에는 설치 훅이 없다"는 결론은 틀렸다. 지워진 버전을 빼고 계산한 값이다.
- "생성 시각이 18.6~18.7시간 전"은 `time.created` 기준으로 맞다(세 번째 쌍 1.1.20은 18.95시간). 당시 해석 버전 기준 나이는 0.68~1.02시간이다.

## 근거

- 조회: `GET https://registry.npmjs.org/easy-day-js` (2026-11-24T12:56:35Z, HTTP 200), 사본 `easy-day-js.packument.2026-11-24.json`
- `GET https://registry.npmjs.org/easy-day-js/1.11.22` → 404 `version not found: 1.11.22`, `GET …/-/easy-day-js-1.11.22.tgz` → 404
- 세부: `X2_REVIEW.md`
