# X2 (신규 의존성) Feature 검토 메모 — 구현·추출 전 (2026-11-24)

## 확인된 사실 (registry 조회 2026-11-24, packument 사본: easy-day-js.packument.json)
- 조사 쌍(Test, mastra-easy-day-js_2026-06): @mastra/agent-browser 0.3.1→0.3.2, @mastra/auth-clerk 1.0.2→1.0.3, @mastra/deployer-netlify 1.1.19→1.1.20
- 세 쌍 모두 새 의존성 1개: easy-day-js, 선언 범위 ^1.11.21
- 현재 versions: ['1.11.21'] 만. dist-tags.latest = 1.11.21
- time 맵: created 2026-06-16T07:05:42.093Z, 1.11.21 2026-06-16T07:05:42.457Z, 1.11.22 2026-06-17T01:01:33.087Z, modified 2026-06-17T06:50:06.352Z
- 1.11.22 manifest·tarball: 404 (version not found)
- mastra new 버전 publish: 0.3.2 01:42:27Z(1.11.22 후 40.9분), 1.0.3 01:46:33Z(45.0분), 1.1.20 02:02:40Z(61.1분)
- 따라서 publish 시점에 ^1.11.21은 1.11.22로 해석될 수 있었다. 이전 메모의 "버전 1개, 설치 훅 없음"은 현재 남은 1.11.21에 대한 사실이며 당시 해석 버전(1.11.22)에 대한 것이 아니다.
- 데이터 저장소 archive(be87ab4c)의 mastra 쌍은 mastra 패키지 자체(normal_raw/malicious_raw)만 보존하고 의존성 tarball은 없다.
- DataDog dataset(api.github.com)·OSV(api.osv.dev)는 이 세션에서 접근 불가(proxy 403/scope)라 확인하지 못했다.

## 조회 시각과 출처
- registry 조회: 2026-11-24 (packument 사본 파일 시각 2026-11-24T12:56:35Z), `https://registry.npmjs.org/easy-day-js`, `/easy-day-js/1.11.22`, `/-/easy-day-js-1.11.22.tgz`
- mastra new 버전 publish 시각: 같은 날 `https://registry.npmjs.org/<package>` packument `time` 맵
- 데이터 저장소 archive: `npm-malware-package-pairs` `be87ab4c` `pairs/mastra-easy-day-js_2026-06/@mastra__agent-browser__0.3.1_to_0.3.2__a5e7a04603d7/` (meta.json 출처: DataDog malicious-software-packages-dataset `6894a19`)
- 외부 분석(Microsoft, JFrog)의 1.11.22 postinstall 설명은 사용자 제공 정보이며 이 세션에서 직접 확인하지 않았다.
