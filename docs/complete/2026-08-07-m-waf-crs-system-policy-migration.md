# OWASP CRS 소스 → 시스템 정책 마이그레이션·전파

## 완료 범위

- CRS 자동 발견과 시스템 정책 생명주기를 분리했다. 자동 갱신 PR은 검증된 `packaging/sources.lock.yaml` 후보만 변경하며 시스템 정책 템플릿을 게시하지 않는다.
- 공식 `coreruleset/coreruleset` stable v4 아카이브의 실제 SHA-256을 인덱서 진입점에서도 재검증한 뒤 여러 줄·chain Rule을 결정적으로 읽고 ID, 파일/줄, phase, PL, severity, tag, message, 변수, operator, 정규화 해시를 생성하는 Rule 인덱서를 추가했다.
- `crs-setup.conf.example`에서 M-WAF 지원 Setup의 upstream 기본값을 추출하며 누락된 지원 키, standalone Rule ID 누락과 중복 Rule ID를 번들 생성 전에 차단한다.
- 서명 번들 manifest schema v2에 `policy_sources`를 추가했다. 기존 schema v1 읽기 호환은 유지하고, 소스 인덱스의 크기·SHA-256·메타데이터·패키지 참조를 Manager 로딩 시 검증한다.
- 시스템 관리자 전용 오픈소스 CRS 목록/상세, Rule 검색, Setup, 현재 시스템 정책 diff, 패키지 준비 상태 화면과 API를 추가했다. Manager는 GitHub에 직접 접속하지 않는다.
- 기존 CRS/정책 버전 직접 입력 게시 경로를 종료하고, 검증된 소스를 선택하는 5단계 시스템 정책 마이그레이션 화면과 상태 비변경 검증 API를 추가했다.
- 삭제 Rule 참조, 존재하지 않는 Target 변수, 제거·타입 변경 Setup, 위험 Service Rule, 변경 Rule 오버레이 미확인, 동시 시스템 정책 변경을 게시 전에 차단한다.
- 모든 활성·미해제 서버에 대해 OS/아키텍처/웹서버/integration mode, Agent의 `policy-bundle-v2` 지원, 대상 CRS 모듈과 명시적 롤백 패키지를 확인한다. 하나라도 불완전하면 게시하지 않는다.
- 신규 정책 artifact를 `manifest.json`, `00-engine.conf`, `20-crs-setup.conf`, `30-before-crs-exclusions.conf`, `40-crs-rules.conf`, `50-after-crs-exclusions.conf`, `60-service-rules.conf` 순서의 결정적 `policy-bundle-v2`로 생성하고 전체 바이트를 기존 Ed25519 정책 키로 서명한다.
- Agent가 tar entry allowlist, symlink/크기 제한, manifest 파일별 SHA-256을 검증하고 revision 디렉터리에 staging한 뒤 `/etc/mwaf/active` 링크를 원자적으로 전환하도록 했다. configtest 또는 reload 실패 시 직전 링크로 복구하고 다시 검증한다.
- 모듈 패키지는 기존 `main.conf`를 호환 legacy revision으로 옮기고 `active/*.conf`를 읽는다. v1 단일 conf와 이전 모듈 롤백을 위한 `main.conf` 호환 진입점은 유지한다.
- 기존 `AUTOMATIC`, `MANUAL`, `PINNED` 전파 전략을 그대로 사용한다. v2로 처음 이동할 때 DetectionOnly 전환 → Agent/모듈 패키지 → 최종 v2 정책 순서를 강제한다.
- 카나리 적용 후 10분 동안 실제 CRS, 정책 revision과 heartbeat를 확인한다. 직전 60분 기준선의 3배와 분당 5건 중 큰 값을 초과하는 차단률이면 확대를 중지하고 변경된 카나리만 직전 패키지·정책으로 복구한다. 통과 후 기존 25대 단위 배포를 재개한다.
- 소스 검증·시스템 정책 게시·마이그레이션 차단·카나리 게이트·복구를 기존 관리자 감사 로그에 기록한다.
- 신규 DB 테이블이나 마이그레이션, WebSocket, Manager의 GitHub 런타임 접근은 추가하지 않았다.

## 호환성과 배포 주의

- 기존 bundle schema v1, `conf-v1`, Agent 조회·보고 API 경로와 기존 응답 필드는 유지된다. `DesiredState.artifact_format`은 선택 필드다.
- 오픈소스 CRS 화면은 schema v2 서명 번들을 배포하고 Manager를 다시 시작한 뒤 채워진다.
- 엄격한 롤백 게이트 때문에 이전 서명 릴리스가 없는 최초 schema v2 릴리스에서는 신규 v2 시스템 정책 게시가 차단될 수 있다. 다음 태그 릴리스가 검증된 이전 패키지를 롤백 대상으로 포함한 뒤 게시할 수 있다.
- 과거 CRS 인덱스는 이후 번들에도 보존하지만, 더 이상 보유하지 않는 과거 패키지 ID는 제거해 감사 조회와 현재 설치 가능 상태를 구분한다.

## 확인 결과

- `gofmt` 적용 완료
- `git diff --check` 통과
- `go build ./...` 통과
- 변경한 모듈 패키지·external 설정 스크립트 `sh -n` 구문 검사 통과
- Rule 인덱서와 policy bundle 변조/결정성 검증용 테스트 코드를 추가했지만 작업 지침에 따라 테스트 명령은 실행하지 않았다.
- 프론트엔드 빌드, 브라우저 반응형 확인, 실제 Apache/Nginx DEB 설치·configtest, Docker E2E, 10분 카나리 실시간 관찰은 실행하지 않았다.
- 현재 실행 중인 Manager가 없어 인증된 UI/API 런타임 확인은 수행하지 않았다.
- DB 초기화·reset·스키마 변경은 수행하지 않았다.
