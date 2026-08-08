# M-WAF 단일 엔드포인트·테넌트 정책·릴리스 개선 완료

## 완료 범위

- Manager 관리자 UI와 Agent API를 기본 `8443` 단일 HTTPS 리스너로 통합했다.
- Agent는 인바운드 포트를 열지 않고 heartbeat 주기마다 Manager로 요청하는 단방향 연결 모델을 유지한다.
- `internal/protocol/agent_v1.go`에 Agent v1 방향, 인증, 기본 폴링 주기, 크기 제한, endpoint와 wire payload 계약을 구조체로 정리했다.
- Manager 라우팅 등록을 공통, 관리자 UI/API, Agent API 파일로 분리했다.
- 시스템 관리자 소속 기업과 전역 운영 권한을 분리하는 `TenantScope`를 추가해 다중 호스팅 기업 구조를 명확히 했다.
- 초기 설치 시 내장 시스템 정책과 기업 정책을 자동 게시하지 않도록 변경했다.
- CI의 CRS updater는 공식 stable v4 후보 source lock만 갱신하며 시스템 정책 템플릿을 만들거나 게시하지 않는다.
- Manager에서 검증된 최신 CRS 소스를 선택해 Setup·before/after overlay·Service Rule을 검토한 뒤 최초 또는 후속 시스템 정책으로 게시하도록 연결했다.
- CRS 소스 최신 정렬을 숫자 버전 비교로 바꿔 `4.28.0`과 `4.9.0` 같은 문자열 정렬 오류를 방지했다.
- 기업 정책 안내형 편집기에 URL 및 IP/CIDR 조건과 탐지·차단 동작을 추가했다. IP/CIDR은 `@ipMatch`와 주소 형식을 제출 전에 검증한다.
- `policy-bundle-v2`는 upstream Setup과 Rule 파일을 읽기 전용 include로 유지하고 M-WAF 변경을 별도 overlay 파일에 배치한다.
- `dev` 푸시는 검증된 Manager 이미지를 `latest`, `dev`, commit SHA 태그로 게시한다.
- `vMAJOR.MINOR.PATCH` 태그는 검증된 버전 이미지와 `latest`를 게시한 후, 해당 커밋으로 `main`을 fast-forward하고 GitHub Release를 생성한다.
- `dev`와 버전 태그의 게시 workflow를 직렬화해 동시에 `latest`를 덮어쓰는 경합을 방지한다.
- README, Compose, 로컬 실행, E2E, 커스텀 웹서버 설치 문서에서 별도 Agent 포트 설정을 제거했다.
- 격리 E2E는 시스템 정책이 없을 때 검증된 최신 CRS를 API로 검증·게시한 뒤 테스트를 계속한다. 원격 E2E는 시스템 전체 변경을 자동 수행하지 않고 관리자 게시를 요구한다.

## 주요 파일

- `.github/workflows/dev-manager-image.yml`
- `.github/workflows/crs-updates.yml`
- `internal/protocol/agent_v1.go`
- `internal/manager/routes.go`
- `internal/manager/routes_admin.go`
- `internal/manager/routes_agent.go`
- `internal/manager/session.go`
- `internal/manager/open_source_policy_handlers.go`
- `internal/manager/system_policy_migration_handlers.go`
- `internal/manager/policy_authoring_handlers.go`
- `internal/policybundle/bundle.go`
- `deploy/compose/compose.yaml`
- `deploy/e2e/run.sh`
- `docs/agent-protocol-v1.md`
- `docs/hosting-tenant-policy-lifecycle.md`

## 정적 확인

- 변경된 Go 파일에 `gofmt`를 적용했다.
- `deploy/compose/run-local.sh`, `deploy/e2e/run.sh`, `deploy/compose/prepare.sh`의 셸 구문을 확인했다.
- GitHub Actions YAML 두 파일을 표준 YAML 파서로 확인했다.
- `git diff --check`를 통과했다.
- 현재 런타임 설정과 일반 문서에서 `10443`, `MWAF_AGENT_PORT`, `MWAF_AGENT_ADDR`, `MWAF_AGENT_PUBLIC_URL`, `--agent-port` 잔존 항목이 없음을 확인했다. 과거 완료 기록은 당시 상태 보존을 위해 수정하지 않았다.

## 수행하지 않은 확인

- 지침에 따라 프론트엔드 빌드와 자동 테스트는 실행하지 않았다.
- 데이터베이스 초기화, reset, migration 실행 또는 데이터 변경은 수행하지 않았다.
- 실행 중인 Manager 프로세스가 없어 새 프로세스를 띄우거나 브라우저 화면을 확인하지 않았다.
- 실제 GitHub `dev` 푸시, GHCR 게시, `main` 승격, GitHub Release 생성은 원격 workflow 실행에서 확인해야 한다.
