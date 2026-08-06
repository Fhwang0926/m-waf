# M-WAF Agent 운영 안정성 및 태그 전용 릴리스 반영

## 작업일

- 2026-08-06

## 결론

PR과 `dev` push, 수동 workflow 실행은 소스, DEB와 실제 Apache/Nginx 설치를 검증하지만 M-WAF Manager Docker image를 생성하거나 게시하지 않는다. 정규식 `vMAJOR.MINOR.PATCH`에 맞는 tag push event에서만 동일 검증을 통과한 세 DEB를 서명 bundle로 조립하고 Manager image를 GHCR에 게시한다.

로컬 개발은 저장소 clone 후 `make dev`로 현재 Go source를 직접 실행한다. 기존 `dist/bundle`이나 공개된 최신 tag bundle이 없더라도 Manager UI/API 개발은 시작할 수 있으며, 이 경우 고객 package 설치 API만 준비되지 않은 상태로 표시된다.

## Annotation 1: 운영 안정성 개선

### Agent 인증서 자동 갱신

- Agent 인증서는 기존과 동일하게 90일 유효기간으로 발급
- 만료 30일 전부터 `/agent/v1/certificate/renew`로 자동 갱신
- 기존 private key를 재사용해 certificate 파일 하나만 원자적으로 교체
- Manager가 새 serial을 저장한 뒤 응답이 끊겨도 기존 인증서는 원래 만료 시각과 최대 갱신 구간 안에서 재시도 가능
- 서버 폐기 상태는 기존 `revoked_at` 검사를 계속 적용
- CA가 CSR의 임의 Common Name을 신뢰하지 않고 Manager의 server ID와 SPIFFE URI를 인증서에 설정하는 단위 테스트 추가

### ModSecurity 감사 로그 회전

- 웹서버 모듈 DEB에 배포판 `logrotate` 의존성과 `/etc/logrotate.d/mwaf-modsecurity` 추가
- 일 단위, 최대 100 MB, 14개, 압축, `copytruncate` 정책 적용
- Agent checkpoint를 offset 정수에서 device, inode, offset JSON으로 확장
- 기존 offset-only checkpoint와 spool 파일을 계속 읽는 하위 호환 처리
- 파일 교체 또는 truncate 이후 새 로그의 처음부터 다시 읽는 회귀 테스트 추가

### 이벤트 회수량 및 장애 재시도

- heartbeat 30초 주기에서 이벤트 1 batch만 처리하던 결합 제거
- 기본 2초 이벤트 전송 주기 분리
- 한 번에 최대 20 batch, batch당 최대 500건을 순차 처리
- Manager 전송 실패 시 2배 지수 backoff, 최대 1분
- 디스크 spool과 batch ID 멱등성은 그대로 유지

### Migration 재실행 안전성

- MariaDB `GET_LOCK`을 동일 전용 connection에서 획득해 동시 migration 실행 차단
- `002_enterprise_rbac.sql`, `004_control_plane_operations.sql`의 column과 index에 `IF NOT EXISTS` 적용
- foreign key는 `information_schema` 확인 후에만 동적 DDL 실행
- DDL 일부가 적용된 뒤 version 기록 전에 중단되어도 같은 migration을 다시 실행할 수 있도록 구성
- 프로젝트 규칙에 따라 실제 MariaDB migration 실행이나 초기화는 수행하지 않음

### Bootstrap API 제한

- 기존 로그인 메모리 limiter 구조를 재사용한 고정 window limiter 추가
- installer, package resolve, public key, enroll 요청을 IP와 경로 기준 분당 60회로 제한
- 유효한 일회용 token의 package 다운로드는 분당 8회로 제한
- 제한 시 `429 Too Many Requests`와 `Retry-After: 60` 반환

### RBAC 및 회귀 검사

- 기업 사용자, 기업 관리자, 시스템 관리자 역할 경계 단위 테스트
- 기업 관리자와 시스템 관리자의 enterprise scope 단위 테스트
- 권한 부족 handler의 403 응답 단위 테스트
- Bootstrap limiter 단위 테스트
- Agent 인증서 발급과 감사 로그 교체 단위 테스트

## Annotation 2: dev 검증과 tag 전용 image 배포

### PR, dev push, 수동 실행

- `go test ./...`, `go vet ./...`
- Agent와 Apache/Nginx module DEB 3개 생성
- 고정된 OWASP CRS archive checksum 검증
- 깨끗한 Ubuntu 24.04 컨테이너에서 Agent+Apache, Agent+Nginx 실제 설치
- 웹서버 version/build hash exact match
- ModSecurity, CRS, logrotate, audit file 권한과 configtest 확인
- 임시 key로 bundle 조립 확인
- Manager Docker image build 및 GHCR publish 없음
- workflow 전체 기본 권한은 `contents: read`

### vMAJOR.MINOR.PATCH tag push

- tag 형식을 `v0.1.0` 형태의 안정 버전으로 제한
- verify job에서 생성하고 설치 검증한 동일 DEB만 workflow artifact로 전달
- `RELEASE_BUNDLE_SIGNING_KEY_B64`가 없으면 fail closed
- Manager image를 다음 tag로 GHCR에 게시
  - `<major.minor.patch>`
  - `<major.minor>`
  - `<major>`
  - `latest`
  - `sha-<full-commit-sha>`
- tag publish job에만 `packages: write`, `attestations: write`, `id-token: write` 부여
- GitHub OIDC provenance 게시

## 배포 명령

### 로컬 source 개발

```sh
git clone https://github.com/Fhwang0926/m-waf.git
cd m-waf
make dev
```

### 릴리스 생성

첫 tag 전에 `RELEASE_BUNDLE_SIGNING_KEY_B64` repository secret을 등록한다.

```sh
git tag v0.1.0
git push origin v0.1.0
```

### tag image 배포

`deploy/compose/.env`에서 이동 가능한 `latest` 대신 전체 version 또는 digest 사용을 권장한다.

```dotenv
MWAF_MANAGER_IMAGE=ghcr.io/fhwang0926/m-waf-manager:0.1.0
```

```sh
make deploy
```

## 검증 결과

성공:

- `go test ./...`
- `go vet ./...`
- 변경 shell script 문법 검사
- GitHub Actions와 image lock YAML parse
- Docker Compose config 검사
- `git diff --check`

수행하지 않음:

- MariaDB 초기화, reset, migration 실행
- Manager→MariaDB를 포함한 전체 runtime E2E와 1천·5천 Agent 실제 부하 시험
- 프로젝트 Docker image build와 GHCR push
- 실제 tag workflow 실행
- 프론트엔드 build, 브라우저 렌더링과 UI test

전체 MariaDB E2E와 실제 다중 Agent 용량 수치는 쓰기 가능한 일회성 검증 DB와 staging Agent 인증서가 필요한 별도 운영 검증 항목으로 유지한다. 이번 변경은 전송 병목과 재시도 구조를 개선했지만 측정하지 않은 처리량 수치를 제품 성능으로 제시하지 않는다.

## 주요 변경 파일

- `.github/workflows/dev-manager-image.yml`
- `Makefile`
- `deploy/compose/compose.yaml`
- `deploy/compose/.env.example`
- `deploy/compose/run-local.sh`
- `internal/agent/agent.go`
- `internal/agent/audit.go`
- `internal/agent/client.go`
- `internal/config/agent.go`
- `internal/manager/ca.go`
- `internal/manager/server.go`
- `internal/manager/session.go`
- `migrations/migrations.go`
- `migrations/002_enterprise_rbac.sql`
- `migrations/004_control_plane_operations.sql`
- `packaging/module/deb/build.sh`
- `README.md`
- `site/index.html`
- `docs/todo/2026-08-06-m-waf-development-plan.md`

## 후속 충돌 방지 보강

같은 날 운영 전 재검토에서 확인된 Agent 이벤트 처리 문제를 기존 구조 안에서 국소 수정했다.

- 감사 로그 한 줄에 여러 ModSecurity 메시지가 있는 경우 배치 경계에서 일부 메시지만 자르고 체크포인트를 넘기던 동작 제거
- JSONL 한 줄을 체크포인트의 최소 단위로 유지하고, 남은 배치 공간보다 큰 줄은 다음 배치에서 전체 재처리
- 한 줄 자체가 배치 크기보다 큰 경우에는 해당 줄 전체를 한 배치로 처리하여 영구 정체와 이벤트 누락 방지
- 이벤트 수집·전송 loop를 heartbeat, 인증서 갱신, 정책·패키지 제어 loop와 분리
- 병렬 전송과 인증서 갱신 중 Agent HTTP client와 server ID 교체가 경쟁하지 않도록 읽기/쓰기 잠금 추가
- 기존 배포, MariaDB, Manager UI 파일은 변경하지 않음

추가 검증:

- `go test -race ./internal/agent`
- `go test ./...`
- `go vet ./...`
- `git diff --check`

MariaDB runtime E2E, 실제 다중 Agent 부하 시험, GitHub tag workflow와 GHCR push는 외부 검증 항목으로 그대로 남긴다.
