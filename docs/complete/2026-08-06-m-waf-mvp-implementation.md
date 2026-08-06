# M-WAF MVP 구현 완료 기록

## 작업일

- 2026-08-06

## 결과

문서의 최소 수직 흐름을 실행 가능한 코드와 배포 자산으로 구현했다.

```text
고객 요청
  -> 기존 Apache/Nginx
  -> 배포판 ModSecurity 모듈 + 원본 OWASP CRS
  -> JSON 감사 로그
  -> mwaf-agent 디스크 spool/배치 전송
  -> 별도 Manager
  -> MariaDB
```

Manager 배포 스택은 `mariadb`와 `manager` 두 컨테이너만 사용한다. 같은 `dev` source commit에서 빌드한 `mwaf-agent`, `mwaf-modsecurity-apache`, `mwaf-modsecurity-nginx` DEB 세 개는 서명된 bundle manifest와 함께 Manager 이미지에 내장된다. 고객 웹 서버에서는 Agent 패키지와 해당 웹서버용 모듈 패키지 두 개만 직접 선택·설치한다.

## 구현 내용

### Manager

- Go 표준 `net/http`, `html/template`, `crypto/*` 중심의 단일 바이너리
- 관리자 로그인, HMAC session, CSRF, 로그인 rate limit, 보안 header
- 서버 등록용 일회성 token과 CSR 기반 Agent 인증서 발급
- Agent 전용 mTLS API와 Admin/Agent 포트 분리
- heartbeat, desired state, 이벤트 500건 batch 수집과 batch 멱등 처리
- 서버, 이벤트, package bundle, 정책 revision 및 관리자 감사 MariaDB schema
- MariaDB connection pool 32개와 짧은 transaction
- 30일 기본 이벤트 보존 및 5,000건 단위 정리
- 서버별 `DetectionOnly`/`On` 정책 생성, Ed25519 서명 및 artifact 제공
- source commit, manifest 서명, SHA-256, OS/architecture/webserver version/build hash를 검증하는 내장 package catalog
- 서버 렌더링 관리자 UI: 대시보드, 서버, 이벤트, 등록 token, 정책 배포

### Agent

- Go 단일 정적 바이너리와 systemd service
- OS, architecture, Apache/Nginx 종류·version·정규화 build hash 수집
- bootstrap token enrollment, 로컬 Ed25519 private key, Manager 발급 client certificate
- mTLS heartbeat와 desired state polling
- 정책 SHA-256/Ed25519 검증
- Apache `configtest`/graceful 또는 Nginx `-t`/reload
- 정책 검증 또는 reload 실패 시 이전 파일 복원과 재검증/reload
- ModSecurity JSONL audit parsing
- 전송 전 mode `0600` 디스크 spool 저장, 같은 batch ID 재전송, 성공 후 offset commit

### 오픈소스 기반 모듈 package

- 자체 WAF engine, Connector, CRS parser를 구현하지 않음
- Apache: Ubuntu 24.04 `libapache2-mod-security2` 2.9.7 계열 사용
- Nginx: Ubuntu 24.04 `libnginx-mod-http-modsecurity` 1.0.3 계열과 그 libmodsecurity v3 dependency 사용
- OWASP CRS v4.28.0 공식 tag archive를 SHA-256 고정 후 rules를 수정 없이 포함
- M-WAF 소유 코드는 include 연결, JSON audit 위치, Agent 활성 정책 경로뿐
- 지원 대상과 정확히 일치하는 package 두 개만 Manager가 resolve

### 배포와 CI

- MariaDB 11.8.6과 distroless Manager Compose stack
- MariaDB host port 미공개, 내부 network 분리, named volume, file secret
- 기존 `.env`, secret, volume을 덮어쓰지 않는 `prepare.sh`
- Go builder, distroless runtime, MariaDB image digest 고정
- `dev` branch push 및 수동 실행용 `.github/workflows/dev-manager-image.yml`
- GHCR tag: `dev`, `dev-<full-commit-sha>`
- 최소 GitHub permission: `contents: read`, `packages: write`, provenance용 OIDC/attestation
- public fork에서는 image-local dev signing key 생성 가능, 저장소 secret이 있으면 지속 signing key 사용

## 실제 검증 결과

### 성공

- `gofmt`
- `go test ./...`
- `go vet ./...`
- shell script 문법 검사
- Docker Compose config 검사
- GitHub Actions/source lock/images lock YAML parse
- `git diff --check`
- Linux amd64 정적 Agent binary build와 `-version` 실행
- Ubuntu 24.04 컨테이너에서 DEB 3종 실제 생성 및 control/file 검사
- Apache 모듈 DEB와 dependency 실제 설치 후 `apachectl configtest`: `Syntax OK`
- Nginx 모듈 DEB와 dependency 실제 설치 후 `nginx -t`: 성공, ModSecurity-nginx v1.0.3에서 CRS 847개 load 확인
- Ed25519 bundle manifest 서명과 artifact 3종 조립
- linux/amd64 Manager Docker image build
- 이미지 내부 bundle 확인: 같은 source commit, artifact 3개
- 검증용 임시 컨테이너는 확인 후 삭제함

### 실행하지 않은 검증

- 사용자 작업 규칙에 따라 실제 MariaDB를 초기화하거나 migration을 실행하지 않았다.
- 실행 중인 Manager가 없으므로 Admin UI browser 확인과 Manager-Agent-MariaDB 전체 runtime 통합은 수행하지 않았다.
- 프론트엔드 build/test는 수행하지 않았다. UI는 별도 프론트 빌드가 없는 서버 렌더링 template이다.
- 외부 상태를 변경하는 Git push, GHCR publish는 수행하지 않았다. `dev` 브랜치에 push되면 workflow가 이를 수행한다.
- 현재 `ghcr.io/fhwang0926/m-waf-manager:dev` 익명 조회는 403이다. 첫 workflow 게시 후 저장소 소유자가 GitHub Package settings에서 한 번 `Public`으로 전환해야 clone-to-deploy 익명 pull이 가능하다.
- 실제 호스팅 서버의 운영 트래픽 성능과 장시간 audit log rotation은 파일럿에서 별도 측정해야 한다.

## 현재 MVP 제한

- 지원: Ubuntu 24.04 amd64의 배포판 기본 Apache/Nginx exact build
- 미지원: Rocky/RPM, ARM64, custom webserver build
- 정책: 전체 CRS 편집 UI가 아니라 안전한 모드 전환만 구현
- 미지원: 서버 그룹, 서비스별 예외, RBAC, 2인 승인, Agent/module 원격 upgrade, HA
- Agent client certificate 자동 갱신은 후속 작업
- 운영 release는 ephemeral dev key를 금지하고 보호된 지속 signing key와 immutable image digest를 사용해야 함

## 주요 파일

- `README.md`
- `.github/workflows/dev-manager-image.yml`
- `deploy/compose/compose.yaml`
- `build/containers/manager/Dockerfile`
- `cmd/mwaf-manager/main.go`
- `cmd/mwaf-agent/main.go`
- `cmd/mwaf-bundle/main.go`
- `internal/manager/`
- `internal/agent/`
- `packaging/`
- `migrations/001_initial.sql`

## 후속 문서 개선

- 2026-08-06: `README.md`에 지원 웹서버 명세를 보강했다.
- 실제 MVP 기준은 Ubuntu 24.04 LTS amd64, Apache 2.4.58 또는 Nginx 1.24.0이다.
- 확인한 Ubuntu package revision, ModSecurity/Connector/CRS version을 표로 기록했다.
- 단순 표시 version뿐 아니라 정규화한 `-V` build hash까지 Manager 내장 manifest와 정확히 일치해야 한다는 설치 조건을 명시했다.
- Ubuntu security update로 build identity가 달라지면 새 `dev` Manager bundle을 빌드해야 하며, custom build와 다른 배포판은 설치 전에 거부한다는 경계를 명시했다.
