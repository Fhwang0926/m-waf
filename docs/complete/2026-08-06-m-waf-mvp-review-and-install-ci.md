# M-WAF MVP 검토 및 자동 설치 검증 반영

## 작업일

- 2026-08-06

## 결론

기존 CI는 Go test와 DEB 생성까지만 수행하고 실제 고객 환경 설치 결과를 확인하지 않은 채 Manager 이미지를 게시했다. 이번 작업에서 `verify`와 `publish` job을 분리하고, 깨끗한 Ubuntu 24.04 amd64 컨테이너 두 개에 Agent+Apache 모듈과 Agent+Nginx 모듈을 각각 실제 설치하는 검증을 게시 전 필수 조건으로 추가했다.

검토 중 bootstrap installer가 다운로드한 DEB를 `.pkg` 확장자로 저장하여 Ubuntu `apt-get`이 아래 오류로 거부하는 문제를 실제 재현했다.

```text
E: Unsupported file /tmp/agent.pkg given on commandline
```

다운로드 파일명을 `mwaf-agent.deb`, `mwaf-module.deb`로 변경했다.

## GitHub Actions 변경

### 읽기 전용 검증 job

- 관련 pull request, `dev` push, 수동 실행에서 동작
- 권한은 `contents: read`만 사용
- Go test와 vet, shell 문법, Compose config 검사
- Linux amd64 Agent와 DEB 3종 생성
- OWASP CRS v4.28.0 archive SHA-256 검증
- 고정한 Ubuntu 24.04 image digest에서 Apache/Nginx 설치 검증
- 설치된 웹서버 version과 정규화 build hash가 생성 metadata와 정확히 일치하는지 검증
- Agent 실행 파일, ModSecurity module load, 원본 CRS, `DetectionOnly` 정책, 감사 로그 권한 확인
- Apache `configtest`, Nginx `-t` 실행
- pull request에서는 임시 Ed25519 key로 bundle을 조립하고 Manager Docker image build까지 확인
- 검증된 `dist/packages`, `dist/metadata`만 3일 workflow artifact로 전달

### 게시 job

- `verify` 성공 후 `dev` push/수동 실행에서만 동작
- pull request에서는 job 자체가 실행되지 않음
- `packages: write`, `attestations: write`, `id-token: write`는 게시 job에만 부여
- 검증 job에서 만든 동일 DEB를 받아 bundle을 다시 서명
- GHCR `:dev`, `:dev-<full-commit-sha>` 게시 및 provenance 생성
- 모든 외부 Action을 공식 release의 full commit SHA로 고정

### Pages workflow

- Checkout, configure-pages, upload-pages-artifact, deploy-pages를 Node 24 기반 공식 release SHA로 갱신
- 기존 Node 20 deprecation 경고 제거 대상 반영

## 현재 MVP에서 우선 개선이 필요한 항목

| 우선순위 | 항목 | 현재 위험 | 다음 조치 |
|---|---|---|---|
| P0 | MariaDB migration 실패 복구 | migration SQL이 여러 문장을 실행한 뒤 마지막에 version을 기록하므로 중간 실패 시 재실행이 중복 column/constraint에서 다시 실패할 수 있음 | migration별 재실행 안전성 또는 명시적 상태/복구 절차 추가 |
| P0 | Agent 인증서 갱신 | Agent 인증서는 90일인데 rotate API와 자동 갱신이 없어 만료 후 전체 통신이 중단됨 | 만료 전 CSR rotation, 폐기/재발급, 관리자 상태 표시 구현 |
| P0 | 고객 audit log rotation | `/var/log/modsecurity/audit.jsonl` 회전 정책과 inode 추적이 없어 디스크 증가 또는 logrotate 후 이벤트 건너뜀 가능 | logrotate package와 inode/device 기반 cursor 구현 |
| P1 | 이벤트 회수 처리량 | Agent는 heartbeat 주기마다 신규 500건만 읽어 기본값 기준 서버당 약 16.7건/초로 회수가 제한됨 | 전송 loop 분리, bounded 연속 batch, 지수 backoff와 처리량 계측 |
| P1 | 전체 수직 통합 검증 | 현재 자동화는 DEB 설치와 웹서버 설정까지이며 Manager→등록→mTLS→정책→감사 이벤트→MariaDB 흐름은 자동화되지 않음 | 승인된 일회성 DB/Manager 통합 환경에서 별도 end-to-end job 추가 |
| P1 | Manager/RBAC 회귀 검증 | Manager handler/store와 기업 격리/RBAC에는 자동화된 test가 없음 | 기업 간 접근 거부, setup race, role별 API test 추가 |
| P1 | 실제 부하 검증 | MariaDB pool과 batch insert는 구현됐지만 여러 Agent의 heartbeat/event burst 수치는 측정되지 않음 | 1천/5천 Agent 시나리오와 이벤트 burst 기준 정의 및 측정 |
| P1 | Bootstrap API abuse 방지 | 등록 token은 짧게 만료되고 package allowlist가 있으나 resolve/download 속도 제한은 없음 | IP/token rate limit, byte quota, 실패 감사 추가 |
| P2 | Agent 권한 축소 | Agent가 웹서버 reload를 위해 root로 상시 실행되고 systemd hardening이 최소 수준임 | 보호 옵션 강화 후 reload 전용 최소 권한 helper 검토 |
| P2 | 대규모 운영 UI/API | 서버·이벤트 조회가 최근 500건 고정이고 metrics endpoint가 없음 | cursor pagination, Prometheus 호환 핵심 지표 추가 |
| P2 | 지원 버전 문서 동기화 | README의 Ubuntu package revision은 security update 후 bundle과 달라질 수 있음 | bundle manifest에서 지원 matrix를 생성하거나 CI drift 검사 추가 |

## 이번 검증 범위

### 성공

- 기존 dirty worktree를 보존한 상태에서 `go test ./...` 성공
- `go vet ./...` 성공
- shell script 문법 검사 성공
- 변경 후 GitHub Actions YAML parse와 `git diff --check` 성공
- Docker Compose config 검사 성공
- Ubuntu 24.04 컨테이너에서 `.pkg` 이름의 DEB 설치 실패 재현
- 기존 로컬 DEB를 깨끗한 Ubuntu 24.04 컨테이너에 설치하여 Apache module load와 `apachectl configtest` 성공
- 별도 깨끗한 컨테이너에서 Nginx module/CRS 847개 load와 `nginx -t` 성공
- 두 설치 환경에서 Agent binary, CRS version/file, 감사 로그 소유권과 mode 확인 성공

### 실행하지 않음

- 프로젝트 규칙에 따라 MariaDB 초기화, reset, migration 실행은 하지 않음
- 프론트엔드 build와 browser UI test는 하지 않음
- GitHub push, 실제 Actions 실행, GHCR publish는 하지 않음
- 로컬 `dist/metadata`는 과거 검증용 더미 build hash를 포함하므로 새 workflow의 동일-run metadata exact-match는 GitHub Actions 실행 전까지 미확인
- 전체 Manager/Agent/MariaDB runtime 통합과 운영 부하 시험은 하지 않음

## 주요 변경 파일

- `.github/workflows/dev-manager-image.yml`
- `.github/workflows/pages.yml`
- `internal/manager/bootstrap-install.sh`
- `README.md`
- `docs/complete/2026-08-06-m-waf-mvp-review-and-install-ci.md`

## 후속 개선

이 문서에서 확인한 인증서 갱신, 감사 로그 회전, 이벤트 회수량, migration 재실행, Bootstrap rate limit과 RBAC 회귀 검사는 같은 날 후속 작업으로 반영했다. 또한 `dev` image 자동 게시 정책을 폐기하고 `vMAJOR.MINOR.PATCH` tag에서만 Manager image를 생성·게시하도록 변경했다.

- 후속 완료 문서: [`2026-08-06-m-waf-agent-hardening-and-tag-release.md`](2026-08-06-m-waf-agent-hardening-and-tag-release.md)
