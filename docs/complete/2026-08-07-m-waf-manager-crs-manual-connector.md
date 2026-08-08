# Manager CRS 연동과 수동 Connector 지원 완료

## 완료 범위

- 예약 GitHub Action 기반 CRS 발견을 제거하고, 시스템 관리자용 **오픈소스 CRS** 화면과 Manager 주기 작업에서 공식 `coreruleset/coreruleset` stable v4를 연동하도록 변경했다.
- Manager는 GitHub가 검증한 annotated tag, 정확한 commit, commit 기준 아카이브 SHA-256, Rule 인덱스와 CRS Setup을 검사한다. 가져온 아카이브·인덱스·서명 manifest는 artifact 저장소에 원자적으로 보존한다.
- 최초 시스템 관리자 설정 후 CRS 연동 화면으로 이동한다. 수동 확인과 `MWAF_CRS_SYNC_INTERVAL` 주기 확인은 소스만 추가하며 시스템 정책을 자동 게시하거나 기업에 자동 전파하지 않는다.
- 신규 마이그레이션은 upstream `crs-setup.conf`, `rules/`와 라이선스를 수정하지 않은 채 포함하는 서명 `policy-bundle-v3`를 만든다. 기존 `conf-v1`과 package 연동 `policy-bundle-v2`는 계속 읽고 적용한다.
- Agent inventory에 설치 방식, Connector 버전·로드 상태, 웹서버 configtest 상태와 지원 정책 형식을 선택 필드로 추가했다. 기존 Agent는 필드가 없어도 legacy package 경로를 유지한다.
- 설치 스크립트에 `--module-install manual`을 추가했다. 이 방식은 `external` 통합에서 기존 Apache/Nginx ModSecurity Connector를 확인하고 M-WAF Agent DEB와 전용 include만 설치한다.
- 수동 Connector 서버의 v3 정책 게시 호환성은 M-WAF 모듈 패키지 유무가 아니라 Agent v3 지원, Connector 로드, configtest 성공으로 판정한다. Manager의 모듈 패키지 업데이트·롤백 명령은 수동 서버에서 차단한다.
- Agent API는 기존 단일 HTTPS listener와 Agent 발신 polling 구조를 유지했다. 신규 wire 필드는 optional이며 기존 endpoint와 DB schema는 변경하지 않았다.

## 검증

- `gofmt` 적용
- 변경된 설치 스크립트 `sh -n` 통과
- `git diff --check` 통과
- `go test ./internal/crsindex ./internal/crssource ./internal/policybundle ./internal/agent ./internal/manager ./internal/packages ./internal/config ./internal/protocol ./internal/systempolicy` 통과 (`GOCACHE`는 작업용 임시 경로 사용)

## 미검증 및 운영 확인

- 프로젝트 규칙에 따라 프론트엔드 빌드와 브라우저 UI 시험은 실행하지 않았다.
- 외부 GitHub 연결, 실제 서명 태그 응답과 아카이브 다운로드는 네트워크가 필요한 운영 환경에서 **최신 CRS 확인**으로 확인해야 한다.
- 실제 커스텀 Apache/Nginx Connector 조합의 설치·configtest·reload는 대상 서버에서 확인해야 한다. 수동 방식도 Agent는 Ubuntu 24.04 amd64 DEB를 사용하며 Agent portable/RPM 설치는 이번 범위가 아니다.
