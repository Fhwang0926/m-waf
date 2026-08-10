# M-WAF 커스텀 웹서버 제어 Hook 반영 완료

## 목적

호스팅사의 커스텀 Apache/Nginx 빌드와 기존 서비스 제어 wrapper를 사용할 수 있게 하되, Manager가 Agent에 임의 셸 명령을 전달하지 않도록 제한된 웹서버 제어 방식을 추가했다.

## 반영 내용

- 서버 상세의 설치 계획에서 다음 정책 재적용 방식을 선택할 수 있게 했다.
  - 표준 웹서버 제어
  - 고객 Hook 사용
- 표준 제어는 Agent가 발견하고 빌드 해시를 확인한 웹서버 바이너리에 고정 인자만 사용한다.
  - Apache: `-t`, `-k graceful`
  - Nginx: `-t`, `-s reload`
- 고객 Hook은 다음 고정 경로만 사용한다.
  - `/opt/m-waf/hooks/{apache|nginx}/configtest`
  - `/opt/m-waf/hooks/{apache|nginx}/reload`
- Agent는 Hook 실행 전에 파일과 상위 디렉터리의 유형, symlink 금지, root 소유, 실행 권한, group/others 쓰기 금지를 확인한다.
- Hook에는 제한된 환경값만 전달하고 명령 문자열, 인자, 파이프, `sudo`, 스크립트 본문은 Manager에서 받지 않는다.
- 선택한 제어 방식은 기존 패키지 배포 상세 필드의 내부 계획으로 저장한다. DB 스키마는 변경하지 않았다.
- Agent가 패키지 설치 후 선택을 `/opt/m-waf`가 아닌 기존 Agent 상태 위치의 `installation-selection.json`에 기록하고 heartbeat inventory에 보고한다.
- 패키지 업데이트·롤백과 시스템 정책 rollout에서도 기존 제어 방식을 유지한다.
- 설치 후에도 서버 상세에서 재설치 없이 표준 제어와 고객 Hook을 전환할 수 있게 했다.
- 운영 중 전환은 기존 Agent 고정 명령 채널의 두 내부 명령만 사용하며 셸 명령으로 전달하지 않는다.
- 배포 결과가 기록된 이후에도 내부 Hook 계획을 보존하고, 관리자 목록에는 사용자용 결과만 표시한다.
- 고객 설정 파일은 자동 수정하지 않는다. 운영자가 M-WAF 전용 설정을 include하면 Agent가 선택된 방식으로 configtest와 reload를 수행한다.
- 기존 제어 선택이 없는 Agent 상태는 `standard`로 처리해 하위 호환성을 유지한다.

## 문서

- `docs/custom-webserver-installation.md`에 표준 제어와 고객 Hook 준비, 권한 조건, 전달 환경, wrapper 예시와 실패 처리 방법을 추가했다.

## 검증

- `gofmt` 적용
- `git diff --check` 통과
- `go test ./internal/agent ./internal/manager` 통과
- `go test ./...` 통과
- 기존 설치 선택 파일의 기본값과 잘못된 제어 모드 차단 테스트 추가
- 패키지 배포 결과 기록 이후 Hook 선택 보존 테스트 추가
- 서버 상세 템플릿의 제어 방식, 고정 Hook 경로와 임의 명령 입력 부재 테스트 추가

## 수행하지 않은 작업

- DB init, reset, migration 실행 안 함
- 프론트엔드 빌드 안 함
- 실행 중인 Manager 재시작·교체 안 함
- 고객 Apache/Nginx 설정 수정 안 함
- 실제 `/opt/m-waf/hooks` 생성 및 root 권한 실행 안 함
- 실제 웹서버 configtest, reload, 패키지 설치 안 함

로컬 `make dev` watcher가 Manager 변경은 자동 재빌드한다. 고객 Hook 실행에는 새 Agent도 필요하므로 로컬 전체 개발에서는 `make dev-full`, 공개 환경에서는 새 release tag의 Manager/Agent bundle을 사용해야 한다.
