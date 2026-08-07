# M-WAF 원격 Manager E2E 설정 완료

## 기준 환경

- Admin UI: `https://192.168.7.200:18443`
- Agent 및 설치 API: `https://192.168.7.200:10443`
- 실행 중인 Admin `/health/ready`가 HTTP 200과 `ready`를 반환하고, `/servers`가 로그인 화면으로 이동하는 것을 확인했다.
- Agent API의 `/bootstrap/v1/install.sh`가 HTTP 200으로 응답하는 것을 확인했다.
- 실행 중인 서버 인증서의 SAN에 `192.168.7.200`이 포함된 것을 확인했다. 현재 로컬 체크아웃의 CA는 이 서버 인증서 발급 CA와 다르므로 원격 배포 서버의 실제 공개 CA를 사용해야 한다.

## 반영 내용

- 기존 `deploy/e2e/run.sh`에 이미 실행 중인 Manager를 대상으로 하는 원격 모드를 추가했다.
- 원격 모드는 Manager와 MariaDB를 새로 시작하거나 최초 관리자 설정을 수행하지 않고 Apache/Nginx 고객 컨테이너만 시작한다.
- 기존 시스템 관리자 자격 증명으로 로그인한 뒤 기업, 서버 그룹, 그룹 정책을 생성 또는 재사용하고 Agent 설치, 등록, 정책 `APPLIED`, 정상·예외 200, 차단 403, 관리자 이벤트 적재를 검증한다.
- Admin URL, Agent URL 및 Manager가 발급한 CA 인증서를 모두 필수 입력으로 검사하며 TLS 검증 우회는 허용하지 않는다.
- `make e2e-remote`, `make e2e-remote-verify`, `make e2e-remote-down`을 `192.168.7.200` 기준 기본값으로 추가했다.
- 원격 환경은 별도 Compose project와 runtime 경로를 사용해 기존 로컬 E2E Agent 상태와 볼륨을 재사용하지 않는다.

## 보안 및 데이터 경계

- 관리자 비밀번호는 명령행 인수로 받지 않고 환경 변수 또는 권한이 제한된 파일에서 runtime 파일로 복사한다.
- 서버의 실제 공개 CA 인증서만 고객 컨테이너에 전달하며 CA 개인키, Manager TLS 개인키 및 Docker socket은 전달하지 않는다.
- DB 초기화, reset 또는 직접 DB 작업은 수행하지 않는다.
- 원격 Manager에는 `mwaf-e2e` 이름의 기업, 그룹, 정책, 서버와 이벤트 기록이 생성 또는 재사용된다.

## 확인 범위

- `deploy/e2e/run.sh` POSIX shell 문법과 도움말 경로를 확인했다.
- 원격 URL 필수값, CA 파일 검증, 원격 최초 설정 차단 및 고객 컨테이너 전용 Compose 기동 경로를 정적으로 확인했다.
- 실행 중인 원격 Manager의 Admin readiness와 Agent bootstrap 응답을 확인했다.
- 실제 원격 CA와 시스템 관리자 자격 증명이 현재 로컬 작업 공간에 없어 전체 Agent 설치 및 정책·차단 E2E는 실행하지 않았다.
- 저장소 지침에 따라 프론트엔드 빌드와 테스트는 수행하지 않았다.
