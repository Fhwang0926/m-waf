# M-WAF 컨테이너 배포 E2E 반영 완료

## 완료 범위

- 기존 Manager/MariaDB Compose를 재사용하는 `deploy/e2e/run.sh`를 추가했다.
- Ubuntu 24.04 Apache 및 Nginx 고객 환경을 systemd 컨테이너로 추가했다.
- E2E 실행 정보, 인증서와 관리자 인증정보를 운영용 `deploy/compose`가 아닌 `.local/mwaf-e2e`에 분리했다.
- 최초 시스템 관리자 설정, 기업 생성, 일회성 토큰 발급과 Agent 설치를 기존 HTTPS 화면/API로 수행하도록 했다.
- 두 Agent의 `ONLINE` 상태와 기업 범위 서버 그룹 구성을 확인하도록 했다.
- 그룹 WAF 정책을 배포하고 서버별 `APPLIED` 상태를 확인하도록 했다.
- 정상 요청 200, 예외 URL 200, 차단 URL 403 및 양쪽 서버의 차단 이벤트 수집을 확인하도록 했다.
- 실패 시 Compose 상태와 크기가 제한된 로그를 실행별 증적 디렉터리에 남기도록 했다.
- `make e2e`, `e2e-up`, `e2e-verify`, `e2e-status`, `e2e-logs`, `e2e-down` 명령을 추가했다.
- Compose 준비 스크립트가 선택적인 환경 파일과 비밀정보 디렉터리를 받을 수 있게 하되 기존 기본 경로 동작은 유지했다.

## 안전 경계

- DB에 직접 접속하거나 테스트 데이터를 임의로 삽입·초기화·리셋하지 않는다.
- `down`은 볼륨 삭제 옵션을 사용하지 않는다.
- Manager와 MariaDB는 privileged로 실행하지 않는다.
- systemd가 필요한 Apache/Nginx 테스트 컨테이너만 privileged로 실행하며 Docker 소켓과 Manager CA 개인키를 전달하지 않는다.
- 서버 재부팅·종료, Agent 중지, 패키지 업데이트·롤백은 자동 테스트하지 않는다.
- 비밀번호와 등록 토큰은 출력 및 증적 로그에서 제외한다.

## 검증 범위

- 소스 반영 후 셸 구문과 Compose 병합 설정을 정적으로 확인한다.
- 저장소 작업 규칙에 따라 컨테이너 이미지 빌드와 실제 E2E 실행은 수행하지 않는다.
- 실제 실행은 Linux amd64 전용 테스트 서버에서 태그 또는 digest로 고정한 Manager 이미지로 수행해야 한다.
