# M-WAF 커스텀 웹서버 통합 완료

## 완료 범위

- Ubuntu Server 24.04 amd64에서 호스팅사가 직접 관리하는 Apache/Nginx를 위한 `external` 통합 모드를 추가했다.
- 고객 서버에는 기존 원칙대로 `mwaf-agent`와 웹서버별 통합 패키지 하나만 설치한다.
  - Apache: `mwaf-modsecurity-apache-external`
  - Nginx: `mwaf-modsecurity-nginx-external`
- external 패키지는 Apache, Nginx, libmodsecurity 또는 Connector를 설치하거나 교체하지 않는다. OWASP CRS, M-WAF 정책 연결 파일, 로그 회전 설정과 사전진단 도구만 제공한다.
- 설치 스크립트에 웹서버 바이너리 절대 경로, 전용 include 경로, 감사 로그, 웹서버 group, 기존 ModSecurity 기본 설정과 reload 옵션을 추가했다.
- Agent가 커스텀 웹서버 바이너리로 inventory, configtest와 정책 reload를 수행하고 `integration_mode`를 Manager에 보고하도록 연결했다.
- Manager 패키지 catalog가 `distro`와 `external`을 분리해 올바른 통합 패키지만 제공하도록 했다. 빈 legacy 값은 기존 `distro`로 처리한다.
- 태그 릴리스 Manager 이미지에 Agent 1개와 Apache/Nginx의 distro/external 통합 패키지 4개, 총 5개 현재 버전 DEB를 포함하도록 번들 구성을 확장했다.
- 직전 릴리스 롤백 대상도 통합 모드별로 구분한다. 기존 3종 번들에서 처음 external 패키지가 추가되는 릴리스는 해당 신규 대상에 직전 패키지가 없어도 안전하게 생성할 수 있다.
- Manager 서버·대시보드 화면에서 보고된 통합 모드를 확인할 수 있게 했다.
- README, 소개 페이지, 제3자 고지와 별도 설치 가이드를 현재 지원 범위에 맞게 갱신했다.

## 설치 안전 경계

- `external` 설치는 Connector가 이미 로드된 경우에만 진행한다.
- 설치기는 고객 웹서버 바이너리, Connector와 주 설정 파일을 수정하지 않는다.
- 호스팅사가 미리 include 대상으로 만든 전용 설정 경로에 M-WAF 파일만 생성한다.
- 같은 경로에 M-WAF가 관리하지 않는 파일이 있으면 덮어쓰지 않고 중단한다.
- 설치 후 Apache/Nginx configtest와 실제 include 여부를 확인한다.
- 설정 검증에 실패하면 M-WAF가 관리하는 통합 설정, 엔진 설정과 로그 회전 설정을 직전 상태로 복원한다.
- Nginx Connector는 대상 Nginx 빌드와 호환되게 호스팅사가 준비해야 한다. M-WAF는 임의 ABI 조합을 자동 컴파일하거나 보장하지 않는다.

## GitHub Actions 자동 검증

- PR, `dev` push와 수동 실행에서는 빌드·설치·테스트만 수행하고 이미지를 게시하지 않는다.
- `vMAJOR.MINOR.PATCH` 태그 push에서만 검증을 통과한 Manager 이미지를 GHCR에 게시한다.
- Agent 1개와 통합 패키지 4개를 동일 commit에서 생성한다.
- distro Apache/Nginx 패키지를 깨끗한 Ubuntu 24.04 컨테이너에 설치해 모듈, CRS, configtest, 로그 권한을 확인한다.
- external Apache/Nginx 패키지는 배포판 웹서버 패키지 의존성이 `logrotate` 외에 없는지 확인하고, 사전 설치된 Connector를 비표준 절대 바이너리 경로로 재사용한다.
- 전용 include, Connector 탐지, configtest 후 웹서버를 실제 기동한다.
- 고정 시험 규칙으로 `/mwaf-ci-block` 요청이 `403`으로 차단되고 JSON 감사 로그가 생성되는지 확인한다.
- external 시험은 M-WAF 통합 계약을 검증하며 고객사의 모든 컴파일러, configure option과 ABI 조합을 대체하지 않는다.

## 사용 문서

- 기본 설치와 배포: `README.md`
- 커스텀 Apache/Nginx 준비, 설치 옵션, 명령 예제, 확인과 실패 처리: `docs/custom-webserver-installation.md`

## 후속 문서 보완

- DEB 설치는 최초 오류에서 중단하며 자동 수동복사 또는 unsigned archive fallback을 제공하지 않는다는 현재 동작을 명시했다.
- APT/DPKG 부분 설치 상태 확인, 오류 유형별 복구, 토큰 재사용 조건과 안전한 재시도 절차를 추가했다.
- 강제 설치, 웹서버 purge, 원인 확인 전 M-WAF 상태 삭제와 수동 바이너리 복사를 금지 복구 방식으로 기록했다.
- DEB를 사용할 수 없는 환경은 현재 미지원이며, 향후 portable 설치가 충족해야 할 서명·manifest·systemd·rollback 조건을 기록했다.

## 확인 결과

- 변경한 Go 파일 포맷 검사 완료
- Go 전체 단위 테스트 통과
- Go vet 통과
- 설치·패키징 shell 문법 검사 통과
- GitHub Actions YAML 파싱 통과
- 변경 파일 whitespace 검사 통과

## 실행하지 않은 항목

- 로컬 환경에 Docker daemon과 Debian 패키징 도구가 없어 컨테이너 기반 DEB 실제 설치 시험은 실행하지 않았다. 이 검증은 GitHub Actions에 추가했다.
- 저장소 규칙에 따라 프론트엔드 빌드와 브라우저 UI 시험은 수행하지 않았다.
- MariaDB 초기화, migration 적용, reset 등 DB 변경 작업은 수행하지 않았다.
- 실제 호스팅사 커스텀 빌드별 ABI 호환성은 각 운영 환경에서 설치 전 Connector 준비와 configtest로 확인해야 한다.
