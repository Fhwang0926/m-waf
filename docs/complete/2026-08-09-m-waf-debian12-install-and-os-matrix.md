# M-WAF Debian 12 설치 및 OS 테스트 매트릭스 완료

## 완료 범위

- 자동 설치 지원 대상을 Ubuntu Server 24.04 LTS amd64에서 Debian 12 Bookworm amd64까지 확장했다.
- Apache와 Nginx의 `distro` 및 `external` 통합 패키지를 두 운영체제에 대해 별도 서명 카탈로그 항목으로 게시하도록 DEB 메타데이터 생성을 확장했다.
- 실행 파일과 DEB 파일은 운영체제별로 중복 빌드하지 않는다. 같은 검증 파일을 사용하되 `os_id`와 `os_version`이 다른 불변 artifact 항목으로 등록해 Manager의 인벤토리 해석은 정확히 유지한다.
- Debian 12의 배포판 패키지 기준을 `packaging/sources.lock.yaml`에 기록했다.
  - Apache: `libapache2-mod-security2 >= 2.9.7-1`
  - Nginx: `nginx >= 1.22.0`, `libnginx-mod-http-modsecurity >= 1.0.3-1`
- Ubuntu 22.04는 공식 저장소에 Nginx ModSecurity Connector가 없어 이번 지원 범위에 포함하지 않았다.

## 설치 UX와 실패 방지

- 설치기는 토큰을 요청하기 전에 운영체제, amd64, 웹서버, APT/DPKG와 systemd 조건을 검사한다.
- 허용 대상은 `/etc/os-release` 기준 `ubuntu:24.04`와 `debian:12`로 제한한다. 그 외 환경에서는 패키지 다운로드나 설정 변경 전에 중단한다.
- Apache와 Nginx가 모두 설치된 대화형 터미널에서는 보호할 웹서버를 묻는다. 비대화형 자동화는 기존처럼 `--webserver apache|nginx`를 명시해야 한다.
- 관리자 화면의 복사 명령은 `curl`과 `base64`를 먼저 확인하고, root에서는 `sudo` 없이 실행하며 일반 계정에서만 `sudo`를 사용한다.
- 설치 환경 카드와 가이드는 Ubuntu 24.04 및 Debian 12 공식 DEB 지원을 함께 표시한다.

## 자동 검증 추가

- GitHub Actions가 고정 digest의 Ubuntu 24.04와 Debian 12 설치 fixture를 각각 만든다.
- 두 운영체제에서 다음 네 경로를 매번 검증하도록 추가했다.
  - Ubuntu 24.04 + Apache
  - Ubuntu 24.04 + Nginx
  - Debian 12 + Apache
  - Debian 12 + Nginx
- 각 경로는 새로 생성한 Agent와 통합 DEB를 설치하고 패키지 상태, Agent 버전, Connector 로드, 감사 로그 권한, `apachectl configtest` 또는 `nginx -t`를 확인한다.
- 서명 검증 bundle은 실제 파일 5개와 운영체제별 artifact 10개가 일치하는지 검사한다.
- 패키지 카탈로그 단위 테스트에 Ubuntu 24.04와 Debian 12의 Apache/Nginx 해석 및 Ubuntu 22.04 거부 시나리오를 추가했다.
- 컨테이너 E2E 고객 이미지가 매개변수화되었고 `make e2e-debian12`가 기존 Ubuntu 상태와 분리된 runtime/project로 전체 설치·등록·정책·이벤트 흐름을 실행한다.

## 호환성과 미수행 범위

- 기존 Ubuntu 24.04 artifact와 설치 URL, Agent API, 등록 토큰, 정책 bundle 형식은 변경하지 않았다.
- RPM 계열, ARM64, Ubuntu 22.04/26.04, Debian 12 이외 버전은 계속 지원하지 않는다.
- DB 스키마와 데이터는 변경하거나 초기화하지 않았다.
- 이번 작업에서는 실제 Docker fixture 빌드, DEB 설치, E2E, Go 테스트, 프론트엔드 빌드와 브라우저 실행을 수행하지 않았다. 이 검증은 변경된 GitHub Actions 또는 별도 요청으로 실행한다.

## 수행한 정적 검증

- 변경한 Go 테스트 파일 `gofmt`
- 설치·패키지·E2E shell 스크립트 `sh -n`
- CRS source lock과 GitHub Actions YAML 파싱
- `git diff --check`
