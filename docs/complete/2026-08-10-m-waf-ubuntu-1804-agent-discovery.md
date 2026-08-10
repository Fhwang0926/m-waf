# Ubuntu 18.04 Agent 선등록 지원 완료

## 변경 내용

- Agent DEB 대상과 웹서버 모듈 DEB 대상을 분리했다.
- Ubuntu 18.04 amd64에서는 의존성 없는 정적 `mwaf-agent` DEB의 설치, 서버 등록, 환경 점검만 허용한다.
- Ubuntu 18.04용 배포판 Apache/Nginx 모듈은 카탈로그에 생성하지 않는다. 보호 활성화에는 Agent가 확인한 웹서버 빌드 및 ABI와 정확히 일치하는 서명 커스텀 ZIP이 필요하다.
- Ubuntu 24.04 amd64와 Debian 12 amd64의 기존 Agent 및 모듈 패키지 지원은 유지했다.
- 설치 화면과 README, 커스텀 웹서버 설치 문서에 Agent 지원 범위와 모듈 지원 범위를 구분해 표시했다.
- 개발 bundle 및 GitHub Actions가 Ubuntu 18.04 Agent artifact는 1개, Ubuntu 18.04 모듈 artifact는 0개인지 검증하도록 했다.
- GitHub Actions에 고정된 Ubuntu 18.04 amd64 이미지의 Agent DEB 실제 설치·실행 검사를 추가했다.

## 검증 결과

- 전체 Go 테스트와 `go vet` 통과
- 변경된 셸 스크립트 구문 검사 통과
- 서명 개발 bundle 생성 및 검증 통과
- bundle manifest 확인: Ubuntu 18.04 Agent 1개, Ubuntu 18.04 모듈 0개, Ubuntu 24.04 전체 artifact 5개, Debian 12 전체 artifact 5개
- 깨끗한 `ubuntu:18.04` amd64 컨테이너에 실제 Agent DEB 설치, 버전 실행, 서비스 명령 존재 여부 확인 통과
- Agent 설치 과정에서 Apache 및 Nginx 경로가 생성되지 않은 것을 확인
- 실행 중인 Manager를 DB migration 없이 새 개발 bundle로 재시작하고 `/health/ready` 정상 응답 및 새 설치 스크립트 제공을 확인

## 수행하지 않은 검증

- 대화에 노출된 단기 등록 토큰은 사용하지 않았다. 새 토큰으로 실제 고객 컨테이너의 Manager 등록을 다시 수행해야 한다.
- Ubuntu 18.04용 ModSecurity 모듈 설치와 보호 동작은 지원 범위가 아니므로 수행하지 않았다.
- 프론트엔드 빌드는 프로젝트 작업 규칙에 따라 수행하지 않았다.
- DB 초기화, reset, schema migration은 수행하지 않았다.
