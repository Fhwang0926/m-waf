# M-WAF 태그 설치·탐지·차단 CI 완료

## 변경 내용

- `.github/workflows/dev-manager-image.yml`의 tag trigger를 모든 Git tag로 확장했다.
- 모든 태그는 패키지 빌드와 설치 smoke 검사를 실행한다.
- 릴리스 게시 범위는 기존과 동일하게 `vMAJOR.MINOR.PATCH` 형식으로 제한한다.
- `v`로 시작하지만 SemVer가 아닌 태그도 smoke 검사 후 버전 검증 단계에서 실패하므로 릴리스되지 않는다.
- README 상단에 GitHub Actions 상태 배지를 추가하고, 태그별 실행 결과는 배지가 연결하는 Actions 화면에서 확인하도록 안내했다.

## Smoke 검사

공통 POSIX shell 검사기 `build/containers/ci-webservers/test-distro-smoke.sh`를 추가해 다음 네 조합에 동일한 검증을 적용한다.

- Ubuntu 24.04 + Apache
- Ubuntu 24.04 + Nginx
- Debian 12 + Apache
- Debian 12 + Nginx

각 조합에서 다음을 확인한다.

1. 새로 빌드한 Agent와 웹서버 통합 DEB 설치
2. Agent 실행 파일과 패키지 상태
3. ModSecurity Connector 로드 및 Apache/Nginx 설정 검사
4. `DetectionOnly` Rule과 일치한 요청이 HTTP 200으로 통과
5. 탐지 marker가 보호된 ModSecurity 감사 로그에 기록
6. 정책을 `On`으로 reload한 뒤 동일 방식의 차단 요청이 HTTP 403 반환
7. 차단 marker가 감사 로그에 기록

테스트는 CRS가 포함된 모듈 패키지에 의존하지 않고, CI 전용 최소 Rule을 `/etc/mwaf/active/main.conf`에 기록한다. 따라서 Agent·통합 패키지 설치, 정책 include, DetectionOnly, 차단과 감사 로그 연결을 짧은 경로로 검증한다.

## 호환성과 미수행 검증

- 기존 PR과 `dev` push 검증은 유지된다.
- 유효한 버전 태그의 서명 bundle 생성, 이미지 게시와 릴리스 승격 순서는 유지된다.
- DB migration, DB 초기화·reset, 프론트엔드 빌드와 브라우저 실행은 수행하지 않았다.
- 로컬에서는 shell/YAML 구문과 diff 형식만 확인한다. 실제 Ubuntu/Debian 컨테이너 설치·HTTP smoke 검사는 GitHub Actions가 수행한다.
