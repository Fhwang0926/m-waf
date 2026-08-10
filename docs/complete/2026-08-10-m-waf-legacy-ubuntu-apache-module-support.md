# 구형 Ubuntu Apache 모듈 자동 설치 지원 완료

## 변경 내용

- Ubuntu 18.04, 20.04와 22.04의 배포판 Apache를 Manager 모듈 자동 설치 대상으로 추가했다.
- Apache 모듈 DEB는 각 배포판 공식 저장소의 `libapache2-mod-security2` 2.9.x를 의존성으로 설치한다.
- Apache artifact는 `modsecurity-v2`, Nginx artifact는 `modsecurity-v3` ABI로 구분한다.
- 구형 Ubuntu에는 Apache 모듈 metadata만 생성하고, 공식 Connector가 없는 Nginx 모듈은 생성하지 않는다.
- 로컬 bundle과 릴리스 workflow의 artifact 기대값을 같은 지원 매트릭스로 맞췄다.
- 실행 불가능한 화면에서는 운영체제 업그레이드를 일반적인 해결책으로 권장하지 않고, 현재 환경과 일치하는 Manager 서명 모듈이 없다는 원인과 필요한 환경키만 표시한다.

## 지원 범위

| 운영체제 | Apache | Nginx |
|---|---|---|
| Ubuntu 18.04·20.04·22.04 | 배포판 모듈 자동 설치 | Manager exact-match 서명 모듈 필요 |
| Ubuntu 24.04·26.04 | 배포판 모듈 자동 설치 | 배포판 모듈 자동 설치 |
| Debian 12 | 배포판 모듈 자동 설치 | 배포판 모듈 자동 설치 |

## 정적 확인

- 수정한 셸 파일의 구문을 확인했다.
- 수정한 Go 파일에 `gofmt`를 적용했다.
- `git diff --check`에서 공백 오류가 없음을 확인했다.
- 로컬 서명 bundle `dev-20260810142222-291e8245183d`을 생성하고 활성화했다.
- 활성 bundle에서 Ubuntu 18.04·20.04·22.04 Apache `modsecurity-v2` 모듈 metadata를 확인했다.
- 실행 중인 Manager의 Ubuntu 18.04 / Apache 2.4.29 서버 상세 화면에서 일반적인 OS 업그레이드 안내가 사라지고 `배포판 패키지` 설치 선택과 실행 버튼이 표시되는 것을 확인했다.

## 수행하지 않은 검증

- 저장소 지침에 따라 Go 테스트, 대상 서버 Docker 설치 테스트와 프론트엔드 빌드는 수행하지 않았다.
- 대상 Ubuntu 컨테이너에 Apache 모듈을 실제 설치하지 않았다.
- DB 조회·변경·초기화는 수행하지 않았다.

## 별도 확인 필요

- Manager 시작 로그의 기존 CRS 원본 공급망 불일치 경고는 이번 모듈 지원 범위와 분리해 점검해야 한다. 활성 bundle의 Apache 설치 선택 화면은 정상적으로 제공된다.

## 공식 확인 자료

- Ubuntu 18.04 Apache ModSecurity 2.9.2 패키지: https://launchpad.net/ubuntu/bionic/amd64/libapache2-mod-security2/2.9.2-1
- Ubuntu 22.04 Apache ModSecurity 2.9.5 패키지: https://packages.ubuntu.com/jammy/libapache2-mod-security2
- Ubuntu Nginx ModSecurity Connector 제공 범위: https://launchpad.net/ubuntu/+source/libnginx-mod-http-modsecurity
- OWASP CRS 4 엔진 요구사항: https://coreruleset.org/20260511/migrating-crs-3-to-4-part-7-engines/
