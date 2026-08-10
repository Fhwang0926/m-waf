# Ubuntu LTS 18.04~26.04 지원 확장 완료

## 지원 범위

| 운영체제 | Agent 설치·등록·점검·업데이트 | 배포판 모듈 자동 설치 | 대체 경로 |
|---|---|---|---|
| Ubuntu 18.04 LTS | 지원 | Apache 지원 | Nginx exact-match 서명 모듈 |
| Ubuntu 20.04 LTS | 지원 | Apache 지원 | Nginx exact-match 서명 모듈 |
| Ubuntu 22.04 LTS | 지원 | Apache 지원 | Nginx exact-match 서명 모듈 |
| Ubuntu 24.04 LTS | 지원 | Apache/Nginx 지원 | exact-match 서명 커스텀 ZIP |
| Ubuntu 26.04 LTS | 지원 | Apache/Nginx 지원 | exact-match 서명 커스텀 ZIP |
| Debian 12 | 기존 지원 유지 | Apache/Nginx 지원 | exact-match 서명 커스텀 ZIP |

Ubuntu 26.04 LTS는 2026년 4월 23일 출시된 현재 최신 Ubuntu LTS다. Ubuntu 18.04·20.04·22.04는 공식 저장소에서 ModSecurity 2.9.x Apache 모듈을 제공하므로 Apache 자동 설치를 지원한다. 해당 버전의 Nginx ModSecurity Connector는 공식 배포판 패키지가 없어 별도 서명 모듈이 필요하다.

## 반영 내용

- Agent DEB metadata와 bootstrap 허용 대상을 Ubuntu 18.04, 20.04, 22.04, 24.04, 26.04 및 Debian 12 amd64로 확장했다.
- Agent 버전을 `0.3.0`으로 올리고 호환 범위와 롤백 경계를 릴리스 노트에 기록했다.
- Ubuntu 26.04용 Apache/Nginx distro·external module metadata와 공식 저장소 최소 패키지 버전을 추가했다.
- 로컬 서명 bundle 생성 대상과 릴리스 bundle 생성 대상을 동일한 OS 매트릭스로 맞췄다.
- 서버 설치 화면에 Ubuntu LTS 18.04~26.04 지원 등급을 표시하고, 서버 상세의 업그레이드 안내에 Ubuntu 26.04를 추가했다.
- 카탈로그 검증에서 Ubuntu 24.04·26.04는 Apache/Nginx 배포판 모듈을 해석하고 Ubuntu 18.04·20.04·22.04는 Apache 모듈만 해석하도록 시나리오를 추가했다.
- CI에 고정 digest Ubuntu 20.04·22.04 Agent 설치 검사와 Ubuntu 26.04 Apache/Nginx 설치·탐지·차단 검증 단계를 추가했다.
- 서명 bundle 예상 구성을 5개 물리 DEB, 21개 OS별 artifact metadata로 갱신했다.

## 확인

- 수정한 셸 스크립트의 구문 검사를 통과했다.
- Go 파일에 포맷을 적용했다.
- 전체 변경의 공백 오류를 확인했다.
- 로컬 Agent `0.3.0~dev.20260810135018.291e8245183d`와 모듈 DEB 4종을 생성했다.
- 서명 개발 bundle `dev-20260810135018-291e8245183d`를 생성하고 서명·catalog 검증을 통과했다.
- 기존 활성 로컬 bundle 확인은 변경 전 Agent-only 범위를 기준으로 수행했다. Apache 확장 반영 후에는 새 bundle 생성과 대상 OS 설치 확인이 필요하다.
- 기존 Ubuntu 18.04·24.04와 Debian 12 Agent의 0.2.1 rollback artifact 연결을 확인했다.
- 실행 중 Manager의 `https://192.168.7.10:8443/health/ready`가 새 bundle 반영 후 `ready`를 반환했다.
- 데이터베이스 조회·초기화·마이그레이션은 수행하지 않았다.
- 지침에 따라 Go 테스트, Docker CI, 프론트엔드 빌드는 수행하지 않았다.

## 공식 기준

- Ubuntu release cycle: https://ubuntu.com/about/release-cycle
- Ubuntu 26.04 LTS release notes: https://documentation.ubuntu.com/release-notes/26.04/
- Ubuntu package index: https://packages.ubuntu.com/
- OWASP CRS engine requirements: https://github.com/coreruleset/coreruleset/blob/main/crs-setup.conf.example
