# M-WAF 소개 페이지 오픈소스 WAF 비교 반영

## 작업 목적

호스팅사 엔지니어가 M-WAF의 차별성, 보안 정책, 구성·구동 방식과 지원 웹서버·WAS 범위를 이해할 수 있도록 제품 소개 페이지를 정리하고, 비교 대상은 상용 제품이 아닌 공개 오픈소스 WAF 프로젝트로 한정했다.

## 반영 내용

- 상단 메뉴를 `차별성`, `보안 정책`, `구성·구동`, `지원 웹서버·WAS` 중심으로 유지했다.
- 차별성 영역에 로컬 검사, 고객 서버 2개 패키지, 오픈소스 기반 self-hosted 중앙 운영을 명시했다.
- 보안 정책 영역에 검증된 CRS, 기업별 보호 수준과 예외, 단계 배포와 롤백 범위를 설명했다.
- 구성도에서 고객 요청 경로와 Agent의 발신 mTLS 관리 경로를 분리했다.
- WAS는 직접 설치·버전별 인증 대상이 아니라 지원 Apache/Nginx 뒤의 HTTP(S) 연동 범위임을 명시했다.
- 공개 프로젝트 비교를 다음 네 가지 대상으로 재구성했다.
  - M-WAF MVP
  - ModSecurity + OWASP Core Rule Set 직접 운영
  - BunkerWeb
  - OWASP Coraza
- 비교 항목을 검사·배치 방식, 정책 기반, 다중 서버 운영, M-WAF와의 구조적 차이로 제한했다.
- 공식 문서에서 확인되지 않은 성능, 탐지율, 처리량 우위는 표시하지 않았다.

## 비교 기준

- ModSecurity와 OWASP CRS는 M-WAF가 사용하는 검사 엔진과 기본 규칙이며 자체적으로 M-WAF의 기업·Agent·단계 배포 관리 계층을 제공하는 것으로 설명하지 않는다.
- BunkerWeb는 NGINX 기반 리버스 프록시 WAF이며 ModSecurity·CRS, Web UI, Scheduler와 DB를 포함하는 별도 보호 계층으로 구분한다.
- Coraza는 Go 기반 WAF 엔진·라이브러리로서 SecLang과 OWASP CRS v4를 지원하지만, 현재 M-WAF의 실행 엔진이나 배포 구성에는 포함되지 않는다.

## 참고한 공식 자료

- OWASP ModSecurity: <https://github.com/owasp-modsecurity/ModSecurity>
- OWASP Core Rule Set: <https://github.com/coreruleset/coreruleset>
- BunkerWeb: <https://docs.bunkerweb.io/>
- OWASP Coraza: <https://www.coraza.io/docs/>

## 확인 범위

- 소개 페이지에서 상용 WAF 제품명과 출처가 제거됐는지 정적으로 확인했다.
- 각 오픈소스 프로젝트 설명은 2026-08-07 기준 공식 저장소와 공식 문서의 공개 범위만 사용했다.
- 내부 링크 대상과 README 지원 버전의 일치 여부를 정적으로 확인했다.
- HTML/CSS 프론트엔드 빌드는 저장소 작업 규칙에 따라 수행하지 않았다.
- GitHub Pages 배포 후 공개 화면에서 비교표와 모바일 가로 스크롤을 별도로 확인한다.

## 변경 파일

- `site/index.html`
- `site/assets/styles.css`
- `README.md`
- `docs/complete/2026-08-07-m-waf-introduction-page-release.md`
- `docs/complete/2026-08-07-m-waf-introduction-open-source-waf-comparison.md`
