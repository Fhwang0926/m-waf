# M-WAF 소개 페이지 제품 정보 보강

## 작업 목적

NAVER Cloud 공공기관용 DeepFinder 마켓플레이스의 제품 설명 구성을 참고해, 호스팅사 엔지니어가 M-WAF의 차별성, 보안 정책, 구성·구동 방식과 지원 웹서버·WAS 범위를 한 페이지에서 판단할 수 있도록 정리했다.

DeepFinder의 문구나 기능을 그대로 가져오지 않고 M-WAF 저장소에서 확인되는 구현 범위만 설명했다. 파일 위변조, 자동 보안 리포트, IIS·WAS 직접 설치와 같이 M-WAF MVP에 없는 기능은 제품 기능으로 표기하지 않았다.

## 반영 내용

- 상단 메뉴를 `차별성`, `보안 정책`, `구성·구동`, `지원 웹서버·WAS` 중심으로 재구성했다.
- 차별성 영역에 로컬 검사, 고객 서버 2개 패키지, 오픈소스 기반 self-hosted 중앙 운영을 명시했다.
- 보안 정책 영역에 다음 실제 운영 범위를 추가했다.
  - 검증된 OWASP CRS 소스와 불변 시스템 정책 버전
  - 탐지/차단, Paranoia Level, Inbound 점수, 요청 본문 검사
  - URL, IP/CIDR, Rule ID·Target 예외와 제한된 추가 Rule
  - 자동·수동·고정 전략, 카나리·확대 배포, configtest와 롤백
- 구성도와 설명에서 요청 처리 경로와 Agent의 발신 mTLS 관리 경로를 분리했다.
- Agent의 정책 polling, 서명 검증, 웹서버 설정 검사, 감사 로그 spool·batch 전송과 Manager 장애 시 마지막 성공 정책 유지 동작을 설명했다.
- 지원표를 운영체제, Apache, Nginx, WAS/Web application, Manager로 분리하고 현재 검증 버전과 적용 방식을 표시했다.
- WAS는 직접 설치·버전별 인증 대상이 아니라 지원 Apache/Nginx 뒤의 HTTP(S) 연동 범위라는 점을 명확히 했다.
- DeepFinder 비교표도 동일한 네 가지 판단 기준으로 축소해 M-WAF의 현재 MVP 범위와 공급사 공개 설명을 구분했다.

## 참고 자료

- NAVER Cloud 공공기관용 DeepFinder 마켓플레이스: <https://www.gov-ncloud.com/marketplace/deepfinder>
- DeepFinder 공급사 제품 소개: <https://www.deepfinder.co.kr/>
- DeepFinder 공개 구성 매뉴얼: <https://docs.deepfinder.co.kr/ko/operation/part1/Architecture/>
- M-WAF 지원 기준: `README.md`의 `Supported customer web servers and versions`
- M-WAF 시스템·기업 정책과 Agent 동작: `README.md`의 `Operate the MVP`, `System policy and CRS lifecycle`

## 확인 범위

- DeepFinder 마켓플레이스에 표시되는 제품 상세, 정책 레벨, Agent/Manager 구성과 웹서버·WAS 지원표를 브라우저에서 확인했다.
- 소개 페이지의 내부 링크 대상, 지원 버전 문구와 README 기준의 일치 여부를 정적으로 확인했다.
- HTML/CSS 프론트엔드 빌드와 별도 개발 서버 실행은 저장소 작업 규칙에 따라 수행하지 않았다.
- GitHub Pages 배포와 실제 공개 URL 반영은 이번 변경 범위에 포함하지 않았다.

## 변경 파일

- `site/index.html`
- `docs/complete/2026-08-07-m-waf-introduction-deepfinder-marketplace-sections.md`
