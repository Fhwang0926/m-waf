# 소개 페이지 최신화 및 Pages 배포

## 변경 목적

공개 GitHub Pages가 저장소의 최신 호스팅사 엔지니어용 소개 페이지보다 오래된 내용을 제공하고 있었다. 실제 기업 설치 토큰 자동등록 흐름과 현재 Manager 운영 기능을 기준으로 제품 설명을 정리하고, 모바일·검색·신뢰·배포 전환 정보를 보강했다.

## 반영 내용

- 서버 사전등록·일회용 토큰 설명을 기업 설치 토큰 기반 자동등록 흐름으로 교체했다.
- Manager에서 확인하는 서버, 정책 rollout, 보안 이벤트 항목을 샘플 화면 형태로 추가했다.
- 태그 릴리스, 자동 설치 검증, 패키지 서명과 GHCR 출처 링크를 추가했다.
- DeepFinder 공개 매뉴얼 비교는 유지하되 기본 접힘 상태의 참고 자료로 변경했다.
- Manager 배포 예시에서 특정 과거 버전을 제거하고 사용할 고정 버전 태그 확인 경로를 추가했다.
- 모바일 메뉴, 제목 줄바꿈, 배포 명령 overflow와 표 스크롤 안내를 보강했다.
- canonical, Twitter metadata, SoftwareApplication 구조화 데이터와 sitemap을 추가했다.
- 프로젝트 자체 라이선스는 임의로 선택하지 않았으며 제3자 사용 조건은 기존 고지 파일로 연결했다.

## 배포 범위

- `site/index.html`
- `site/assets/styles.css`
- `site/robots.txt`
- `site/sitemap.xml`
- 본 완료 문서

Manager, Agent, DB, 배포 Compose의 다른 작업 중 변경은 이번 Pages 커밋에 포함하지 않는다.

## 검증 경계

- HTML과 CSS 프론트엔드 빌드·테스트는 저장소 작업 지침에 따라 실행하지 않는다.
- `git diff --check`와 배포 후 실제 GitHub Pages의 데스크톱·모바일 렌더링을 확인한다.
