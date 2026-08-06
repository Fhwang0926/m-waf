# M-WAF 엔터프라이즈 소개 페이지 및 DeepFinder 비교 반영

## 작업일

- 2026-08-06

## 작업 목적

기존 GitHub Pages 소개 화면의 네온 그라데이션, 모의 콘솔, 과도한 영문 레이블을 정리하고 호스팅사 보안 제품 제안서에 가까운 엔터프라이즈 화면으로 개편했다. 소프트웨어 웹방화벽의 비교 기준으로 DeepFinder 공개 매뉴얼을 검토하여 M-WAF MVP의 공통점, 현재 차이, 다음 개발 과제를 함께 명시했다.

## 화면 개선

- 흰색·네이비 중심의 절제된 색상과 얇은 경계선, 표 기반 정보 구조로 변경
- 모의 터미널과 발광 효과를 제거하고 표준 운영 구성 요약 패널로 대체
- 한국어 중심의 제품 메시지와 전통적인 기업용 상단 내비게이션 적용
- 고객 웹서버, 로컬 검사·차단, outbound mTLS, 별도 Manager의 운영 경계를 구조도로 표현
- 지원 웹서버와 exact build match 조건을 유지하면서 가독성을 개선
- Compose 배포 흐름을 Clone, Configure, Deploy의 세 단계로 정리
- JavaScript와 추가 프론트엔드 라이브러리는 도입하지 않고 기존 정적 HTML/CSS만 사용

## DeepFinder 비교 반영

DeepFinder 공급사 공개 매뉴얼에서 확인 가능한 내용만 다음 기준으로 비교했다.

- 제품 접근 방식과 웹서버 설치 구조
- 요청 검사 위치와 Manager 역할
- 회사, 도메인 그룹, 도메인 단위 정책 구조
- 보안 패턴, 예외, 헤더, IP, URL, 업로드·파일 검사 정책
- 실시간 대시보드, 다차원 분석, PDF·Excel 보고서
- 역할 기반 접근 제어
- 공개 매뉴얼에 제시된 설치 유형
- 공급사가 설명한 이론상 1,000개 이상 Agent 관리 규모

비교표에는 DeepFinder의 기능·성능을 독립적으로 재현하거나 검증한 결과가 아니며 공급사 문서를 요약한 것임을 명시했다. M-WAF에는 부하 시험이 완료되지 않았으므로 다중 서버 용량 수치를 추가하지 않았다.

## 비교에서 도출한 우선 과제

1. 도메인·서버 그룹 정책과 정책 상속·예외·스냅샷
2. 공격 유형·IP·도메인 기준 분석과 정기 보고서
3. 1천·5천 Agent heartbeat 및 이벤트 burst 부하 시험
4. 인증서 갱신, Agent·모듈 업그레이드, Manager HA 운영 자동화

## 참고한 공개 자료

- DeepFinder 구성 및 특징: <https://docs.deepfinder.co.kr/ko/operation/part1/Architecture/>
- DeepFinder 정책관리: <https://docs.deepfinder.co.kr/ko/operation/part2/Policy/>
- DeepFinder 보안패턴: <https://docs.deepfinder.co.kr/ko/operation/part2/SecurityPattern/>

확인 기준일은 2026-08-06이며 제품 업데이트에 따라 공개 문서의 내용은 변경될 수 있다.

## 검증 범위

- `site/index.html`의 내부 section ID와 anchor 연결, 외부 자료 링크를 정적으로 확인
- 변경 파일의 공백 오류를 확인
- 프로젝트 규칙에 따라 프론트엔드 build, 로컬 웹서버 실행, 브라우저 렌더링 및 UI test는 수행하지 않음
- GitHub push와 Pages 배포는 수행하지 않음

## 변경 파일

- `site/index.html`
- `site/assets/styles.css`
- `README.md`
- `docs/complete/2026-08-06-m-waf-enterprise-introduction-and-deepfinder-comparison.md`
