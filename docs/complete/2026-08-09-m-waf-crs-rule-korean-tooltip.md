# M-WAF CRS Rule 한글 설명 툴팁 반영 완료

## 작업 목적

CRS Rule 목록에서 영문 원문과 내부 제어 Rule만으로 용도를 파악하기 어려운 문제를 보완해 각 Rule의 역할을 한글로 빠르게 확인할 수 있게 했다.

## 반영 내용

- 모든 Rule ID 옆에 `한글 설명` 툴팁 버튼을 추가했다.
- 마우스를 올리거나 키보드 focus·클릭 시 같은 설명을 표시한다.
- Rule 설명은 다음 인덱스 정보를 조합해 서버에서 생성한다.
  - SQLi, XSS, RCE, LFI, RFI, SSRF, SSTI 등 공격 tag
  - 요청 파라미터, 쿠키, 헤더, URL, 업로드 파일, 응답 본문 등 검사 대상
  - phase별 요청·응답 처리 단계
  - CRS Setup 초기화, Paranoia Level 구간 제어와 이상 점수 판정
- 영문 메시지가 없는 초기화·제어 Rule도 `설명 없는 Rule`로 두지 않고 실제 역할을 설명한다.
- Rule API 응답에 `korean_description` 필드를 추가했다.
- 원본 영문 메시지, SecRule, 고정 commit 링크와 기존 검색 인터페이스는 유지했다.

## 확인 범위

- 초기 Setup 점검 Rule, Setup 기본값 초기화 Rule, SQL 삽입 Rule과 Paranoia Level 제어 Rule 설명 회귀 테스트를 통과했다.
- 서버 렌더링 템플릿에 한글 설명 툴팁과 접근성 연결 정보가 포함되는지 확인했다.
- 실행 중인 Manager의 CRS 4.25.1 Rule 901001 화면에서 툴팁 버튼과 한글 설명이 표시되고, 버튼 클릭 후 `role=tooltip`이 활성화되는 것을 확인했다.
- `gofmt`와 `git diff --check`를 통과했다.

## 수행하지 않은 검증

- 프로젝트 지침에 따라 프론트엔드 빌드와 프론트엔드 자동 테스트는 수행하지 않았다.
- DB init/reset, 스키마 변경과 데이터 변경은 수행하지 않았다.
- 실제 Agent 정책 게시와 배포는 수행하지 않았다.
