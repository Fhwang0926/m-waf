# M-WAF CRS 상세 서버 렌더링 탭 반영 완료

## 작업 목적

CRS 상세의 출처, Rule, Setup, 변경 비교와 적용 준비 정보를 한 페이지에 모두 출력하지 않고 필요한 정보만 탭 단위로 확인하도록 개선했다.

## 반영 내용

- CRS 상세를 `개요`, `Rule Set`, `CRS Setup`, `변경 비교`, `적용 준비` 탭으로 구분했다.
- 탭은 화면에서 섹션을 숨기는 방식이 아니라 `?tab=` 조회 파라미터를 사용하는 서버 렌더링 방식으로 구성했다.
- 선택한 탭의 패널 하나만 HTML에 출력한다.
- 잘못되거나 없는 탭 값은 `개요`로 정규화한다.
- Rule 검색 폼과 이전·다음 페이지 URL은 `tab=rules`와 기존 검색 조건을 유지한다.
- Rule 목록은 Rule 탭 또는 기존 Rules API 요청에서만 필터링·페이지 구성한다.
- CRS Setup 목록은 Setup 탭에서만 상세 데이터에 포함한다.
- 현재 CRS와의 Rule·Setup 차이는 변경 비교 탭을 열었을 때만 계산한다.
- 기존 CRS 상세·Rule·diff API와 시스템 오버라이드 작성 URL은 유지했다.
- 기존 앵커 탭용 CSS를 제거하고 현재 탭에만 기존 관리 콘솔 스타일의 활성 상태를 적용했다.
- 상세 상단에서는 시스템 오버라이드 작업 버튼을 제거하고 `CRS 목록으로 돌아가기`만 표시한다.
- 시스템 오버라이드 작업이 필요한 경우 `적용 준비` 탭 안에서만 제공한다.

## 탭 URL

- `/open-source-policies/{source_id}?tab=overview`
- `/open-source-policies/{source_id}?tab=rules`
- `/open-source-policies/{source_id}?tab=setup`
- `/open-source-policies/{source_id}?tab=diff`
- `/open-source-policies/{source_id}?tab=readiness`

## 확인 범위

- 변경한 Go 파일과 추가한 테스트 파일에 `gofmt`를 적용했다.
- Rule 페이지 URL이 탭과 필터를 보존하는 회귀 테스트를 추가했다.
- 템플릿이 선택한 패널 하나만 출력하고 기존 앵커 탭을 포함하지 않는 회귀 테스트를 추가했다.
- `git diff --check`로 공백 오류가 없음을 확인했다.

## 수행하지 않은 검증

- 프로젝트 지침에 따라 프론트엔드 빌드와 자동 테스트는 실행하지 않았다.
- DB init/reset, 마이그레이션과 데이터 변경은 수행하지 않았다.
- 현재 브라우저 세션에 시스템 관리자 로그인이 없어 실제 탭 전환 화면은 확인하지 못했다.
- Manager 재시작과 배포는 수행하지 않았다.
