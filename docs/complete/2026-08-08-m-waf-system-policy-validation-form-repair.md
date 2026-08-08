# M-WAF 시스템 정책 검증 폼·기준 오류 표시 개선 완료

## 원인

- 시스템 정책 검증 화면은 브라우저의 `FormData`를 사용해 `multipart/form-data` 요청을 전송했다.
- Manager 검증 API는 Go 표준 `Request.ParseForm`을 사용하므로 multipart 본문을 읽지 않았고, `expected_system_policy_id`를 포함한 폼 값이 빈 값으로 처리됐다.
- 현재 정책이 존재하는 상태에서 기준 정책 값이 비어 들어가면서 실제 동시 게시가 없는데도 “다른 관리자가 최초 시스템 정책을 게시했습니다” 오류가 발생했다.
- 해당 오류는 hidden 필드에 연결되어 단계 배지에는 오류 수가 표시됐지만 1단계 본문에는 원문이 보이지 않았다.

## 반영 내용

- 검증 API 요청 본문을 표준 `application/x-www-form-urlencoded` 형식으로 변경했다.
- 기존 CSRF 헤더, 검증 digest, 서버 동시성 검증 구조는 유지했다.
- `expected_system_policy_id`, `source_id` 같은 hidden 기준 필드에서 오류가 발생하면 1단계에 오류 원문을 표시한다.
- 기준 충돌 화면에 `최신 기준으로 다시 열기`, `CRS 소스 선택` 후속 동작을 추가했다.
- 오류를 다시 검증할 때 이전 기준 오류 메시지와 목록을 정리하도록 처리했다.
- URL-encoded 요청에서 기준 정책과 CRS 소스가 보존되는 회귀 테스트를 추가했다.

## 변경 파일

- `web/static/app.js`
- `web/static/app.css`
- `web/templates/system-policy-migration.html`
- `internal/manager/system_policy_ui_test.go`

## 확인 범위

- 변경된 Go 테스트 파일에 `gofmt`를 적용했다.
- `git diff --check`와 변경 파일의 공백 검사를 수행했다.
- 현재 실행 중인 개발 Manager의 별도 검증 화면에서 기준 정책 `crs-baseline@1.0.0`과 선택한 CRS 소스가 유지되는 것을 확인했다.
- 5단계까지 이동해 검증 요청을 실행했고 `validationState=valid`, 검증 digest 생성, `게시 가능` 안내를 확인했다.
- 기존 오탐 문구인 “다른 관리자가 최초 시스템 정책을 게시했습니다”가 화면에 없고, 브라우저 콘솔 오류도 없는 것을 확인했다.
- 실제 기준 정책 또는 CRS 소스 충돌 시 1단계에 표시되는 안내 영역은 템플릿·스크립트 연결까지만 확인했으며, 운영 데이터를 변경하는 충돌 재현은 수행하지 않았다.

## 수행하지 않은 작업

- 프로젝트 지침에 따라 프론트엔드 빌드와 자동 테스트는 실행하지 않았다.
- DB init/reset, 마이그레이션, 데이터 수정은 수행하지 않았다.
- 정책 게시와 Agent 배포는 수행하지 않았다.
