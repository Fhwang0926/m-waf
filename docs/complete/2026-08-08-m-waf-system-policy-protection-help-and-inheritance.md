# M-WAF 시스템 정책 보호 설정 설명·상속 UX 개선 완료

## 완료 범위

- 시스템 정책 작성 3단계의 보호 모드, 요청·응답 본문 검사, Paranoia Level, 임계점수와 모든 고급 CRS 설정에 키보드 포커스를 지원하는 설명 툴팁을 추가했다.
- 고급 CRS 설정은 현재 정책 값을 기본 상속하고, 운영자가 `직접 변경`을 선택한 항목만 편집·전송하도록 변경했다.
- 최초 정책에는 검토된 CRS 기본값을 상속하고, 기존 정책 기반 새 버전에는 현재 게시 정책의 값을 유지하도록 구분했다.
- 허용 HTTP Method와 Content-Type은 원시 문자열 대신 일반 항목을 체크하는 방식으로 변경했다. 기타 값은 별도 입력할 수 있고 Content-Type은 내부에서 CRS의 `|값|` 형식으로 변환한다.
- 단일·전체 업로드 크기는 바이트 숫자와 `unlimited`를 모두 받을 수 있게 했다.

## 기본값·정책 생성 안전성

- `crs-setup.conf.example`의 주석 속 사용 예시를 upstream 기본값으로 오인하던 처리를 제거했다.
- Early Blocking 기본값은 `0`, 업로드 크기 기본값은 `unlimited`로 유지한다.
- 기존 MariaDB 인덱스는 데이터 수정 없이 조회 시 검토된 기본값으로 정규화한다. DB init, reset, 수동 데이터 변경은 수행하지 않았다.
- `unlimited`는 유효한 정책 설정으로 저장하되 ModSecurity `setvar`로 출력하지 않고 upstream의 무제한 상태를 상속한다.
- 전체 파일 제한이 단일 파일 제한보다 작거나, 단일 파일만 unlimited이고 전체 파일은 유한한 조합은 게시 검증에서 차단한다.

## 변경 파일

- `web/templates/system-policy-migration.html`
- `web/static/app.js`
- `web/static/app.css`
- `internal/crsindex/index.go`
- `internal/manager/store_crs_policy.go`
- `internal/manager/system_policy_migration_handlers.go`
- `internal/manager/policy_configuration.go`
- `internal/policybundle/bundle.go`
- 관련 단위 테스트 파일

## 확인 범위

- 변경된 Go 파일에 `gofmt`를 적용했다.
- 상속값과 직접 변경값이 하나의 `setup.<key>` 값만 전송하도록 템플릿·스크립트 경로를 정적으로 확인했다.
- 기존 인덱스 보정은 조회 시점에만 수행하며 DB 스키마와 Agent 프로토콜을 변경하지 않는 것을 확인했다.
- 현재 실행 중인 개발 Manager의 로그인된 `/system-policies/migrations/new` 화면을 새로 불러와 보호 설정 3단계를 확인했다.
- 보호 설정 툴팁 20개와 고급 설정 카드 13개가 렌더링되고, 모든 고급 항목이 기본 상속·편집 비활성 상태인 것을 확인했다.
- Early Blocking `0`, 단일·전체 파일 `unlimited`, CRS 구분자를 포함한 Content-Type 기본값을 확인했다.
- 허용 HTTP Method의 `직접 변경`을 켰을 때 편집 필드만 `setup.allowed_methods`로 전송되고, 해제하면 상속 hidden 필드로 복원되는 것을 확인했다.
- 해당 화면의 브라우저 오류 로그가 비어 있는 것을 확인했다.

## 수행하지 않은 검증

- 프로젝트 지침에 따라 프론트엔드 빌드와 자동 테스트는 실행하지 않았다.
- DB init/reset, 마이그레이션 실행, 데이터 갱신을 수행하지 않았다.
- Manager를 명시적으로 재시작하거나 새 이미지를 배포하지 않았다. 실행 중인 개발 감시 프로세스가 작업 트리 변경을 반영한 화면만 확인했다.
