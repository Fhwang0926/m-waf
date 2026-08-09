# M-WAF CRS 동기화 rate-limit 복구 개선

## 문제

로컬 개발에서 코드 변경마다 Manager가 재시작되고 시작 시 LTS·Stable CRS 동기화를 반복하면서 GitHub 익명 REST API의 시간당 호출 한도를 소진했다. GitHub의 `403` 응답은 원인과 재시도 시각 없이 `502` 전체 오류 화면으로 표시되어 기존 CRS와 현재 시스템 정책까지 사용할 수 없는 것처럼 보였다.

## 반영 내용

- GitHub의 `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`과 `Retry-After` 헤더를 구조화된 `RateLimitError`로 해석한다.
- LTS 동기화에서 rate-limit을 확인하면 같은 요청의 Stable 동기화를 반복하지 않는다.
- 관리자 수동 동기화 실패 시 일반 오류 화면으로 이동하지 않고 `/open-source-policies`의 기존 CRS 목록을 다시 렌더링한다.
- rate-limit이면 HTTP `503`과 `Retry-After`를 반환하고 호출 한도 초기화 시각을 한국 시간으로 표시한다.
- 그 외 GitHub·네트워크 오류는 HTTP `502`를 유지하되 기존 검증 CRS와 시스템 정책이 계속 사용된다는 안내와 접힌 기술 정보를 표시한다.
- Admin JSON API도 rate-limit을 `503`과 `Retry-After`로 구분한다.
- 개발 live reload에서는 Manager 재시작 직후 CRS 동기화를 생략한다. 설정 주기와 시스템 관리자의 수동 동기화는 유지한다.
- 운영 모드에서는 기존처럼 Manager 시작 시 CRS 동기화를 수행한다.
- CRS 관리 화면에 GitHub 인증/익명 연결 여부와 개발 모드 동기화 동작을 표시한다.
- 프로세스 재시작 후 메모리의 마지막 동기화 시각이 사라져도 기존 CRS 검증 시각을 마지막 성공 기록의 대체값으로 사용한다.
- `make dev` 시작 시 토큰이 없으면 `deploy/compose/.env`의 `MWAF_CRS_GITHUB_TOKEN` 설정 방법을 안내한다. 토큰 값은 출력하지 않는다.

## 호환성

- 기존 CRS 저장소, 시스템 정책, 기업 정책과 Agent 적용 방식은 변경하지 않았다.
- 기존 `/open-source-policies`, 수동 동기화 POST와 Admin JSON API URL은 유지했다.
- DB migration, schema 변경과 데이터 쓰기 작업은 추가하지 않았다.
- 운영 환경의 시작 시·주기 동기화 기본 동작은 유지했다.

## 확인 범위

- GitHub rate-limit 헤더 파싱, 관리자 오류 표시와 `Retry-After`에 대한 테스트 소스를 추가했다.
- 변경한 Go 파일에 `gofmt`를 적용했다.
- Go 템플릿 파싱, Go 패키지·테스트 소스 로딩, shell 문법과 `git diff --check`를 정적으로 확인했다.

## 수행하지 않은 검증

- 저장소 지침에 따라 자동 테스트와 프론트엔드 빌드는 실행하지 않았다.
- 실제 GitHub 동기화, rate-limit 소진 재현과 로그인 후 브라우저 렌더링은 수행하지 않았다.
- DB migration, init/reset, Manager 수동 재시작, 시스템 정책 게시와 Agent rollout은 수행하지 않았다.
