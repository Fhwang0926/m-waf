# M-WAF 기본 정책 + 기업 오버라이드 전송 구조 반영

## 완료 내용

- 기업 보호 정책의 운영 값을 `시스템 기본값 상속`과 `기업 직접 설정`으로 구분해 저장하도록 정리했다.
- 새 구조화 개정본은 OWASP CRS와 시스템 공통 설정을 담은 `policy-base-v1`과 기업 설정만 담은 `policy-override-v1`으로 분리해 서명한다.
- Manager가 기본 정책과 기업 오버라이드의 CRS identity, 시스템 공통 overlay, 최종 설정 digest를 비교하고 검증 식별자를 오버라이드 manifest에 기록하도록 했다.
- 시스템 조건부 예외의 내부 Rule ID를 먼저 고정하고 기업 조건부 예외 ID를 그 뒤에서 재할당해 두 계층 간 충돌을 차단했다.
- Desired State에 기본 정책과 오버라이드의 URL, 형식, SHA-256, 서명 및 합성 검증 정보를 추가했다.
- Agent가 두 artifact를 Manager에서 각각 내려받고 두 서명, SHA-256, base pin, override/effective digest, CRS source를 확인한 뒤 한 revision 디렉터리에 병합하도록 했다.
- 병합 후 기존과 동일하게 Apache/Nginx configtest, 원자적 활성화, reload 및 실패 시 rollback을 수행한다.
- 분리 형식을 지원하지 않는 구 Agent에는 새 형식의 정책을 배정하지 않도록 capability gate를 추가했다.
- 보호 정책 작성 화면에서 기본 정책 상속과 기업 오버라이드를 선택할 수 있게 했고, 상세 화면에 `기본 정책 + 기업 오버라이드 → Agent 최종 적용`과 백엔드 합성 검증 상태를 한 위젯으로 표시했다.
- 기존 `conf-v1`, `policy-bundle-v2`, 단일 `policy-bundle-v3` 개정본의 읽기·적용 호환 경로는 유지했다.

## 변경된 주요 경로

- `internal/policybundle`
- `internal/manager/policy_delivery.go`
- `internal/manager/policy_config.go`
- `internal/manager/policy_configuration.go`
- `internal/manager/store.go`
- `internal/agent/policy.go`
- `internal/model/model.go`
- `internal/protocol/agent_v1.go`
- `web/templates/policy.html`
- `web/templates/enterprise-policy.html`
- `web/static/app.js`
- `web/static/app.css`
- `docs/agent-protocol-v1.md`

## 확인 범위

- Go 파일 포맷을 정리했다.
- 변경 diff의 공백 오류를 정적으로 확인한다.
- 저장소 작업 규칙에 따라 프론트엔드 빌드, Go 테스트, DB 초기화·리셋·마이그레이션은 실행하지 않는다.
- 실제 Manager/Agent 재시작과 원격 웹서버 적용 검증은 별도 실행이 필요하다.
