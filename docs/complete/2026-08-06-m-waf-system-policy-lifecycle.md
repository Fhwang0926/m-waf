# M-WAF 시스템 정책·기업 정책 분리 및 수명주기 반영

## 결론

시스템 정책과 기업 정책을 별도 수명주기로 분리했다. 시스템 정책은 GitHub에서만 유지·검증·게시되는 불변 버전 카탈로그이며 Manager 화면은 조회 전용이다. 기업 정책은 게시된 시스템 정책 버전을 채택하고 기업 대상, 동작 모드, URL/IP 예외, 검증된 사용자 규칙과 업데이트 전략을 소유한다.

최초 보호 서버에는 최신 기본 `DetectionOnly` 시스템 정책을 기반으로 기업 기본 정책을 한 번 생성하고 단계 배포한다. 초기 전략은 `MANUAL`이다. 이후 업데이트 적용, 실패 재시도와 직전 성공본 롤백은 해당 기업의 기업 사용자·기업 관리자 또는 전체 범위의 시스템 관리자가 결정한다.

## 1. GitHub 시스템 정책 카탈로그

- `internal/systempolicy/catalog.json`에 정책 키별 현재 버전과 `PUBLISHED`, `DEPRECATED`, `WITHDRAWN` 상태를 기록한다.
- `internal/systempolicy/templates/*.json`은 기존 버전을 덮어쓰지 않는 불변 템플릿이다. Manager는 원문 SHA-256이 이미 동기화된 버전과 달라지면 동기화를 거부한다.
- `system_policy_versions`는 템플릿 digest, CRS 버전, Manager source commit, migration 안내와 채택 기업/서버 집계의 기준을 저장한다.
- 시스템 관리자 UI는 버전과 상태를 조회할 수 있지만 생성·편집·게시 동작은 제공하지 않는다.
- 일일 GitHub Actions는 공식 `coreruleset/coreruleset` 안정 릴리스 중 GitHub가 서명을 검증한 annotated tag만 선택하고, archive SHA-256·source lock·새 템플릿 버전·수명주기 카탈로그를 함께 변경하는 PR을 만든다. PR을 병합하거나 고객 서버에 직접 적용하지 않는다.

## 2. 기업 정책과 기존 데이터 전환

- `enterprise_policies`는 기업, 이름, 대상, 시스템 정책 키와 현재 버전, 현재/직전 성공 개정본, `MANUAL`·`AUTOMATIC`·`PINNED` 전략을 관리한다.
- `policy_revisions`는 기업 정책, 시스템 정책 버전, 부모 개정본과 생성 원인을 연결한다. 기업 설정이 포함된 서명 artifact는 계속 불변으로 유지한다.
- 신규 기업 정책은 `PUBLISHED` 시스템 정책을 기반으로만 생성한다. 독립 정책 생성 경로는 관리자 화면에서 제거했다.
- 기존 `system-seed`는 기업 기본 정책과 `MANUAL`로, 관리자 `auto_update=true`는 `AUTOMATIC`, `false`는 `PINNED`로 변환한다.
- `migrated_from` 체인은 하나의 기업 정책 개정 이력으로 연결한다. 시스템 템플릿 출처나 유효 대상을 확인할 수 없는 정책은 `LEGACY_LOCKED` 읽기 전용으로 보존한다.
- `LEGACY_LOCKED` 정책은 현재 기업 설정을 보존하면서 최신 기본 시스템 정책 기반 개정본으로 명시적으로 전환할 수 있다.

## 3. 승인 전략과 동시성 보호

- `MANUAL`: 새 시스템 버전의 불변 기업 개정본과 rollout을 준비하고 `AWAITING_APPROVAL`에서 대기한다.
- `AUTOMATIC`: 새 버전이 게시되면 `QUEUED` rollout을 시작한다.
- `PINNED`: 새 버전 정보만 표시하고 rollout을 만들지 않는다. 대기 중인 수동 승인 rollout은 전략을 `PINNED`로 변경하면 취소한다.
- 전략 변경, 승인, 재시도, 전환과 롤백은 CSRF 및 기업 범위 검사를 거치고 관리자 감사 로그를 남긴다.
- 모든 변경 요청은 화면에 표시된 현재 개정본을 함께 제출한다. 서버의 현재 개정본이나 rollout 상태가 달라졌으면 `409 Conflict`로 중복·지연 요청을 거부한다.

## 4. 단계 배포와 CRS 연계

- `policy_rollouts`와 `policy_rollout_targets`가 초기 시드, 업데이트, 롤백, 자동 복구의 승인자·이전/목표 버전·서버별 단계를 기록한다.
- 온라인 서버 한 대를 canary batch `0`으로 선택하고 성공한 뒤 최대 25대 단위로 확대한다. 최초 canary가 오프라인이면 다음 온라인 서버와 batch 위치를 교환한다.
- 오프라인 서버는 이전 진행 단계를 보존한 `DEFERRED`로 남고 온라인 서버 진행을 막지 않는다. 다시 연결되면 중단한 단계부터 재개한다.
- 한 서버라도 실패하면 남은 배포를 `PAUSED`로 전환한다. 재시도는 기존 rollout을 다시 사용하며 중복 요청은 거부한다.
- CRS 변경 전 최소 서명 `DetectionOnly` 전환 정책을 적용하고 Agent의 정책 적용 결과와 다음 heartbeat를 확인한다.
- 이후 목표 CRS가 포함된 서명 Agent/module 패키지를 배포하고 package `APPLIED`와 heartbeat의 CRS 버전을 함께 확인한다.
- 마지막으로 기업 설정과 예외를 보존한 목표 개정본을 적용하고 policy `APPLIED`와 다음 heartbeat의 개정본 일치를 확인해야 서버 rollout이 완료된다.
- 대상 충돌은 `서버 > 그룹 > 기업 기본 정책` 순서로 계산하고 새 정책 및 전환 rollout도 실제 승자 서버만 대상으로 한다.

## 5. 직전 성공본 롤백과 자동 복구

- 기업 정책은 완료된 rollout의 현재 개정본과 직전 성공 개정본 한 개를 유지한다.
- 기업 사용자의 롤백은 직전 성공 정책과 그 시스템 정책이 요구하는 호환 Agent/CRS 패키지를 하나의 staged rollout으로 복구한다.
- 목표 시스템 정책이 `WITHDRAWN`이거나 호환 패키지가 현재 서명 bundle에 없으면 롤백 시작을 차단한다.
- 자동 업데이트 중 이미 변경된 canary 또는 batch 서버에서 실패하면 원래 성공 개정본으로 `RECOVERY` rollout을 자동 생성한다.
- 복구용 CRS 패키지가 없으면 최소 `DetectionOnly` 전환 상태를 유지한 채 rollout을 `PAUSED`로 남기고 운영 상세 사유를 표시한다.

## 6. 데이터 변경

- 전진형 migration `006_policy_domains_and_rollouts.sql`을 추가했다.
- 신규 테이블: `system_policy_versions`, `enterprise_policies`, `policy_rollouts`, `policy_rollout_targets`.
- 기존 `policy_revisions`에는 기업 정책·시스템 정책·부모 개정본·생성 원인 연결을 추가했다.
- 기존 정책/패키지 deployment에는 `rollout_id` 연결을 추가했다.
- migration은 실제 DB에 적용하지 않았으며 DB 초기화·reset·데이터 삭제도 수행하지 않았다. 기존 데이터 변환은 migration 이후 Manager의 멱등 동기화 과정에서 전진형으로 수행된다.

## 7. 확인 범위

- 변경한 Go 파일에 `gofmt`를 적용했다.
- JSON 카탈로그 대응, GitHub Actions YAML 파싱, 템플릿 블록, SQL 구문 구조 및 `git diff --check`를 정적으로 확인했다.
- 저장소 지침에 따라 Go/프론트엔드 빌드, 자동 테스트, 브라우저 실행, GitHub Actions 실행, 실제 CRS 다운로드와 DB migration 적용은 수행하지 않는다.
- 운영 반영 전 별도 승인 환경에서 migration 적용 후 `DetectionOnly 전환 → 패키지 APPLIED → heartbeat CRS 확인 → 기업 정책 APPLIED → heartbeat 개정본 확인`과 coordinated rollback을 검증해야 한다.
