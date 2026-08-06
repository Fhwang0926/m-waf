# M-WAF 시스템 정책·OWASP CRS 수명주기 반영

## 결론

시스템 초기 정책은 더 이상 모듈 패키지의 최소 `DetectionOnly` 파일에만 의존하지 않는다. Manager의 시스템 정책 컨트롤러가 최초 서버 등록 시 기업별 `CRS 기본 보호 정책` 개정본을 생성하고 서명한 뒤 배포한다. 자동 생성 배포의 `requested_by`는 `NULL`, 정책 출처는 `system-seed`로 기록해 관리자 요청과 구분하고, 정책 화면과 Manager 구조화 로그에서 생성 주체를 확인할 수 있게 했다.

공식 CRS 저장소의 변경은 즉시 운영 서버로 직행하지 않는다. GitHub Actions가 신규 안정 릴리스를 발견해 검증 가능한 변경 PR을 만들고, 기존 패키지 설치 검증과 승인 과정을 거쳐 서명 bundle이 배포된 다음에만 Manager가 서버별 CRS 패키지와 정책 개정을 순서대로 동기화한다.

## 1. 템플릿화

- `internal/systempolicy/templates/*.json`을 Manager 바이너리에 포함하는 시스템 정책 카탈로그를 추가했다.
- 기본 템플릿은 DetectionOnly, CRS 민감도 1, 인바운드 임계점수 5, 요청 본문 검사 활성화로 시작한다.
- 관리자가 만드는 정책도 선택한 템플릿 키·버전, CRS 트랙·버전, 대상과 자동 갱신 여부를 정책 설정에 함께 저장한다.
- 기존 정책 생성기의 CRS v4 민감도 변수명을 `blocking_paranoia_level`과 `detection_paranoia_level`로 바로잡았다.

## 2. 버전 관리

- `packaging/sources.lock.yaml`을 승인된 CRS tag, commit, archive, SHA-256의 단일 기준으로 유지한다.
- 모듈 DEB와 bundle manifest에 실제 포함된 CRS 버전을 기록하고 Agent heartbeat의 설치 버전과 비교할 수 있게 했다.
- 시스템 정책 템플릿은 자체 버전을 가지며 업데이트 도구는 기존 JSON을 덮어쓰지 않고 새 템플릿 버전 파일을 추가한다.
- 정책 개정본은 생성 당시의 템플릿/CRS 버전을 복사해 저장하므로 이후 저장소가 갱신되어도 당시 적용 내용을 추적할 수 있다.

## 3. 정책별 마이그레이션

- 자동 갱신을 선택한 정책 binding만 새 템플릿으로 마이그레이션한다.
- 기존 동작 모드, 민감도, 임계점수, 본문 검사, URL/IP 예외와 검증된 사용자 규칙은 정책별로 보존한다.
- 새 정책은 기존 개정본을 수정하지 않고 `migrated_from`을 가진 새 서명 개정본으로 생성한다.
- 대상 충돌 시 `서버 > 그룹 > 기업 기본 정책` 순서로 적용하며, 템플릿 밖에서 명시적으로 지정한 정책은 서버 잠금으로 보고 자동 동기화가 덮어쓰지 않는다.

## 4. 지속 업데이트와 반영

- `.github/workflows/crs-updates.yml`이 매일 공식 `coreruleset/coreruleset` 안정 릴리스를 확인한다.
- draft/prerelease를 제외하고 GitHub가 서명 검증 완료로 표시한 annotated tag만 허용한다.
- 새 archive를 직접 내려받아 SHA-256을 계산한 뒤 source lock과 새 템플릿 버전을 변경하는 PR을 열거나 갱신한다.
- Manager는 시작 시, 서버 등록 직후, 이후 기본 15분 간격으로 자동 관리 정책을 동기화한다.
- 대상 서버의 CRS가 템플릿 버전과 다르면 먼저 해당 CRS가 포함된 호환 서명 bundle을 배포 대기시킨다.
- heartbeat가 목표 CRS 설치를 보고한 서버부터 새 정책 개정본을 생성·배포하고, 아직 준비되지 않은 서버는 기존 개정본을 유지한 채 다음 주기에 이어서 반영한다. 패키지 배포 실패는 자동 반복하지 않고 로그에 남겨 운영 확인 대상으로 둔다.

## 데이터 변경

- 전진형 migration `005_system_policy_sync.sql`은 시스템 생성 정책 배포를 관리자 요청과 구분할 수 있도록 `policy_deployments.requested_by`만 nullable로 변경한다.
- 신규 정책 테이블이나 별도 마이그레이션 상태 테이블은 추가하지 않고 기존 `policy_revisions.settings_json`, `desired_states`, 배포 이력을 재사용했다.
- 실제 MariaDB migration, 초기화, reset 또는 데이터 변경은 수행하지 않았다.

## 확인 범위

- 변경한 Go 파일에 `gofmt`를 적용했다.
- source lock 읽기, 템플릿 카탈로그, 동기화 우선순위, 패키지 선행 조건과 문서의 연결을 정적으로 검토했다.
- 저장소 지침에 따라 Go/프론트엔드 빌드, 자동 테스트, 브라우저 실행, GitHub Actions 실행, 실제 CRS 다운로드와 DB migration 적용은 수행하지 않았다.
- 운영 반영 전 PR 검증 workflow와 staging Agent에서 `패키지 적용 → heartbeat CRS 확인 → 정책 migration` 순서를 확인해야 한다.
