# M-WAF 간편 운영형 MVP와 정책 수명주기 개선

## 완료 범위

### 간편 운영 화면

- 기업 사용자의 기본 메뉴를 운영 현황, 보안 이벤트, 보호 설정, IP 관리, 보호 서버로 축소했다.
- 기업 관리자는 사용자 관리, 시스템 관리자는 기업 관리, 시스템 업데이트, 시스템 관리를 추가로 사용한다.
- 운영 현황의 활성·온라인 서버 수는 화면용 서버 목록 상한과 분리한 기업·그룹·서버 범위 SQL 집계로 계산한다.
- 기존 그룹과 설치 URL은 유지하되 그룹은 보호 설정의 적용 대상, 설치는 보호 서버의 서버 추가 흐름으로 연결했다.
- 정책 생성·편집 화면에서 PL, 임계점수, Rule ID와 원본 SecRule 입력을 숨기고 적용 대상, 탐지만·차단 모드, 업데이트 방식과 간편 규칙만 제공한다.
- 신규 설정은 게시된 LTS 시스템 정책의 PL1, inbound 5, outbound 4, 요청 본문 검사 On, 응답 본문 검사 Off와 early blocking Off 기본값을 사용한다.
- 기존 고급 설정과 legacy 전체 우회는 숨겨진 값을 그대로 보존하며, 간편 규칙은 URL·메서드·Host·User-Agent·이름 있는 요청 인자와 일치·시작·포함 조건만 서버에서도 허용한다.

### 공격 요청 중심 이벤트

- `migrations/013_operator_mvp.sql`에 `security_incidents`, 이벤트 선택 필드, 정책 snapshot IP Rule과 시스템 hot-rule 메타데이터를 추가했다.
- Agent 이벤트에 `request_id`, `client_ip`, `matched_variable`, `rule_tags`를 선택 필드로 추가하고 구버전 payload 호환을 유지했다.
- matched value 원문은 저장하지 않고 입력 변수명만 저장한다.
- Manager는 같은 요청·transaction의 여러 Rule 이벤트를 incident 한 건으로 묶고 949·959·980 평가 Rule을 대표 공격에서 제외한다.
- 공격 유형은 HTTP·프로토콜, 인젝션, XSS, 파일·경로 공격, 스캐너·자동화, 기타로 고정했다.
- Agent tag가 없으면 현재 정책의 CRS DB Rule 인덱스를 조회하고, 그래도 없을 때만 메시지 기반 분류를 사용한다.
- 로컬 MaxMind 호환 MMDB를 선택적으로 사용하며 외부 GeoIP API는 호출하지 않는다. 사설·예약 주소는 내부 네트워크, 조회 실패는 알 수 없음으로 유지한다.
- 기존 이벤트를 1,000건 단위로 backfill하는 named-lock worker와 incident 조회 API를 추가했다.

### 이벤트 예외와 IP 관리

- 이벤트 상세에서 입력 항목, 정확한 URL, 모든 요청 범위의 구조화된 Rule 예외를 만들 수 있게 했다.
- 모든 요청 범위 예외에는 추가 확인을 요구하고, 모든 변경에 CSRF, 기업 범위와 `expected_revision_id` 충돌 검사를 적용한다.
- IP·CIDR은 Go `net/netip`으로 canonical 형식으로 저장한다. 단일 IPv4와 IPv6는 각각 `/32`, `/128`로 변환한다.
- BLOCK Rule은 CRS 전에 HTTP 403으로 차단하고 TRUST Rule은 WAF 검사를 일시 제외한다.
- TRUST의 기본 만료는 24시간, 최대 만료는 7일이며 시간별 worker가 만료된 Rule을 제외한 새 불변 개정본과 단계 배포를 만든다.
- 기업 사용자와 기업 관리자 모두 정책·예외·IP 운영을 수행하고 사용자·권한 관리는 기업 관리자만 수행하는 기존 RBAC를 유지했다.

### 설치와 안전한 제거

- Ubuntu 24.04 amd64 Apache·Nginx 설치는 패키지 checksum 확인, 등록, 초기 서명 LTS 정책 적용, include 활성화, configtest·reload, heartbeat 확인 순서로 변경했다.
- 초기 정책이나 적용 개정본 heartbeat를 확인하지 못하면 웹서버 include를 비활성화하고 설치를 실패 처리한다.
- `/var/lib/mwaf/install-state.json`에 패키지, 연동 방식, 관리 파일 checksum, 활성 정책 경로와 백업 위치를 기록한다.
- `/usr/sbin/mwaf-uninstall`에 `--dry-run`, 기본 제거, `--purge`와 패키지 prerm 경로를 추가했다.
- 제거 시 웹서버 설정 검사를 통과한 뒤 reload하며, Manager 등록 해제 실패는 로컬 제거를 막지 않는다.
- 사용자 수정 파일은 checksum 차이가 있으면 삭제하지 않고 별도 위치에 보존한다. 배포판 Apache·Nginx·ModSecurity connector는 제거하지 않는다.

### Filter·Rule 수명주기

- 신규 integration/filter 패키지에서 CRS 파일과 자동 include 활성화를 제거했다.
- 신규 package manifest에 `runtime_abi`와 `policy_delivery: bundle`을 추가했다.
- 신규 filter는 `policy-bundle-v3`의 CRS 버전과 독립적으로 재사용하고, 기존 CRS 포함 패키지는 rollback 호환 대상으로 계속 해석한다.
- `rules/hot/manifest.json`과 `rules/hot/rules.conf`를 추가하고 CI가 digest, 10,000~39,999 ID 범위, 중복과 정규화 Rule 형식을 검증하도록 했다.
- hot-rule 원문과 digest는 공식 CRS source와 함께 서명 bundle manifest에 포함된다. Manager는 서명 catalog만 읽으며 main branch 원문을 직접 적용하지 않는다.
- 시스템 정책 게시 시 hot-rule version·digest를 불변 시스템 정책 버전에 기록하고, 기존 MANUAL·AUTOMATIC·PINNED 및 canary rollout 흐름을 유지한다.

## 호환성과 책임 경계

- 기존 `security_events`, 이벤트 API, Admin API, Agent desired-state, artifact download와 `policy-bundle-v3` 서명·원자 적용·직전 성공본 rollback 형식을 유지했다.
- 정책 개정본, 구조화 설정, rollout과 rollback은 authoritative 내부 계층으로 유지하고 일반 운영 화면에서만 복잡도를 숨겼다.
- 국가별 차단, 고급 정책 편집기 재노출, RPM·ARM64·추가 배포판과 외부 이벤트 저장소는 구현하지 않았다.
- `013_operator_mvp.sql`은 전진형 migration 파일만 작성했으며 실제 DB migration, incident backfill, init 또는 reset은 수행하지 않았다.

## 정적 확인 범위

- 변경 Go 코드에 `gofmt`를 적용했다.
- `go list -test ./...`로 전체 패키지와 테스트 소스의 정적 패키지 로딩을 확인했다. 테스트 함수는 실행하지 않았다.
- Go 표준 `html/template` 파서로 전체 관리자 템플릿을 파싱했다.
- JavaScript 구문, shell 스크립트 구문, workflow YAML, hot-rule JSON·digest, migration 필수 구조와 템플릿 참조를 정적으로 확인했다.
- `git diff --check`를 수행했다.

## 수행하지 않은 확인

- 저장소 지침에 따라 실제 DB migration·backfill, DB init/reset, 전체 Go 테스트, 프론트엔드 빌드, 브라우저 실행을 수행하지 않았다.
- 실제 Ubuntu 설치·제거, Apache/Nginx configtest, Agent heartbeat, 정책 rollout·rollback과 CI 서명 릴리스는 실행하지 않았다.
