# M-WAF CRS 정책 DB 구조화 및 수명주기 개선 완료

## 완료 범위

OWASP CRS 원본을 DB 문자열로 옮기지 않고, 검증된 원본 artifact·검색 가능한 DB 메타데이터·Agent 실행용 서명 정책을 분리했다.

```text
signed OWASP CRS tag/commit/archive
  -> 불변 CRS archive 및 source manifest
  -> DB release/setup/rule 인덱스
  -> 불변 system policy와 enterprise effective snapshot
  -> deterministic policy-bundle-v3
  -> Agent 서명 검증, configtest, 원자적 적용 및 실패 rollback
```

- CRS archive의 `rules`, `data`, `LICENSE`, `crs-setup.conf.example` 원문은 artifact 저장소에 보존한다.
- DB는 릴리스 식별자, 검증 상태, Setup schema, Rule·tag·variable 검색 인덱스와 정책 작성용 구조화 값을 관리한다.
- `directive_text`는 조회·비교 캐시이며 Agent가 실행하는 원본은 서명 bundle에 포함된 CRS 파일이다.
- 기업 정책 개정본은 시스템 범위와 기업 범위를 합친 완전한 effective snapshot을 저장한다.
- Agent desired-state API와 `policy-bundle-v3` 서명·digest 검증 계약은 변경하지 않았다.

## DB와 legacy backfill

전진형 migration `migrations/010_crs_policy_storage.sql`에 다음 구조를 추가했다.

- `crs_releases`, `crs_setup_definitions`, `crs_rules`, `crs_rule_tags`, `crs_rule_variables`
- `policy_configurations`, `policy_configuration_setup_values`
- `policy_configuration_exclusions`, `policy_configuration_exclusion_conditions`
- `policy_configuration_custom_rules`, `policy_migration_impacts`
- `system_policy_versions`, `policy_revisions`의 `config_storage_version`, `config_migration_status`, `config_migration_detail`

`defaults_json`과 `settings_json`은 삭제하지 않았다. 구조화 행이 있으면 이를 authoritative source로 사용하고, 기존 행은 JSON fallback으로 계속 읽는다.

startup 정책 동기화 전에 MariaDB named lock을 얻어 시스템 정책과 정책 개정본을 각각 최대 100개씩 구조화한다. 작업은 owner unique key와 transaction으로 멱등성을 유지하며 artifact를 다시 만들거나 rollout하지 않는다. 변환할 수 없는 행은 원문과 기존 artifact를 보존한 채 `LEGACY_LOCKED`로 표시한다. 주기 정책 동기화가 다음 batch를 계속 처리한다.

SQL migration 파일만 추가했으며 실제 DB에는 적용하지 않았다.

## LTS와 Stable 수명주기

`packaging/sources.lock.yaml`을 schema 2 채널 목록으로 변경했다.

- LTS: 고정된 `4.25` 계열에서 가장 높은 signed patch tag만 선택한다.
- Stable: 가장 높은 signed non-prerelease v4 tag를 선택한다.
- annotated tag 서명을 확인한 뒤 tag가 가리키는 commit archive를 받아 digest를 검증한다.
- 동일 tag가 기존 DB의 commit 또는 digest와 다르면 overwrite하지 않고 공급망 오류로 차단한다.

CI bundle은 `crs-lts-baseline@1.0.0`과 `crs-stable-baseline@1.0.0`을 제공한다. 신규 기업의 기본 정책은 LTS DetectionOnly이고 Stable은 시스템 관리자가 명시적으로 선택한다. 기존 `crs-baseline`은 삭제하거나 의미를 바꾸지 않았으며 신규 기업 정책 선택에서는 제외한다.

Manager는 시작 직후와 `MWAF_CRS_SYNC_INTERVAL` 주기로 LTS와 Stable을 확인한다. 검증된 source를 원자적으로 저장하고 DB 인덱스를 transaction으로 등록하지만 시스템 정책을 자동 게시하지 않는다. GitHub 장애 시 기존 검증 source와 현재 정책으로 계속 운영한다.

일일 GitHub Actions는 두 채널의 signed tag를 확인하고 `packaging/sources.lock.yaml` 변경 PR을 생성한다. 새로운 LTS major/minor 계열과 정책 schema major는 이 CI seed 경로를 통해서만 도입한다.

## 게시, migration, rollout

시스템 관리자의 기존 migration 화면을 후속 정책 게시 경로로 유지했다.

- 같은 정책 key·채널·schema의 다음 patch만 Manager에서 게시할 수 있다.
- LTS는 현재 major/minor line 안의 patch만 허용한다.
- Rule 추가·삭제·내용 변경과 Setup schema 변경을 DB 인덱스로 비교한다.
- `expected_system_policy_id`와 validation digest가 바뀌면 게시를 `409 Conflict`로 차단한다.
- 게시된 새 정책은 동일 key의 이전 게시본을 `DEPRECATED`로 전환한다.
- 안전한 `AUTOMATIC` 정책은 canary 대기열, `MANUAL`은 승인 대기, `PINNED`는 정보 표시 상태를 유지한다.
- 삭제·변경 Rule을 기업 예외가 참조하거나 custom Rule ID가 충돌하면 해당 기업만 `MIGRATION_REQUIRED`로 둔다.

## 정책 구조와 renderer

새 내부 모델은 `CRSRelease`, `PolicyConfiguration`, `CRSSetupValue`, `PolicyExclusion`, `PolicyExclusionCondition`, `PolicyCustomRule`, migration impact를 기준으로 한다. `PolicySettings`는 legacy JSON 호환 경계로 유지한다.

renderer는 저장된 immutable snapshot만 사용하며 다음 고정 순서로 파일을 만든다.

1. 엔진 모드와 요청·응답 본문 검사
2. CRS Setup과 M-WAF override
3. 조건부 `BEFORE_CRS` 예외
4. 변경하지 않은 upstream CRS Rule
5. 정적 `AFTER_CRS` 예외
6. 시스템·기업 custom Rule

Blocking PL, Executing PL, inbound/outbound threshold, request/response body, early blocking, sampling을 별도 값으로 검증한다. 같은 snapshot은 byte-identical gzip/tar bundle을 만들도록 timestamp와 파일 순서를 고정했다.

## 예외와 Rule ID 전환

- 일반 신규 예외는 Rule, Target, Tag만 제공한다.
- 조건부 runtime 예외는 `BEFORE_CRS`, 무조건 정적 예외는 `AFTER_CRS`로 강제한다.
- 조건 필드와 연산자는 renderer allowlist로 제한한다.
- 신규 `ENGINE_BYPASS`는 사유와 만료 시각이 필요하고 최대 7일이다.
- 기존 URL/IP `ctl:ruleEngine=Off`는 의미를 바꾸지 않고 `legacy=true`로 보존한다. 새 개정본 또는 다음 시스템 정책 전환 전에 제거·대체 또는 명시적 유지 확인이 필요하다.

신규 local Rule ID 범위는 다음과 같다.

- `1,000..4,999`: Setup overlay
- `5,000..9,999`: 조건부 예외와 긴급 bypass
- `10,000..39,999`: 시스템 공통 Rule
- `40,000..89,999`: 기업 Rule
- `90,000..99,999`: 예약

기존 `100,000..199,999`, `240,000..249,999`는 자동 재번호화하지 않는다. DB backfill에서는 `legacy_id_range=true`로 읽을 수 있고 현재 성공 artifact와 rollback은 유지한다. 새 개정본이나 새 시스템 정책 게시에서는 현재 namespace로 명시적으로 변경하기 전까지 차단한다. CRS Rule, 생성 Rule, 시스템 Rule, 기업 Rule 전체에서 ID 충돌을 검사한다.

## API와 관리자 UI

- `GET /api/v1/open-source-policies`는 선택적 `channel=lts|stable` 필터와 검증·digest·DB index 상태를 제공한다.
- 기존 Rule·diff 응답 계약은 유지하되 DB 인덱스를 사용한다.
- migration validate는 `config_schema_version: 2` 구조화 입력을 지원한다.
- schema version이 없으면 기존 요청으로 해석하고, v2와 legacy 필드가 섞이면 `400`으로 거부한다.
- 기존 URL, 세션, CSRF, RBAC, 기업 범위와 Agent desired-state/artifact download 형식은 유지한다.

CRS 화면은 LTS/Stable, signed tag, commit, archive/index digest, Rule/Setup 수와 DB 상태를 표시한다. 동기화와 정책 게시를 별도 작업으로 안내한다. 시스템 정책 화면은 CI seed가 없으면 직접 최초 정책을 만들지 않고 bundle 갱신을 안내한다. 기업 정책 화면은 시스템 상속과 기업 override, legacy bypass와 Rule ID 전환 필요 상태를 구분한다.

## 실패 처리

- unsigned/lightweight/prerelease source와 digest 불일치는 import하지 않는다.
- index 실패, 중복 Rule ID, 필수 Setup 불일치는 `REJECTED` source와 감사 로그로 남긴다.
- artifact 저장 후 DB 등록이 실패하면 활성화하지 않으며 다음 시작 시 서명 source manifest로 DB 등록을 복구한다.
- publish validation 상태가 바뀌면 `409 Conflict`로 차단한다.
- 기업 migration 실패는 해당 기업만 차단하고 다른 rollout은 계속 처리한다.
- Agent configtest 실패 시 직전 symlink로 복구하고 rollout을 중지한다.

## 수행한 정적 검증

- 변경 Go 파일 `gofmt`
- `go list -test ./...`를 통한 Go package·test package 정적 로드
- 관리자 Go template 37개 파싱
- `packaging/sources.lock.yaml`과 GitHub workflow YAML 파싱 및 schema/channel 값 확인
- shell script `sh -n`
- migration SQL의 괄호, 필수 table, FK/check/unique 구조 점검
- lock의 LTS·Stable archive SHA-256 값 확인
- `git diff --check`

## 수행하지 않은 검증

저장소 지침과 요청 범위에 따라 다음은 수행하지 않았다.

- 실제 DB migration 적용, init, reset 및 live DB backfill
- 전체 Go build/test/vet 실행
- 프론트엔드 build
- 브라우저 실행과 화면 수동 검증
- 실제 GitHub sync, 시스템 정책 게시, canary rollout 및 Agent 적용

## 후속 범위

- CRS 플러그인 설치·검증·ID namespace 계약
- 폐쇄망 signed bundle export/import와 trust root 운영
- 실제 MariaDB migration staging 검증과 다중 Manager 동시 backfill 검증
- signed CI bundle을 사용한 LTS/Stable seed 및 Agent v3 end-to-end 검증
