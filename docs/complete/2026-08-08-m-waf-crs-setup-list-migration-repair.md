# M-WAF CRS Setup list 타입 마이그레이션 복구

## 현상

- 로컬 Manager가 검증된 LTS CRS 소스를 DB에 인덱싱하는 과정에서 시작에 실패했다.
- MariaDB가 `chk_crs_setup_type` 제약 위반을 반환했다.

## 원인

- 현재 CRS 인덱스는 HTTP Method, Content-Type, HTTP 버전, 제한 확장자와 헤더를 `list` Setup 타입으로 관리한다.
- 현재 migration 소스도 `list`를 허용하지만, 개발 DB에는 `010_crs_policy_storage.sql`의 이전 제약이 이미 적용된 상태였다.
- 적용 완료된 migration 파일은 다시 실행되지 않으므로 기존 제약에는 `list`가 추가되지 않았다.

## 변경

- 전진형 `012_crs_setup_list_type.sql`을 추가했다.
- 기존 `chk_crs_setup_type` 제약만 제거한 뒤 현재 허용 타입인 `integer`, `string`, `boolean`, `enum`, `list`로 다시 생성한다.
- 테이블이나 CRS 데이터를 초기화하거나 삭제하지 않는다.
- 신규 DB는 `010`의 현재 정의로 생성된 뒤 `012`를 적용해 동일한 최종 스키마가 된다.

## 확인

- 현재 개발 DB의 테이블 정의와 migration 적용 목록을 읽기 전용으로 확인했다.
- 기존 제약에 `list`가 없고, 검증된 LTS CRS 인덱스에는 `list` Setup 항목 6개가 있는 것을 확인했다.
- 로컬 live reload가 `012_crs_setup_list_type.sql`을 적용한 뒤 실제 CHECK 제약이 `list`를 포함하고 migration 이력이 기록된 것을 읽기 전용으로 다시 확인했다.
- 현재 8443 리스너가 열려 있지 않아 Manager 전체 시작과 health 응답은 확인하지 못했다. 중단된 watcher는 다음 소스 변경 또는 `make dev` 재실행으로 Manager를 다시 시작해야 한다.
- DB 초기화/reset과 프론트엔드 build/test는 수행하지 않는다.
