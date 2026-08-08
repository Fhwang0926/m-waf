# Manager 자동 재빌드 오류 수정

- `internal/manager/system_policy_sync.go`에 남아 있던 미사용 `strconv` import를 제거했다.
- 이전 개발 버전이 보존한 runtime CRS source에 upstream signed-tag 메타데이터가 없을 때 Manager 전체가 종료되던 문제를 수정했다.
- legacy source 파일은 감사와 기존 rollback을 위해 삭제하지 않고, 신규 정책 작성 source에서만 제외한다. Manager 시작 후 새 signed CRS source 동기화가 대체 source를 등록한다.
- DB 구조는 변경하지 않았다.
- 실제 DB migration, 전체 테스트, 프론트엔드 build, 브라우저 실행은 수행하지 않았다.
