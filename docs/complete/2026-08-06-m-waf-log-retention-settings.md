# M-WAF 로그 보존 설정 및 순환 정리 구현

## 완료 범위

- 시스템 관리자 전용 `시스템 설정 > 로그 보존 설정` 화면 추가
- WAF 보안 이벤트 보존 기간을 1~3650일 범위에서 설정
- 관리자 감사 로그 보존 기간을 30~3650일 범위에서 설정
- 기본값은 WAF 이벤트 30일, 관리자 감사 로그 365일
- 설정값은 `system_settings`에 저장하고 변경 관리자와 변경 시간을 기록
- 보존 설정 변경 자체도 관리자 감사 로그에 기록

## 순환 정리

- Manager 시작 시 한 번 정리하고 이후 `MWAF_CLEANUP_INTERVAL` 간격으로 반복
- 정리 시마다 DB의 최신 시스템 설정을 다시 조회
- 한 번에 5,000건씩 최대 20회 처리해 긴 DB lock을 피하면서 오래된 기록을 순차 삭제
- WAF 이벤트와 관리자 감사 로그를 각각 설정된 기간 기준으로 삭제
- 기존 `MWAF_EVENT_RETENTION` 값은 DB 설정이 아직 저장되지 않았을 때의 초기 fallback으로 유지

## 런타임 로그 제한

- Manager와 MariaDB container 출력은 Docker `local` logging driver로 순환
- container별 로그 파일은 최대 10MB, 최대 5개, 압축 보관
- 별도 host logrotate가 없는 Compose 구조에서 파일이 무제한 증가하지 않도록 MariaDB slow query file log를 기본 비활성화

## 권한 및 안전 경계

- 로그 보존 기간 조회와 변경은 시스템 관리자만 가능
- 기업 관리자와 기업 사용자는 시스템 설정 route에 접근할 수 없음
- 관리자 감사 로그는 보안 추적 보호를 위해 최소 30일 보존
- 운영 DB migration과 로그 삭제 작업은 현재 환경에서 실행하지 않음

## 확인 범위

- 변경 Go 파일에 `gofmt` 적용
- `git diff --check` 및 변경 파일 trailing whitespace 확인
- 지침에 따라 Go build/test와 frontend build/test는 수행하지 않음
- 실행 중인 Manager가 없어 시스템 설정 화면과 실제 정리 주기는 runtime 확인하지 않음
