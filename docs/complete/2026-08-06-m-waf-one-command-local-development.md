# M-WAF 단일 명령 로컬 개발 환경

## 완료 범위

- `make dev` 단일 명령으로 로컬 개발 환경 실행
- 개발용 secret과 TLS/CA/policy signing 인증서가 없으면 자동 생성
- 운영 Compose와 분리된 `mwaf-local` project 및 MariaDB volume 사용
- MariaDB는 로컬 loopback `127.0.0.1:3306`에만 공개
- 현재 작업 tree의 Manager를 `go run ./cmd/mwaf-manager`로 실행
- 시스템 관리자 UI는 `https://localhost:8443/setup`에서 시작

## package bundle 처리

- 현재 checkout에 `dist/bundle`과 signing public key가 있으면 그대로 사용
- fresh clone처럼 bundle이 없으면 `MWAF_DEV_BUNDLE_IMAGE`에서 서명된 bundle과 public key만 추출
- published Manager container 자체는 실행하지 않으므로 현재 Go/UI source가 그대로 사용됨

## 안전 경계

- `MWAF_DB_DSN`과 직접 지정된 DB password 환경변수를 제거하고 로컬 MariaDB host와 secret file을 강제
- 개발 Compose project 기본 이름을 `mwaf-local`로 고정해 배포용 `mwaf` volume과 분리
- 종료는 `make dev-down`이며 volume을 삭제하지 않음
- init/reset/down-volume 명령은 추가하지 않음

## 보조 명령

- `make dev-down`: foreground Manager 종료 후 로컬 MariaDB와 network 정리, DB volume 보존
- `make dev-db-logs`: 로컬 MariaDB container 출력 확인

## 확인 범위

- shell script 구문과 Compose 파일은 정적으로 검토
- `git diff --check`와 변경 파일 trailing whitespace 확인
- 지침에 따라 `make dev`, Docker container 실행, DB migration, Go build/test는 수행하지 않음
