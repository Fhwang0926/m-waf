# 기업 설치 토큰 기반 자동 등록 완료

## 변경 목적

호스팅사가 Manager에서 서버 레코드와 일회용 토큰을 서버마다 먼저 만들지 않고, 기업별 설치 토큰을 미리 생성해 여러 Apache/Nginx 서버 설치에 재사용할 수 있도록 등록 흐름을 개선했다.

## 반영 내용

- `enterprise_install_tokens`와 기존 `enrollment_tokens.install_token_id`를 추가하는 순방향 MariaDB migration을 작성했다.
- 기업 설치 토큰은 256-bit 난수로 생성하고 원문 대신 SHA-256 해시와 화면 식별용 접두어만 저장한다.
- 기업 범위, 만료, 선택적 등록 한도, 등록 완료 수, 마지막 사용, 폐기 상태를 Manager에서 관리한다.
- `/bootstrap/v1/sessions`가 기업 설치 토큰과 서버 inventory를 확인하고 기존 형식의 짧은 일회용 enrollment token을 서버마다 발급한다.
- Apache/Nginx와 커스텀 빌드마다 별도 단기 token을 사용하므로 기존 `allowed_packages_json` 선택이 서로 충돌하지 않는다.
- Agent 등록 transaction에서 기업 token의 폐기·만료·등록 한도를 다시 확인하고 성공한 등록만 원자적으로 집계한다.
- 기업 token 폐기는 신규 session과 아직 사용하지 않은 하위 session을 차단하지만 이미 등록된 Agent의 mTLS 인증서에는 영향을 주지 않는다.
- 설치기는 `--install-token-stdin`, `--install-token-file`, `--name`을 지원하며 기존 `--token`도 호환용으로 유지한다.
- 재사용 기업 token은 curl 인자에 넣지 않고 권한 제한 임시 header 파일을 통해 전달하며 Agent 설정에는 단기 token만 기록한다.
- `/var/lib/mwaf-agent/server-id`가 있는 서버에서 재설치를 거부해 중복 서버 등록을 방지한다.
- Manager의 `서버 등록` 메뉴를 `설치 및 등록`으로 바꾸고 기업 token 생성, 설치 블록, 상태·사용량·만료·폐기 화면을 추가했다.
- 공개 CA 인증서를 base64로 포함한 설치 블록을 제공해 별도 CA 파일 전송 없이 검증된 TLS 연결을 시작할 수 있게 했다.
- E2E 설치 경로는 기업 token 하나를 Apache와 Nginx 컨테이너가 함께 사용하도록 변경했다.
- README, 커스텀 웹서버 설치 문서와 개발 계획서를 새 흐름에 맞게 갱신했다.

## 보안 경계

- 기업 설치 토큰은 Bootstrap session 발급만 허용하며 Agent API 인증이나 패키지 직접 다운로드에는 사용할 수 없다.
- 각 Agent는 등록 후 기존과 동일하게 고유 개인키와 Manager 발급 mTLS 인증서를 사용한다.
- 토큰 원문은 생성 응답에서 한 번만 제공하고 DB, 감사 로그와 일반 HTTP 로그에 저장하지 않는다.
- 기업 및 토큰 단위 권한 격리, CSRF, 요청 횟수 제한, package allowlist와 기존 서명·SHA-256 검증을 유지한다.

## 검증 범위

- 변경한 Go 파일에 `gofmt`를 적용했다.
- 설치 스크립트와 E2E 스크립트의 POSIX shell 문법을 확인했다.
- `git diff --check`로 공백 오류를 확인했다.
- 저장소 작업 지침에 따라 Go test, 프론트엔드 빌드, Docker E2E와 실제 MariaDB migration 실행은 수행하지 않았다.
