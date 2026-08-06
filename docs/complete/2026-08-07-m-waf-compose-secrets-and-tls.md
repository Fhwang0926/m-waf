# M-WAF Compose secret 권한 및 TLS 호환성 개선

## 해결한 문제

- 로컬 Docker Compose의 파일 기반 secret이 호스트 `root:root`, `0600` 권한을 유지해 비루트 UID/GID `65532` Manager가 `/run/secrets/mariadb_app_password`부터 읽지 못하고 재시작하던 문제를 수정했다.
- 기존 Ed25519 서버 인증서를 일부 브라우저가 협상하지 못해 `ERR_SSL_VERSION_OR_CIPHER_MISMATCH`를 표시하던 신규 설치 경로를 개선했다.
- `MWAF_MANAGER_HOST`에 IP를 설정해도 인증서에 DNS SAN으로 기록하고 `localhost/127.0.0.1`만 유효했던 문제를 수정했다.

## 반영 내용

- secret 디렉터리는 `0700`으로 고정하고 Compose가 실제 마운트하는 파일만 `0644`로 설정한다.
- 호스트에서는 디렉터리 탐색 권한으로 다른 사용자의 접근을 차단하면서, 컨테이너에서는 비루트 Manager가 읽기 전용 bind mount를 읽을 수 있다.
- 신규 Agent CA와 Manager TLS 키를 ECDSA P-256으로 생성하고 SHA-256으로 인증서를 서명한다.
- Manager host가 IPv4/IPv6이면 IP SAN, DNS 이름이면 DNS SAN으로 생성하며 `localhost`와 `127.0.0.1`도 유지한다.
- 기존 CA·TLS 인증서는 자동 교체하지 않는다. CA 서명 관계를 검증하고 host SAN 불일치 또는 ECDSA P-256이 아닌 인증서는 경고해 운영자가 명시적으로 회전하도록 한다.
- 정책 artifact 서명용 Ed25519 키는 브라우저 TLS와 무관하므로 변경하지 않았다.

## 회귀 방지

- `deploy/compose/test-prepare.sh`를 추가해 IPv4와 DNS 두 경우의 디렉터리·파일 권한, ECDSA P-256 CA/TLS 인증서, SAN, CA 검증과 재실행 시 키·인증서 비덮어쓰기를 확인한다.
- GitHub Actions 검증 단계에서 shell 문법 검사와 위 prepare 회귀 검사를 실행하도록 연결했다.

## 기존 설치 주의사항

- 기존 Agent CA, TLS 인증서와 키는 보존된다. 기존 인증서가 Ed25519이거나 현재 Manager host SAN이 없으면 `prepare.sh`가 경고하지만 자동으로 교체하지 않는다.
- 이미 Agent가 등록된 환경에서 CA를 교체하면 Agent 신뢰 체계가 끊어지므로 백업·재등록 또는 별도 CA 회전 절차 없이 삭제하거나 재생성하면 안 된다.
- 신규 설치이면서 Agent 등록 전인 경우에만 기존 인증서를 백업한 뒤 명시적으로 ECDSA P-256 CA/TLS 쌍으로 교체할 수 있다.

## 확인 범위

- `sh -n`으로 변경한 shell 파일의 문법을 확인했다.
- Docker Compose 설정 렌더링과 `git diff --check`를 정적으로 확인했다.
- 저장소 지침에 따라 빌드, 자동 테스트, 브라우저 실행과 DB migration 적용은 수행하지 않았다.
