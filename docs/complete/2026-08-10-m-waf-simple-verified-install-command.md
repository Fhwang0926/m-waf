# M-WAF 간편 검증 설치 명령 적용 완료

## 반영 내용

- 서버 설치 화면의 복사 명령을 한 줄 설치 흐름으로 단순화했다.
  - `mkdir -p ./mwaf_install`
  - `wget --no-check-certificate`로 설치기 다운로드
  - 관리자 화면이 제공한 SHA-256으로 설치기 바이트 검증
  - 검증된 설치기에 단기 등록 토큰을 표준입력으로 전달
- `wget --no-check-certificate`는 최초 설치기 다운로드 한 번에만 사용한다.
- 설치기는 기존 Manager TLS SPKI 공개키 pin을 사용해 공개 M-WAF CA를 받는다.
- CA를 받은 뒤 등록, 패키지 다운로드와 Agent 통신은 기존 `--cacert`·mTLS 검증을 유지한다.
- 설치기에 다음 간편 입력을 추가했다.
  - `-d`를 `--manager`의 짧은 별칭으로 제공
  - `--token-stdin`으로 단기 등록 토큰 수신
  - 비-root 실행 시 설치기 내부에서 기존 인자를 유지한 채 `sudo`로 재실행
- 기존 `--manager`, `--token-file`, `--ca`, 기업 설치 토큰 입력 경로는 유지했다.
- 설치 화면에 필요한 기존 명령 `wget`, `sha256sum`, `curl`을 표시했다.

## 보안 경계

- 인증서 검사를 생략한 설치기를 검증 없이 실행하지 않는다.
- 설치기 SHA-256은 로그인된 Manager 화면이 렌더링한 현재 embedded 설치기와 일치한다.
- 단기 등록 토큰은 설치기 프로세스 인자나 URL에 넣지 않고 표준입력으로 전달한다.
- 공개키 pin 검증은 CA bootstrap에 유지한다.
- 의존성 패키지는 자동으로 설치하지 않는다.

## 확인 결과

- `sh -n internal/manager/bootstrap-install.sh`: 성공
- `git diff --check`: 성공
- `go test ./internal/manager ./internal/agent ./internal/config`: 성공
- 실행 중인 로컬 Manager 확인: 성공
  - `/bootstrap/v1/install.sh`에 `-d`, `--token-stdin`, 내부 sudo와 `--pinnedpubkey` 포함
  - source 설치기 SHA-256과 실제 HTTPS 응답 SHA-256 일치
  - 확인 SHA-256: `4506f7dde4708d97b913e4ede3222b0a521504963a9fdc057d8f68eb4b569990`

## 수행하지 않은 검증

- 프론트엔드 빌드는 수행하지 않았다.
- DB init/reset/migration은 수행하지 않았다.
- 새 단기 토큰을 소비하는 실제 고객 서버 등록은 수행하지 않았다.
- 고객 서버에 `wget` 또는 다른 의존성을 자동 설치하지 않았다.
