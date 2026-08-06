# M-WAF GitHub Actions 캐시 최적화

## 목적

PR, `dev` push, 태그 검증에서 매번 반복되던 Go 의존성 처리, OWASP CRS 다운로드, Ubuntu Apache/Nginx 패키지 다운로드와 Manager 이미지 레이어 빌드를 줄였다. 검증 결과나 릴리스 서명 산출물을 재사용하지 않고, 다시 받아도 동일성이 확인되는 입력과 재생성 가능한 빌드 레이어만 캐시한다.

## 반영 내용

- 모든 Go workflow가 `go.sum`을 캐시 키 입력으로 명시해 Go module 및 build cache를 재사용한다.
- `packaging/sources.lock.yaml`에서 읽은 정확한 CRS SHA-256을 키로 `dist/coreruleset.tar.gz`를 캐시한다.
- CRS cache hit 여부와 무관하게 package build 직전에 SHA-256을 다시 검증한다. 손상된 cache는 제거하고 공식 lock URL에서 다시 받은 뒤 최종 해시를 재검증한다.
- Apache, Nginx, `curl`, `jq`, `logrotate`와 두 ModSecurity Connector DEB를 포함한 CI 전용 Ubuntu 24.04 fixture를 최소 전용 build context에서 만들고 BuildKit의 `gha` cache로 재사용한다. 이미 설치된 기반 패키지 archive는 제거하고 시험에 필요한 Connector와 미설치 의존성 DEB만 보존한다. Ubuntu 저장소 변화가 계속 가려지지 않도록 UTC 주차가 바뀌면 APT layer를 갱신한다.
- 네 개의 설치 시험은 fixture 위에서 매번 현재 실행이 만든 M-WAF DEB를 `apt-get --no-download`로 실제 설치한다.
- Manager image의 BuildKit cache는 `mwaf-manager-amd64`, 설치 fixture는 `mwaf-ci-webservers-amd64` scope를 사용해 서로 덮어쓰지 않는다.
- Manager Docker build context는 `dist/bundle`, `dist/package-signing.pub`, `dist/empty`만 허용해 CRS archive, DEB, metadata와 private signing key가 context에 들어가지 않도록 줄였다.
- Pages는 별도 build 단계가 없는 정적 업로드이므로 불필요한 cache action을 추가하지 않았다.

## 유지한 검증 및 보안 경계

- 새로 빌드한 Agent와 모듈 DEB의 설치, Apache/Nginx configtest, ModSecurity load, CRS 파일, HTTP 403 차단과 JSON audit log 확인은 매 실행마다 수행한다.
- cache miss면 고정된 Ubuntu base image에서 fixture를 다시 만들고 CRS를 공식 lock URL에서 다시 받는다.
- release signing key, 임시 test key, 서명 bundle, package metadata, DEB, workflow artifact와 이전 GHCR rollback image는 cross-run cache 대상이 아니다.
- cache 저장 실패는 검증 실패 원인이 되지 않지만, 다운로드·빌드·해시 검증·설치 시험의 실패는 기존처럼 workflow를 실패시킨다.
- DB 초기화, migration, reset은 수행하지 않았다.

## 확인 범위

- GitHub Actions YAML 파싱
- workflow `run` script shell 문법 검사
- 신규 CI fixture를 `linux/amd64`로 실제 build하고, 동일 입력 재build에서 APT layer `CACHED` 확인
- fixture가 Connector 관련 DEB 12개만 보존하는지 확인하고, 저장된 APT archive만 사용해 두 ModSecurity Connector를 `--no-download`로 설치한 뒤 Apache/Nginx configtest 통과
- 축소된 root build context로 Manager image를 실제 build해 `dist/bundle`, 공개키와 두 `dist/empty` COPY 통과
- `git diff --check`
- 저장소 지침에 따라 프론트엔드 빌드와 테스트는 수행하지 않았다.
- 로컬 검증용 Docker image tag는 확인 후 모두 제거했다.
- 실제 GitHub `gha` cache hit와 전체 GitHub Actions 실행은 push 이후 확인해야 한다.
