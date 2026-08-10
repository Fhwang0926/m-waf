# M-WAF 로컬 전체 개발과 태그 전용 이미지 배포 반영 완료

## 목적

일반 개발은 GitHub Actions와 GHCR 이미지 생성을 사용하지 않고 저장소 소스로 실행하며, Manager 이미지와 공개 서명 bundle은 의미 버전 태그에서만 생성하도록 개발·릴리스 경계를 분리했다.

## 개발 실행 방식

### Manager·UI 개발

```sh
make dev
```

- 현재 Go·템플릿·CSS·JavaScript 소스를 감시해 Manager를 자동 재빌드·재시작한다.
- Manager Docker 이미지를 만들지 않는다.
- 설치 파일은 마지막 공개 서명 release bundle을 사용한다.
- Manager 화면과 API 개발에 사용한다.

### Manager·Agent·패키지 전체 개발

```sh
make dev-full
```

- 현재 Linux amd64 Agent를 빌드한다.
- Docker 기반의 캐시 가능한 Ubuntu 24.04 패키지 빌더에서 Agent와 Apache/Nginx distro/external DEB를 만든다.
- Ubuntu 24.04와 Debian 12 package metadata를 만든다.
- 캐시된 검증 완료 schema-v2 release bundle에서 immutable CRS source 두 개를 재사용한다.
- 공개 release key와 분리된 로컬 Ed25519 key로 개발 bundle을 서명한다.
- 새 bundle을 다시 검증한 뒤 로컬 source Manager에서 사용한다.
- 기존 local MariaDB volume을 유지하고 schema migration을 비활성화한다.

Agent/package bundle만 다시 만들 때는 다음 명령을 사용한다.

```sh
make dev-bundle
```

개발 bundle과 signing key는 `.local` 및 ignored `deploy/compose/secrets`에만 저장하며 Git에 포함하거나 외부 registry에 업로드하지 않는다.

## GitHub Actions 변경

- Pull request: 검증 job만 실행
- 수동 workflow dispatch: 검증 job만 실행
- `dev` push: Manager workflow 실행 안 함, 이미지 생성 안 함
- `vMAJOR.MINOR.PATCH` tag: 검증 후 GHCR 이미지, version/latest/sha tag, provenance와 GitHub Release 생성
- `RELEASE_BUNDLE_SIGNING_KEY_B64`는 tag publication에서만 필요

GitHub Pages의 소개 페이지 workflow는 별도이며 이번 Manager 이미지 정책 변경 대상이 아니다.

## 실제 로컬 bundle 생성 결과

- bundle schema: 2
- package artifact metadata: 10개
- CRS source: Stable/LTS 2개
- Agent 대상: Ubuntu 24.04 amd64, Debian 12 amd64
- bundle signature 재검증 완료
- Docker package builder 최초 생성 완료, 이후 layer cache 사용 가능

## 검증

- `sh -n deploy/compose/build-local-bundle.sh` 통과
- `sh -n deploy/compose/run-local.sh` 통과
- 로컬 bundle signature 및 catalog 검증 통과
- `go test ./...` 통과
- `go vet ./...` 통과
- `git diff --check` 통과

## 실행 상태

- 기존 `make dev` watcher가 Manager 소스 변경을 자동 재빌드해 현재 Manager 코드와 화면 변경은 로컬 8443 listener에 반영됐다.
- 새 Agent가 포함된 개발 bundle은 생성·검증됐지만 실행 중 Manager의 bundle을 강제로 교체하거나 등록 서버에 Agent를 설치하지 않았다.
- 전체 전환은 기존 `make dev`를 `Ctrl-C`로 종료한 뒤 `make dev-full`로 시작한다. 대상 Agent 업데이트는 서버 상세의 서명 패키지 배포 절차로 수행한다.

## 수행하지 않은 작업

- DB init/reset 실행 안 함
- 실행 중 MariaDB volume 삭제·재생성 안 함
- 고객 서버 Agent 강제 설치 안 함
- release tag 생성·push 및 GHCR publication 안 함
