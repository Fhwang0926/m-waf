# M-WAF 로컬 개발 DB 연결 수정 완료

## 문제

- `make dev`가 MariaDB를 healthy 상태로 시작했지만 Manager는 `database_unavailable: context deadline exceeded`로 종료됐다.
- 렌더링된 Compose 설정에는 `127.0.0.1:3306` 게시가 있었지만, MariaDB가 내부 전용 `db_net`에만 연결되어 Docker Desktop의 실제 컨테이너 포트 게시가 비어 있었다.

## 반영 내용

- 로컬 전용 `compose.local.yaml`에서 MariaDB를 비내부 `manager_net`에도 연결했다.
- DB 호스트 포트는 계속 `127.0.0.1:3306`으로만 제한한다.
- 로컬 실행 스크립트는 MariaDB health 완료까지 최대 60초 기다린 뒤 현재 소스의 Manager를 시작한다.
- `make dev`를 실행할 때마다 GHCR의 `m-waf-manager:latest`를 확인하고, 서명 번들을 이미지 ID별 개발 캐시에 추출해 사용한다.
- 로컬 `dist/bundle`은 latest 이미지를 새로 받을 수 없을 때만 오프라인 대체 번들로 사용한다.
- 특정 릴리스 재현은 `MWAF_DEV_BUNDLE_IMAGE`에 불변 태그를 명시한 경우에만 허용한다.
- 기존 `mwaf-local_mariadb_data` 볼륨은 유지했으며 초기화나 reset을 수행하지 않았다.

## 확인 범위

- Compose 구성 렌더링과 shell 문법을 확인했다.
- MariaDB 컨테이너를 기존 볼륨으로 재생성한 뒤 healthy 상태와 `127.0.0.1:3306` 게시를 확인했다.
- 호스트에서 `127.0.0.1:3306` TCP 연결 성공을 확인했다.
- `git diff --check`를 확인했다.
- Manager 실행, 자동 migration, Go build/test와 브라우저 실행은 수행하지 않았다.

## 최신 서명 번들 자동 전환 보완

- 이후 로컬 실행 경로는 기존 `.env`의 오래된 `MWAF_BUNDLE_IMAGE` 고정을 사용하지 않고 개발용 `MWAF_DEV_BUNDLE_IMAGE`의 기본값을 `latest`로 사용한다.
- 매 실행 시 `docker pull`로 latest digest를 확인하며, 같은 image ID는 기존 검증 캐시를 재사용한다.
- v1 파일을 v2로 위조 변환하거나 시스템 정책을 자동 게시하지 않는다. latest 자체가 v1이면 새 v2 태그가 게시될 때까지 호환 모드로 유지된다.
- 실행 중인 로컬 Manager를 중단하지 않고 `sh -n deploy/compose/run-local.sh`와 `git diff --check`만 다시 확인했다. 새 선택 로직은 다음 `make dev` 재시작부터 적용된다.
