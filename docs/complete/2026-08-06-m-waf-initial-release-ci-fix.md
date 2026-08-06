# M-WAF 최초 태그 릴리스 CI 수정

## 문제

- `v0.1.0`과 후속 재시도 태그가 이미지 게시 전에 실패해 GHCR `latest`가 존재하지 않았다.
- 릴리스 workflow는 태그 이름이 정확히 `v0.1.0`인 경우에만 이전 이미지 없는 번들 생성을 허용해, 실제 최초 성공 릴리스가 될 `v0.1.2`를 차단했다.
- verify job에서 생성한 빈 `dist/empty` 디렉터리는 workflow artifact에 전달되지 않아 Manager 이미지 build 시 Dockerfile의 빈 디렉터리 복사가 실패할 수 있었다.

## 수정

- 태그 문자열로 최초 릴리스를 판단하지 않고 GitHub Packages API에서 `m-waf-manager` 컨테이너 패키지 존재 여부를 확인한다.
- 패키지가 없는 `404`일 때만 현재 태그를 최초 릴리스로 허용한다.
- 패키지가 존재하는 `200`인데 `latest` pull이 실패하면 검증된 롤백 패키지가 없으므로 계속 실패 처리한다.
- API 응답이 `200` 또는 `404`가 아니면 상태를 추정하지 않고 실패 처리한다.
- publish job에서 Docker build 전에 `dist/empty`를 다시 생성한다.
- README에 최초 성공 릴리스와 두 번째 이후 롤백 검증 동작을 명시했다.

## 유지한 안전 경계

- 기존 `latest`를 가져올 수 있으면 이전 서명 번들을 검증하고 N-1 롤백 패키지를 포함하는 기존 흐름을 유지한다.
- 기존 패키지가 있는데 `latest`가 없거나 GitHub API 확인이 실패한 경우 새 릴리스를 강행하지 않는다.
- DB 초기화, migration, reset은 수행하지 않았다.

## 확인 범위

- GitHub Actions YAML 파싱 확인
- shell 구문 정적 확인
- `git diff --check` 확인
- 실제 태그 workflow 재실행과 GHCR push는 이 작업에서 수행하지 않았다.
- 프론트엔드 빌드와 테스트는 수행하지 않았다.
