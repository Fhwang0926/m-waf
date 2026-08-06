# GitHub Pages 배포 timeout 수정

## 원인

- 최신 `Publish introduction page` 실행 `31095951142`는 체크아웃, Pages 설정, 정적 사이트 업로드까지 성공했다.
- `Deploy GitHub Pages` 단계가 9분 54초 동안 대기한 뒤 job의 `timeout-minutes: 10`에 도달해 전체 실행이 취소됐다.
- 직전 성공 실행 `31088695419`도 같은 배포 단계에 8분 26초가 걸려 기존 10분 제한의 여유가 부족했다.
- 현재 고정된 공식 `actions/deploy-pages` 액션도 별도의 기본 배포 대기 제한 10분을 사용한다.

## 변경

- Pages deploy job 제한을 10분에서 25분으로 늘렸다.
- `actions/deploy-pages`의 배포 상태 대기 제한을 20분으로 명시했다.
- 업로드 경로, 권한, 배포 환경과 동시 실행 취소 정책은 변경하지 않았다.

## 확인 범위

- GitHub 공개 Actions API에서 최신 취소 실행과 직전 성공 실행의 단계별 시간을 비교했다.
- 고정된 `actions/deploy-pages` 리비전의 공식 `action.yml`에서 `timeout` 입력 단위가 밀리초임을 확인했다.
- 워크플로 YAML 파싱과 `git diff --check`만 수행했으며 실제 재배포는 push 이후 GitHub Actions에서 확인해야 한다.
