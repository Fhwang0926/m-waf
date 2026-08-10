# 컨테이너 Agent 설치 출력·로그 개선 완료

## 반영 내용

- 컨테이너 supervisor 실행에서 `nohup`을 제거하고 HUP을 무시하는 분리 셸 프로세스를 사용하도록 변경했다.
- PID 1의 stdout/stderr가 터미널이어도 설치 작업 디렉터리에 `nohup.out`을 생성하지 않는다.
- bootstrap 최초 설치·레거시 전환·Manager 자기 업데이트·자동 롤백의 로컬 DEB 설치에 `APT::Sandbox::User=root`를 적용했다.
- 이 설정은 Manager가 서명과 SHA-256을 검증해 내려준 로컬 파일에만 사용하며 root 전용 상태·임시 디렉터리 권한은 완화하지 않는다.
- Agent DEB control에 실제 KiB 단위 `Installed-Size`를 추가했다.
- Agent 패키지 변경에 따라 버전을 0.3.1로 올리고 릴리스 노트를 추가했다.

## 검증 범위

- `make agent-check`와 `go test ./internal/manager`를 통과했다.
- Go vet, 셸 문법과 diff 검사를 통과했다.
- 로컬 서명 Agent `0.3.1~dev.20260810140156.291e8245183d` bundle을 생성했다.
- DEB control에서 `Installed-Size: 7316`을 확인했다.
- TTY가 연결된 깨끗한 Ubuntu 24.04 컨테이너에서 로컬 DEB 설치를 실행해 다음을 확인했다.
  - `_apt`의 `unsandboxed as root` 경고가 발생하지 않음
  - 설치 전 예상 디스크 사용량이 `7492 kB`로 표시됨
  - supervisor 시작·상태 확인·중지 정상
  - 컨테이너 루트에 `nohup.out`이 생성되지 않음
- DB init/reset/migration과 프론트엔드 빌드는 수행하지 않는다.

## 별도 확인 항목

- 실제 고객 컨테이너의 재설치는 운영자가 새 0.3.1 설치 명령으로 확인한다.
- 기존 컨테이너에 이미 만들어진 `nohup.out`은 자동 삭제하지 않는다.
