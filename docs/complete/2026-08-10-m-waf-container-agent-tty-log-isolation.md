# 컨테이너 Agent 터미널 로그 분리 완료

## 원인

- systemd 없는 컨테이너에서 Agent supervisor가 PID 1의 stdout/stderr를 로그 대상으로 사용했다.
- PID 1이 대화형 셸인 검증용 컨테이너에서는 해당 출력이 설치 터미널과 같아, 설치 완료 후 Agent 로그가 프롬프트에 섞였다.

## 반영 내용

- PID 1의 stdout 대상이 `/dev/tty*`, `/dev/pts/*` 또는 `/dev/console`인지 확인한다.
- 대화형 터미널이면 Agent 로그를 `/var/log/mwaf-agent/agent.log`로 분리한다.
- 실제 서비스 컨테이너의 비터미널 stdout/stderr 로깅은 유지한다.
- 일반 서버의 systemd 서비스 실행 방식은 변경하지 않았다.
- 변경된 Agent 패키지를 기존 0.3.1과 구분하도록 버전을 0.3.2로 올리고 릴리스 기록을 추가했다.

## 검증 범위

- 변경 파일의 공백 오류를 확인했다.
- 지침에 따라 Agent 빌드, 패키지 생성, 셸 실행 시험과 실제 컨테이너 재설치는 수행하지 않았다.
