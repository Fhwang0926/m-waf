# M-WAF systemd 없는 컨테이너 Agent 지원 완료

## 반영 내용

- 기존 Ubuntu 24.04·Debian 12 일반 서버는 systemd 서비스를 그대로 사용한다.
- 설치 스크립트가 Docker/OCI 컨테이너를 자동 감지한다.
  - systemd가 없는 컨테이너라고 설치를 차단하지 않는다.
  - systemd 또는 추가 런타임 패키지를 설치하지 않는다.
  - 서명된 Agent DEB만 설치한 뒤 패키지에 포함된 컨테이너 감독 프로세스를 시작한다.
- 호스트와 컨테이너가 함께 사용하는 `/usr/sbin/mwaf-agent-service`를 Agent DEB에 추가했다.
  - 일반 서버에서는 기존 systemd unit을 제어한다.
  - systemd 없는 컨테이너에서는 경량 감독 프로세스를 제어한다.
  - `start`, `status`, `restart`, `stop`만 제공한다.
  - Agent가 비정상 종료하면 5초 후 다시 실행한다.
  - PID 파일이 가리키는 프로세스 명령을 확인해 다른 프로세스를 종료하지 않는다.
  - 로그는 가능하면 컨테이너 stdout/stderr로 전달하고, 불가능할 때만 `/var/log/mwaf-agent/agent.log`를 사용한다.
- Agent 패키지 업데이트와 Manager의 Agent 재시작·중지 명령이 systemd 또는 컨테이너 감독 프로세스를 현재 환경에 맞게 선택한다.
- systemd 없는 컨테이너에서는 호스트 재부팅·종료 명령을 지원하지 않는 명령으로 처리한다.
- 제거 시 컨테이너 감독 프로세스도 먼저 중지한다.
- 서버 설치 화면에 일반 서버와 Docker 실행 환경 자동 감지를 표시했다.
- 컨테이너 재시작·재생성 시 필요한 시작 명령, 영속 볼륨과 이미지 보안 기준을 README와 커스텀 웹서버 문서에 추가했다.

## 컨테이너 운영 경계

- 최초 설치는 현재 컨테이너의 writable layer에 Agent 바이너리를 설치한다.
- 같은 컨테이너 재시작 시 기존 웹서버 시작 절차 앞에서 `/usr/sbin/mwaf-agent-service start`를 실행해야 한다.
- `/etc/mwaf-agent`, `/var/lib/mwaf-agent`, `/etc/mwaf`, `/opt/m-waf`와 ModSecurity audit log를 볼륨으로 보존해야 한다.
- 원본 이미지로 재생성하면 설치된 Agent 바이너리도 사라지므로 동일한 검증 DEB가 포함된 파생 이미지를 사용해야 한다.
- 등록 토큰, Agent 개인키와 인증서는 이미지에 넣지 않는다.
- Agent sidecar는 보호 대상 웹서버의 프로세스·파일을 직접 점검할 수 없으므로 추가하지 않았다.

## 확인 결과

- `sh -n internal/manager/bootstrap-install.sh`: 성공
- `sh -n packaging/agent/container/mwaf-agent-service`: 성공
- `sh -n packaging/agent/mwaf-uninstall`: 성공
- `git diff --check`: 성공
- `go test ./internal/agent ./internal/manager ./internal/config`: 성공
- 로컬 서명 개발 번들 생성 및 검증: 성공
  - `.local/mwaf-manager/dev-bundles/dev-20260810015737-8b29ea03f140`
- systemd 없는 Ubuntu 24.04 임시 컨테이너 검증: 성공
  - Agent DEB 설치
  - `/usr/sbin/mwaf-agent-service` 시작·상태 확인·재시작·중지
  - 제거한 긴 컨테이너 전용 명령이 DEB에 남지 않았는지 확인
- 격리된 systemd 분기 검증: 성공
  - 동일한 `/usr/sbin/mwaf-agent-service` 명령이 `enable/start`, `status`, `restart`, `stop`을 기존 systemctl unit으로 전달하는지 확인
- 로컬 Manager를 위 개발 번들로 실행하고 다음을 확인했다.
  - `https://192.168.7.10:8443/health/live`: 정상
  - `/bootstrap/v1/install.sh`: 컨테이너 감지와 컨테이너 Agent 시작 경로 포함

## 수행하지 않은 검증

- 프론트엔드 빌드는 수행하지 않았다.
- DB init/reset/migration은 수행하지 않았다.
- 새 등록 토큰을 사용한 실제 고객 컨테이너의 Manager 등록은 수행하지 않았다.
- Apache/Nginx 모듈 설치, 설정 반영, configtest와 reload는 수행하지 않았다.
- 컨테이너 재생성용 고객별 파생 이미지는 웹서버 이미지와 시작 명령이 정해져야 하므로 임의 생성하지 않았다.
