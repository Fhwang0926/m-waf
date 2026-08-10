# M-WAF LAN Agent 설치 시험 주소 노출 완료

## 작업 목적

로컬 개발 Manager를 같은 LAN 또는 VPN의 원격 Ubuntu 서버에서 접근할 수 있도록 `192.168.7.10:8443`에 노출하고 Agent 설치 시험에 필요한 TLS 주소를 구성했다.

## 반영 내용

- 개발 Manager 바인딩을 `192.168.7.10`으로 변경했다.
- 컨테이너 배포 바인딩도 동일한 IP로 맞췄다.
- Manager 공개 URL을 `https://192.168.7.10:8443`으로 설정했다.
- 개발 시작 안내의 관리자 UI 주소도 하드코딩된 localhost 대신 Manager 공개 URL을 표시하도록 정리했다.
- 기존 M-WAF CA는 유지하고 Manager 서버 인증서에 `192.168.7.10` IP SAN을 추가했다.
- 새 인증서는 기존 `localhost`, `127.0.0.1` SAN도 유지한다.
- 교체 전 Manager 인증서와 개인키를 `deploy/compose/secrets/backup-2026-08-09-before-192.168.7.10`에 보관했다.

## 실행 확인

- 사용자가 개발 Manager를 재시작했다.
- Manager가 `192.168.7.10:8443`에서 수신하는 것을 확인했다.
- M-WAF CA를 사용한 `https://192.168.7.10:8443/health/ready` 요청이 `ready`로 응답했다.
- 로그인 화면과 `/bootstrap/v1/install.sh`가 모두 HTTP 200으로 응답했다.
- Manager 인증서의 CA 서명과 `192.168.7.10` IP 일치를 확인했다.
- macOS 애플리케이션 방화벽은 비활성 상태임을 확인했다.

## 원격 시험 조건

- 원격 서버가 `192.168.7.10`으로 라우팅 가능한 같은 LAN 또는 VPN에 있어야 한다.
- 원격 서버에는 M-WAF 공개 CA 인증서를 안전하게 복사하고 `curl --cacert`로 준비 상태를 먼저 확인한다.
- Manager의 서버 설치 화면에서 생성한 명령은 `https://192.168.7.10:8443`을 Manager 주소로 사용한다.
- 설치 토큰은 명령 인자에 넣지 않고 `--install-token-stdin`으로 입력한다.

## 수행하지 않은 검증

- 실제 원격 서버에서의 Agent·ModSecurity 설치는 수행하지 않았다.
- 프로젝트 지침에 따라 별도 빌드와 자동 테스트는 수행하지 않았다.
- DB 조회·직접 변경, init, reset 작업은 수행하지 않았다.
