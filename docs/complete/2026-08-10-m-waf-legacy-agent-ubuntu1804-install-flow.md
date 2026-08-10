# 구형 Agent·Ubuntu 18.04 설치 흐름 개선 완료

## 반영 내용

- Bootstrap 등록 단계는 웹서버 모듈 유무와 분리해 Agent artifact만 확인하도록 변경했다. Ubuntu 18.04는 Agent 설치·등록·환경 점검까지 진행할 수 있다.
- Agent의 `agent-self-update-v1`, `agent-local-rollback-v1` capability가 모두 확인되기 전에는 화면과 설치 API에서 모듈 설치를 차단한다.
- 서버 상세의 설치 탭 상단에 호환 상태 기반 `현재 해야 할 일` 카드를 추가했다.
- 기업 관리자는 개발 명령 대신 복사 가능한 지원 요청 정보를 확인하고, 시스템 관리자 계정은 현재 활성 bundle 버전과 필요한 Agent target을 확인한 뒤 시스템 설정으로 이동할 수 있다.
- `module_version=unknown`과 빈 값은 모듈 미설치로 표시한다.
- 지원되는 배포판 모듈 DEB가 없으면 비활성 설치 폼을 제거하고 다음 두 경로를 안내한다.
  - Ubuntu 24.04 LTS 또는 Debian 12로 업그레이드
  - 현재 웹서버용 exact-match 서명 ZIP 준비
- package-managed Apache/Nginx라도 배포판 모듈 DEB가 없고 정확 일치 ZIP이 있으면 커스텀 ZIP 설치를 선택할 수 있게 했다.
- 커스텀 ZIP은 OS·architecture·웹서버 종류뿐 아니라 웹서버 버전과 빌드 해시가 모두 일치하고 설치 루트가 `/opt/m-waf`일 때만 catalog에서 해석된다.
- `mwaf-module-zip`에 `-webserver-version` 필수 옵션을 추가해 ZIP metadata가 정확 일치 판정에 필요한 값을 포함하도록 했다.
- 고객 Hook은 기존 고정 경로만 사용하고, 임의 명령 입력과 고객 Apache/Nginx 설정 자동 수정은 추가하지 않았다.
- `현재 해야 할 일` 카드에 상태별 순서형 작업 안내를 추가했다. 호환 Agent가 없을 때는 지원 정보 전달, bundle 반영, 새로고침, 등록 유지 재설치 순서를 표시한다.
- 기존 `1회 전환` 문구를 `등록 유지 Agent 재설치`로 명확히 바꾸고, 기존 Agent를 먼저 제거하지 않아야 하는 이유를 화면에 표시한다.
- 신원 파일이 손상된 레거시 Agent에만 사용할 완전 제거·신규 등록 복구 절차를 접힌 안내로 추가했다.
  - Manager에서 기존 서버 등록 해제
  - `mwaf-uninstall --dry-run`으로 영향 확인
  - 승인 후 `mwaf-uninstall --purge`
  - 서버 설치 화면에서 신규 등록
- 완전 제거 시 새 서버 ID가 생성되고 기존 이력이 자동 병합되지 않으며 보호가 일시 중단된다는 경고를 추가했다.
- 컨테이너 supervisor가 `nohup`으로 실행될 때 무시된 SIGHUP 때문에 패키지만 교체되고 이전 Agent 프로세스가 남는 문제를 확인했다.
- 컨테이너의 Agent `restart`를 supervisor 완전 중지·재시작 방식으로 변경하고 Agent 버전을 0.2.1로 올렸다.
- 레거시 전환 완료 API가 새 heartbeat를 기다리는 동안 발생하는 HTTP 409를 사용자 터미널에 반복 출력하지 않도록 변경했다.
- 실제 Ubuntu 18.04 컨테이너에서 0.1.0→0.2.0 DEB 교체는 성공했지만 Manager가 계속 0.1.0 heartbeat를 수신하는 현상으로 위 supervisor 원인을 확인했다.

## 확인 결과

- `go test ./cmd/mwaf-module-zip ./internal/packages ./internal/manager` 통과
- 템플릿 파싱과 다음 화면 회귀 시나리오를 확인했다.
  - 구형 Agent에서 전환 명령 조건부 표시
  - Agent 전환 전 모듈 설치 폼 미표시
  - Ubuntu 18.04 배포판 Apache에서 설치 버튼 대신 OS 업그레이드·ZIP 준비 안내
  - package-managed 웹서버의 exact ZIP 대체 설치 폼
  - `unknown` 모듈 버전의 미설치 표시
- Catalog 테스트에서 웹서버 버전 불일치, 빌드 해시 불일치, `/opt/m-waf` 외 설치 루트를 모두 거부하는지 확인했다.
- 현재 실행 중인 Manager의 Ubuntu 18.04·Apache 2.4.29 서버 화면에서 다음을 확인했다.
  - 호환 Agent가 없는 활성 bundle은 `AGENT_ARTIFACT_MISSING`으로 표시
  - `현재 해야 할 일`과 `지원 요청 정보 복사` 표시
  - 실행 불가능한 1회 전환 명령 미표시
  - Agent 전환 전 모듈 설치 form 0개
  - 패키지 준비부터 등록 유지 재설치까지 3단계 작업 순서 표시
  - 접힌 복구 안내에서 등록 유지 경로와 완전 제거·신규 등록 경로 분리
  - 완전 제거 사전 확인, 신규 서버 ID와 보호 중단 경고 및 위험 작업·서버 설치 링크 표시
  - 브라우저 콘솔 오류 없음
- 수정 후 로컬 서명 Agent 0.2.1 bundle을 생성했고 실행 중인 Manager가 `dev-20260810113802-291e8245183d` 및 Ubuntu 18.04용 0.2.1 Agent를 제공하는 것을 확인했다.
- DB init/reset/migration은 수행하지 않았다.
- 프론트엔드 빌드는 수행하지 않았다.

## 수행하지 않은 검증

- 수정된 0.2.1 package로 실제 Ubuntu 18.04 컨테이너의 Agent 1회 전환 완료
- 실제 커스텀 Connector ZIP 제작·서명·설치
- Apache/Nginx include 반영, configtest와 reload
- 운영 서버 또는 원격 GitHub Actions 실행

위 작업은 서비스와 대상 서버에 영향을 줄 수 있으므로 별도의 테스트 서버와 서명 bundle이 준비된 경우에만 수행한다.
