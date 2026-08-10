# M-WAF Agent 지속 업데이트 구현 완료

## 반영 내용

- 최초 등록 이후 기존 서버 ID와 mTLS 인증 정보를 유지하면서 Agent가 Manager에 계속 polling하도록 기존 연결 구조를 유지했다.
- Agent 단독 업데이트 scope와 `agent-self-update-v1`, `agent-local-rollback-v1` capability를 추가했다.
- 서버 상세의 패키지 화면에서 Agent와 웹서버 모듈을 분리하고 Agent 업데이트·롤백 작업을 제공했다.
- 구형 Agent는 새 등록 토큰 없이 기존 mTLS 신원으로 한 번 전환할 수 있게 했다.
- Agent 업데이트가 웹서버 모듈, 정책 revision, Apache/Nginx 설정과 reload를 변경하지 않게 했다.
- 새 Agent가 제한 시간 안에 정상 heartbeat를 보내지 않으면 독립 updater가 직전 서명 Agent DEB로 복구하도록 했다.
- Agent 버전 기준 파일, 변경 이력 문서, 버전 증가 검사와 로컬 Agent 전용 bundle 명령을 추가했다.
- 로컬 bundle의 활성 링크를 Manager watcher가 감지해 DB migration 없이 새 Agent catalog를 반영하도록 했다.
- DB 스키마는 변경하지 않고 기존 배포 레코드의 현재 모듈 ID를 유지해 Agent-only 배포를 기록한다.

## 검수 결과

- 전체 Go 테스트를 통과했다.
- 전체 Go vet와 Agent 버전 증가 검사를 통과했다.
- Agent 설치·updater·로컬 bundle 관련 셸 구문 검사를 통과했다.
- 연속으로 Agent 전용 개발 bundle을 생성하고 각 지원 OS에 직전 Agent rollback artifact가 포함되는지 확인했다.
- Agent 전용 bundle 전환 전후 웹서버 모듈 artifact ID, 버전과 SHA-256이 동일한지 확인했다.
- 실행 중인 로컬 Manager가 활성 bundle 경로를 사용하고 기존 Agent의 heartbeat와 polling을 계속 수신하는 것을 확인했다.
- 현재 Manager의 인증된 서버 상세 화면이 새 패키지 UI로 응답하는 것을 확인했다.

## 수행하지 않은 검증

- 실행 중인 보호 서버의 Agent 업데이트·롤백 버튼은 서비스 재시작을 수반하므로 임의로 누르지 않았다.
- 지침에 따라 프론트엔드 빌드는 수행하지 않았다.
- DB migration, init, reset은 생성하거나 수행하지 않았다.
- GitHub Actions 원격 실행은 수행하지 않았으며 로컬에서 동일한 버전 검사와 테스트 경로를 확인했다.
