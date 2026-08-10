# M-WAF Agent 지속 연결·단독 업데이트 구현 계획

## 1. 목표

최초 설치 명령으로 한 번 등록된 Agent가 이후에는 설치 토큰을 다시 사용하지 않고 지속적으로 Manager와 연결되며, 로컬 개발 Manager의 서버 상세 화면에서 새 Agent 버전을 확인하고 업데이트·롤백할 수 있게 한다.

운영 흐름은 다음으로 고정한다.

`최초 등록 → mTLS 지속 연결 → 새 Agent bundle 게시 → Manager에서 업데이트 예약 → Agent polling → 서명 DEB 교체 → Agent 재시작 → 새 버전 heartbeat 확인`

다음 원칙을 유지한다.

- Manager가 고객 서버로 접속하거나 포트를 열지 않는다. Agent가 기존 outbound HTTPS polling으로 작업을 가져간다.
- 최초 등록 토큰은 최초 신원 발급에만 사용한다. 이후 연결과 업데이트는 Agent 인증서와 mTLS를 사용한다.
- Agent 업데이트는 웹서버 모듈, CRS 정책, Apache/Nginx 설정과 분리한다.
- 오프라인 서버에도 업데이트를 예약할 수 있고, Agent가 다시 연결되면 이어서 적용한다.
- 고객 서버에 컴파일러나 개발 도구를 설치하지 않는다.
- 배포 파일은 Manager의 서명 bundle과 SHA-256 검증을 통과한 Agent DEB만 허용한다.

## 2. 현재 구현과 부족한 부분

### 이미 구현된 기능

- Agent는 기본 30초 주기로 Manager에 heartbeat, inventory, 정책 상태와 명령 상태를 전송한다.
- 네트워크 오류가 발생해도 Agent 프로세스는 종료하지 않고 다음 주기에 다시 연결한다.
- 최초 등록 이후에는 서버별 mTLS 인증서를 사용하며, 만료 전에 인증서를 자동 갱신한다.
- 호스트에서는 systemd enable/start, Docker/OCI에서는 `mwaf-agent-service` supervisor를 사용한다.
- 패키지 배포에서 Agent 버전이 바뀌면 서명 DEB를 내려받아 설치하고 Agent 서비스를 재시작한다.
- 재시작한 Agent가 heartbeat에서 설치 버전을 다시 보고한 후 배포 완료를 확정한다.

### 현재 부족한 기능

- 패키지 배포가 `Agent + 웹서버 모듈` 한 쌍을 필수로 요구한다.
- 모듈이 아직 없는 최초 등록 서버와 Ubuntu 18.04 Agent-only 서버에는 Agent 단독 업데이트를 예약할 수 없다.
- 서버 상세의 업데이트 버튼도 모듈이 설치된 일부 서버에만 표시된다.
- 로컬 bundle을 새로 만들더라도 실행 중인 Manager는 시작할 때 읽은 catalog를 계속 사용하므로 수동 재시작이 필요하다.
- Agent 코드 변경에 대한 독립적인 버전 원본과 버전 증가 검사 규칙이 없다.
- 컨테이너를 원본 이미지에서 재생성하면 writable layer에 설치한 Agent 바이너리가 사라진다.

## 3. 지속 연결 기준

### 호스트 설치

- 최초 등록 성공 시 생성한 서버 ID, 인증서, 개인키와 Manager CA를 유지한다.
- systemd의 `mwaf-agent.service`를 enable 상태로 두어 서버 재부팅 후 자동 시작한다.
- Manager 장애나 네트워크 단절 중에는 정책 상태와 이벤트 spool을 유지하고 재연결을 반복한다.
- 인증서 갱신 실패만으로 기존 유효 인증서를 즉시 폐기하지 않는다. 다음 polling에서 갱신을 재시도한다.
- 시스템 관리자가 서버 등록을 해제한 경우에만 기존 인증서 연결을 영구 차단한다.

### Docker/OCI 설치

- 실행 중인 컨테이너에서는 supervisor가 Agent 종료를 감지해 다시 실행한다.
- 컨테이너 restart 후에는 기존 entrypoint에서 `/usr/sbin/mwaf-agent-service start`를 실행해야 한다.
- 컨테이너 recreate까지 유지하려면 Agent DEB를 포함한 파생 이미지를 사용하고 다음 상태를 volume으로 보존한다.
  - `/etc/mwaf-agent`
  - `/var/lib/mwaf-agent`
  - `/etc/mwaf`
  - `/opt/m-waf`
- 원본 이미지에 Agent 바이너리가 없는 상태에서 volume만 보존하는 방식은 지원하지 않는다. 이 제한을 설치 완료 화면과 서버 상세에 명확히 표시한다.
- 파생 이미지가 이전 Agent 버전을 포함해도 보존된 mTLS 신원으로 연결한 뒤 최신 Agent를 다시 적용할 수 있게 한다.

## 4. Agent 버전 관리 지침

### 버전 원본

- `packaging/agent/VERSION` 한 줄을 Agent 버전의 원본으로 추가한다.
- 형식은 `MAJOR.MINOR.PATCH`만 허용한다.
- Manager, 웹서버 모듈과 Agent의 버전을 분리한다. Agent 코드만 바뀐 경우 모듈 버전과 모듈 파일은 변경하지 않는다.
- 동일한 정식 Agent 버전에 서로 다른 바이너리 SHA-256을 다시 게시하지 않는다.

### 증가 기준

| 변경 유형 | 증가 | 예시 |
|---|---|---|
| 버그 수정, 재시도·로그·성능 개선 | PATCH | `0.1.0 → 0.1.1` |
| 하위 호환 inventory, capability, 명령 추가 | MINOR | `0.1.1 → 0.2.0` |
| 기존 Manager 또는 설정과 호환되지 않는 변경 | MAJOR | `0.2.0 → 1.0.0` |
| 테스트·주석·문서만 변경 | 없음 | 버전 유지 |

Agent 영향 경로는 최소한 다음을 포함한다.

- `cmd/mwaf-agent/**`
- `internal/agent/**`
- Agent가 사용하는 `internal/config`, `internal/model`, `internal/protocol` 변경
- `packaging/agent/**`
- Agent 바이너리에 포함되는 의존성이 달라지는 `go.mod`, `go.sum`

### 개발 버전

- 로컬 빌드는 `0.2.0~dev.YYYYMMDDHHMMSS.<commit>`처럼 정식 버전에 개발 suffix를 붙인다.
- dirty worktree에서도 같은 버전과 다른 바이트가 충돌하지 않도록 빌드 시각과 소스 digest를 metadata에 기록한다.
- 정식 태그 bundle은 suffix 없는 `packaging/agent/VERSION` 값을 사용한다.
- CI는 Agent 영향 경로가 변경됐는데 `packaging/agent/VERSION`이 기준 브랜치보다 증가하지 않으면 실패한다.
- CI 검사는 표준 셸과 기존 Go 코드만 사용하며 새 버전 라이브러리를 추가하지 않는다.

### 개발자 작업 순서

1. Agent 코드를 수정한다.
2. 변경 호환성에 따라 `packaging/agent/VERSION`을 증가시킨다.
3. `docs/agent-releases/<version>.md`에 변경 내용, 호환 Manager, 롤백 주의사항을 기록한다.
4. `make agent-check`로 Agent 단위 테스트, vet, Linux amd64 빌드와 DEB 설치 검사를 수행한다.
5. `make dev-agent-bundle`로 Agent만 새 버전으로 빌드하고 기존 모듈 artifact를 그대로 유지한 로컬 서명 bundle을 만든다.
6. 로컬 Manager의 **보호 서버 → 서버 상세 → 패키지**에서 새 버전을 확인한다.
7. **Agent 업데이트**를 누르고 재시작 후 보고된 버전과 배포 결과를 확인한다.
8. 실패 시 같은 화면의 **Agent 롤백**으로 직전 검증 버전을 적용한다.

## 5. 로컬 개발 bundle 흐름

### 새 명령

- `make agent-check`: Agent 관련 테스트와 패키지 정적 검증만 수행
- `make dev-agent-bundle`: Agent 바이너리와 Agent DEB만 새 버전으로 생성
- 기존 `make dev-bundle`: Agent와 모듈을 함께 검증해야 할 때 사용

### bundle 구성

- 새 Agent artifact는 현재 개발 소스에서 빌드한다.
- Apache/Nginx 모듈 artifact와 CRS source는 현재 검증된 base bundle에서 그대로 복사한다.
- Agent artifact ID, version, SHA-256과 대상 OS metadata만 새로 생성한다.
- 개발 서명키로 전체 bundle을 다시 서명하고 검증한 뒤에만 활성화한다.
- bundle 게시 경로는 고정된 `dev-bundle-active` symlink를 사용하고 새 bundle로 원자적으로 교체한다.
- Manager 개발 watcher는 활성 manifest 변경을 감지해 DB migration 없이 Manager 프로세스만 재시작한다.
- 브라우저 새로고침 후 최신 Agent version이 바로 표시되어야 한다.

## 6. Agent 단독 업데이트 인터페이스

### 요청 모델

기존 `PackageDeployment`을 하위 호환으로 확장한다.

- `scope`: `agent` 또는 기존 `agent_module`
- `agent`: 필수
- `module`: `agent` scope에서는 생략 가능
- `rollback_agent`: 자동 복구에 사용할 직전 검증 Agent artifact

기존 Agent는 `scope`가 없는 요청을 현재의 `agent_module` 배포로 처리한다. Manager는 capability가 없는 Agent에 Agent-only 요청을 보내지 않는다.

Inventory에는 다음 capability를 추가한다.

- `agent-self-update-v1`
- `agent-local-rollback-v1`

Inventory는 기존 JSON column에 저장되므로 capability 자체를 위한 새 DB column은 만들지 않는다.

### Manager 저장 구조

- DB 스키마와 기존 `package_deployments` 호환성을 유지한다.
- Agent-only 여부는 배포 plan의 `scope=agent`로 구분한다.
- 필수인 `module_package_id`에는 현재 적용 중인 모듈 ID를 그대로 기록하고, Agent-only 실행에서는 모듈을 내려받거나 적용하지 않는다.
- `desired_states.agent_package_id`만 새 ID로 갱신하고 기존 `module_package_id`는 그대로 유지한다.
- Agent-only update가 module 상태, policy revision, 설치 유형과 웹서버 제어 방식을 변경하지 않게 한다.
- 오프라인 Agent의 PENDING 요청은 다른 요청으로 대체되거나 서버가 등록 해제될 때까지 유지한다.

### Manager API

- `POST /servers/{id}/agent-package`
  - `operation=update`
  - `operation=rollback`
- 기존 CSRF, 기업 범위, 실제 서버 소유권과 관리자 조작 권한 검증을 유지한다.
- update는 `ResolveAgent(inventory)`로 현재 OS/architecture용 최신 Agent만 선택한다.
- rollback은 현재 Agent artifact의 `rollback_id`를 사용한다.
- 최신 버전과 현재 버전이 같으면 중복 배포를 만들지 않는다.
- 명시적 rollback이 아닌 요청에서 낮은 정식 버전으로 내려가는 것을 차단한다.
- Agent 다운로드는 기존 mTLS `/agent/v1/packages/{id}`와 서버별 assigned-package 검증을 재사용한다.

## 7. Agent 적용 절차

Agent-only 배포를 받으면 다음 순서로 처리한다.

1. deployment ID가 이미 완료·실패 처리됐는지 확인한다.
2. target Agent와 rollback Agent metadata를 검증한다.
3. mTLS로 target DEB를 내려받고 catalog SHA-256을 확인한다.
4. 웹서버 모듈, 정책 파일과 Apache/Nginx 설정을 건드리지 않는다.
5. 기존 config/state/spool을 유지한 채 Agent DEB만 설치한다.
6. 독립 updater helper가 Agent 서비스를 재시작한다.
7. 새 Agent가 같은 서버 ID와 인증서로 Manager에 연결한다.
8. heartbeat의 `agent_version`이 target과 일치하면 APPLIED를 보고한다.
9. 제한 시간 안에 새 heartbeat가 없거나 프로세스가 반복 실패하면 캐시한 rollback DEB를 설치하고 서비스를 다시 시작한다.
10. rollback 결과도 Manager에 별도 상태와 상세 사유로 기록한다.

업데이트 helper는 Agent 프로세스와 분리된 고정 경로에서 실행한다. Agent가 자기 자신을 종료한 이후에도 재시작 확인과 로컬 롤백을 수행할 수 있어야 한다.

## 8. 관리자 화면

서버 상세의 **패키지** 탭을 Agent와 웹서버 모듈 영역으로 분리한다.

### Agent 영역

- 현재 보고 버전
- Manager bundle 최신 버전
- 상태: 최신 / 업데이트 가능 / 예약됨 / 적용 중 / 실패 / 롤백됨
- 마지막 heartbeat와 연결 상태
- `Agent 업데이트`
- `Agent 롤백`

Agent 업데이트 버튼은 모듈 설치 전 `PLAN_REQUIRED` 서버와 Ubuntu 18.04 Agent-only 서버에도 표시한다.

- 온라인: 다음 polling에서 적용 안내
- 오프라인: 재연결 시 적용되는 예약임을 안내
- capability 없음: `Agent 단독 업데이트 1회 전환 필요` 안내
- catalog에 호환 Agent 없음: 버튼 비활성화와 OS/architecture 사유 표시
- 이미 최신: 버튼 대신 `최신 버전` 표시

### 웹서버 모듈 영역

- 현재 설치 유형, 모듈 버전, Connector와 configtest 상태를 표시한다.
- 기존 패키지 기반/커스텀 ZIP 설치와 모듈 롤백 기능을 유지한다.
- Agent 업데이트를 눌렀을 때 모듈 버전이나 웹서버 reload가 바뀌지 않음을 명시한다.

## 9. 기존 Agent 전환

현재 배포된 Agent는 Agent-only deployment 형식을 알지 못하므로 최초 전환 경로가 필요하다.

- 모듈이 설치된 기존 서버: 현재의 Agent+module 배포로 self-update capability가 포함된 첫 Agent까지 갱신한다.
- 모듈이 없는 Ubuntu 18.04/최초 등록 서버: 기존 mTLS 신원을 재사용하는 `installer.sh --upgrade-agent` 1회 전환 명령을 제공한다.
- 전환 명령은 새 등록 토큰을 요구하거나 새 서버를 만들지 않는다.
- 전환 완료 후에는 모든 후속 업데이트를 Manager 버튼으로 수행한다.
- Manager UI는 Agent capability를 기준으로 버튼 또는 1회 전환 안내 중 하나만 보여준다.

## 10. 실패와 복구

- 다운로드·SHA 검증 실패: 기존 Agent를 유지하고 FAILED 보고
- DEB 설치 실패: 기존 서비스 상태를 확인하고 package manager 결과를 제한된 길이로 기록
- 재시작 실패: updater helper가 rollback DEB 적용
- 새 Agent heartbeat 불일치: 자동 rollback 후 기대/실제 버전을 기록
- Manager 단절: helper의 로컬 timeout으로 판단하고 기존 Agent로 rollback
- 업데이트 중 Manager 재시작: DB의 deployment ID와 Agent 상태 파일로 이어서 처리
- 같은 업데이트 재수신: 동일 deployment ID는 재설치하지 않고 기존 결과를 다시 보고
- 서버 등록 해제: 다운로드와 desired-state 조회 모두 거부

## 11. 테스트 및 검수

### 단위·서버 테스트

- `ResolveAgent`가 OS/architecture별 최신 Agent와 rollback Agent를 정확히 선택하는지 확인
- module ID가 없는 Agent-only deployment를 저장·조회할 수 있는지 확인
- Agent-only update가 기존 module package ID와 policy revision을 유지하는지 확인
- 일반 기업 관리자가 다른 기업 서버에 업데이트를 예약할 수 없는지 확인
- CSRF, 중복 배포, downgrade, revoked 서버가 차단되는지 확인
- capability가 없는 Agent에는 Agent-only 요청이 생성되지 않는지 확인
- Agent 코드 변경 시 VERSION 미증가가 CI에서 실패하는지 확인

### Agent 테스트

- 통신 실패 후 프로세스가 종료되지 않고 재연결하는지 확인
- 인증서 자동 갱신 후 같은 서버 ID로 계속 연결되는지 확인
- Agent DEB만 교체하고 module/policy/config 파일 SHA가 유지되는지 확인
- systemd와 systemd-free container supervisor에서 재시작되는지 확인
- target 버전 heartbeat 후 APPLIED가 한 번만 보고되는지 확인
- 새 Agent 시작 실패 시 rollback Agent가 다시 연결되는지 확인
- 동일 deployment 재수신이 재설치를 만들지 않는지 확인

### 로컬 통합 검수

1. 기존 Agent를 Manager에 등록한다.
2. Agent 코드를 수정하고 VERSION을 증가시킨다.
3. `make dev-agent-bundle`을 실행한다.
4. Manager가 자동 재시작되고 서버 상세에 새 버전이 표시되는지 확인한다.
5. `Agent 업데이트`를 누른다.
6. 다음 polling에서 다운로드·설치·재시작이 진행되는지 확인한다.
7. 같은 서버 ID로 재연결되고 화면의 현재 버전이 변경되는지 확인한다.
8. 모듈 버전, 정책 revision과 웹서버 프로세스가 변경되지 않았는지 확인한다.
9. Agent rollback을 실행해 직전 버전으로 복귀하는지 확인한다.
10. Agent를 오프라인으로 만든 뒤 업데이트를 예약하고, 재연결 후 적용되는지 확인한다.

### 컨테이너 검수

- Agent 포함 파생 이미지와 identity/state volume으로 container restart 후 자동 연결 확인
- 이전 Agent가 포함된 이미지 recreate 후 최신 Agent 재적용 확인
- volume만 있고 Agent 바이너리가 없는 원본 이미지 recreate는 명확한 오류로 안내되는지 확인

## 12. 구현 순서

1. Agent VERSION 원본, 개발 suffix와 CI version-bump guard 추가
2. DB 스키마를 유지하는 Agent-only deployment 모델 추가
3. Manager 저장·API·catalog update/rollback 선택 구현
4. Agent capability와 Agent-only 적용·재시작·결과 보고 구현
5. updater helper와 자동 로컬 rollback 구현
6. 서버 상세 Agent/모듈 UI 분리
7. `make agent-check`, `make dev-agent-bundle`, 활성 bundle 자동 reload 구현
8. 기존 Agent의 `--upgrade-agent` 전환 경로 추가
9. 단위·패키지·로컬 mTLS 통합·컨테이너 테스트 추가
10. 개발 지침과 운영 업데이트/복구 문서 확정

## 13. 완료 기준

- 최초 등록 후 토큰 없이 mTLS로 지속 연결되어야 한다.
- Manager가 중단됐다가 복구돼도 Agent가 자동 재연결되어야 한다.
- 모듈이 없는 서버에서도 Agent 단독 업데이트가 가능해야 한다.
- 로컬 Agent 코드 변경과 버전 증가 후 Manager 화면에서 새 버전이 보여야 한다.
- 업데이트 버튼이 Agent만 교체하고 웹서버 모듈·정책·설정을 변경하지 않아야 한다.
- 재시작 후 같은 서버 ID로 새 버전을 보고해야 한다.
- 실패한 Agent 업데이트는 로컬 rollback으로 기존 Agent 연결을 복구해야 한다.
- 오프라인 서버의 예약이 재연결 후 적용되어야 한다.
- 기존 Agent의 1회 전환 경로와 컨테이너 recreate 제한이 문서와 화면에 명확히 표시되어야 한다.

## 14. 구현 안전 범위

- DB migration, init, reset을 수행하지 않는다.
- 프론트엔드 빌드를 수행하지 않는다.
- 운영 서버의 Agent 업데이트 버튼을 임의로 실행하지 않는다.
- Agent 단독 업데이트에서 웹서버 모듈, 정책, Apache/Nginx 설정을 변경하지 않는다.
- 현재 작업 트리의 다른 변경 파일을 수정하거나 정리하지 않는다.
