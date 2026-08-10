# M-WAF 구형 Agent·Ubuntu 18.04 설치 흐름 개선 계획

## 1. 현재 문제

현재 화면은 다음 두 문제를 동시에 보여주지만 사용자가 실제로 무엇을 해야 하는지 안내하지 못한다.

1. 기존 Agent가 자기 업데이트 capability를 지원하지 않는다.
2. 현재 Manager가 사용 중인 bundle에 Ubuntu 18.04 amd64용 최신 Agent가 없다.
3. Ubuntu 18.04 배포판 Apache에는 지원되는 모듈 DEB가 없다.
4. 호환 Agent와 모듈이 없는데도 설치 폼과 비활성 버튼이 계속 표시된다.
5. 로컬 개발 bundle에는 Ubuntu 18.04 Agent가 있어도 실행 중인 Manager가 다른 bundle을 사용하면 이를 화면에서 구분할 수 없다.
6. 배포판 웹서버로 감지되면 호환 DEB가 없는 경우에도 커스텀 ZIP 대체 경로를 선택할 수 없다.

따라서 사용자는 `Manager bundle 반영`, `Agent 1회 전환`, `운영체제 업그레이드 또는 커스텀 ZIP 준비` 중 어떤 작업이 먼저인지 알기 어렵다.

## 2. 개선 목표

- 화면 상단에서 지금 수행할 수 있는 한 가지 작업을 명확히 안내한다.
- Agent 공급 상태와 웹서버 모듈 호환 상태를 별도로 판정한다.
- 실행할 수 없는 명령과 설치 버튼을 노출하지 않는다.
- 기존 서버 ID, mTLS 인증서, 정책, 로그와 웹서버 설정을 유지한다.
- Ubuntu 18.04의 지원 범위를 Agent 설치·점검으로 유지한다.
- Ubuntu 18.04에서 보호 활성화가 필요하면 OS 업그레이드 또는 exact-match 커스텀 ZIP 경로를 제공한다.
- 기업 관리자에게 개발·배포 명령을 노출하지 않고, 시스템 관리자에게만 bundle 조치 정보를 제공한다.
- DB 스키마와 기존 등록·Agent polling 구조는 변경하지 않는다.

## 3. 목표 운영 흐름

```text
서버 등록 상태 확인
→ 호환 Agent artifact 확인
→ 구형 Agent 1회 전환
→ 새 Agent heartbeat와 capability 확인
→ 웹서버·빌드 정보 확인
→ 설치 유형 결정
   ├─ 지원 OS + 배포판 웹서버: 모듈 DEB
   ├─ exact-match ZIP 있음: 커스텀 ZIP
   └─ 둘 다 없음: OS 업그레이드 또는 ZIP 제작 안내
→ 모듈 설치
→ 운영자가 전용 설정 include
→ configtest·정책 적용·보호 확인
```

Agent가 자기 업데이트 가능한 버전으로 전환되기 전에는 모듈 설치를 시작하지 않는다.

## 4. 호환 상태 판정 개선

문자열 오류를 화면에서 해석하지 않고 Manager가 다음 상태 코드를 계산한다.

### Agent 상태

- `AGENT_READY`: 자기 업데이트와 로컬 롤백 capability 확인
- `AGENT_TRANSITION_REQUIRED`: 구형 Agent이며 호환 Agent artifact 존재
- `AGENT_ARTIFACT_MISSING`: 구형 Agent지만 활성 bundle에 호환 Agent 없음
- `AGENT_UPDATE_PENDING`: Agent 전환 또는 업데이트 예약됨
- `AGENT_UPDATE_FAILED`: 적용 또는 재연결 실패

### 모듈 상태

- `MODULE_PACKAGE_READY`: 지원 OS의 모듈 DEB 사용 가능
- `MODULE_CUSTOM_ZIP_READY`: 웹서버 빌드 해시와 정확히 일치하는 서명 ZIP 사용 가능
- `MODULE_DISTRO_UNSUPPORTED`: Ubuntu 18.04처럼 배포판 모듈 DEB를 지원하지 않음
- `MODULE_CUSTOM_ZIP_MISSING`: 커스텀 설치가 필요하지만 exact-match ZIP 없음
- `MODULE_INTEGRATION_REQUIRED`: 파일 설치 후 운영자 include 필요
- `MODULE_PROTECTED`: configtest와 정책 적용 확인

이 상태는 기존 Inventory와 bundle catalog에서 요청 시 계산한다. 별도 DB column이나 migration을 추가하지 않는다.

## 5. 관리자 화면 개선

### 공통 상단 안내

진행 단계 위에 `현재 해야 할 일` 카드를 추가한다.

예시:

```text
현재 해야 할 일
Manager에 Ubuntu 18.04 amd64용 Agent가 준비되지 않았습니다.
시스템 관리자에게 Agent 패키지 반영을 요청하세요.
```

한 번에 하나의 우선 작업만 강조하고 후속 단계는 대기 상태로 표시한다.

### 기업 관리자 화면

- 활성 bundle 내부 구조나 개발 명령을 표시하지 않는다.
- `시스템 관리자에게 패키지 준비 요청` 상태를 표시한다.
- 복사 가능한 진단 정보에는 다음 항목만 포함한다.
  - 서버명
  - OS와 architecture
  - Agent 현재 버전
  - 웹서버 종류·버전·빌드 해시
  - 필요한 artifact 종류
- 호환 artifact가 준비되면 `1회 전환 명령 복사`를 표시한다.
- Agent 전환 전에는 모듈 설치 폼을 접고 `Agent 전환 후 선택할 수 있습니다`로 표시한다.

### 시스템 관리자 화면

- 활성 Manager bundle 버전과 source를 표시한다.
- 필요한 대상 tuple을 표시한다.
  - `agent / ubuntu / 18.04 / amd64`
  - `module / apache / ubuntu / 18.04 / amd64`
- Agent artifact가 저장소에는 있지만 활성 Manager가 읽지 못하는 경우 `Manager bundle 재반영 필요`로 구분한다.
- 개발 환경에서는 로컬 bundle 갱신 절차를 안내한다.
- 배포 환경에서는 태그 이미지 배포와 Manager 재시작 필요 상태를 안내한다.
- 화면에서 임의 빌드나 서명키 사용 명령을 실행하지 않는다.

### 모듈 선택 화면

호환 DEB가 없는 경우 기존 패키지 설치 폼을 비활성 상태로 계속 보여주지 않는다.

대신 다음 두 경로를 표시한다.

1. `지원 운영체제로 업그레이드` — 권장
   - Ubuntu 24.04 LTS 또는 Debian 12
   - 패키지 기반 Agent·모듈 설치 지원
2. `커스텀 ZIP 준비`
   - 현재 Apache 2.4.29 빌드와 정확히 일치하는 Connector 필요
   - ZIP은 서명된 bundle artifact로만 공급
   - `/opt/m-waf` 아래에만 설치
   - OS 의존성 패키지 설치 금지
   - 고객 Apache 설정 자동 수정 금지

## 6. 구형 Agent 1회 전환

### 준비 조건

- 활성 Manager catalog에 같은 OS·버전·architecture용 Agent artifact가 정확히 하나 있어야 한다.
- 설치 스크립트 SHA-256을 확인할 수 있어야 한다.
- 서버의 기존 ID와 mTLS 인증서가 유효해야 한다.

### 실행 흐름

1. Manager가 호환 Agent 존재 여부를 확인한다.
2. 존재할 때만 전환 명령과 복사 버튼을 표시한다.
3. 전환 명령은 기존 서버 ID와 mTLS 인증서를 사용한다.
4. Agent DEB만 교체하고 Agent 서비스를 한 번 재시작한다.
5. 새 heartbeat에 `agent-self-update-v1`, `agent-local-rollback-v1`이 나타나는지 확인한다.
6. 같은 서버 항목에서 현재 버전이 갱신되면 Agent 단계를 완료한다.
7. 이후 업데이트는 Manager 버튼과 로컬 롤백 경로를 사용한다.

최초 전환 실패 시 기존 Agent 자체에는 자동 롤백 capability가 없으므로, 전환 명령은 설치 전 기존 Agent DEB와 설정 보존 여부를 확인하고 실패 시 복구 안내를 출력해야 한다.

## 7. Ubuntu 18.04 모듈 처리

### 기본 정책

- Ubuntu 18.04 배포판 모듈 DEB는 생성하지 않는다.
- Agent 설치·등록·환경 점검과 Agent 자체 업데이트만 지원한다.
- 보호 활성화 기본 권고는 Ubuntu 24.04 또는 Debian 12 업그레이드다.

### 커스텀 ZIP 대체 경로

PackageManaged 웹서버라도 모듈 DEB가 없으면 exact-match ZIP을 대체 선택지로 허용한다.

허용 조건:

- Agent Inventory가 보고한 웹서버 종류, 버전과 빌드 해시가 모두 존재한다.
- ZIP metadata의 `web_server`, `web_server_version`, `web_server_build_hash`, architecture가 모두 일치한다.
- 서명과 SHA-256 검증이 성공한다.
- 설치 루트가 `/opt/m-waf`다.
- 임의 command 입력을 받지 않는다.
- configtest와 reload는 기존 표준 제어 또는 고정 Hook 경로만 사용한다.

ZIP이 없으면 설치 버튼을 만들지 않고 `이 빌드용 ZIP이 필요합니다`와 빌드 식별 정보만 표시한다.

## 8. Manager와 bundle 개선

### 개발 환경

- `make dev-agent-bundle`이 Ubuntu 18.04 Agent와 직전 rollback Agent를 생성·검증한다.
- 활성 bundle 링크 변경을 Manager watcher가 감지한다.
- Manager가 실제로 읽는 bundle version을 화면과 health 정보에 표시한다.
- 로컬에 새 bundle이 있어도 실행 Manager가 이전 bundle을 읽으면 명시적으로 경고한다.

### 태그 배포 환경

- 태그에서만 Manager 이미지를 생성한다는 기존 원칙을 유지한다.
- 게시 이미지에 Ubuntu 18.04 Agent artifact 포함 여부를 검증한다.
- Ubuntu 18.04 모듈 DEB가 0개인지 검증한다.
- 배포 후 Manager catalog에서 대상 Agent 해석을 확인한 뒤 전환 버튼을 활성화한다.

### 카탈로그 API

기존 catalog 해석을 재사용하되 UI용 진단 결과를 추가한다.

- Agent 일치 artifact 수
- 배포 가능한 최신 Agent와 rollback Agent
- distro module 지원 여부
- exact-match custom ZIP 존재 여부
- 불가 사유 코드와 운영자용 설명

패키지 파일 다운로드와 배포 권한은 기존 서버별 mTLS와 관리자 권한 검증을 유지한다.

## 9. 설치 API 안전성

- `/servers/{id}/installation`에서 `install_type=custom_zip`을 package-managed 후보에도 허용한다.
- 단, 정확히 일치하는 서명 ZIP이 catalog에 있을 때만 요청을 생성한다.
- 요청의 웹서버 종류와 빌드 해시는 사용자가 임의 입력한 값이 아니라 최신 Inventory 후보와 일치해야 한다.
- Agent 전환이 끝나지 않았으면 모듈 설치 요청을 거부한다.
- 다른 기업 서버 ID와 직접 URL 요청은 기존 enterprise scope로 차단한다.
- CSRF와 확인 checkbox를 유지한다.
- Agent·모듈·정책 상태를 한 작업에서 묶어 변경하지 않는다.

## 10. 테스트 계획

### Manager·템플릿

- 구형 Agent + Agent artifact 없음: 전환 명령이 표시되지 않는지 확인
- 구형 Agent + Agent artifact 있음: 1회 전환 명령만 표시되는지 확인
- 전환 완료 전: 모듈 설치 폼이 차단되는지 확인
- Ubuntu 18.04 distro Apache + DEB 없음: 패키지 설치 버튼이 표시되지 않는지 확인
- exact-match ZIP 없음: 필요한 빌드 식별 정보가 표시되는지 확인
- exact-match ZIP 있음: 커스텀 ZIP 선택이 활성화되는지 확인
- 기업 관리자와 시스템 관리자에게 서로 다른 조치가 표시되는지 확인
- `module_version=unknown`이 미설치로 표시되는지 확인

### Catalog·API

- Ubuntu 18.04 Agent 최신·rollback 해석
- Ubuntu 18.04 distro module 거부
- package-managed Apache의 exact-match ZIP 대체 해석
- 버전 또는 빌드 해시가 다른 ZIP 거부
- Agent capability가 없는 서버의 모듈 설치 요청 거부
- 다른 기업 서버와 revoked 서버 요청 거부

### 로컬 실행 검수

1. 이전 bundle Manager에서 `AGENT_ARTIFACT_MISSING` 확인
2. `make dev-agent-bundle` 실행
3. Manager가 새 활성 bundle을 읽는지 확인
4. 같은 서버 화면에서 1회 전환 명령이 나타나는지 확인
5. 전환 후 동일 서버 ID와 새 capability 확인
6. Ubuntu 18.04 모듈 화면에서 OS 업그레이드와 ZIP 경로가 구분되는지 확인
7. exact-match 테스트 ZIP을 제공했을 때만 설치가 활성화되는지 확인
8. 모듈 설치 전후 고객 Apache 주 설정 파일이 변경되지 않는지 확인

실제 전환·설치 검수는 대상 테스트 서버에서만 수행하고 운영 서버에는 자동 실행하지 않는다.

## 11. 구현 순서

1. Agent·모듈 호환 결과 코드와 화면용 진단 모델 추가
2. 상단 `현재 해야 할 일`과 역할별 안내 추가
3. Agent artifact가 없을 때 전환 명령을 차단하는 현재 동작을 상태 모델에 연결
4. Agent 전환 완료 전 모듈 설치 폼 차단
5. Ubuntu 18.04의 패키지 설치 폼을 OS 업그레이드·ZIP 준비 안내로 교체
6. package-managed 웹서버의 exact-match ZIP 대체 선택 구현
7. 설치 API의 Inventory 일치·서명 ZIP 검증 강화
8. 활성 Manager bundle 버전과 대상 artifact 진단 표시
9. 단위·카탈로그·API·실행 화면 검수
10. README, 커스텀 설치 문서와 당일 완료 문서 갱신

## 12. 완료 기준

- 사용자가 화면만 보고 지금 해야 할 한 가지 작업을 이해할 수 있어야 한다.
- 호환 Agent가 없을 때 실행 불가능한 전환 명령이 표시되지 않아야 한다.
- 구형 Agent 전환이 완료되기 전 모듈 설치를 요청할 수 없어야 한다.
- Ubuntu 18.04에서 지원하지 않는 패키지 설치 버튼이 표시되지 않아야 한다.
- Ubuntu 18.04를 유지할 때 exact-match 서명 ZIP 경로가 명확해야 한다.
- package-managed 웹서버도 호환 DEB가 없으면 검증된 ZIP 대체 경로를 사용할 수 있어야 한다.
- 기업 관리자와 시스템 관리자의 조치 안내가 권한에 맞게 분리되어야 한다.
- 기존 서버 ID, mTLS 인증서, 정책, 로그와 고객 웹서버 설정이 유지되어야 한다.
- DB schema, 등록 토큰, Agent polling과 태그 전용 이미지 게시 원칙이 유지되어야 한다.

## 13. 이번 계획에서 수행하지 않는 작업

- 코드와 UI를 변경하지 않는다.
- DB migration, init, reset을 수행하지 않는다.
- 프론트엔드 빌드를 수행하지 않는다.
- 실제 Agent 전환, 모듈 설치, 웹서버 설정 변경과 reload를 수행하지 않는다.
- Ubuntu 18.04 배포판 모듈 DEB 지원을 새로 추가하지 않는다.
