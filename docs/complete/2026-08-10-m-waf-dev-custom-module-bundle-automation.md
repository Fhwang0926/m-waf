# 개발용 커스텀 모듈 bundle 자동화 완료

## 반영 내용

- `make dev-custom-bundle MWAF_DEV_CUSTOM_SOURCE_DIR=...` 개발 명령을 추가했다.
- 대상별 `spec.json`과 `payload/module`, `payload/integration/mwaf.conf`를 읽어 ZIP과 metadata를 자동 생성한다.
- 여러 Apache/Nginx 빌드 대상을 한 번에 처리한다.
- 생성 artifact에 개발 빌드별 고유 ID와 버전을 사용해 이전 활성 bundle의 동일 대상 artifact를 롤백 입력으로 유지할 수 있게 했다.
- 로컬 bundle 빌더에 검증된 커스텀 ZIP metadata·package import 경로를 추가했다.
- 커스텀 artifact는 external integration, ZIP 형식, `/opt/m-waf`, bundle policy delivery와 64자리 웹서버 빌드 해시를 강제한다.
- ZIP 생성 후 표준 패키지·Agent·CRS와 병합하고 개발 키 서명, 검증, 활성 symlink 전환까지 자동 수행한다.
- 실행 중인 Manager는 기존 live reload 경로로 새 bundle을 읽으며 DB 스키마와 Agent 프로토콜은 변경하지 않는다.

## 보안 경계

- 고객 서버에서 Connector를 컴파일하거나 개발 의존성을 설치하지 않는다.
- Connector는 대상 Apache/Nginx와 동일한 ABI로 사전에 빌드된 파일만 입력으로 받는다.
- 기업 관리자는 검증된 bundle artifact를 선택해 설치하며 임의 ZIP이나 명령을 Agent에 전달할 수 없다.
- 고객 웹서버의 주 설정 파일은 자동 수정하지 않는다.

## 검증 결과

- `sh -n`으로 로컬 bundle 스크립트 두 개의 셸 문법을 확인했다.
- `git diff --check`를 통과했다.
- 다음 Go 테스트를 통과했다.
  - `cmd/mwaf-module-zip`
  - `cmd/mwaf-bundle`
  - `internal/packages`
  - `internal/manager`
- 운영 Manager와 분리된 임시 runtime에서 Apache·Nginx 가짜 payload 두 개를 사용해 전체 명령을 실행했다.
  - ZIP·metadata 2종 자동 생성
  - 표준 Agent·모듈과 커스텀 artifact 병합
  - 로컬 bundle 서명 및 검증
  - `dev-bundle-active` 전환
  - manifest의 OS·웹서버 버전·빌드 해시·ABI·`/opt/m-waf` 확인
- 테스트 payload는 실제 Connector가 아니므로 고객 웹서버 설치는 수행하지 않았다.
- 실제 개발 runtime에서 전체 로컬 bundle을 다시 생성하고 서명·검증한 뒤 활성 bundle로 전환했다.
- 현재 실행 중인 Manager가 새 bundle을 감지한 상태에서 Ubuntu 18.04의 배포판 Apache 2.4.29 서버를 확인했다.
  - `배포판 패키지` 설치 유형 자동 선택
  - 정책 적용 방식과 설치 영향 확인 항목 표시
  - `패키지 기반으로 설치` 버튼 활성화
- 화면 검수에서는 고객 서버로 설치 요청을 보내지 않았다.
- DB init/reset/migration과 프론트엔드 빌드는 수행하지 않았다.
