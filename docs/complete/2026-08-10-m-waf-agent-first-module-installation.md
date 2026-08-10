# M-WAF Agent 우선 설치와 모듈 설치 유형 분리 완료

## 반영 범위

- 고객 서버의 최초 설치 스크립트를 Agent 전용 설치로 변경했다.
  - OS/아키텍처와 Manager 등록 정보만 확인한다.
  - 서명된 Agent DEB 하나만 내려받아 SHA-256을 확인하고 설치한다.
  - Apache, Nginx, ModSecurity, logrotate, CRS/통합 모듈을 설치하지 않는다.
  - 웹서버 설정 파일을 편집하거나 configtest/reload하지 않는다.
- Agent inventory에 설치 단계와 웹서버 후보 정보를 추가했다.
  - `PLAN_REQUIRED`, `INSTALLING`, `INTEGRATION_REQUIRED`, `PROTECTED`
  - 실행 중인 프로세스와 PATH에서 Apache/Nginx 실제 바이너리를 찾는다.
  - 버전, 정규화 빌드 해시, 배포판 패키지 소유 여부, configtest, Connector/include 상태를 보고한다.
- 서버 상세에서 감지된 웹서버별 설치 유형을 선택하도록 변경했다.
  - 배포판 패키지 소유 웹서버: 패키지 기반 설치
  - 커스텀 웹서버: 정확한 빌드 전용 ZIP 설치
  - 설치 대기 중 중복 예약 UI를 숨기고 완료 후 연동 가이드를 표시한다.
- 기존 desired state와 package deployment를 재사용했다.
  - DB 스키마와 Agent API 경로는 변경하지 않았다.
  - artifact metadata를 desired-state 응답에 전달해 Agent가 고정 동작만 수행한다.
- 패키지 기반 설치를 Agent 재설치와 분리했다.
  - Agent 버전이 같으면 모듈 DEB만 설치한다.
  - Agent 버전이 바뀔 때만 Agent DEB를 함께 갱신하고 서비스를 재시작한다.
- 커스텀 ZIP 설치를 추가했다.
  - Manager 서명 artifact의 웹서버, 빌드 해시, ABI, 설치 루트를 검증한다.
  - ZIP 내부 `mwaf-module.json`과 서명 metadata가 정확히 일치해야 한다.
  - path traversal, symlink, 특수 파일, 중복 파일, 파일 수와 압축 해제 크기 한도를 검사한다.
  - `/opt/m-waf/modules/{webserver}/{version}-{sha}`에만 추출하고 `current` symlink로 전환한다.
  - ZIP 설치에서는 APT/RPM을 실행하지 않는다.
- 표준 라이브러리 기반 `cmd/mwaf-module-zip` 도구를 추가했다.
  - `module/` payload와 `integration/mwaf.conf`를 고정 구조 ZIP으로 만든다.
  - `mwaf-bundle`이 읽을 metadata JSON을 함께 생성한다.
- 웹서버 활성화 경계를 명확히 했다.
  - Agent는 M-WAF 소유 policy placeholder와 Nginx 보조 설정만 준비한다.
  - 고객 Apache/Nginx 주 설정과 reload는 운영자가 기존 변경 절차로 수행한다.
  - Agent가 실제 M-WAF include와 configtest를 확인한 뒤에만 서명 정책을 적용하고 `PROTECTED`로 보고한다.
- 설치가 끝나지 않은 서버를 시스템 정책 호환성 검증 대상에서 제외했다.
  - Agent 등록만 된 서버가 시스템 정책 게시를 차단하지 않는다.
  - 반대로 미완료 서버에 정책 롤아웃이 모듈 설치를 암묵적으로 시작하지 못하게 했다.
- Agent 우선 설치, 패키지/ZIP 구분, `/opt/m-waf` 범위와 운영자 연동 절차를 README 및 커스텀 설치 문서에 반영했다.

## 추가 정리

- 기존 미완료 정책 membership 변경에서 롤백 호환성 검사에 필요한 `servers` 조회가 빠져 Manager가 컴파일되지 않던 부분을 최소 복구했다.
- Apache 모듈 DEB의 M-WAF post-install 단계에서 직접 `a2enmod`를 실행하지 않도록 변경하고, 서버 상세의 운영자 연동 절차로 이동했다.

## 확인 결과

- `sh -n internal/manager/bootstrap-install.sh`: 성공
- `git diff --check`: 성공
- 다음 Go 테스트 성공
  - `internal/model`
  - `internal/config`
  - `internal/packages`
  - `internal/agent`
  - `internal/manager`
  - `cmd/mwaf-bundle`
  - `cmd/mwaf-module-zip`
- custom ZIP 생성 테스트에서 manifest, module payload, integration 설정과 metadata를 확인했다.
- 서버 상세 템플릿 테스트에서 패키지 기반/커스텀 ZIP 작업이 분리되어 표시되는지 확인했다.

## 수행하지 않은 검증

- 프론트엔드 빌드는 수행하지 않았다.
- DB init/reset/migration은 수행하지 않았다.
- 실제 고객 서버에서 APT 모듈 설치, `/opt/m-waf` ZIP 배치, Apache/Nginx configtest·reload는 수행하지 않았다.
- 현재 실행 중인 Manager를 재빌드·재시작하거나 브라우저 인증 화면을 변경된 바이너리로 검수하지 않았다.
- 공개 Manager bundle에는 호스팅사 커스텀 빌드 ZIP이 자동 생성되지 않는다. 호스팅사가 대상 빌드별 ZIP/metadata를 생성해 서명 bundle에 포함해야 버튼이 활성화된다.
