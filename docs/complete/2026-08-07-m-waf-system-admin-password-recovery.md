# M-WAF 시스템 관리자 비밀번호 복구 완료

## 반영 내용

- 기존 Manager 실행 파일에 `reset-system-admin-password` 일회성 복구 명령을 추가했다.
- `deploy/compose/reset-system-admin-password.sh USERNAME PASSWORD_FILE` 스크립트가 배포 Compose의 기존 Manager 이미지, 네트워크와 DB 자격 증명을 재사용한다.
- 비밀번호는 명령행이나 환경 변수가 아니라 표준입력으로 전달하며 파일의 마지막 LF 또는 CRLF만 제거한다.
- 활성화되어 있고 삭제되지 않은 `system_admin` 계정만 사용자명으로 선택한다. 기업 관리자·기업 사용자, 비활성 계정 및 삭제 계정은 변경할 수 없다.
- 비밀번호는 최초 설정 및 계정 변경과 동일한 PBKDF2-SHA256 정책으로 새 salt와 함께 저장한다.
- 비밀번호 변경과 `system_admin.password_reset` 관리자 감사 로그 기록을 한 transaction으로 처리한다.
- 기존 로그인 세션은 저장된 비밀번호 해시 기반 credential tag 검증에서 자동으로 무효화된다.

## 안전 경계

- MariaDB 초기화, migration, reset 또는 직접 SQL 실행은 하지 않는다.
- 실행 중인 Manager와 MariaDB를 중지하거나 재시작하지 않는다.
- DB가 이미 실행 중이고 준비된 경우에만 `--no-deps` 일회성 Manager 컨테이너를 실행한다.
- 이전 이미지가 복구 하위 명령을 무시하고 일반 서버로 시작하지 않도록, 실행 중인 Manager 이미지의 `io.mwaf.feature.system-admin-password-reset=true` 표식을 확인한 뒤에만 일회성 컨테이너를 실행한다.
- 계정 권한, 활성 상태, 표시 이름 및 다른 사용자 정보는 변경하지 않는다.
- 비밀번호 값은 로그와 성공 메시지에 출력하지 않는다.

## 사용법

```sh
chmod 600 ./admin.password
./deploy/compose/reset-system-admin-password.sh 3vi ./admin.password
```

성공 후 기존 브라우저 세션은 사용할 수 없으며 새 비밀번호로 다시 로그인해야 한다. 배포된 Manager 이미지에도 이 복구 명령이 포함된 버전을 사용해야 한다.

## 확인 범위

- 비밀번호 파일 한 줄 처리, LF/CRLF 처리와 다중 행·빈 입력 거부 unit test를 추가했다.
- 잘못된 사용자명과 12자 미만 또는 256자 초과 비밀번호가 Store 접근 전에 거부되는 unit test를 추가했다.
- 복구 스크립트 POSIX shell 문법 및 도움말 경로를 확인한다.
- 실제 배포 DB의 비밀번호 변경은 수행하지 않았다.
- 저장소 지침에 따라 프론트엔드 빌드와 테스트는 수행하지 않았다.
