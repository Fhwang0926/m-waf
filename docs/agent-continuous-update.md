# M-WAF Agent 지속 연결과 업데이트

## 운영 방식

Agent는 최초 등록 때만 설치 토큰을 사용합니다. 등록이 끝나면 서버 ID, 개인키, Manager 발급 인증서와 CA를 보존하고 outbound HTTPS mTLS polling으로 계속 연결합니다. Manager가 일시 중단되거나 네트워크가 끊겨도 Agent 프로세스는 종료하지 않으며 다음 주기에 다시 연결합니다.

Manager는 Agent 서버로 접속하거나 inbound 포트를 열지 않습니다. 업데이트 예약도 기존 desired-state polling 응답으로 전달합니다.

## 관리자 화면에서 업데이트

1. **보호 서버 → 대상 서버 → 패키지**를 엽니다.
2. **정책 관리 Agent**에서 현재 버전과 Manager bundle의 최신 버전을 확인합니다.
3. **Agent 업데이트**를 누릅니다.
4. Agent가 다시 연결되는 다음 polling에서 서명 DEB를 내려받고 SHA-256을 확인합니다.
5. Agent DEB만 교체한 뒤 Agent 프로세스를 한 번 재시작합니다.
6. 새 버전 heartbeat가 확인되면 배포 상태가 완료됩니다.

이 작업은 웹서버 모듈, CRS/기업 정책, Apache/Nginx 설정과 reload를 변경하지 않습니다. 서버가 오프라인이면 요청은 대기하고 재연결 후 적용됩니다.

새 버전이 제한 시간 안에 heartbeat를 보내지 못하면 독립 updater가 bundle에 포함된 직전 서명 Agent DEB를 설치하고 서비스를 다시 시작합니다. 다운로드, checksum 또는 DEB 설치가 실패하면 기존 프로세스를 유지하고 실패 결과를 Manager에 보고합니다.

## 구형 Agent 1회 전환

`agent-self-update-v1` capability가 없는 기존 Agent에는 화면에 **전환 명령 복사**가 표시됩니다. 이 명령은 새 등록 토큰이나 새 서버 등록을 만들지 않습니다. 기존 `/var/lib/mwaf-agent`의 서버 ID와 mTLS 인증서를 사용해 최신 Agent만 설치합니다.

전환 완료 후의 모든 업데이트와 롤백은 Manager 버튼으로 수행합니다.

## 개발 중 Agent 버전 올리기

Agent 버전의 기준은 [`packaging/agent/VERSION`](../packaging/agent/VERSION) 한 줄입니다.

- 호환 버그 수정: PATCH 증가
- 하위 호환 capability 또는 기능 추가: MINOR 증가
- 기존 설정이나 Manager와 호환되지 않는 변경: MAJOR 증가
- 문서·테스트만 변경: 버전 유지

개발 순서:

```sh
# 1. packaging/agent/VERSION과 docs/agent-releases/<version>.md 수정
make agent-check

# 2. Agent만 새 개발 버전으로 만들고 기존 모듈 artifact는 그대로 유지
make dev-agent-bundle
```

로컬 Agent 버전은 `0.2.0~dev.YYYYMMDDHHMMSS.commit` 형식입니다. `make dev-agent-bundle`은 현재 활성 bundle의 CRS와 모듈 파일을 그대로 복사하고 Agent artifact만 교체합니다. 검증과 서명이 끝나면 `.local/mwaf-manager/dev-bundle-active`가 새 bundle을 가리키며, 로컬 Manager watcher가 manifest 변경을 감지해 DB migration 없이 Manager 프로세스만 다시 시작합니다.

Pull request에서는 Agent 영향 경로가 변경됐는데 `packaging/agent/VERSION`이 기준 브랜치보다 증가하지 않으면 검증이 실패합니다. 동일한 정식 Agent 버전에 다른 바이너리를 다시 게시하지 않습니다.

## 컨테이너 주의사항

실행 중인 컨테이너와 일반 restart에서는 `/usr/sbin/mwaf-agent-service` supervisor가 Agent를 다시 실행합니다. 컨테이너 recreate까지 유지하려면 다음 경로를 volume으로 보존하고 Agent DEB가 포함된 파생 이미지를 사용합니다.

- `/etc/mwaf-agent`
- `/var/lib/mwaf-agent`
- `/etc/mwaf`
- `/opt/m-waf`

원본 이미지에 `/usr/bin/mwaf-agent`가 없으면 volume만으로 Agent 바이너리를 복구할 수 없습니다. 등록 토큰, Agent 개인키와 인증서는 이미지에 포함하지 않습니다.
