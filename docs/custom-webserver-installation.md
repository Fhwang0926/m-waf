# 커스텀 Apache/Nginx 설치 가이드

## 설치 원칙

M-WAF는 고객 서버 설치를 두 단계로 분리한다.

1. 공통 설치 명령은 `mwaf-agent`만 설치하고 Manager에 서버를 등록한다.
2. Agent가 운영체제, 아키텍처, 실행 중인 Apache/Nginx 경로, 버전, 빌드 해시와 패키지 소유 여부를 점검한다.
3. 운영자는 Manager의 **보호 서버 → 서버 상세 → 설치 유형과 웹서버 연동**에서 설치 유형을 선택한다.
4. Agent가 Manager의 서명 bundle에 포함된 파일을 검증한 뒤 모듈을 설치한다.
5. 운영자는 화면에 표시된 전용 설정 경로를 기존 웹서버 설정에 포함한다.
6. Agent가 Connector와 M-WAF include를 확인한 뒤 선택된 제어 방식으로 configtest와 reload를 수행하고, 서명 정책 적용이 끝나면 서버 상태가 `보호 중`으로 바뀐다.

Agent와 모듈 설치는 분리된다. 초기 설치 스크립트는 Apache/Nginx/ModSecurity 패키지를 설치하거나, 고객 설정 파일을 편집하거나, 웹서버를 reload하지 않는다. 웹서버 제어는 서버 상세에서 설치 계획을 확정한 뒤에만 활성화된다.

## 설치 유형

| 유형 | 대상 | Manager가 제공하는 파일 | 고객 서버 영향 |
|---|---|---|---|
| 패키지 기반 | Ubuntu 24.04 또는 Debian 12의 배포판 Apache/Nginx | Agent DEB + 웹서버용 모듈 DEB | 모듈 DEB의 APT 의존성이 설치될 수 있다. 고객 웹서버 설정과 reload는 자동 수행하지 않는다. |
| 커스텀 ZIP | 호스팅사가 직접 빌드한 Apache/Nginx | Agent DEB + 해당 빌드 전용 ZIP | OS 의존성 패키지를 추가하지 않는다. ZIP은 `/opt/m-waf/modules` 아래에만 풀고 고객 설정은 수정하지 않는다. |

배포판 패키지 소유로 확인된 웹서버에는 패키지 기반만, 그 외 빌드에는 커스텀 ZIP만 선택할 수 있다. 커스텀 ZIP은 비슷한 버전이 아니라 Agent가 수집한 `web_server_build_hash`와 정확히 일치해야 한다.

## 지원 조건

- 운영체제: Ubuntu Server 24.04 LTS 또는 Debian 12 Bookworm
- 아키텍처: amd64
- Agent: 서명된 `mwaf-agent` DEB
- 웹서버: Apache HTTP Server 2.4 또는 Nginx
- 서비스 관리: systemd
- 커스텀 빌드: 실행 중인 프로세스의 실제 바이너리를 `/proc`에서 확인할 수 있어야 한다.
- 운영자가 기존 웹서버 설정에 M-WAF 전용 파일 하나를 포함하고 configtest/reload할 수 있어야 한다.

Agent가 웹서버 실행 경로를 확인하지 못하면 Manager에서 설치 유형을 선택할 수 없다. 컨테이너 격리, 숨겨진 mount namespace, 실행 중이지 않은 커스텀 웹서버는 현재 자동 점검 범위 밖이다.

## 1단계: Agent 설치

Manager에서 **서버 설치 → Agent 설치 명령 복사**를 누르고 대상 서버에서 실행한다. 명령은 다음 작업만 수행한다.

- Manager CA와 단기 등록 토큰 확인
- OS/아키텍처에 맞는 Agent DEB 조회
- SHA-256 검증
- Agent DEB 설치
- `/etc/mwaf-agent` 설정과 `/var/lib/mwaf-agent` 상태 디렉터리 생성
- systemd Agent 시작 및 Manager 등록

Agent DEB에는 런타임 패키지 의존성이 없다. 이 단계에서는 Apache, Nginx, Connector, CRS 모듈과 logrotate 패키지를 추가하지 않는다.

## 2단계: Agent 점검 결과 확인

서버 상세에는 감지된 웹서버마다 다음 정보가 표시된다.

- Apache/Nginx 종류와 버전
- 실제 실행 바이너리 경로
- 정규화한 빌드 정보의 SHA-256
- 배포판 패키지 소유 여부
- configtest 가능 여부

Apache와 Nginx가 같이 있거나 동일 종류의 커스텀 바이너리가 여러 개면 각각 별도 후보로 표시한다. 운영자가 선택한 후보의 빌드 해시는 설치 직전에 Agent가 다시 확인한다. 그 사이 바이너리가 교체되면 설치를 중단한다.

## 3-A단계: 패키지 기반 설치

배포판 패키지로 설치된 웹서버에서 **패키지 기반 설치**를 선택한다. Agent는 다음 고정 작업만 수행한다.

1. Manager mTLS API에서 할당된 Agent/모듈 DEB 다운로드
2. 크기와 SHA-256 검증
3. `apt-get install --no-install-recommends`로 모듈 DEB 설치
4. Agent 버전이 바뀌는 경우에만 Agent DEB도 함께 갱신
5. 설치 결과와 버전을 Manager에 보고

모듈 패키지가 선언한 Apache/Nginx용 ModSecurity 의존성은 APT가 설치할 수 있다. 설치 전에 변경 허용 정책과 저장소 상태를 확인해야 한다. Agent는 `/etc/apache2`, `/etc/nginx`의 고객 설정을 직접 편집하거나 웹서버를 reload하지 않는다.

## 3-B단계: 커스텀 ZIP 준비와 설치

커스텀 빌드는 호스팅사가 대상 웹서버와 동일한 소스·옵션·ABI로 Connector를 준비한다. 범용 ZIP 하나를 여러 빌드에 사용하지 않는다.

입력 디렉터리의 최소 구조는 다음과 같다.

```text
custom-module/
├── module/
│   └── connector.so
└── integration/
    └── mwaf.conf
```

`integration/mwaf.conf`는 고객의 주 설정 파일이 아니라, 운영자가 주 설정에서 include할 M-WAF 전용 설정이다. ZIP과 metadata는 표준 라이브러리 기반 도구로 만든다.

```sh
go run ./cmd/mwaf-module-zip \
  -input ./custom-module \
  -output ./dist/packages/mwaf-nginx-custom-1.24.0.zip \
  -metadata-output ./dist/metadata/mwaf-nginx-custom-1.24.0.json \
  -id mwaf-nginx-custom-build-7f3a \
  -version 1.0.0 \
  -os-id ubuntu \
  -os-version 24.04 \
  -webserver nginx \
  -webserver-build AGENT_SCREEN_BUILD_HASH \
  -runtime-abi modsecurity-v3
```

생성된 ZIP과 metadata를 기존 `mwaf-bundle` 입력에 추가하고 호스팅사 Manager 이미지를 빌드한다. bundle 서명 후 Manager가 ZIP을 제공한다. 정확히 일치하는 ZIP이 없으면 서버 상세의 **커스텀 ZIP 설치** 버튼은 비활성화된다.

Agent는 ZIP 설치 시 다음을 강제한다.

- Manager가 서명한 artifact metadata와 SHA-256
- ZIP 루트의 `mwaf-module.json`과 metadata의 웹서버·버전·빌드 해시·ABI 일치
- 절대 경로, `..`, symlink, 과도한 파일 수/크기 거부
- `/opt/m-waf/modules/{apache|nginx}/{version}-{sha}/`에만 추출
- 검증이 끝난 버전을 `/opt/m-waf/modules/{apache|nginx}/current` symlink로 전환
- APT/RPM 실행 안 함
- 고객 Apache/Nginx 설정 파일 편집 및 reload 안 함

M-WAF의 커스텀 모듈 payload에만 `/opt/m-waf`를 사용한다. Agent 설정·인증서·상태·정책·감사 로그는 Linux 표준 경로인 `/etc/mwaf-agent`, `/var/lib/mwaf-agent`, `/etc/mwaf`, `/var/log/modsecurity`를 유지한다.

## 4단계: 웹서버 연동

모듈 설치가 끝나면 Manager 상태는 `웹서버 연동 필요`가 된다. 운영자는 서버 상세에 표시된 경로를 기존 웹서버 설정에서 include한다.

### 커스텀 Apache

```apache
Include /opt/m-waf/modules/apache/current/integration/mwaf.conf
```

```sh
/opt/hosting/apache/bin/apachectl configtest
/opt/hosting/apache/bin/apachectl graceful
```

### 커스텀 Nginx

`http` 또는 해당 패키지가 지정한 올바른 컨텍스트에서 전용 파일을 포함한다.

```nginx
include /opt/m-waf/modules/nginx/current/integration/mwaf.conf;
```

```sh
/opt/hosting/nginx/sbin/nginx -t
/opt/hosting/nginx/sbin/nginx -s reload
```

M-WAF는 고객의 Apache/Nginx 주 설정 파일을 수정하지 않는다. 운영자가 include를 반영하면 Agent가 다음 polling에서 실제 구성을 확인하고, 설치 계획에서 선택한 방식으로 정책을 검증·재적용한다.

## 웹서버 제어 방식

### 표준 웹서버 제어

Agent가 감지하고 빌드 해시를 확인한 바이너리에 고정 인자만 사용한다.

| 웹서버 | 설정 검사 | 재적용 |
|---|---|---|
| Apache | `<감지된 바이너리> -t` | `<감지된 바이너리> -k graceful` |
| Nginx | `<감지된 바이너리> -t` | `<감지된 바이너리> -s reload` |

### 고객 Hook

호스팅사의 supervisor, service wrapper 또는 커스텀 제어 절차가 필요하면 Manager에서 **고객 Hook 사용**을 선택한다. Manager에는 명령 문자열을 입력하지 않는다. 대상 서버에 다음 두 실행 파일을 미리 준비한다.

```text
/opt/m-waf/hooks/apache/configtest
/opt/m-waf/hooks/apache/reload
/opt/m-waf/hooks/nginx/configtest
/opt/m-waf/hooks/nginx/reload
```

선택한 웹서버 디렉터리의 `configtest`, `reload`만 필요하다. Agent는 설치 전에 다음 조건을 검사한다.

- symlink가 아닌 일반 파일
- Hook 파일과 `/opt/m-waf`, `hooks`, 웹서버별 상위 디렉터리가 root 소유
- 소유자 실행 권한
- Hook 파일과 상위 디렉터리에 group/others 쓰기 권한 없음
- 고정된 `/opt/m-waf/hooks/{apache|nginx}` 경로

Hook에는 `PATH`, `MWAF_WEB_SERVER`, `MWAF_WEB_SERVER_BINARY`, `MWAF_POLICY_PATH`만 전달된다. `configtest`가 성공한 경우에만 `reload`를 실행한다. 어느 단계든 실패하면 정책을 이전 상태로 되돌리고 같은 Hook으로 다시 검증·재적용한다.

예시는 호스팅사가 이미 운영하는 제어 도구를 호출하는 최소 wrapper다.

```sh
#!/bin/sh
exec /opt/hosting/apache/bin/apachectl configtest
```

```sh
#!/bin/sh
exec /usr/local/sbin/hosting-web-control reload tenant-apache
```

Hook 파일은 고객이 서버에서 직접 검토·배치한다. Manager가 임의 셸 명령, 인자, 파이프, `sudo` 또는 스크립트 본문을 Agent로 전달하는 기능은 제공하지 않는다.

설치 후 제어 방식을 변경하려면 **보호 서버 → 서버 상세 → 설치 유형과 웹서버 연동 → 정책 재적용 방식 변경**을 사용한다. Agent는 재설치 없이 로컬 설치 선택을 갱신하며, 변경된 방식은 다음 정책 적용부터 사용한다. 고객 Hook으로 변경할 때는 두 Hook 파일의 보안 조건을 먼저 검증하고, 실패하면 기존 방식을 유지한다.

## 상태 의미

| Manager 상태 | 의미 | 다음 작업 |
|---|---|---|
| 설치 유형 선택 필요 | Agent 등록과 점검은 끝났지만 모듈 계획이 없다. | 웹서버 후보와 설치 유형 선택 |
| 패키지 적용 대기 | Manager가 설치 파일을 할당했고 Agent polling을 기다린다. | Agent 연결·로그 확인 |
| 웹서버 연동 필요 | 모듈은 설치됐지만 M-WAF 전용 설정 include가 확인되지 않았다. | 운영자가 include를 반영하고 선택한 제어 방식 준비 |
| 보호 중 | Connector, include, configtest와 서명 정책 적용이 확인됐다. | 이벤트 수신과 탐지/차단 검증 |
| 실패 | 다운로드, 해시, ABI, ZIP, APT 또는 버전 검증이 실패했다. | 상세 오류를 해결한 뒤 재예약 |

고객 Hook을 선택한 경우 Hook 파일이 없거나 권한 검증에 실패해도 설치를 시작하지 않는다. 서버에서 파일과 권한을 수정한 뒤 같은 설치 계획을 다시 예약한다.

## 실패 처리

### Agent DEB 실패

```sh
sudo dpkg --audit
dpkg-query -W -f='${binary:Package}\t${db:Status-Abbrev}\t${Version}\n' mwaf-agent 2>/dev/null || true
systemctl status mwaf-agent --no-pager || true
journalctl -u mwaf-agent -n 100 --no-pager || true
```

systemd가 없는 Docker/OCI 컨테이너에서는 아래 상태 명령을 사용한다.

```sh
/usr/sbin/mwaf-agent-service status
```

호스트와 컨테이너는 모두 `/usr/sbin/mwaf-agent-service` 명령을 사용한다. 컨테이너 재시작 시에는 기존 Apache/Nginx 시작 전에 `/usr/sbin/mwaf-agent-service start`를 실행한다. Agent 설정·인증서·상태·정책·커스텀 모듈은 각각 `/etc/mwaf-agent`, `/var/lib/mwaf-agent`, `/etc/mwaf`, `/opt/m-waf` 볼륨으로 보존한다. 원본 이미지로 컨테이너를 재생성하면 설치된 Agent 바이너리는 사라지므로 동일한 검증 DEB를 포함한 파생 이미지를 사용해야 한다. 등록 토큰과 Agent 개인키는 이미지에 포함하지 않는다.

잠금, 공간, 저장소, 중단된 DPKG 원인을 먼저 해결한다. Agent DEB를 수동 복사하거나 서명 검증을 우회하지 않는다.

### 패키지 기반 모듈 실패

서버 상세의 배포 결과와 Agent 로그를 확인하고 APT가 보고한 정확한 의존성을 점검한다. 실패했다고 Apache/Nginx 전체를 purge하거나 `dpkg --force-*`를 사용하지 않는다.

### 커스텀 ZIP 실패

- `selected build is no longer present`: 웹서버가 점검 이후 교체되었다. Agent의 새 점검 결과를 기다린다.
- `does not match signed package metadata`: ZIP manifest 또는 Manager bundle metadata가 대상 빌드와 다르다. 다시 빌드·서명한다.
- `unsafe custom module ZIP entry`: 경로 이동 또는 symlink가 포함됐다. 입력 구조를 정리하고 새 ZIP을 만든다.
- `destination already exists with different contents`: 동일 버전/해시 경로에 다른 파일이 있다. 자동 덮어쓰지 않으므로 원인을 조사한다.

커스텀 ZIP은 고객 설정을 건드리지 않으므로 설치 실패만으로 웹서버가 reload되지는 않는다. 운영자가 include를 반영하기 전까지 기존 웹 서비스는 그대로 유지된다.
