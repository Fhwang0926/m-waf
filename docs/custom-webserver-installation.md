# 커스텀 Apache/Nginx 설치 가이드

## 목적

호스팅사가 직접 컴파일했거나 제3자 저장소로 설치한 Apache/Nginx를 M-WAF에 연결하는 방법을 설명한다.

`external` 통합은 고객 웹서버와 ModSecurity Connector를 빌드하거나 교체하지 않는다. 호스팅사가 호환성을 확인해 미리 설치한 Connector를 그대로 사용하며 설치 방식은 두 가지다.

1. 기본 `package`: `mwaf-agent`와 Apache/Nginx용 M-WAF external 통합 패키지를 설치한다.
2. `manual`: 서명된 `mwaf-agent`만 설치하고, 기존 Connector에 M-WAF 전용 include와 로그 회전 설정을 연결한다.

두 방식 모두 Apache, Nginx, libmodsecurity와 Connector를 패키지로 교체하지 않는다. `manual`은 Connector 수동 설치를 허용하는 방식이지, Agent 바이너리나 정책을 검증 없이 복사하는 우회 경로가 아니다. Agent와 정책은 계속 Manager가 제공하고 서명을 검증한다.

## 지원 조건

- 운영체제: Ubuntu Server 24.04 LTS
- 아키텍처: amd64
- 웹서버 제어 바이너리의 절대 경로를 알고 있어야 한다.
- Apache는 `apachectl`을 제공하고 `security2_module`이 이미 로드되어 있어야 한다.
- Nginx는 해당 Nginx 빌드와 호환되는 ModSecurity-nginx Connector가 이미 컴파일·로드되어 있어야 한다.
- 웹서버의 기존 include 대상 디렉터리에 M-WAF 전용 파일 하나를 추가할 수 있어야 한다.
- ModSecurity가 JSON 감사 로그 형식을 지원해야 한다.
- 웹서버 로그 파일을 기록할 기존 Unix group을 지정해야 한다.

`external` 모드는 임의의 사전 빌드 Connector를 배포하지 않는다. Nginx Connector는 고객 Nginx와 동일한 소스·컴파일 조건 또는 호환 빌드 조건으로 준비해야 한다. Apache DSO는 대상 Apache의 `apxs`와 헤더를 사용해 준비하는 것을 권장한다.

## 설치 전에 준비할 항목

### Apache

다음은 커스텀 Apache가 `/opt/hosting/apache`에 설치된 예다.

1. `/opt/hosting/apache/bin/apachectl -M`에서 `security2_module`을 확인한다.
2. Apache 주 설정이 전용 설정 디렉터리를 포함하도록 한다.

```apache
IncludeOptional /opt/hosting/apache/conf/extra/*.conf
```

3. 변경 전 설정을 검사한다.

```sh
/opt/hosting/apache/bin/apachectl configtest
```

설치기는 `/opt/hosting/apache/conf/extra/mwaf.conf` 한 파일만 생성한다. 이미 같은 경로에 M-WAF가 관리하지 않는 파일이 있으면 덮어쓰지 않고 중단한다.

### Nginx

다음은 커스텀 Nginx가 `/opt/hosting/nginx`에 설치된 예다.

1. `/opt/hosting/nginx/sbin/nginx -V`와 현재 설정에서 ModSecurity-nginx Connector가 로드되었는지 확인한다.
2. `http` 컨텍스트가 전용 설정 디렉터리를 포함하도록 한다.

```nginx
http {
    include /opt/hosting/nginx/conf/conf.d/*.conf;
}
```

3. 변경 전 설정을 검사한다.

```sh
/opt/hosting/nginx/sbin/nginx -t
```

Nginx의 기존 `modsecurity_rules_file`과 같은 컨텍스트에 M-WAF 설정을 중복 선언하면 안 된다. 기존 ModSecurity 기본 설정이 필요하면 해당 파일 경로를 설치 명령의 `--modsecurity-base`로 전달한다.

## 공통 설치 파일 받기

Manager의 **설치 및 등록**에서 기업 설치 토큰을 생성한다. 화면에서 제공하는 CA 포함 설치 블록을 사용하거나 공개 CA 인증서를 고객 서버로 복사한 뒤 설치 스크립트를 내려받아 검토한다.

```sh
curl --fail \
  --cacert ./mwaf_ca_cert.pem \
  https://manager.example.com:8443/bootstrap/v1/install.sh \
  -o /tmp/mwaf-install.sh
```

## 커스텀 Apache 설치

```sh
sudo sh /tmp/mwaf-install.sh \
  --manager https://manager.example.com:8443 \
  --ca ./mwaf_ca_cert.pem \
  --install-token-stdin \
  --webserver apache \
  --integration external \
  --module-install manual \
  --webserver-bin /opt/hosting/apache/bin/apachectl \
  --integration-config /opt/hosting/apache/conf/extra/mwaf.conf \
  --audit-log /var/log/modsecurity/mwaf-audit.jsonl \
  --web-group www-data \
  --reload
```

Apache 기본 ModSecurity 설정이 다른 파일에 있고 기존 Apache 설정에서 아직 포함하지 않았다면 다음 옵션을 추가할 수 있다.

```sh
--modsecurity-base /opt/hosting/apache/conf/modsecurity.conf
```

같은 기본 설정을 Apache가 이미 포함하고 있다면 중복 Rule ID를 방지하기 위해 이 옵션을 사용하지 않는다.

## 커스텀 Nginx 설치

```sh
sudo sh /tmp/mwaf-install.sh \
  --manager https://manager.example.com:8443 \
  --ca ./mwaf_ca_cert.pem \
  --install-token-stdin \
  --webserver nginx \
  --integration external \
  --module-install manual \
  --webserver-bin /opt/hosting/nginx/sbin/nginx \
  --integration-config /opt/hosting/nginx/conf/conf.d/mwaf.conf \
  --modsecurity-base /opt/hosting/nginx/conf/modsecurity.conf \
  --audit-log /var/log/modsecurity/mwaf-audit.jsonl \
  --web-group www-data \
  --reload
```

커스텀 supervisor나 별도 service wrapper로만 reload할 수 있다면 `--reload`를 생략한다. 설치 완료 후 호스팅사의 기존 운영 절차로 reload해야 M-WAF 설정이 실제 worker에 반영된다.

## 옵션 설명

| 옵션 | 의미 |
|---|---|
| `--install-token-stdin` | 기업 설치 토큰을 터미널에서 숨김 입력한다. 일반 수동 설치에 권장한다. |
| `--install-token-file` | 자동화 도구가 권한 0600 비밀 파일로 제공한 기업 설치 토큰을 읽는다. |
| `--name` | Manager에 자동 등록할 서버 이름을 지정한다. 생략하면 호스트명을 사용한다. |
| `--integration external` | 배포판 웹서버·Connector 패키지를 설치하지 않고 기존 Connector를 사용한다. |
| `--module-install package\|manual` | 기본값은 M-WAF external 통합 패키지를 함께 설치하는 `package`다. `manual`은 Agent 패키지만 설치하고 기존 Connector에 최소 설정을 연결한다. `external`에서만 사용할 수 있다. |
| `--webserver apache\|nginx` | 한 Agent가 관리할 웹서버 종류를 고정한다. |
| `--webserver-bin` | Agent가 inventory, configtest와 정책 reload에 사용할 절대 경로다. Apache는 `apachectl` 경로를 사용한다. |
| `--integration-config` | 기존 Apache/Nginx include 범위 안에 생성할 M-WAF 전용 파일이다. |
| `--modsecurity-base` | M-WAF 엔진 설정에서 먼저 포함할 기존 ModSecurity 기본 설정이다. 선택 항목이다. |
| `--audit-log` | Agent가 읽고 ModSecurity가 기록할 JSONL 파일이다. |
| `--web-group` | 감사 로그에 쓰기 권한을 가질 기존 Unix group이다. |
| `--reload` | configtest 성공 후 웹서버 기본 제어 명령으로 reload한다. |

## 설치기가 확인하는 내용

1. Ubuntu 24.04 amd64 여부
2. 웹서버 바이너리 절대 경로와 실행 권한
3. 웹서버 버전과 정규화된 빌드 해시
4. Apache `security2_module` 또는 Nginx Connector 로드 흔적
5. 지정한 Unix group과 설정 디렉터리 존재 여부
6. 기존 설정 파일을 덮어쓰지 않는지 여부
7. 설치한 전용 설정이 실제 웹서버 include 결과에 나타나는지 여부
8. `apachectl configtest` 또는 `nginx -t` 성공 여부
9. Agent와, `package` 방식이면 통합 패키지의 SHA-256 및 Manager 서명 번들 일치 여부

설정 검사에 실패하면 설치기는 기존 M-WAF 전용 통합 설정을 복원하거나 새로 만든 통합 설정을 제거한다. 고객 웹서버 바이너리, Connector와 기존 주 설정은 수정하지 않는다. Agent 패키지 설치 자체는 APT 트랜잭션이므로 자동 제거하지 않는다.

## 설치 후 확인

### Apache

```sh
/opt/hosting/apache/bin/apachectl configtest
/opt/hosting/apache/bin/apachectl -M | grep security2_module
/opt/hosting/apache/bin/apachectl -t -D DUMP_INCLUDES | grep mwaf.conf
systemctl status mwaf-agent --no-pager
```

### Nginx

```sh
/opt/hosting/nginx/sbin/nginx -t
/opt/hosting/nginx/sbin/nginx -T 2>&1 | grep -A2 'mwaf.conf'
systemctl status mwaf-agent --no-pager
```

### 공통

```sh
test -s /etc/mwaf/active/main.conf
test -L /etc/mwaf/active
test -e /var/log/modsecurity/mwaf-audit.jsonl
journalctl -u mwaf-agent -n 100 --no-pager
```

Manager의 **서버** 화면에서 `integration_mode=external`, `installation_mode`, 웹서버 버전·빌드 해시, Connector 로드/configtest 상태와 지원 정책 형식을 확인한다. `manual` 서버에는 M-WAF 모듈 패키지 버전 대신 탐지된 Connector 정보가 표시된다.

## DEB 설치가 실패한 경우

### 현재 동작

설치 스크립트는 다음 단계 중 하나라도 실패하면 즉시 종료한다.

1. Manager 연결 또는 기업 설치 토큰·단기 등록 세션 검증
2. 호환 Agent 패키지와, `package` 방식이면 통합 패키지 조회·다운로드
3. SHA-256 검증
4. APT/DPKG 설치
5. external Connector와 전용 include 확인
6. Apache/Nginx configtest와 선택적 reload
7. Agent 설정 생성과 systemd 서비스 시작

다른 형식의 패키지나 서명되지 않은 파일로 자동 전환하지 않는다. APT는 `package` 방식에서 Agent와 통합 패키지를 한 명령으로 설치하고, `manual` 방식에서는 Agent만 설치한다. 실패 시 먼저 처리된 패키지가 `unpacked` 또는 `installed` 상태로 남을 수 있으며 설치 스크립트는 이를 자동 제거하지 않는다.

external 설정 도구가 실패한 경우에는 M-WAF가 관리하는 전용 include, `/etc/mwaf/external` 설정과 로그 회전 설정을 실행 직전 상태로 복원한다. 고객 웹서버 바이너리, Connector와 주 설정 파일은 변경하거나 제거하지 않는다.

### 1. 설치 전 사전진단

설치 전에 다음 항목을 확인하면 일반적인 DEB 실패를 줄일 수 있다.

```sh
test "$(uname -m)" = x86_64
. /etc/os-release && test "$ID" = ubuntu && test "$VERSION_ID" = 24.04
df -h / /var /tmp
sudo dpkg --audit
sudo apt-get update
sudo apt-get --simulate install logrotate
```

`distro` 모드는 선택한 Apache/Nginx와 ModSecurity Ubuntu 패키지의 의존성도 APT가 해결할 수 있어야 한다. `external` 모드는 웹서버 패키지를 설치하지 않으며 통합 DEB의 런타임 의존성은 `logrotate`뿐이다.

### 2. 실패 상태 확인

먼저 설치 명령의 최초 오류를 보존하고 다음 명령으로 M-WAF 패키지 상태를 확인한다.

```sh
sudo dpkg --audit
dpkg-query -W -f='${binary:Package}\t${db:Status-Abbrev}\t${Version}\n' \
  mwaf-agent mwaf-modsecurity-apache mwaf-modsecurity-apache-external \
  mwaf-modsecurity-nginx mwaf-modsecurity-nginx-external 2>/dev/null || true
```

`ii`는 정상 설치, `iU`는 unpack 후 미설정 상태다. Agent 서비스까지 생성된 경우에는 다음 로그도 확인한다.

```sh
systemctl status mwaf-agent --no-pager || true
journalctl -u mwaf-agent -n 100 --no-pager || true
```

### 3. 오류 유형별 처리

| 오류 | 확인할 내용 | 처리 원칙 |
|---|---|---|
| `Could not get lock` | 다른 APT/DPKG 작업 실행 여부 | 기존 패키지 작업이 정상 종료될 때까지 기다린다. 잠금 파일을 강제로 삭제하지 않는다. |
| `No space left on device` | `/`, `/var`, `/tmp` 여유 공간과 inode | 공간을 확보한 뒤 DPKG 상태를 복구한다. |
| 의존성 또는 저장소 오류 | Ubuntu 24.04 저장소와 proxy/mirror 상태 | 저장소를 복구하고 `sudo apt-get --fix-broken install`을 실행한다. |
| `dpkg was interrupted` | `sudo dpkg --audit` 결과 | 원인을 해결한 뒤 `sudo dpkg --configure -a`를 실행한다. |
| checksum 또는 서명 불일치 | Manager 번들, 프록시 변조, 잘못된 파일 | 설치를 강행하지 않는다. Manager의 같은 태그 번들과 인증서를 확인한다. |
| 호환 패키지 없음 | OS, amd64, 웹서버 종류, `integration_mode` | 조건을 바꾸어 우회하지 않는다. 커스텀 빌드는 명시적으로 `external`을 선택한다. |
| Connector 미탐지 | Apache `security2_module`, Nginx Connector 로드 상태 | 대상 웹서버와 호환되는 Connector를 먼저 준비한다. |
| include/configtest 실패 | 전용 경로가 실제 include 범위인지, 중복 Rule/설정인지 | 주 설정을 임의 교체하지 말고 원인을 수정한 뒤 같은 명령을 재실행한다. |
| Agent 시작 실패 | `agent.json`, 인증서 경로, Manager 연결, systemd 로그 | Agent 로그를 해결한 뒤 서비스를 다시 시작한다. |

복구 명령은 오류에 해당할 때만 사용한다. 특히 `--fix-broken install`이나 `dpkg --configure -a`를 실행하기 전에 현재 진행 중인 패키지 작업이 없는지 확인한다.

### 4. 안전한 재시도

원인을 해결한 다음 처음 검토했던 동일한 설치 명령을 다시 실행한다. external 설정 파일은 M-WAF 관리 marker가 있는 경우에만 갱신되므로 재실행할 수 있다.

DEB 설치 단계에서 실패하면 같은 기업 설치 토큰으로 다시 실행할 수 있으며 Manager가 새 단기 등록 세션을 발급한다. 기업 설치 토큰은 관리자가 폐기하기 전까지 같은 기업의 여러 서버에서 계속 사용할 수 있다. 토큰을 폐기했거나 원문을 분실했다면 기존 토큰을 폐기한 뒤 새 토큰을 생성한다. 재시도 전에 Manager의 **서버** 목록과 `/var/lib/mwaf-agent/server-id`를 확인한다. 이미 등록된 서버에서는 설치기가 중복 등록을 거부한다.

설치기는 기업 토큰을 `/etc/mwaf-agent/event-verification.token`에 권한 `0600`으로 저장한다. Agent는 이 값을 탐지 이벤트 배치에만 추가하며, Manager는 mTLS로 확인한 서버와 토큰이 같은 기업에 속할 때만 로그를 수신한다. heartbeat, 정책, 패키지, 명령과 인증서 API에는 이 토큰을 보내지 않는다. 기존 Agent를 업그레이드할 때는 Manager의 필수 검증을 켜기 전에 토큰 파일과 `event_verification_token_file` 설정을 함께 배포해야 한다.

다음 복구 방식은 사용하지 않는다.

- `dpkg --force-*`로 호환성이나 의존성 검사를 무시
- Apache/Nginx 패키지 전체 purge
- 원인 확인 전 `/etc/mwaf`, `/var/lib/mwaf-agent` 삭제
- Manager 번들을 거치지 않은 Agent 바이너리나 CRS 수동 복사
- `distro`와 `external` 패키지 동시 설치

### 5. Agent DEB를 사용할 수 없는 환경

현재 Agent의 공식 설치 형식은 Ubuntu 24.04 amd64 DEB뿐이다. Connector는 `external/manual`로 운영자가 설치할 수 있지만 Agent의 `tar.gz` portable 설치, RPM, ARM64와 수동 파일 복사는 아직 지원하지 않는다. 따라서 Agent DEB를 설치할 수 없는 이미지형 서버나 변경 불가능한 어플라이언스에는 설치를 강행하지 않는다.

향후 portable 설치를 추가하더라도 고객 설치 범위는 Agent와 웹서버 통합 구성 두 개로 유지하고, 다음 조건을 충족해야 한다.

- Manager 서명과 SHA-256 검증
- systemd 등록 및 전용 사용자·권한 설정
- 설치 manifest 기반 업그레이드와 제거
- configtest 실패 시 설정 롤백
- Manager에서 설치 방식과 버전 식별

이 조건이 구현되기 전에는 수동 복사를 공식 우회 경로로 취급하지 않는다.

## 실패 처리와 운영 주의사항

- `unmanaged integration config` 오류는 지정 경로에 기존 파일이 있다는 뜻이다. 다른 전용 경로를 선택해야 한다.
- Connector를 찾지 못하면 M-WAF가 임의 모듈을 설치하지 않고 중단한다.
- configtest 실패 시 웹서버 오류 로그를 확인하고 기존 ModSecurity 설정의 중복 Include와 Rule ID를 점검한다.
- 웹서버를 다시 컴파일하거나 Nginx configure option을 변경했다면 Connector도 다시 호환 빌드하고 configtest를 수행해야 한다.
- Agent의 통합 모드를 `external`에서 `distro`로 자동 전환하지 않는다. 전환은 별도 유지보수 작업으로 진행한다.
- GitHub Actions의 external 시험은 M-WAF 전용 include, 절대 바이너리 경로, Connector 재사용, 패키지 무의존성과 configtest를 확인한다. 이어서 Apache/Nginx를 실제 기동해 고정 시험 규칙의 `403` 차단과 JSON 감사 로그 생성을 검증한다. 고객사의 모든 컴파일러와 ABI 조합을 보장하지는 않는다.
