# M-WAF 개발계획서 MariaDB 및 Docker Compose 반영 완료

## 작업 일자

- 2026-08-06

## 완료 내용

- Manager 운영 DB를 Embedded SQLite에서 MariaDB Community Server LTS의 InnoDB로 변경했다.
- Go DB 접근 기술을 `database/sql`과 `go-sql-driver/mysql` 조합으로 변경했다.
- Manager 서버의 상시 실행 구성을 `mwaf-manager`와 `mariadb` 두 컨테이너로 제한했다.
- 고객 Apache/Nginx 서버는 Docker 없이 기존 두 패키지만 설치하는 원칙을 유지했다.
- Manager/MariaDB Docker Compose 예시, 내부 DB network, secret file, 영속 volume과 healthcheck를 개발계획서에 추가했다.
- MariaDB와 Manager image를 정확한 version/digest로 고정하는 `images.lock.yaml` 산출물을 추가했다.
- Agent 이벤트 batch, multi-row INSERT, DB commit 후 ACK, 멱등 키, bounded connection pool과 backpressure 기준을 추가했다.
- MariaDB 장애, connection 포화, volume 손상, 백업·복구와 image rollback 기준을 추가했다.
- MariaDB 및 Compose 기준 통합·성능 테스트와 MVP 인수 기준을 추가했다.

## 변경 문서

- `docs/todo/2026-08-06-m-waf-development-plan.md` v0.4

## 확인 범위

- 문서 안의 현재 아키텍처 및 개발 항목에서 SQLite/PostgreSQL 운영 전환 표현이 남아 있지 않은지 정적 검색했다.
- Docker Compose 예시의 서비스, network, secret, volume과 healthcheck 구성을 문서 기준으로 검토했다.
- 실제 Manager image, MariaDB container, Compose 배포 파일은 아직 구현되지 않았으므로 실행 검증하지 않았다.
- 애플리케이션 코드, DB Schema 및 migration은 아직 생성하거나 실행하지 않았다.
