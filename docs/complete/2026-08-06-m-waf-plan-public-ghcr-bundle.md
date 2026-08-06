# M-WAF 공개 저장소 GHCR 및 Manager 내장 패키지 계획 반영 완료

## 작업 일자

- 2026-08-06

## 완료 내용

- 공개 GitHub 저장소 `dev` 브랜치 push에서 백엔드 `mwaf-manager` image를 빌드해 GHCR에 게시하는 CI 계획을 추가했다.
- Agent 및 Apache/Nginx package matrix가 모두 성공한 뒤 Manager image를 생성하는 순차 build gate를 정의했다.
- 공개 image 경로를 `ghcr.io/fhwang0926/m-waf-manager`로 정하고 `dev`, commit 고정 tag와 digest 정책을 정의했다.
- GitHub Actions `GITHUB_TOKEN` 최소 권한, action commit SHA 고정, fork/PR publish 차단, SBOM과 provenance 기준을 추가했다.
- 공개 저장소 clone 후 `make deploy-dev`로 MariaDB와 Manager를 기동하는 배포 진입점을 정의했다.
- 배포 stack의 DB/Manager는 Compose service, Agent/module은 Manager image 내장 설치 payload라는 실행 위치를 명확히 했다.
- Manager OCI image에 Agent, Apache/Nginx별 module DEB/RPM, compatibility manifest, checksum, signature, SBOM과 license를 포함하도록 했다.
- 일회용 bootstrap token과 서버 inventory를 기반으로 Agent 1개와 호환 module 1개만 선택하는 API/설치 절차를 추가했다.
- Manager 내장 catalog 밖 package, URL, shell command와 운영 서버 source build를 금지했다.
- Agent self-upgrade 및 module canary/순차 upgrade와 N/N-1 rollback 계획을 추가했다.
- Package catalog, 배포 상태용 Manager 모듈/API/UI/DB table, 장애 처리, 테스트, 위험과 인수 기준을 추가했다.

## 변경 문서

- `docs/todo/2026-08-06-m-waf-development-plan.md` v0.5

## 확인 범위

- 공개 저장소 remote가 `github.com:Fhwang0926/m-waf.git`로 설정되어 있음을 확인했다.
- 문서 내 설치 단위 2개, Compose runtime 2개와 Manager 내장 Agent/module 배포 모델의 표현 정합성을 정적 확인했다.
- 실제 Agent/Manager source, Dockerfile, GitHub Actions workflow 및 Compose 배포 파일은 아직 구현되지 않아 build, push 또는 실행 검증하지 않았다.
- GitHub repository, branch protection, Environment secret 및 GHCR visibility 설정은 변경하지 않았다.
