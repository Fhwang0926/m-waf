# M-WAF CRS 확인 작업 통합

## 변경

- CRS 소스 화면의 `LTS 확인`, `Stable 확인` 버튼을 `최신 CRS 확인` 한 개로 통합했다.
- 한 번의 작업으로 LTS 고정 계열과 최신 Stable v4를 모두 확인한다.
- 빈 화면의 초기 확인 작업도 같은 단일 버튼을 사용한다.
- 완료 후 `channel` 쿼리를 남기지 않아 특정 채널만 숨겨지는 문제를 방지한다.
- 기존 채널별 HTML/API 호출은 호환성을 위해 유지한다.

## 확인 범위

- 변경 Go 파일을 `gofmt`로 정리했다.
- Go template에서 중복 LTS/Stable 버튼이 제거되고 `channel=all` 통합 form만 남은 것을 정적으로 확인했다.
- live reload 후 실행 중인 Manager의 `/health/ready` HTTP 200을 확인했다.
- 실제 GitHub CRS 동기화는 외부 상태를 변경할 수 있어 수행하지 않는다.
- 프론트엔드 build/test는 수행하지 않는다.
