# M-WAF CRS operator DB 인덱스 복구

## 현상

- CRS Setup 제약을 복구한 뒤 Manager가 `operator_name` 길이 초과로 다시 중단됐다.
- 검증된 LTS CRS 인덱스의 가장 긴 operator 값은 12,265자였고 DB 컬럼은 255자였다.

## 원인

- 서명된 CRS source index의 `operator`에는 `@rx` 이름뿐 아니라 정규식 operand까지 포함된 원문 표현이 저장된다.
- DB 검색 인덱스의 `operator_name` 컬럼에도 원문 전체를 그대로 넣어 컬럼 의미와 적재 값이 달랐다.

## 변경

- DB 적재 시 `@rx`, `!@rx`, `@pmFromFile`처럼 연산자 이름만 추출한다.
- 명시적 연산자가 없는 ModSecurity 조건은 기본 연산자인 `@rx`로 분류한다.
- 서명된 source index, 원본 Rule, source digest와 artifact 파일은 변경하지 않는다.
- DB 컬럼 확장이나 데이터 초기화 migration은 추가하지 않는다.

## 확인

- LTS source index에서 255자를 넘는 operator 원문과 최대 길이를 확인했다.
- 실제 `crs_rules.operator_name` 정의가 `VARCHAR(255)`인 것을 읽기 전용으로 확인했다.
- 연산자 이름 추출에 대한 단위 회귀 테스트를 추가했다.
- live reload 빌드 후 Manager가 재시작된 것을 확인했다.
- LTS 627개, Stable 629개 Rule이 DB에 적재됐고 저장된 연산자 이름의 최대 길이는 19자임을 읽기 전용으로 확인했다.
- `/health/live`와 `/health/ready`가 모두 HTTP 200을 반환했다.
- 저장소 지침에 따라 추가한 단위 테스트를 실행하지는 않았다.
- DB 초기화/reset과 프론트엔드 build/test는 수행하지 않는다.
