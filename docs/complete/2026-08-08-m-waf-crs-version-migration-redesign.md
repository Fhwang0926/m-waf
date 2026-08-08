# M-WAF CRS 버전 관리·시스템 정책 마이그레이션 재설계

## 완료 범위

- `/open-source-policies`를 검증된 LTS·Stable 전체 버전 목록과 시스템 정책 반영 시작 화면으로 재구성했다.
- 상단 중복 흐름·상태 카드를 제거하고 현재 시스템 정책 버전, 고정 CRS·채널, 보호 모드, 현재 Manager 프로세스의 마지막 LTS·Stable 확인 시각을 하나의 연결 요약으로 표시한다.
- CRS 목록에 버전·태그·commit 검색, 채널, 연결 상태, 페이지 필터를 추가하고 URL 쿼리로 상태를 복원한다.
- 목록 API의 기존 `items`를 유지하면서 `link_status`, 연결 시스템 정책 ID·버전, 마이그레이션 가능 여부와 차단 사유, 페이지 정보를 추가했다.
- source ID와 archive/index digest가 모두 일치하는 경우만 `CURRENT`로 판정한다. 버전만 같거나 source pin이 불완전한 기존 정책은 `LEGACY_UNPINNED`로 분리한다.
- 같은 채널의 낮거나 같은 버전은 일반 마이그레이션에서 차단하고, LTS·Stable 채널 전환은 별도 경고와 명시적 확인 후 허용한다.
- 목록에서 선택한 CRS는 5단계 마법사에서 숨은 고정 값으로 유지하며 다른 원본은 목록으로 돌아가 다시 선택하도록 했다.
- 게시된 시스템 정책이 없는 경우 Manager가 선택한 CRS로 `crs-baseline@1.0.0` 후보를 만들 수 있게 했다. 최초 기본값은 DetectionOnly, PL1, 요청 본문 검사 사용, 응답 본문 검사 미사용이다.
- 기존 `crs-baseline`은 다음 patch로 갱신하고, 기존 `crs-lts-baseline` 또는 `crs-stable-baseline`만 있으면 해당 설정을 상속한 canonical `crs-baseline@1.0.0`으로 전환한다.
- 게시 트랜잭션이 세 baseline 계열을 함께 잠그고 `expected_system_policy_id`를 비교하도록 변경했다. 동시 변경은 HTTP 409로 처리하며 게시 시 기존 baseline 게시본은 `DEPRECATED`가 된다.
- legacy enterprise policy key를 canonical `crs-baseline`으로 함께 전환해 기존 기업 설정을 유지하면서 AUTOMATIC, MANUAL, PINNED 후속 절차가 기존 정책 동기화기에 의해 생성되도록 했다.
- CI package bundle 동기화는 검증된 CRS source·Rule index만 저장하며 시스템 정책을 자동 게시하지 않도록 변경했다.
- 활성 서버 검증은 policy-bundle-v3 지원, Connector, configtest와 함께 package 관리 서버의 OS·아키텍처·웹서버 호환 Agent·모듈 및 rollback artifact를 확인한다.
- CRS 상세 화면의 오래된 CI seed 안내와 source가 빠진 생성 링크를 제거하고 현재 정책 보기 또는 선택 source 고정 마이그레이션으로 통일했다.
- README의 초기 seed·단일 기준 정책·채널 전환 설명을 현재 동작에 맞게 갱신했다.
- 760px 이하에서 5단계 마법사를 세로 단계로 바꿔 가로 잘림을 제거하고, 연결 요약·필터·고정 source 영역을 390px까지 재배치했다.
- CRS 목록의 현재 연결 현황은 시스템 정책 버전과 CRS 버전·채널만 간략히 표시하도록 정리했다. 보호 모드는 정책 버전 화면에만 남겼다.
- source pin이 불완전할 때만 `연동 정보 보완 필요` 경고 바를 표시하고, 정상 연동 상태에서는 경고 영역을 렌더링하지 않는다.
- 마지막 CRS 확인 시각은 현황 카드에서 제거하고 `최신 CRS 확인` 버튼 바로 아래에 표시한다. 확인 이력이 없으면 `최신 확인 정보 없음`으로 안내한다.
- 현재 연결 현황의 제목, 시스템 정책, CRS와 조건부 경고를 데스크톱 한 행으로 통합하고, 경고 문구를 운영 조치 중심으로 축약했다.
- 페이지 제목과 중복되던 버전 목록의 제목·설명을 제거해 CRS 검색 필터가 바로 시작되도록 정리했다.
- CRS 버전 목록의 검증값 드롭다운을 제거하고 archive·index SHA-256을 한 번에 복사하는 단일 버튼으로 변경했다.
- 검증값 복사 작업은 짧은 `복사` 버튼만 표시하고 결과 안내는 접근성 알림으로 처리해 표를 단순화했다.

## 확인 결과

- 변경한 Go 파일에 `gofmt`를 적용했고 `git diff --check`를 통과했다.
- 실행 중인 로컬 Manager의 `/health/ready`가 HTTP 200을 반환했다.
- 인증된 실행 화면에서 Stable 4.28.0과 LTS 4.25.1이 최신순으로 표시되고, 기존 source-unpinned `crs-baseline@1.0.0`이 `연동 정보 보완 필요`로 표시되는 것을 확인했다.
- URL에서 `q`, `channel`, `link_status`, `page`를 함께 사용했을 때 필터 값과 결과 행이 복원되는 것을 확인했다.
- 실행 화면에서 선택 source가 select 없이 고정되고 5개 마법사 단계와 다음 patch `1.0.1`이 표시되는 것을 확인했다.
- 1440px, 1024px, 760px, 390px에서 본문·연결 요약·필터가 viewport 밖으로 넘치지 않고 마법사 단계가 겹치지 않는 것을 확인했다. 좁은 화면의 버전 표는 기존 공통 표 컨테이너 안에서만 스크롤된다.
- 최초 정책, exact source pin, legacy-unpinned 상태를 위한 Go 회귀 테스트 코드를 추가했다.

## 수행하지 않은 검증

- 저장소 지침에 따라 프론트엔드 build/test와 테스트 명령은 실행하지 않았다.
- 실제 시스템 정책 검증·게시, DB 쓰기, enterprise rollout 생성, Agent 배포와 rollback은 실행하지 않았다.
- GitHub CRS 동기화와 외부 package 다운로드는 실행하지 않았다.
- 실제 무정책 DB와 동시 게시 요청을 만들지 않았으므로 최초 게시 및 HTTP 409는 추가한 handler·transaction·회귀 테스트 코드 기준으로만 확인했다.
- DB 스키마와 Agent API, 기업 정책 API, artifact 형식은 변경하지 않았다.
