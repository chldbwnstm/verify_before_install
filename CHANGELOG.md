# Changelog

이 프로젝트는 [Semantic Versioning](https://semver.org/lang/ko/) 을 따릅니다.

## [1.0.0] — 2026-06-27

첫 공개 릴리스. AI가 설치/추가하려는 패키지를 **설치 직전**에 검증하는 가드레일.

### 추가됨
- **실존 검증** — npm · PyPI · crates.io · RubyGems 공식 레지스트리 조회. 없으면 🔴(환각 의심).
- **평판 신호** — 다운로드 수, 최초/최근 배포일, 메인테이너, 저장소 링크, deprecated 종합.
- **타이포·슬롭스쿼팅 휴리스틱** — Damerau 편집거리(인접 글자 바꿔치기 포함) + 구분자 사칭
  (crossenv↔cross-env) + 접사 사칭(python-<유명>, <유명>-js) + 호모글리프(유사 알파벳) 탐지.
  강신호(저장소 없음 + 신생/저다운로드)는 🔴 차단, 약신호는 🟡 주의로 강등. 유명 패키지 목록 확장.
- **교차 레지스트리 혼동** — 요청한 생태계엔 없고 다른 생태계엔 있으면 🔴.
- **보안 경고(OSV.dev)** — 설치될 최신 버전에 알려진 취약점이 남아 있으면 🟡.
- **사람 승인 게이트** — 🔴/🟡는 사용자 명시 승인 전까지 설치를 멈춤. 🔴는 화이트리스트 등록 거부.
- **차단 목록(denylist)** — 알려진 악성·사칭 패키지는 레지스트리에 존재해도 항상 🔴(환각명 선점 대비).
- **설정 파일** — `.slopsquatrc.json`/`SLOPSQUAT_CONFIG`/`--config` 로 임계값·목록 경로 조정.
- **응답 캐시 + 재시도** — 레지스트리 응답을 TTL 동안 디스크 캐시(반복 검사 ~8배 빠름), 429/5xx 지수 백오프 재시도. `--no-cache`/`cache-clear` 지원.
- **병렬 검사**(`--jobs`, 기본 8) — 여러 패키지를 동시에 검사(순서 유지, 8개 27s→5s). 캐시 병렬 안전.
- **안전 설치** — 잠금파일 고정 + 해시 검증 명령만 안내. `install-cmd` 가 생태계별 명령을 자동 생성(버전 자동 조회).
- **매니페스트 자동 검사**(`--manifest`) — requirements.txt·package.json·pyproject.toml·Cargo.toml·Gemfile 에서 의존성 추출.
- **한국어 리포트**(`--report`) — 비개발자용 평이한 한국어 + 비유.
- **입력/이름 검증** — JSON 타입 검증, 경로조작 이름 차단, 패키지별 오류 격리(fail-closed).
- **화이트리스트** — `approve` 서브커맨드(원자적 쓰기, 손상 시 보호).
- **CLI** — `--ecosystem`/`--json`/`--stdin`/`--report`/`--offline`/`--timeout`, 종료코드(🔴=2/🟡=1/🟢=0).
- **테스트** — `tests/test_verify.py`(50개) + `selftest` 서브커맨드. 모든 판정 경로를 네트워크 없이 검증.
- **하드닝** — 차단목록 손상 시 fail-closed(🟡)+경고, 명시 설정 경로 누락/손상 시 즉시 오류(정책 누락 방지),
  OSV 보안경고는 캐시 미사용(새 CVE 즉시 반영), 매니페스트 이상 형식·잘못된 설정값에 트레이스백 대신 깔끔한 처리,
  `requirements.txt` 의 `http`-접두 패키지(httpx 등) 정상 검사, 사용자 문구에 영문 예외명 비노출.
- **문서** — SKILL.md, README.md, references/REPORT_FORMAT.md, LICENSE(MIT).

[1.0.0]: https://example.com/slopsquat-guard/releases/tag/v1.0.0
