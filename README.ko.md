# slopsquat-guard 🛡️

[English](README.md) · **한국어**

> AI가 코딩 중에 설치하려는 패키지가 **진짜 존재하는지·평판이 정상인지** 설치 직전에 자동으로 확인하고,
> 위험하면 설치를 막아 주는 가드레일. 코드를 못 읽는 바이브 코더를 위한 안전벨트.

이것은 [Claude Code](https://claude.com/claude-code) / Codex / Gemini CLI 등 **SKILL.md 표준**을 쓰는
코딩 에이전트용 [에이전트 스킬](https://docs.claude.com/en/docs/claude-code/skills)입니다.

---

## 왜 필요한가 — "슬롭스쿼팅(slopsquatting)"

- AI가 생성한 코드의 **약 20%가 존재하지 않는 패키지**를 import 하거나 설치하려 합니다.
- 그렇게 지어낸(환각한) 이름의 **약 43%는 같은 이름으로 반복**됩니다.
- 반복된다는 것은 공격자가 **그 이름을 미리 악성 패키지로 등록**해 둘 수 있다는 뜻입니다.
  실제로 자격증명·API 키를 탈취하는 악성 패키지가 확인됐습니다.
- 비개발자는 `module not found` / `No module named` 오류가 나면 **의심 없이 시키는 대로 설치**합니다.

**slopsquat-guard 는 바로 그 순간(설치 직전)을 가로채** 패키지를 검증하고, 위험하면 멈춥니다.

---

## 무엇을 검사하나

| # | 검사 | 위험 신호 |
|---|------|-----------|
| 1 | **실존 여부** | 공식 레지스트리(npm·PyPI·crates.io·RubyGems)에 진짜 있는가 → 없으면 🔴 환각 의심 |
| 2 | **평판 신호** | 다운로드 수, 최초/최근 배포일, 메인테이너, 저장소 링크, deprecated |
| 3 | **타이포·슬롭스쿼팅** | 유명 패키지와 한두 글자 차이(편집거리)인데 평판이 약하면 🔴 사칭 의심 |
| 4 | **생태계 혼동** | 요청한 곳엔 없는데 다른 생태계엔 있으면 🔴 (받는 곳을 헷갈렸거나 페이로드) |
| 5 | **보안 경고** | 설치될 최신 버전에 알려진 취약점(OSV.dev)이 남아 있으면 🟡 |

> 네트워크 실패·타임아웃은 **절대 자동 통과시키지 않고** "검증 불가(🟡)"로 처리합니다.

---

## 빠른 시작

**요구사항**: Python 3.7+ (표준 라이브러리만 사용, 외부 의존성 0개).

1. 이 저장소를 에이전트의 스킬 디렉터리에 `slopsquat-guard` 라는 이름으로 둡니다.
   ```bash
   # Claude Code (프로젝트)
   git clone https://github.com/chldbwnstm/verify_before_install .claude/skills/slopsquat-guard
   # Claude Code (전역)
   git clone https://github.com/chldbwnstm/verify_before_install ~/.claude/skills/slopsquat-guard
   ```
2. 끝. 에이전트가 패키지를 설치/추가하려는 순간 스킬이 자동으로 발동합니다.

직접 실행해 볼 수도 있습니다:

```bash
# 한국어 리포트로 검사
python scripts/verify_packages.py --report --ecosystem pypi requests tqdm image-utils-pro

# 잘 동작하는지 자체 점검(네트워크 불필요)
python scripts/verify_packages.py selftest
```

---

## 사용법 (CLI)

```bash
# 위치 인자 + 생태계 (가장 간단)
python scripts/verify_packages.py --ecosystem npm  react left-pad

# JSON 입력 (여러 생태계 한 번에)
python scripts/verify_packages.py --json '[{"name":"react","ecosystem":"npm"},{"name":"requests","ecosystem":"pypi"}]'
echo '{"npm":["react"],"pypi":["requests"]}' | python scripts/verify_packages.py --stdin

# 매니페스트 파일에서 전체 의존성 자동 추출 + 검사 (생태계는 파일 종류로 자동 판별)
python scripts/verify_packages.py --report --manifest requirements.txt
python scripts/verify_packages.py --manifest package.json --manifest Cargo.toml

# 한국어 리포트 출력 (사용자에게 그대로 보여주기)
python scripts/verify_packages.py --report --ecosystem pypi pillow

# 사용자가 승인한 뒤 화이트리스트 등록 (🔴 판정은 거부됨)
python scripts/verify_packages.py approve requests pypi

# 안전 설치 명령 생성 (버전 생략 시 최신 버전 자동 조회)
python scripts/verify_packages.py install-cmd requests pypi

# 자체 점검 / 버전
python scripts/verify_packages.py selftest
python scripts/verify_packages.py --version
```

**생태계 별칭**: `pypi`(=py/pip/python), `npm`(=node/yarn/pnpm/js), `crates`(=cargo/rust), `rubygems`(=gem/ruby).

**종료 코드** (셸 게이트로 활용): `0` = 전부 🟢, `1` = 🟡 있음, `2` = 🔴 있음.

---

## 판정 등급

| 등급 | 비유 | 의미 |
|------|------|------|
| 🟢 **안전** | 신원조회 통과 | 공식 목록에 있고 평판 정상 — 잠금파일+해시로 설치 |
| 🟡 **주의** | 신분증이 좀 이상 | 신생·저다운로드·저장소 없음·검증 불가·보안 경고 — 사용자 확인 필요 |
| 🔴 **차단** | 위조 신분증/명단에 없음 | 존재하지 않음·사칭 의심·받는 곳 혼동 — 설치 중단, 명시적 승인 필요 |

---

## 출력 예시

```
📦 패키지 안전 점검 결과

🟢 안전 — requests : 사전 승인(화이트리스트)된 패키지이고 알려진 보안 취약점이 없습니다.
🟢 안전 — tqdm : 공식 패키지 목록에 정식 등록돼 있고 평판 신호가 정상입니다.
🔴 차단 — image-utils-pro : Python(pip) 공식 패키지 목록(앱을 받는 공식 앱스토어 같은 곳)에 이런 이름이 없습니다(AI가 이름을 지어냈을 가능성). → 설치를 멈췄습니다. 진행하려면 승인이 필요합니다.

※ 이 중 하나라도 🔴/🟡가 있으면 제가 임의로 설치하지 않습니다.
```

---

## 안전 설치 (잠금파일 고정 + 해시 검증)

승인된 패키지는 항상 **정확한 버전 + 무결성 해시**로만 설치합니다.

| 도구 | 명령 |
|------|------|
| pip | `pip-compile --generate-hashes` → `pip install --require-hashes -r requirements.txt` |
| npm | `npm install <pkg>@<버전> --save-exact` → `npm ci` |
| pnpm | `pnpm add <pkg>@<버전> --save-exact` → `pnpm install --frozen-lockfile` |
| yarn | `yarn add <pkg>@<버전> --exact` → `yarn install --immutable` |
| poetry | `poetry add <pkg>@<버전>` → `poetry install` |
| cargo | `cargo add <pkg>@<버전>` (Cargo.lock 체크섬) |

> 위 명령을 `python scripts/verify_packages.py install-cmd <패키지> <생태계>` 로 **자동 생성**할 수 있습니다(버전 자동 조회).

---

## 에이전트는 언제 이 스킬을 쓰나

`SKILL.md` 의 `description` 이 라우팅 규칙으로 작동합니다. 다음 순간에 자동 발동합니다:

- `npm install` / `pip install` / `yarn add` / `pnpm add` / `poetry add` / `cargo add` / `gem install` 실행 직전
- `requirements.txt` · `package.json` · `pyproject.toml` · `Cargo.toml` · `Gemfile` 에 새 패키지 추가
- 코드에 새 **서드파티** import/require 추가 (표준 라이브러리·내부 import 는 제외)
- `module not found` / `No module named` / `Cannot find module` 오류를 설치로 해결하려 할 때

---

## 설정

판정 임계값은 `scripts/verify_packages.py` 상단 상수에서 조정합니다:

```python
NEW_PACKAGE_DAYS  = 90     # 며칠 이내면 '신생'으로 볼지
LOW_DOWNLOADS     = {...}  # 생태계별 '저다운로드' 기준
TYPO_DISTANCE_MAX = 2      # 유명 패키지와 몇 글자 차이까지 사칭 후보로 볼지
HTTP_TIMEOUT      = 8      # 레지스트리 응답 대기(초)
```

또는 **설정 파일**로 조정합니다. `assets/.slopsquatrc.example.json` 을 프로젝트 루트나 스킬 폴더에
`.slopsquatrc.json` 으로 복사하거나, 환경변수 `SLOPSQUAT_CONFIG=경로` 로 지정합니다:

```bash
python scripts/verify_packages.py --config ./.slopsquatrc.json --report --ecosystem pypi requests
```

- **화이트리스트** `assets/allowlist.json` — 사전 승인 패키지(`approve` 로 추가, 🔴는 등록 거부).
- **차단 목록** `assets/denylist.json` — 알려진 악성·사칭 패키지. 여기 있는 이름은 레지스트리에
  존재하더라도 **항상 🔴**. 조직 차원의 금지 패키지를 추가할 수 있습니다.

**캐시 & 재시도**: 레지스트리 응답은 TTL(기본 6시간) 동안 디스크에 캐시하고, 429/5xx 는 지수 백오프로
재시도합니다(반복 검사 ~8배 빠름, 레이트리밋에 강함). `--no-cache` 로 끄거나 `cache-clear` 로 비웁니다.

**병렬 검사**: 여러 패키지(특히 매니페스트)는 동시에 검사합니다(`--jobs N`, 기본 8). 8개 패키지 기준
순차 27s → 병렬 5s. 순차로 강제하려면 `--jobs 1`.

---

## 테스트

```bash
python tests/test_verify.py        # 외부 의존성 없이 실행 (pytest 도 가능)
python scripts/verify_packages.py selftest
```

모든 판정 경로를 **네트워크 없이** 결정적으로 검증합니다.

---

## 한계

- 평판/타이포 휴리스틱은 100% 탐지를 보장하지 않습니다 — **사람 승인 게이트가 최종 방어선**입니다.
- PyPI 는 공식 API 가 다운로드 수를 주지 않아 best-effort(pypistats)로만 봅니다.
- 알려진(공개된) 취약점만 OSV.dev 로 확인합니다 — 0-day 는 알 수 없습니다.

---

## 파일 구조

```
slopsquat-guard/
├── SKILL.md                      # 에이전트용 발동 규칙 + 동작 절차
├── README.md                     # 영어 문서
├── README.ko.md                  # 이 문서(한국어)
├── scripts/verify_packages.py    # 결정적 검증 로직
├── assets/allowlist.json         # 사전 승인 패키지 화이트리스트
├── assets/denylist.json          # 알려진 악성·사칭 차단 목록
├── assets/.slopsquatrc.example.json  # 설정 파일 예시
├── references/REPORT_FORMAT.md   # 사용자용 한국어 리포트 포맷
├── tests/test_verify.py          # 테스트 스위트
├── CHANGELOG.md
└── LICENSE                       # MIT
```

## 라이선스

MIT — [`LICENSE`](LICENSE) 참조.
