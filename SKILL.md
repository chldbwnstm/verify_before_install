---
name: slopsquat-guard
description: >-
  패키지를 설치하거나 새 import/의존성을 추가하기 '직전'에 발동하라. "npm install",
  "pip install", "yarn add", "pnpm add", "poetry add", "cargo add", "gem install"
  을 실행하려 할 때 / requirements.txt·package.json·pyproject.toml·Cargo.toml·Gemfile
  을 고쳐 새 패키지를 넣으려 할 때 / 코드에 설치가 필요한 외부·서드파티 패키지의
  import·require 를 새로 추가하려 할 때(표준 라이브러리·프로젝트 내부/상대 import 는 제외) /
  "module not found"·"No module named"·"Cannot find module" 오류를 설치로 해결하려 할 때,
  먼저 이 스킬로 패키지의 실존·평판을 검증하라. 검증 전에는 어떤 설치 명령도 실행하지 마라.
  (triggers: install package, add dependency, add library, add third-party import,
  fix module-not-found, npm/pip/yarn/pnpm/poetry/cargo/gem install)
allowed-tools: Bash, Read
---

# slopsquat-guard — 설치 직전 패키지 검증 게이트

AI가 생성한 코드의 약 20%는 **존재하지 않는 패키지**를 참조하고, 그렇게 지어낸 이름의
약 43%는 같은 이름으로 반복 등장한다. 반복된다는 건 공격자가 그 이름을 미리 악성 패키지로
선점해 둘 수 있다는 뜻이다(슬롭스쿼팅). 비개발자는 `module not found` 오류가 뜨면
의심 없이 시키는 대로 설치한다 — 이 스킬은 **바로 그 순간**을 가로채 막는다.

## 🛑 절대 규칙 (HARD RULES)

1. **검증되지 않은 패키지를 자동 설치하지 않는다.** 항상 사람 승인 게이트를 거친다.
2. **설치 명령을 먼저 실행하지 않는다.** 검증 → 리포트 → (필요시) 승인 순서를 지킨다.
3. 🔴(차단)/🟡(주의)가 하나라도 있으면 **설치를 멈추고** 사용자 승인을 먼저 받는다.
4. 🔴는 사용자가 **"위험을 이해했고 그래도 진행한다"**고 명시적으로 답하기 전엔 진행 불가.
5. 설치는 **잠금파일 고정 + 해시 검증으로만** 한다(package-lock.json / requirements 해시 /
   poetry.lock / pnpm-lock.yaml / Cargo.lock 등).
6. 코드엔 있는데 레지스트리엔 없는 이름이면 **"AI가 지어낸 이름일 수 있다"**고 먼저 알린다.
7. **🔴는 화이트리스트에 넣지 않는다.** 사용자가 위험을 감수하고 강제 진행하더라도 그건 '이번 한 번'일
   뿐이며, `approve`로 영구 등록하는 것은 🟢/🟡 승인에만 허용된다(🔴를 등록하면 슬롭스쿼팅 우회로가 된다).

## 동작 절차 (이 순서를 지킨다)

> 참고: 아래 명령의 `scripts/`·`references/`·`assets/` 경로는 모두 **이 SKILL.md 가 있는 스킬 폴더 기준**이다.
> 사용자 프로젝트 루트에서 실행할 때는 스킬 폴더의 절대경로를 앞에 붙여라
> (예: `python "<스킬폴더>/scripts/verify_packages.py" ...` — Windows 등 경로에 공백이 있으면 큰따옴표로 감싼다).

1. **개입 시점** — 패키지를 설치하거나 코드에 새 import/의존성을 추가하기 **직전**에 멈춘다.
   설치 명령을 먼저 실행하지 않는다.
2. **추출** — 추가하려는 패키지 이름과 생태계(npm / pypi / crates / rubygems)를 모은다.
3. **검증** — `scripts/verify_packages.py` 를 실행한다.
   ```bash
   python scripts/verify_packages.py --report --ecosystem pypi  <패키지...>
   python scripts/verify_packages.py --json '[{"name":"react","ecosystem":"npm"}]'
   python scripts/verify_packages.py --report --manifest requirements.txt   # 매니페스트 전체 자동 추출
   ```
   (`--report` = 한국어 리포트 텍스트, 인자 없이 = JSON. 종료코드: 🔴=2, 🟡=1, 전부 🟢=0.
   매니페스트 파일을 수정해 새 패키지를 넣으려 할 땐 `--manifest <파일>` 로 한 번에 검사한다.)
4. **리포트** — 결과를 `references/REPORT_FORMAT.md` 형식의 **한국어**로 사용자에게 보여준다.
5. **게이트** — 🔴 또는 🟡가 하나라도 있으면 **설치를 멈추고** 명시적 승인을 요청한다.
   승인 전까지 어떤 설치 명령도 실행하지 않는다.
6. **승인 후 설치** — 잠금파일 + 해시로만 설치한다. 화이트리스트(`approve`) 등록은
   **🟢/🟡 판정을 사용자가 승인한 경우에만** 한다. 🔴를 강제 진행하면 이번 한 번만 설치하고
   등록하지 않는다(다음에 다시 검증받게 둔다 — 스크립트도 기본적으로 🔴 등록을 거부한다.
   의도적 강제 옵션이 있으나 일반 절차에서는 쓰지 않는다).
   ```bash
   python scripts/verify_packages.py approve <패키지> <생태계>           # 🟢/🟡 승인 기록 (🔴엔 쓰지 않는다)
   python scripts/verify_packages.py install-cmd <패키지> <생태계> [버전]  # 안전 설치 명령(잠금+해시) 생성
   ```
   `install-cmd` 가 출력한 명령을 **그대로** 실행한다(직접 설치 명령을 지어내지 않는다).

### 승인 후 안전 설치 명령 (잠금파일 고정 + 해시 검증)

- **pip** : `pip-compile --generate-hashes` 로 해시 박힌 requirements 생성 →
  `pip install --require-hashes -r requirements.txt`
- **npm** : `npm install <pkg>@<정확한버전> --save-exact` → 이후 `npm ci` (lockfile 무결성 검증)
- **pnpm** : `pnpm add <pkg>@<버전> --save-exact` → `pnpm install --frozen-lockfile`
- **yarn** : `yarn add <pkg>@<버전> --exact` → `yarn install --immutable`
- **poetry** : `poetry add <pkg>@<버전>` (poetry.lock 에 해시 기록) → `poetry install`
- **cargo** : `cargo add <pkg>@<버전>` (Cargo.lock 에 체크섬 기록)

## 워크드 예시

> 사용자: "이미지 처리 기능 추가해줘"
> → AI가 `pip install image-utils-pro` 를 실행하려 함.
> → **스킬 발동**: 설치를 멈추고 `python scripts/verify_packages.py --report --ecosystem pypi image-utils-pro` 실행.
> → PyPI에 `image-utils-pro` 없음.
> → 리포트(스크립트 실제 출력):
> ```
> 📦 패키지 안전 점검 결과
>
> 🔴 차단 — image-utils-pro : Python(pip) 공식 패키지 목록(앱을 받는 공식 앱스토어 같은 곳)에 이런 이름이 없습니다(AI가 이름을 지어냈을 가능성). → 설치를 멈췄습니다. 진행하려면 승인이 필요합니다.
>
> ※ 이 중 하나라도 🔴/🟡가 있으면 제가 임의로 설치하지 않습니다.
> ```
> → "정확한 이미지 라이브러리(예: Pillow)를 찾아드릴까요?"라고 묻고, 승인 없이는 설치하지 않는다.

## 동봉 파일

- `scripts/verify_packages.py` — 실존·평판·타이포스쿼팅·교차 레지스트리·보안경고 검증(결정적 로직).
- `assets/allowlist.json` — 사전 승인 패키지 화이트리스트(재검증 없이 통과, deprecated·보안 취약점이면 예외).
- `assets/denylist.json` — 알려진 악성·사칭 차단 목록(존재해도 항상 🔴).
- `references/REPORT_FORMAT.md` — 사용자에게 보여줄 한국어 리포트 포맷.
