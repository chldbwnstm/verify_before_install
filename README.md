# slopsquat-guard 🛡️

**English** · [한국어](README.ko.md)

> A guardrail that, the moment before an AI installs a package, automatically checks whether it
> **actually exists and has a healthy reputation** — and blocks the install if it looks dangerous.
> A safety belt for "vibe coders" who can't read the code being written for them.

This is an [agent skill](https://docs.claude.com/en/docs/claude-code/skills) for coding agents that
use the **SKILL.md standard** — [Claude Code](https://claude.com/claude-code), Codex, Gemini CLI, and others.

---

## Why it matters — "slopsquatting"

- About **20% of AI-generated code** imports or installs **a package that doesn't exist**.
- About **43% of those hallucinated names repeat** — the same fake name shows up again and again.
- Repetition means an attacker can **pre-register that name as a malicious package**.
  Real-world packages that steal credentials and API keys have already been found.
- Non-developers, when they hit a `module not found` / `No module named` error, **install whatever they're told to, no questions asked.**

**slopsquat-guard intercepts exactly that moment (just before install)**, verifies the package, and stops if it's risky.

---

## What it checks

| # | Check | Danger signal |
|---|-------|---------------|
| 1 | **Existence** | Is it really in the official registry (npm · PyPI · crates.io · RubyGems)? If not → 🔴 likely hallucinated |
| 2 | **Reputation** | Download count, first/last publish date, maintainers, repo link, deprecation |
| 3 | **Typo / slopsquatting** | One or two characters off a famous package (edit distance) but weak reputation → 🔴 likely impersonation |
| 4 | **Ecosystem confusion** | Missing in the requested registry but present in another → 🔴 (wrong source, or a payload) |
| 5 | **Security advisory** | The latest version still has a known vulnerability (OSV.dev) → 🟡 |

> Network failures and timeouts are **never auto-passed** — they become "cannot verify (🟡)".

---

## Quick start

**Requirements**: Python 3.7+ (standard library only, zero external dependencies).

1. Place this repo in your agent's skills directory, named `slopsquat-guard`:
   ```bash
   # Claude Code (project)
   git clone https://github.com/chldbwnstm/verify_before_install .claude/skills/slopsquat-guard
   # Claude Code (global)
   git clone https://github.com/chldbwnstm/verify_before_install ~/.claude/skills/slopsquat-guard
   ```
2. Done. The skill fires automatically the moment the agent tries to install/add a package.

You can also run it directly:

```bash
# Check packages (report output)
python scripts/verify_packages.py --report --ecosystem pypi requests tqdm image-utils-pro

# Make sure it works (no network needed)
python scripts/verify_packages.py selftest
```

---

## Usage (CLI)

```bash
# Positional args + ecosystem (simplest)
python scripts/verify_packages.py --ecosystem npm  react left-pad

# JSON input (multiple ecosystems at once)
python scripts/verify_packages.py --json '[{"name":"react","ecosystem":"npm"},{"name":"requests","ecosystem":"pypi"}]'
echo '{"npm":["react"],"pypi":["requests"]}' | python scripts/verify_packages.py --stdin

# Auto-extract & check every dependency from a manifest (ecosystem inferred from the filename)
python scripts/verify_packages.py --report --manifest requirements.txt
python scripts/verify_packages.py --manifest package.json --manifest Cargo.toml

# Human-readable report (show it to the user as-is)
python scripts/verify_packages.py --report --ecosystem pypi pillow

# Record an approval after the user consents (block verdicts are refused)
python scripts/verify_packages.py approve requests pypi

# Generate the safe install command (latest version auto-resolved if omitted)
python scripts/verify_packages.py install-cmd requests pypi

# Self-test / version
python scripts/verify_packages.py selftest
python scripts/verify_packages.py --version
```

**Ecosystem aliases**: `pypi` (= py/pip/python), `npm` (= node/yarn/pnpm/js), `crates` (= cargo/rust), `rubygems` (= gem/ruby).

**Exit codes** (handy as a shell gate): `0` = all 🟢, `1` = some 🟡, `2` = some 🔴.

> The report itself is written in plain Korean by design — the target users are Korean-speaking
> non-developers. The JSON output (`--json` / no `--report`) is language-neutral and structured for agents.

---

## Verdict grades

| Grade | Analogy | Meaning |
|-------|---------|---------|
| 🟢 **Safe** | passed the background check | In the official registry, healthy reputation — install with lockfile + hashes |
| 🟡 **Caution** | ID looks a bit off | New / low-download / no repo / cannot-verify / security advisory — needs user confirmation |
| 🔴 **Block** | forged ID, or not on the list | Does not exist / likely impersonation / wrong source — install stopped, explicit approval required |

---

## Example output

```
📦 패키지 안전 점검 결과

🟢 안전 — requests : 사전 승인(화이트리스트)된 패키지이고 알려진 보안 취약점이 없습니다.
🟢 안전 — tqdm : 공식 패키지 목록에 정식 등록돼 있고 평판 신호가 정상입니다.
🔴 차단 — image-utils-pro : Python(pip) 공식 패키지 목록(앱을 받는 공식 앱스토어 같은 곳)에 이런 이름이 없습니다(AI가 이름을 지어냈을 가능성). → 설치를 멈췄습니다. 진행하려면 승인이 필요합니다.

※ 이 중 하나라도 🔴/🟡가 있으면 제가 임의로 설치하지 않습니다.
```

*(The user-facing report is intentionally in plain Korean — see "Usage" above.)*

---

## Safe install (pinned lockfile + hash verification)

Approved packages are always installed with **an exact version + integrity hashes**.

| Tool | Command |
|------|---------|
| pip | `pip-compile --generate-hashes` → `pip install --require-hashes -r requirements.txt` |
| npm | `npm install <pkg>@<version> --save-exact` → `npm ci` |
| pnpm | `pnpm add <pkg>@<version> --save-exact` → `pnpm install --frozen-lockfile` |
| yarn | `yarn add <pkg>@<version> --exact` → `yarn install --immutable` |
| poetry | `poetry add <pkg>@<version>` → `poetry install` |
| cargo | `cargo add <pkg>@<version>` (Cargo.lock checksums) |

> These commands can be **generated automatically** with
> `python scripts/verify_packages.py install-cmd <package> <ecosystem>` (version auto-resolved).

---

## When the agent uses this skill

The `description` in `SKILL.md` acts as a routing rule. The skill fires automatically when:

- About to run `npm install` / `pip install` / `yarn add` / `pnpm add` / `poetry add` / `cargo add` / `gem install`
- A new package is added to `requirements.txt` · `package.json` · `pyproject.toml` · `Cargo.toml` · `Gemfile`
- A new **third-party** import/require is added to code (standard library and internal imports are excluded)
- A `module not found` / `No module named` / `Cannot find module` error is about to be "fixed" by installing

---

## Configuration

Tune the thresholds at the top of `scripts/verify_packages.py`:

```python
NEW_PACKAGE_DAYS  = 90     # how recent counts as "new"
LOW_DOWNLOADS     = {...}  # per-ecosystem "low downloads" threshold
TYPO_DISTANCE_MAX = 2      # max edit distance to a famous name to be an impersonation candidate
HTTP_TIMEOUT      = 8      # registry response timeout (seconds)
```

Or use a **config file**. Copy `assets/.slopsquatrc.example.json` to your project root or skill folder
as `.slopsquatrc.json`, or point to it with `SLOPSQUAT_CONFIG=<path>`:

```bash
python scripts/verify_packages.py --config ./.slopsquatrc.json --report --ecosystem pypi requests
```

- **Allowlist** `assets/allowlist.json` — pre-approved packages (add with `approve`; block verdicts are refused).
- **Denylist** `assets/denylist.json` — known malicious / impersonation names. Anything here is **always 🔴**,
  even if it exists in the registry. Add your organization's banned packages here.

**Cache & retry**: registry responses are cached on disk for a TTL (default 6h), and 429/5xx are retried with
exponential backoff (~8× faster on repeat checks, resilient to rate-limiting). Disable with `--no-cache`,
clear with `cache-clear`. (The OSV security-advisory lookup is never cached, so new CVEs show up immediately.)

**Parallel checks**: multiple packages (especially manifests) are checked concurrently (`--jobs N`, default 8).
8 packages: ~27s sequential → ~5s parallel. Force sequential with `--jobs 1`.

---

## Tests

```bash
python tests/test_verify.py        # runs with no external deps (pytest also works)
python scripts/verify_packages.py selftest
```

Every verdict path is verified deterministically, **with no network**.

---

## Limitations

- Reputation/typo heuristics do not guarantee 100% detection — **the human approval gate is the last line of defense.**
- PyPI's official API does not expose download counts, so those are best-effort only (via pypistats).
- Only *known/published* vulnerabilities are checked via OSV.dev — zero-days are unknowable.

---

## File structure

```
slopsquat-guard/
├── SKILL.md                      # agent trigger rules + procedure
├── README.md                     # this document (English)
├── README.ko.md                  # Korean document
├── scripts/verify_packages.py    # deterministic verification logic
├── assets/allowlist.json         # pre-approved allowlist
├── assets/denylist.json          # known malicious / impersonation denylist
├── assets/.slopsquatrc.example.json  # example config file
├── references/REPORT_FORMAT.md   # user-facing (Korean) report format
├── tests/test_verify.py          # test suite
├── CHANGELOG.md
└── LICENSE                       # MIT
```

## Author

**humblebee** — THE BETTER COMPANY AI

## License

MIT © 2026 humblebee (THE BETTER COMPANY AI) — see [`LICENSE`](LICENSE).
