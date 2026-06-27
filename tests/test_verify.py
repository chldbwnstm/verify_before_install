#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
slopsquat-guard 테스트 — 네트워크 없이 결정적으로 검증한다.

실행:
  python tests/test_verify.py          # 또는
  pytest tests/test_verify.py
둘 다 동작한다(외부 의존성 없음). 종료코드 0 = 통과.
"""
import os
import sys
import json
import time
import tempfile
import importlib.util
from datetime import datetime, timezone, timedelta

_HERE = os.path.dirname(os.path.abspath(__file__))
_SCRIPT = os.path.join(_HERE, "..", "scripts", "verify_packages.py")
_spec = importlib.util.spec_from_file_location("verify_packages", _SCRIPT)
m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(m)

OLD = datetime.now(timezone.utc) - timedelta(days=4000)
RECENT = datetime.now(timezone.utc) - timedelta(days=10)


def sig(**kw):
    s = m._blank()
    s["exists"] = True
    s.update(kw)
    return s


# ---- 순수 함수 -------------------------------------------------------------
def test_levenshtein():
    assert m.levenshtein("react", "react") == 0
    assert m.levenshtein("requests", "reqests") == 1
    assert m.levenshtein("colors", "colours") == 1
    assert m.levenshtein("", "abcd") == 4


def test_normalize_pypi():
    assert m.normalize_pypi("Flask__Login") == "flask-login"
    assert m.normalize_pypi("Django.REST.Framework") == "django-rest-framework"
    assert m.normalize_pypi("--weird--") == "weird"


def test_valid_name():
    assert m.valid_name("react-dom", "npm")
    assert m.valid_name("@scope/pkg", "npm")
    assert m.valid_name("beautifulsoup4", "pypi")
    assert not m.valid_name("../evil", "pypi")
    assert not m.valid_name("a/b", "pypi")
    assert not m.valid_name("x" * 300, "npm")


def test_parse_dt():
    assert m.parse_dt(12345) is None
    assert m.parse_dt(None) is None
    assert m.parse_dt("") is None
    assert m.parse_dt("2020-01-02T03:04:05Z") is not None
    assert m.parse_dt("2020-01-02T03:04:05.123456+00:00") is not None


def test_typosquat():
    strong = m.typosquat_hit("expresss", "npm", sig(downloads=5, repo=None, created=RECENT))
    assert strong and strong[0] == "express" and strong[2] is True
    weak = m.typosquat_hit("reqeusts", "pypi", sig(downloads=None, repo=None, created=None))
    assert weak and weak[2] is False
    assert m.typosquat_hit("fastai", "pypi", sig(repo="https://github.com/fastai/fastai", created=OLD)) is None
    assert m.typosquat_hit("react", "npm", sig()) is None  # 자기 자신


def test_damerau_transposition():
    assert m.damerau("flask", "flsak") == 1   # 인접 글자 바꿔치기
    assert m.levenshtein("flask", "flsak") == 2  # 일반 편집거리는 2
    assert m.damerau("requests", "reqeusts") == 1


def test_closest_popular():
    # 정확 이름 → 없음
    assert m.closest_popular("react", "npm") == (None, None)
    # 오타(전치)
    t, d = m.closest_popular("flsak", "pypi")
    assert t == "flask" and d == 1
    # 구분자 사칭: crossenv ↔ cross-env (실제 공격 사례)
    t, d = m.closest_popular("crossenv", "npm")
    assert t == "cross-env" and d <= 1
    # 접사 사칭
    t, d = m.closest_popular("requests-py", "pypi")
    assert t == "requests"
    t, d = m.closest_popular("python-flask", "pypi")
    assert t == "flask"
    # 전혀 다른 이름 → 없음
    assert m.closest_popular("my-unique-internal-tool-xyz", "npm") == (None, None)


def test_denylist():
    # 시드 차단 목록에 든 이름은 항상 🔴 (네트워크 조회 전, 존재 여부 무관)
    assert m.is_denylisted("colourama", "pypi")
    assert m.is_denylisted("crossenv", "npm")
    assert not m.is_denylisted("requests", "pypi")
    with _Patch(is_allowlisted=lambda n, e: False):
        r = m.assess("colourama", "pypi")
    assert r["level"] == "block" and "차단 목록" in r["reason_ko"]


def test_http_cache():
    import tempfile
    saved = (m.CACHE_DIR, m._USE_CACHE, m.CACHE_TTL)
    m.CACHE_DIR, m._USE_CACHE, m.CACHE_TTL = tempfile.mkdtemp(prefix="ssg-test-"), True, 100
    try:
        url = "https://example.invalid/fake-endpoint"
        m._cache_put(url, "ok", {"hello": 1})
        d, err = m.http_json(url)               # 캐시 적중 → 네트워크 호출 없음
        assert err is None and d == {"hello": 1}
        m._cache_put(url + "/missing", "missing", None)
        d2, err2 = m.http_json(url + "/missing")
        assert d2 is None and err2 == "missing"
        assert m._cache_get(url) is not None
        m.CACHE_TTL = 0                          # 캐시 비활성 → 조회 무시
        assert m._cache_get(url) is None
    finally:
        m.CACHE_DIR, m._USE_CACHE, m.CACHE_TTL = saved


def test_config_apply():
    saved_days, saved_typo = m.NEW_PACKAGE_DAYS, m.TYPO_DISTANCE_MAX
    try:
        m.apply_config({"new_package_days": 5, "typo_distance_max": 1})
        assert m.NEW_PACKAGE_DAYS == 5 and m.TYPO_DISTANCE_MAX == 1
    finally:
        m.apply_config({"new_package_days": saved_days, "typo_distance_max": saved_typo})


def test_assess_many_parallel_matches_sequential():
    items = [("alpha", "pypi"), ("bravo", "pypi"), ("charlie", "pypi"), ("delta", "pypi")]
    with _Patch(is_allowlisted=lambda n, e: False,
                osv_has_vuln=lambda *a, **k: (False, None),
                url_exists=lambda *a, **k: False):
        m.FETCHERS["pypi"] = lambda n, t: sig(downloads=10**6, created=OLD,
                                              repo="https://github.com/x", latest_version="1.0")
        seq = m.assess_many(items, jobs=1)
        par = m.assess_many(items, jobs=4)
    assert [r["package"] for r in par] == ["alpha", "bravo", "charlie", "delta"]  # 순서 유지
    assert [r["level"] for r in seq] == [r["level"] for r in par] == ["safe"] * 4


def test_assess_many_isolates_failure():
    # 한 패키지의 fetcher 가 예외를 던져도 나머지는 정상 처리(fail-closed → 🟡)
    def boom(n, t):
        if n == "bad":
            raise RuntimeError("kaboom")
        return sig(downloads=10**6, created=OLD, repo="https://x", latest_version="1.0")
    with _Patch(is_allowlisted=lambda n, e: False,
                osv_has_vuln=lambda *a, **k: (False, None),
                url_exists=lambda *a, **k: False):
        m.FETCHERS["pypi"] = boom
        res = m.assess_many([("good", "pypi"), ("bad", "pypi")], jobs=2)
    levels = {r["package"]: r["level"] for r in res}
    assert levels["good"] == "safe" and levels["bad"] == "warn"
    bad = next(r for r in res if r["package"] == "bad")
    assert "RuntimeError" not in bad["reason_ko"]   # 영문 예외명이 사용자 문구에 새지 않는다


# ---- 차단 목록 fail-closed --------------------------------------------------
def test_denylist_fails_closed_when_corrupt():
    saved = m.DENYLIST_PATH
    fd, path = tempfile.mkstemp(prefix="ssg-deny-", suffix=".json")
    os.close(fd)
    with open(path, "w", encoding="utf-8") as f:
        f.write("not valid json {{{")
    try:
        m.DENYLIST_PATH = path
        dl, ok = m.load_denylist()
        assert ok is False                          # 손상 → fail-closed 신호
        with _Patch(is_allowlisted=lambda n, e: False):
            r = m.assess("crossenv", "npm")         # 손상 시 조용히 통과하지 않고 🟡
        assert r["level"] == "warn" and "차단 목록" in r["reason_ko"]
    finally:
        m.DENYLIST_PATH = saved
        os.remove(path)


def test_denylist_absent_is_ok():
    saved = m.DENYLIST_PATH
    try:
        m.DENYLIST_PATH = os.path.join(tempfile.gettempdir(), "ssg-nonexistent-deny.json")
        dl, ok = m.load_denylist()
        assert ok is True and dl == {}              # 부재는 정상(차단 없음)
    finally:
        m.DENYLIST_PATH = saved


# ---- 매니페스트: http 접두 패키지 & 이상 형식 방어 -------------------------
def test_requirements_keeps_http_prefixed_packages():
    txt = "httpx==0.27\nhttpie\nhttp-prompt\nrequests\ngit+https://github.com/x/y.git\nthing @ https://e.com/t.whl\n"
    names = [n for n, e in m.parse_manifest_text(txt, "requirements.txt")]
    assert "httpx" in names and "httpie" in names and "http-prompt" in names and "requests" in names
    assert not any("github.com" in n for n in names)   # URL/VCS 줄은 여전히 제외


def test_manifest_malformed_shape_raises_clean():
    # 이상 형식은 트레이스백(AttributeError/TypeError) 없이 처리해야 한다 — ValueError 이거나 빈 결과
    for bad in ("[1,2,3]", '{"dependencies":"requests"}', '{"dependencies":[1,2]}'):
        try:
            res = m.parse_manifest_text(bad, "package.json")
            assert isinstance(res, list)
        except ValueError:
            pass


# ---- 설정: 명시 경로 fail-closed, 잘못된 값 방어 ---------------------------
def test_config_explicit_missing_path_errors():
    try:
        m.load_config("/no/such/.slopsquatrc.json")
        assert False, "explicit missing config should raise SystemExit"
    except SystemExit:
        pass


def test_config_apply_tolerates_bad_values():
    saved = (m.NEW_PACKAGE_DAYS, m.HTTP_TIMEOUT)
    try:
        m.apply_config({"new_package_days": None, "http_timeout": "abc"})  # 크래시 없이 기본값 유지
        assert m.NEW_PACKAGE_DAYS == saved[0] and m.HTTP_TIMEOUT == saved[1]
    finally:
        m.NEW_PACKAGE_DAYS, m.HTTP_TIMEOUT = saved


# ---- approve(): 🔴 거부 / --force / 손상 보호 ------------------------------
def _temp_allowlist(initial_bytes):
    fd, path = tempfile.mkstemp(prefix="ssg-allow-", suffix=".json")
    os.close(fd)
    if initial_bytes is None:
        os.remove(path)
    else:
        with open(path, "wb") as f:
            f.write(initial_bytes)
    return path


def test_approve_refuses_block_verdict():
    path = _temp_allowlist(b'{"pypi": ["already"]}')
    saved_path, saved_assess = m.ALLOWLIST_PATH, m.assess
    try:
        m.ALLOWLIST_PATH = path
        m.assess = lambda n, e, **k: m.verdict_obj(n, e, "block", "사칭", "중단")
        before = open(path, "rb").read()
        try:
            m.approve("evilpkg", "pypi")
            assert False, "approve should refuse a block verdict"
        except SystemExit:
            pass
        assert open(path, "rb").read() == before        # 파일 변경 없음
    finally:
        m.ALLOWLIST_PATH, m.assess = saved_path, saved_assess
        if os.path.exists(path):
            os.remove(path)


def test_approve_force_writes_block():
    path = _temp_allowlist(None)
    saved_path, saved_assess = m.ALLOWLIST_PATH, m.assess
    try:
        m.ALLOWLIST_PATH = path
        m.assess = lambda n, e, **k: m.verdict_obj(n, e, "block", "사칭", "중단")
        m.approve("evilpkg", "pypi", force=True)
        assert "evilpkg" in json.load(open(path, encoding="utf-8"))["pypi"]
    finally:
        m.ALLOWLIST_PATH, m.assess = saved_path, saved_assess
        if os.path.exists(path):
            os.remove(path)


def test_approve_aborts_on_corrupt_allowlist():
    corrupt = b"not json at all {"
    path = _temp_allowlist(corrupt)
    saved_path, saved_assess = m.ALLOWLIST_PATH, m.assess
    try:
        m.ALLOWLIST_PATH = path
        m.assess = lambda n, e, **k: m.verdict_obj(n, e, "safe", "정상", "설치")
        try:
            m.approve("requests", "pypi")
            assert False, "approve should abort on corrupt allowlist"
        except SystemExit:
            pass
        assert open(path, "rb").read() == corrupt        # 기존 내용 보존
    finally:
        m.ALLOWLIST_PATH, m.assess = saved_path, saved_assess
        if os.path.exists(path):
            os.remove(path)


# ---- 캐시 만료 + TOML 폴백 + HTTP 재시도 -----------------------------------
def test_cache_expiry():
    saved = (m.CACHE_DIR, m._USE_CACHE, m.CACHE_TTL)
    m.CACHE_DIR, m._USE_CACHE, m.CACHE_TTL = tempfile.mkdtemp(prefix="ssg-exp-"), True, 100
    try:
        url = "https://example.invalid/expiring"
        with open(m._cache_path(url), "w", encoding="utf-8") as f:
            json.dump({"ts": time.time() - (m.CACHE_TTL + 1), "status": "ok", "data": {"stale": 1}}, f)
        assert m._cache_get(url) is None              # 만료된 레코드는 무시
    finally:
        m.CACHE_DIR, m._USE_CACHE, m.CACHE_TTL = saved


def test_toml_fallback_parsers():
    cargo = '[dependencies]\nserde = "1"\ntokio = { version = "1" }\n[dev-dependencies]\ncriterion = "0.5"\n'
    keys = m._toml_fallback_keys(cargo, ("dependencies", "dev-dependencies", "build-dependencies"))
    assert "serde" in keys and "tokio" in keys and "criterion" in keys
    # pyproject 정규식 폴백(tomllib 강제 비활성)
    saved = m._toml_loads
    try:
        m._toml_loads = lambda t: None
        py = '[project]\ndependencies = ["requests>=2", "flask"]\n[tool.poetry.dependencies]\npython = "^3.10"\nnumpy = "^1"\n'
        names = m._parse_pyproject(py)
        assert "requests" in names and "flask" in names and "numpy" in names and "python" not in names
    finally:
        m._toml_loads = saved


def test_http_json_retry_and_no_cache_for_transient():
    import urllib.error
    saved = (m.CACHE_DIR, m._USE_CACHE, m.CACHE_TTL, m._backoff, m.urllib.request.urlopen)
    m.CACHE_DIR, m._USE_CACHE, m.CACHE_TTL = tempfile.mkdtemp(prefix="ssg-retry-"), True, 100
    m._backoff = lambda *a, **k: None                 # 실제 sleep 회피

    class _Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return b'{"ok": 1}'
    calls = {"n": 0}

    def flaky_open(req, timeout=None):
        calls["n"] += 1
        if calls["n"] <= 2:
            raise urllib.error.HTTPError(req.full_url, 503, "busy", {}, None)
        return _Resp()
    try:
        m.urllib.request.urlopen = flaky_open
        d, err = m.http_json("https://example.invalid/retry")
        assert err is None and d == {"ok": 1} and calls["n"] == 3   # 1 + HTTP_RETRIES(2)

        def always_503(req, timeout=None):
            raise urllib.error.HTTPError(req.full_url, 503, "busy", {}, None)
        m.urllib.request.urlopen = always_503
        url2 = "https://example.invalid/always-503"
        d2, err2 = m.http_json(url2)
        assert d2 is None and err2 == "http_503"
        assert m._cache_get(url2) is None             # 일시적 오류는 캐시하지 않음
    finally:
        (m.CACHE_DIR, m._USE_CACHE, m.CACHE_TTL, m._backoff, m.urllib.request.urlopen) = saved


def test_homoglyph_disguise():
    # 키릴 'е'(U+0435) 가 섞인 'rеquests' → 형식 검증에서 사칭으로 차단
    disguised = "rеquests"
    assert m._looks_disguised(disguised)
    with _Patch(is_allowlisted=lambda n, e: False):
        r = m.assess(disguised, "pypi")
    assert r["level"] == "block" and "사칭" in r["reason_ko"]


def test_items_from_json_validation():
    for bad in ('{"npm":"react"}', '[{"ecosystem":"npm"}]', 'not json', '"x"', '5'):
        try:
            m.items_from_json(bad)
            assert False, "should have raised for %r" % bad
        except ValueError:
            pass
    assert m.items_from_json('[{"name":"react","ecosystem":"npm"}]') == [("react", "npm")]
    assert m.items_from_json('{"npm":["a","b"]}') == [("a", "npm"), ("b", "npm")]


def test_report_format():
    rep = m.render_report([
        m.verdict_obj("a", "pypi", "safe", "정상", "설치"),
        m.verdict_obj("b", "npm", "warn", "주의", "확인"),
        m.verdict_obj("c", "pypi", "block", "차단", "중단"),
    ])
    assert rep.startswith("📦 패키지 안전 점검 결과\n\n")
    assert "🟢 안전 — a : 정상" in rep
    assert "🟡 주의 — b : 주의 → 확인" in rep
    assert "🔴 차단 — c : 차단 → 설치를 멈췄습니다. 진행하려면 승인이 필요합니다." in rep
    assert rep.rstrip().endswith("※ 이 중 하나라도 🔴/🟡가 있으면 제가 임의로 설치하지 않습니다.")


# ---- 판정 경로 (몽키패치로 네트워크 차단) ----------------------------------
class _Patch:
    """assess() 가 부르는 네트워크/상태 함수를 임시 교체."""
    def __init__(self, **funcs):
        self.funcs = funcs

    def __enter__(self):
        g = vars(m)
        self.saved = {k: g[k] for k in self.funcs}
        self.saved_fetchers = dict(m.FETCHERS)
        g.update(self.funcs)
        if "pypi_fetch" in self.funcs:
            m.FETCHERS["pypi"] = self.funcs["pypi_fetch"]
        return self

    def __exit__(self, *a):
        vars(m).update(self.saved)
        m.FETCHERS.clear()
        m.FETCHERS.update(self.saved_fetchers)


def _patched(fetch, allow=False, vuln=False, cross=False):
    base = dict(
        is_allowlisted=lambda n, e: allow,
        osv_has_vuln=lambda *a, **k: (vuln, None),
        url_exists=lambda *a, **k: cross,
    )
    p = _Patch(**base)
    p.__enter__()
    m.FETCHERS["pypi"] = fetch
    return p


def _assess(name, **kw):
    fetch = kw.pop("fetch")
    p = _patched(fetch, **kw)
    try:
        return m.assess(name, "pypi")
    finally:
        p.__exit__()


def test_path_safe():
    f = lambda n, t: sig(downloads=10**6, created=OLD, repo="https://github.com/x", latest_version="1.0")
    assert _assess("goodpkg", fetch=f)["level"] == "safe"


def test_path_osv_vuln():
    f = lambda n, t: sig(downloads=10**6, created=OLD, repo="https://github.com/x", latest_version="1.0")
    assert _assess("goodpkg", fetch=f, vuln=True)["level"] == "warn"


def test_path_hallucination():
    f = lambda n, t: dict(m._blank(), exists=False)
    assert _assess("totallyfake", fetch=f)["level"] == "block"


def test_path_cross_registry():
    f = lambda n, t: dict(m._blank(), exists=False)
    assert _assess("react-dom", fetch=f, cross=True)["level"] == "block"


def test_path_network_error():
    f = lambda n, t: sig(error="neterr:TimeoutError")
    r = _assess("anything", fetch=f)
    assert r["level"] == "warn"
    assert "neterr" not in r["reason_ko"]  # 원시 코드 노출 금지


def test_path_deprecated():
    f = lambda n, t: sig(deprecated=True, created=OLD, repo="https://x", latest_version="1.0")
    assert _assess("oldpkg", fetch=f)["level"] == "warn"


def test_path_weak_block():
    f = lambda n, t: sig(downloads=1, created=RECENT, repo=None, latest_version="0.0.1")
    assert _assess("brandnew", fetch=f)["level"] == "block"


def test_path_weak_warn():
    f = lambda n, t: sig(downloads=10**6, created=RECENT, repo="https://x", latest_version="1.0")
    assert _assess("youngpopular", fetch=f)["level"] == "warn"


def test_path_invalid_name():
    f = lambda n, t: sig()
    assert _assess("../evil", fetch=f)["level"] == "block"


def test_path_allowlist():
    f = lambda n, t: sig(created=OLD, repo="https://x", latest_version="1.0")
    assert _assess("requests", fetch=f, allow=True)["level"] == "safe"
    fd = lambda n, t: sig(deprecated=True, created=OLD, latest_version="1.0")
    assert _assess("requests", fetch=fd, allow=True)["level"] == "warn"


def test_offline():
    with _Patch(is_allowlisted=lambda n, e: True):
        assert m.assess("requests", "pypi", offline=True)["level"] == "safe"
    with _Patch(is_allowlisted=lambda n, e: False):
        assert m.assess("whatever", "pypi", offline=True)["level"] == "warn"


def test_builtin_selftest():
    assert m.run_selftest(verbose=False) == 0


# ---- 매니페스트 파싱 -------------------------------------------------------
def test_detect_manifest_kind():
    assert m.detect_manifest_kind("/x/requirements.txt") == "requirements.txt"
    assert m.detect_manifest_kind("requirements-dev.txt") == "requirements.txt"
    assert m.detect_manifest_kind("package.json") == "package.json"
    assert m.detect_manifest_kind("a/b/Cargo.toml") == "cargo.toml"
    assert m.detect_manifest_kind("pyproject.toml") == "pyproject.toml"
    assert m.detect_manifest_kind("Gemfile") == "gemfile"
    assert m.detect_manifest_kind("random.txt") is None


def test_parse_requirements():
    txt = (
        "# comment\n"
        "requests>=2.0\n"
        "Flask==1.0  # inline comment\n"
        "package[extra]==1.2\n"
        "pkg ; python_version < '3.8'\n"
        "-r other.txt\n"
        "--hash=sha256:abc\n"
        "git+https://github.com/x/y.git\n"
        "thing @ https://example.com/thing.whl\n"
        "\n"
    )
    pairs = m.parse_manifest_text(txt, "requirements.txt")
    names = [n for n, e in pairs]
    assert names == ["requests", "Flask", "package", "pkg"]
    assert all(e == "pypi" for _, e in pairs)


def test_parse_package_json():
    txt = """{
      "dependencies": {"react": "^18", "left-pad": "1.0.0", "local": "file:../local"},
      "devDependencies": {"eslint": "^9"},
      "peerDependencies": {"ws": "workspace:*"}
    }"""
    names = [n for n, e in m.parse_manifest_text(txt, "package.json")]
    assert "react" in names and "left-pad" in names and "eslint" in names
    assert "local" not in names and "ws" not in names  # file:/workspace 제외


def test_parse_gemfile():
    txt = "source 'https://rubygems.org'\ngem 'rails', '~> 7'\n# gem 'commented'\ngem \"pg\"\n"
    names = [n for n, e in m.parse_manifest_text(txt, "gemfile")]
    assert names == ["rails", "pg"]
    assert all(e == "rubygems" for _, e in m.parse_manifest_text(txt, "gemfile"))


def test_parse_cargo():
    txt = (
        "[dependencies]\n"
        'serde = "1.0"\n'
        'tokio = { version = "1", features = ["full"] }\n'
        'mylocal = { path = "../mylocal" }\n'
        "[dev-dependencies]\n"
        'criterion = "0.5"\n'
    )
    names = [n for n, e in m.parse_manifest_text(txt, "cargo.toml")]
    assert "serde" in names and "tokio" in names and "criterion" in names
    assert "mylocal" not in names  # path 의존성 제외


def test_parse_pyproject():
    txt = (
        "[project]\n"
        'dependencies = ["requests>=2", "flask"]\n'
        "[project.optional-dependencies]\n"
        'dev = ["pytest>=7"]\n'
        "[tool.poetry.dependencies]\n"
        'python = "^3.10"\n'
        'numpy = "^1.26"\n'
    )
    names = [n for n, e in m.parse_manifest_text(txt, "pyproject.toml")]
    assert "requests" in names and "flask" in names and "pytest" in names and "numpy" in names
    assert "python" not in names  # poetry 의 python 제외


def test_parse_manifest_dedup():
    txt = "requests\nrequests==2.0\nflask\n"
    pairs = m.parse_manifest_text(txt, "requirements.txt")
    assert pairs == [("requests", "pypi"), ("flask", "pypi")]


# ---- 안전 설치 명령 생성기 ------------------------------------------------
def test_render_install_npm():
    out = m.render_install("react", "npm", "18.2.0")
    assert "npm install react@18.2.0 --save-exact" in out
    assert "npm ci" in out and "pnpm" in out and "yarn" in out


def test_render_install_pypi():
    out = m.render_install("requests", "pypi", "2.31.0")
    assert "requests==2.31.0" in out
    assert "--require-hashes" in out and "--generate-hashes" in out


def test_render_install_crates_rubygems():
    assert "cargo add serde@1.0.0 --locked" in m.render_install("serde", "crates", "1.0.0")
    assert 'bundle add rails --version "7.1.0"' in m.render_install("rails", "rubygems", "7.1.0")


def test_render_install_placeholder_and_alias():
    out = m.render_install("foo", "pip", None)        # pip alias → pypi, no version
    assert "foo==<버전>" in out
    assert m.render_install("foo", "golang", "1") is None  # 미지원 생태계


# ---- 러너 (pytest 없이도 실행 가능) ---------------------------------------
def _run():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print("  PASS %s" % t.__name__)
        except Exception as e:
            failed += 1
            print("  FAIL %s — %s: %s" % (t.__name__, type(e).__name__, e))
    print("\n%d/%d passed" % (len(tests) - failed, len(tests)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run())
