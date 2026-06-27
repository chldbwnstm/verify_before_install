#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
slopsquat-guard / verify_packages.py

AI가 코드에 추가하거나 설치하려는 패키지를 '설치 직전'에 검증하는 결정적 로직.
모델의 판단이 아니라 이 스크립트의 규칙으로 판정한다.

검사 항목
  1) 실존 여부        : 공식 레지스트리(npm/PyPI/crates.io/RubyGems) 조회
  2) 평판 신호        : 다운로드 수, 최초/최근 배포일, 메인테이너, 저장소 링크, deprecated
  3) 슬롭/타이포스쿼팅 : 유명 패키지와의 편집거리(Levenshtein) 휴리스틱
  4) 교차 레지스트리 혼동 : 요청한 생태계엔 없고 다른 생태계엔 있는 경우
  5) 보안 경고        : (화이트리스트/정상 판정 직전) OSV.dev 알려진 취약점 조회

원칙
  - 네트워크 실패/타임아웃은 절대 자동 통과시키지 않는다 → '검증 불가(🟡)'.
  - 모든 임계값은 파일 상단 상수로 분리해 쉽게 조정 가능하다.

사용법
  python verify_packages.py --ecosystem pypi  image-utils-pro requests
  python verify_packages.py --ecosystem npm   left-pad expresss
  python verify_packages.py --json '[{"name":"react","ecosystem":"npm"}]'
  echo '{"pypi":["requests"],"npm":["react"]}' | python verify_packages.py --stdin
  python verify_packages.py --report --ecosystem pypi pillow   # 한국어 리포트로 출력
  python verify_packages.py approve requests pypi              # 🟢/🟡 승인 후 화이트리스트 등록
"""

import sys
import os
import re
import json
import time
import hashlib
import tempfile
import threading
import argparse
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone, timedelta

# Windows 콘솔(cp949 등) 에서도 이모지/한글이 깨지지 않도록 출력 인코딩을 UTF-8 로 강제.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except Exception:
        pass

__version__ = "1.0.0"

# ----------------------------------------------------------------------------
# 판정 임계값 (여기만 고치면 정책 조정 가능)
# ----------------------------------------------------------------------------
HTTP_TIMEOUT      = 8        # 초. 레지스트리 응답 대기 한도
NEW_PACKAGE_DAYS  = 90       # 이 일수 이내에 처음 배포되면 '신생'으로 본다
TYPO_DISTANCE_MAX = 2        # 유명 패키지와 편집거리가 이 값 이하면 사칭 의심 후보

# '저다운로드' 기준 (생태계별). 데이터가 없으면 None 으로 둔다.
LOW_DOWNLOADS = {
    "npm":      1000,   # 최근 30일 다운로드
    "crates":   1000,   # 누적 다운로드
    "rubygems": 5000,   # 누적 다운로드
    # PyPI 는 JSON API 가 다운로드 수를 주지 않아 best-effort(pypistats)로만 본다.
    "pypi":     500,    # 최근 30일 다운로드(pypistats 가 응답할 때만 적용)
}

USER_AGENT = "slopsquat-guard/%s (+package verification gate)" % __version__

CACHE_TTL    = 6 * 3600     # 초. 레지스트리 응답 캐시 유효기간(0 이면 캐시 안 함)
HTTP_RETRIES = 2            # 429/5xx/네트워크 오류 재시도 횟수
CACHE_DIR    = os.environ.get("SLOPSQUAT_CACHE_DIR") or os.path.join(
    tempfile.gettempdir(), "slopsquat-guard-cache")
_USE_CACHE   = True         # --no-cache 로 런타임에서 끔

# 사용자에게 보여줄 친근한 생태계 표시명 (원시 키 pypi/npm 누출 방지)
ECO_LABEL = {
    "npm":      "JavaScript(npm)",
    "pypi":     "Python(pip)",
    "crates":   "Rust(cargo)",
    "rubygems": "Ruby(gem)",
}

# OSV.dev 가 쓰는 생태계 이름
OSV_ECO = {"npm": "npm", "pypi": "PyPI", "crates": "crates.io", "rubygems": "RubyGems"}

# 생태계별 정상 패키지 이름 형식 (네트워크 호출 전 경로조작/이상문자 차단용)
NAME_RE = {
    "npm":      re.compile(r"^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$", re.I),
    "pypi":     re.compile(r"^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$", re.I),
    "crates":   re.compile(r"^[a-z0-9][a-z0-9_-]*$", re.I),
    "rubygems": re.compile(r"^[a-z0-9][a-z0-9._-]*$", re.I),
}

# ----------------------------------------------------------------------------
# 유명 패키지 목록 (타이포/슬롭스쿼팅 비교 기준)
# ----------------------------------------------------------------------------
POPULAR = {
    "npm": [
        "react", "react-dom", "react-router", "react-router-dom", "lodash", "express",
        "axios", "chalk", "commander", "request", "async", "moment", "vue", "webpack",
        "babel-core", "jquery", "underscore", "bluebird", "debug", "colors", "dotenv",
        "mongoose", "body-parser", "socket.io", "next", "typescript", "eslint", "prettier",
        "redux", "rxjs", "cross-env", "node-fetch", "uuid", "yargs", "glob", "fs-extra",
        "semver", "ws", "cors", "jsonwebtoken", "bcrypt", "nodemon", "classnames",
        "styled-components", "tailwindcss", "vite", "rollup", "esbuild", "jest", "mocha",
        "chai", "sinon", "nodemailer", "passport", "helmet", "morgan", "winston", "pino",
        "ioredis", "sequelize", "prisma", "graphql", "dayjs", "date-fns", "ramda", "immer",
        "zustand", "formik", "yup", "zod", "redux-thunk", "redux-saga", "ts-node", "nanoid",
        "qs", "cheerio", "puppeteer", "playwright", "sharp", "multer", "knex", "got",
    ],
    "pypi": [
        "requests", "numpy", "pandas", "flask", "django", "pillow", "scipy", "matplotlib",
        "setuptools", "urllib3", "boto3", "pytest", "click", "jinja2", "sqlalchemy",
        "beautifulsoup4", "selenium", "scrapy", "tensorflow", "torch", "transformers",
        "fastapi", "uvicorn", "pydantic", "aiohttp", "certifi", "cryptography", "pyyaml",
        "python-dateutil", "six", "wheel", "virtualenv", "openai", "scikit-learn",
        "opencv-python", "seaborn", "plotly", "keras", "nltk", "spacy", "gensim", "xgboost",
        "lightgbm", "statsmodels", "sympy", "networkx", "tqdm", "rich", "typer", "httpx",
        "starlette", "gunicorn", "celery", "redis", "pymongo", "psycopg2", "asyncpg",
        "alembic", "marshmallow", "djangorestframework", "black", "flake8", "mypy", "isort",
        "poetry", "twine", "anyio", "websockets", "orjson", "loguru", "dnspython", "colorama",
    ],
    "crates": [
        "serde", "tokio", "rand", "clap", "reqwest", "syn", "quote", "regex", "log",
        "anyhow", "thiserror", "libc", "futures", "hyper", "serde_json", "chrono",
        "itertools", "rayon", "bytes", "async-trait", "tracing", "once_cell", "lazy_static",
        "parking_lot", "crossbeam", "base64", "sha2", "ring", "rustls", "tonic", "axum",
        "actix-web", "diesel", "sqlx", "tower", "hashbrown", "indexmap", "time", "uuid",
    ],
    "rubygems": [
        "rails", "rake", "bundler", "rspec", "nokogiri", "devise", "puma", "sidekiq",
        "sinatra", "faraday", "pg", "redis", "json", "activerecord", "rack", "sequel",
        "rubocop", "pry", "capybara", "factory_bot", "httparty", "jwt", "dotenv", "kaminari",
        "will_paginate", "carrierwave", "sass", "webpacker", "rest-client", "mysql2",
    ],
}

# 접사 사칭(예: python-<유명>, <유명>-js) 탐지용 흔한 접두/접미
_TYPO_PREFIXES = ("python-", "python3-", "py-", "node-", "js-", "go-", "lib")
_TYPO_SUFFIXES = ("js", "-js", ".js", "py", "-py", "2", "3", "-python", "-node", "-cli", "-sdk")

# 생태계 별칭 정규화
ECO_ALIASES = {
    "py": "pypi", "pip": "pypi", "python": "pypi", "pypi": "pypi",
    "npm": "npm", "node": "npm", "yarn": "npm", "pnpm": "npm", "js": "npm",
    "crates": "crates", "crate": "crates", "cargo": "crates", "rust": "crates",
    "rubygems": "rubygems", "gem": "rubygems", "gems": "rubygems", "ruby": "rubygems",
}

ALLOWLIST_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "assets", "allowlist.json"
)

# 화이트리스트 JSON 의 키 ↔ 내부 생태계 키
ALLOWLIST_KEY = {"pypi": "pypi", "npm": "npm", "crates": "crates", "rubygems": "rubygems"}

# 알려진 악성/사칭 패키지 차단 목록 — 레지스트리에 존재하더라도 항상 🔴
DENYLIST_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "assets", "denylist.json"
)


# ----------------------------------------------------------------------------
# 유틸
# ----------------------------------------------------------------------------
def norm_eco(name):
    return ECO_ALIASES.get((name or "").strip().lower(), (name or "").strip().lower())


def eco_disp(eco):
    return ECO_LABEL.get(eco, eco)


def normalize_pypi(name):
    """PEP 503: 소문자화 + 연속된 . _ - 를 하나의 - 로."""
    out, prev_sep = [], False
    for ch in name.strip().lower():
        if ch in "._-":
            if not prev_sep:
                out.append("-")
            prev_sep = True
        else:
            out.append(ch)
            prev_sep = False
    return "".join(out).strip("-")


def valid_name(name, eco):
    """네트워크 호출 전 이름 형식 검증. '..'·이상한 '/'·제어문자를 차단한다."""
    if not name or len(name) > 214 or ".." in name:
        return False
    rx = NAME_RE.get(eco)
    return bool(rx.match(name)) if rx else True


def levenshtein(a, b):
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def damerau(a, b):
    """인접 글자 바꿔치기(transposition)까지 거리 1로 보는 편집거리 — 오타 모델에 더 정확."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if not la:
        return lb
    if not lb:
        return la
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


def _norm_sep(s):
    return re.sub(r"[-_.]", "", s)


def _looks_disguised(name):
    """진짜처럼 보이게 하는 비-ASCII 유사 알파벳(호모글리프)이 섞였는가."""
    return any(ord(c) > 127 and c.isalpha() for c in (name or ""))


def closest_popular(cand, eco):
    """유명 패키지 중 가장 가까운 것을 (이름, 거리)로 반환. 후보 자신이 유명하면 (None, None).

    Damerau 편집거리 + 구분자 무시 비교(crossenv↔cross-env) + 접사 사칭을 모두 고려한다.
    """
    pool = POPULAR.get(eco, [])
    bare = cand.split("/")[-1] if "/" in cand else cand     # @scope/name → name
    if cand in pool or bare in pool:
        return None, None
    nb = _norm_sep(bare)
    best, best_d = None, 99
    for fam in pool:
        if bare == fam:
            return None, None
        if _norm_sep(fam) == nb:
            d = 1                                            # 구분자만 다름 = 사칭
        else:
            d = min(damerau(bare, fam), damerau(nb, _norm_sep(fam)))
        if 1 <= d < best_d:
            best, best_d = fam, d
    pset = set(pool)                                         # 접사 사칭: 유명이름 ± 흔한 접사
    for pre in _TYPO_PREFIXES:
        if bare.startswith(pre) and bare[len(pre):] in pset:
            best, best_d = bare[len(pre):], min(best_d, 1)
    for suf in _TYPO_SUFFIXES:
        if bare.endswith(suf) and len(bare) > len(suf) and bare[:-len(suf)] in pset:
            best, best_d = bare[:-len(suf)], min(best_d, 1)
    if best is None or best_d > TYPO_DISTANCE_MAX:
        return None, None
    return best, best_d


def _cache_path(key):
    return os.path.join(CACHE_DIR, hashlib.sha256(key.encode("utf-8")).hexdigest() + ".json")


def _cache_get(key):
    if not _USE_CACHE or CACHE_TTL <= 0:
        return None
    try:
        with open(_cache_path(key), "r", encoding="utf-8") as f:
            rec = json.load(f)
        if (time.time() - rec["ts"]) <= CACHE_TTL:
            return rec
    except Exception:
        return None
    return None


def _cache_put(key, status, data):
    if not _USE_CACHE or CACHE_TTL <= 0:
        return
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        path = _cache_path(key)
        # 프로세스·스레드·난스로 고유한 임시파일(병렬·다중프로세스 안전)
        tmp = "%s.%d.%d.%s.tmp" % (path, os.getpid(), threading.get_ident(), os.urandom(6).hex())
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"ts": time.time(), "status": status, "data": data}, f)
        os.replace(tmp, path)
    except Exception:
        pass


def _backoff(httperr, attempt):
    delay = 0.5 * (2 ** attempt)                  # 0.5s, 1.0s, ...
    if httperr is not None and httperr.headers:
        ra = httperr.headers.get("Retry-After")
        if ra and str(ra).isdigit():
            delay = float(ra)
    time.sleep(min(delay, 5.0))                   # 상한 5초


def http_json(url, timeout=HTTP_TIMEOUT, data=None, no_cache=False):
    """(data, error). 200+JSON→(dict,None), 404→(None,'missing'), 그 외→(None,'에러문').

    응답은 TTL 동안 디스크에 캐시하고, 429/5xx/네트워크 오류는 지수 백오프로 재시도한다.
    성공(200)·없음(404)만 캐시하고, 일시적 오류는 캐시하지 않는다(다음에 다시 시도).
    no_cache=True 면 캐시를 건너뛴다(보안 경고 조회처럼 신선도가 중요한 경우).
    """
    key = url if data is None else url + "\n" + data.decode("utf-8", "replace")
    if not no_cache:
        cached = _cache_get(key)
        if cached is not None:
            if cached["status"] == "ok":
                return cached["data"], None
            if cached["status"] == "missing":
                return None, "missing"

    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, headers=headers, data=data,
                                 method="POST" if data is not None else "GET")
    attempt = 0
    while True:
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                d = json.loads(resp.read().decode("utf-8", "replace"))
                if not no_cache:
                    _cache_put(key, "ok", d)
                return d, None
        except urllib.error.HTTPError as e:
            if e.code == 404:
                if not no_cache:
                    _cache_put(key, "missing", None)
                return None, "missing"
            if (e.code == 429 or 500 <= e.code < 600) and attempt < HTTP_RETRIES:
                _backoff(e, attempt)
                attempt += 1
                continue
            return None, "http_%d" % e.code
        except Exception as e:  # 타임아웃/DNS/연결 거부 등
            if attempt < HTTP_RETRIES:
                _backoff(None, attempt)
                attempt += 1
                continue
            return None, "neterr:%s" % type(e).__name__


def url_exists(url, timeout=HTTP_TIMEOUT):
    """타 레지스트리 실존 확인. True(존재)/False(404=없음)/None(판정 불가)."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 400
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False                 # 확실히 없음
        if 200 <= e.code < 400:
            return True                  # 확실히 있음
        return None                      # 403/429/5xx 등 → 혼동으로 단정하지 않음
    except Exception:
        return None


def parse_dt(s):
    if not isinstance(s, str):
        return None
    s = s.strip().replace("Z", "+00:00")
    for cut in (s, s[:19]):
        try:
            dt = datetime.fromisoformat(cut)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def days_since(dt):
    if dt is None:
        return None
    return (datetime.now(timezone.utc) - dt).days


def osv_has_vuln(name, eco, version=None, timeout=HTTP_TIMEOUT):
    """OSV.dev 에 '설치될 최신 버전'을 직접 겨냥해 알려진 취약점이 있는지 조회. (True/False/None, error).

    버전을 지정해 질의하므로, 이미 고쳐진 과거 취약점까지 싸잡아 경고하는 오탐(알람 피로)을 피한다.
    버전을 알 수 없으면 조회를 건너뛴다(None) — 불확실할 때 굳이 🟡로 겁주지 않는다.
    """
    osv_eco = OSV_ECO.get(eco)
    if not osv_eco:
        return None, "unsupported_eco"
    if not version:
        return None, "no_version"
    pkg = normalize_pypi(name) if eco == "pypi" else name
    body = json.dumps({"package": {"name": pkg, "ecosystem": osv_eco}, "version": version}).encode("utf-8")
    # 보안 경고는 신선도가 중요 — 캐시를 건너뛴다(새로 공개된 CVE를 6시간 가리지 않도록).
    data, err = http_json("https://api.osv.dev/v1/query", timeout, data=body, no_cache=True)
    if err:
        return None, err
    return bool(data.get("vulns")), None


# ----------------------------------------------------------------------------
# 레지스트리별 신호 수집
#   반환: dict(exists, downloads, created, last_release, maintainers,
#             repo, deprecated, error)
# ----------------------------------------------------------------------------
def _blank():
    return dict(exists=None, downloads=None, created=None, last_release=None,
                maintainers=None, repo=None, deprecated=False, latest_version=None, error=None)


def fetch_npm(name, timeout):
    s = _blank()
    data, err = http_json("https://registry.npmjs.org/%s" % urllib.parse.quote(name, safe="@/"), timeout)
    if err == "missing":
        s["exists"] = False
        return s
    if err:
        s["error"] = err
        return s
    s["exists"] = True
    times = data.get("time", {}) or {}
    s["created"] = parse_dt(times.get("created"))
    s["last_release"] = parse_dt(times.get("modified"))
    s["maintainers"] = len(data.get("maintainers", []) or []) or None
    repo = (data.get("repository") or {})
    s["repo"] = repo.get("url") if isinstance(repo, dict) else (repo if isinstance(repo, str) else None)
    latest = (data.get("dist-tags", {}) or {}).get("latest")
    s["latest_version"] = latest
    versions = data.get("versions", {}) or {}
    if latest and latest in versions and versions[latest].get("deprecated"):
        s["deprecated"] = True
    if not s["repo"] and data.get("homepage"):
        s["repo"] = data.get("homepage")
    dl, derr = http_json("https://api.npmjs.org/downloads/point/last-month/%s" % urllib.parse.quote(name, safe="@/"), timeout)
    if dl and isinstance(dl.get("downloads"), int):
        s["downloads"] = dl["downloads"]
    return s


def fetch_pypi(name, timeout):
    s = _blank()
    pkg = normalize_pypi(name)
    data, err = http_json("https://pypi.org/pypi/%s/json" % urllib.parse.quote(pkg), timeout)
    if err == "missing":
        s["exists"] = False
        return s
    if err:
        s["error"] = err
        return s
    s["exists"] = True
    info = data.get("info", {}) or {}
    # 저장소 링크
    purls = info.get("project_urls") or {}
    repo = info.get("home_page") or None
    for k, v in (purls or {}).items():
        if any(t in (k or "").lower() for t in ("source", "repository", "github", "code", "tracker")):
            repo = v
            break
    s["repo"] = repo
    # deprecated 신호: 최신 yanked, 또는 비활성 classifier
    classifiers = info.get("classifiers", []) or []
    if any("Inactive" in c for c in classifiers):
        s["deprecated"] = True
    if (info.get("yanked") is True):
        s["deprecated"] = True
    # 배포일: releases 전체에서 최초/최근 upload_time
    dates = []
    for files in (data.get("releases", {}) or {}).values():
        for f in (files or []):
            dt = parse_dt(f.get("upload_time_iso_8601") or f.get("upload_time"))
            if dt:
                dates.append(dt)
    if dates:
        s["created"] = min(dates)
        s["last_release"] = max(dates)
    s["maintainers"] = 1 if (info.get("author") or info.get("maintainer")) else None
    s["latest_version"] = info.get("version")
    # 다운로드(best-effort): pypistats
    dl, derr = http_json("https://pypistats.org/api/packages/%s/recent" % urllib.parse.quote(pkg), timeout)
    if dl and isinstance(dl.get("data"), dict) and isinstance(dl["data"].get("last_month"), int):
        s["downloads"] = dl["data"]["last_month"]
    return s


def fetch_crates(name, timeout):
    s = _blank()
    data, err = http_json("https://crates.io/api/v1/crates/%s" % urllib.parse.quote(name), timeout)
    if err == "missing":
        s["exists"] = False
        return s
    if err:
        s["error"] = err
        return s
    crate = data.get("crate", {}) or {}
    s["exists"] = True
    s["downloads"] = crate.get("downloads")
    s["created"] = parse_dt(crate.get("created_at"))
    s["last_release"] = parse_dt(crate.get("updated_at"))
    s["repo"] = crate.get("repository") or crate.get("homepage")
    s["latest_version"] = crate.get("max_stable_version") or crate.get("newest_version")
    return s


def fetch_rubygems(name, timeout):
    s = _blank()
    data, err = http_json("https://rubygems.org/api/v1/gems/%s.json" % urllib.parse.quote(name), timeout)
    if err == "missing":
        s["exists"] = False
        return s
    if err:
        s["error"] = err
        return s
    s["exists"] = True
    s["downloads"] = data.get("downloads")
    s["repo"] = data.get("source_code_uri") or data.get("homepage_uri")
    s["latest_version"] = data.get("version")
    # 배포일은 별도 엔드포인트
    vers, verr = http_json("https://rubygems.org/api/v1/versions/%s.json" % urllib.parse.quote(name), timeout)
    if isinstance(vers, list) and vers:
        dts = [parse_dt(v.get("created_at")) for v in vers if v.get("created_at")]
        dts = [d for d in dts if d]
        if dts:
            s["created"] = min(dts)
            s["last_release"] = max(dts)
    return s


FETCHERS = {"npm": fetch_npm, "pypi": fetch_pypi, "crates": fetch_crates, "rubygems": fetch_rubygems}

# 교차 레지스트리 혼동 검사 시 '다른 생태계'에서 존재 확인용 URL 빌더
EXISTS_URL = {
    "npm":      lambda n: "https://registry.npmjs.org/%s" % urllib.parse.quote(n, safe="@/"),
    "pypi":     lambda n: "https://pypi.org/pypi/%s/json" % urllib.parse.quote(normalize_pypi(n)),
    "crates":   lambda n: "https://crates.io/api/v1/crates/%s" % urllib.parse.quote(n),
    "rubygems": lambda n: "https://rubygems.org/api/v1/gems/%s.json" % urllib.parse.quote(n),
}


# ----------------------------------------------------------------------------
# 화이트리스트
# ----------------------------------------------------------------------------
def load_allowlist():
    try:
        with open(ALLOWLIST_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            return {k: set(x.lower() for x in v) for k, v in data.items() if isinstance(v, list)}
    except Exception:
        return {}


def _name_in_list(listdict, name, eco):
    key = ALLOWLIST_KEY.get(eco, eco)
    cands = {name.lower()}
    if eco == "pypi":
        cands.add(normalize_pypi(name))
    return bool(listdict.get(key, set()) & cands)


def is_allowlisted(name, eco):
    return _name_in_list(load_allowlist(), name, eco)


def load_denylist():
    """(dict, ok). 파일 부재 → ({}, True). 손상/읽기 실패 → 경고 출력 후 ({}, False)(fail-closed)."""
    if not os.path.exists(DENYLIST_PATH):
        return {}, True
    try:
        with open(DENYLIST_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {k: set(x.lower() for x in v) for k, v in data.items() if isinstance(v, list)}, True
    except Exception as e:
        print("⚠ 차단 목록(denylist)을 읽지 못했습니다: %s — 안전을 위해 이 실행을 신뢰하지 마세요." % e,
              file=sys.stderr)
        return {}, False


def is_denylisted(name, eco):
    dl, _ok = load_denylist()
    return _name_in_list(dl, name, eco)


def load_config(explicit=None):
    """설정 파일을 찾아 (dict, path).

    명시 경로(--config / SLOPSQUAT_CONFIG)는 없거나 손상되면 SystemExit — 경로 오타로 정책
    (더 엄격한 임계값·조직 차단목록 등)이 조용히 누락되는 fail-open 을 막는다.
    암묵 경로(cwd / 스킬폴더 .slopsquatrc.json)는 없으면 조용히 건너뛰고, 손상되면 경고만 한다.
    """
    explicit_paths = []
    if explicit:
        explicit_paths.append(explicit)
    if os.environ.get("SLOPSQUAT_CONFIG"):
        explicit_paths.append(os.environ["SLOPSQUAT_CONFIG"])
    for p in explicit_paths:
        if not os.path.exists(p):
            raise SystemExit("설정 파일을 찾을 수 없습니다(경로 오타로 정책이 누락될 수 있음): %s" % p)
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            raise SystemExit("설정 파일을 읽지 못했습니다(%s): %s" % (p, e))
        if not isinstance(data, dict):
            raise SystemExit("설정 파일 형식이 올바르지 않습니다(객체가 아님): %s" % p)
        return data, p
    for p in (os.path.join(os.getcwd(), ".slopsquatrc.json"),
              os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".slopsquatrc.json")):
        if not os.path.exists(p):
            continue
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data, p
            print("⚠ 설정 파일이 객체가 아니라 무시합니다: %s" % p, file=sys.stderr)
        except Exception as e:
            print("⚠ 설정 파일을 읽지 못해 무시합니다(%s): %s" % (p, e), file=sys.stderr)
    return {}, None


def _cfg_num(cfg, key, cast, current):
    """설정값을 안전하게 캐스팅한다. 잘못된 값(null/문자열 등)은 경고 후 기본값 유지."""
    if key not in cfg:
        return current
    try:
        return cast(cfg[key])
    except (TypeError, ValueError):
        print("⚠ 설정값 '%s' 가 올바르지 않아 무시합니다(기본값 사용): %r" % (key, cfg.get(key)), file=sys.stderr)
        return current


def apply_config(cfg):
    """설정값으로 모듈 상수를 덮어쓴다(없는 키는 무시, 잘못된 값은 기본값 유지)."""
    global NEW_PACKAGE_DAYS, TYPO_DISTANCE_MAX, HTTP_TIMEOUT, ALLOWLIST_PATH, DENYLIST_PATH
    global CACHE_TTL, CACHE_DIR, HTTP_RETRIES
    NEW_PACKAGE_DAYS = _cfg_num(cfg, "new_package_days", int, NEW_PACKAGE_DAYS)
    TYPO_DISTANCE_MAX = _cfg_num(cfg, "typo_distance_max", int, TYPO_DISTANCE_MAX)
    HTTP_TIMEOUT = _cfg_num(cfg, "http_timeout", float, HTTP_TIMEOUT)
    CACHE_TTL = _cfg_num(cfg, "cache_ttl", int, CACHE_TTL)
    HTTP_RETRIES = _cfg_num(cfg, "http_retries", int, HTTP_RETRIES)
    if isinstance(cfg.get("low_downloads"), dict):
        for k, v in cfg["low_downloads"].items():
            try:
                LOW_DOWNLOADS[k] = int(v)
            except (TypeError, ValueError):
                print("⚠ low_downloads['%s'] 값이 올바르지 않아 무시합니다: %r" % (k, v), file=sys.stderr)
    if cfg.get("allowlist_path"):
        ALLOWLIST_PATH = cfg["allowlist_path"]
    if cfg.get("denylist_path"):
        DENYLIST_PATH = cfg["denylist_path"]
    if cfg.get("cache_dir"):
        CACHE_DIR = cfg["cache_dir"]
    return cfg


def approve(name, eco, force=False, timeout=HTTP_TIMEOUT):
    """화이트리스트에 추가한다. 🔴(차단) 판정은 영구 우회로가 되므로 등록을 거부한다."""
    eco = norm_eco(eco)
    key = ALLOWLIST_KEY.get(eco, eco)

    # 심층 방어: 등록 전 재검증해서 🔴면 거부(--force 로만 우회).
    res = assess(name, eco, timeout=timeout)
    if res["level"] == "block" and not force:
        raise SystemExit(
            "🔴 차단 판정 패키지는 화이트리스트에 등록하지 않습니다(영구 우회 위험). "
            "사유: " + res["reason_ko"] + " / 정말 등록하려면 --force 를 쓰세요."
        )

    # 파일이 존재하는데 읽지 못하면(파싱 실패/잠금/손상) 기존 승인 목록을
    # 덮어쓰지 않고 중단한다. 정말로 파일이 없을 때만 새로 생성한다.
    if os.path.exists(ALLOWLIST_PATH):
        try:
            with open(ALLOWLIST_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            raise SystemExit(
                "allowlist.json 을 읽지 못했습니다(" + str(e) + "). "
                "기존 승인 목록을 보호하기 위해 추가를 중단합니다. 파일을 직접 확인하세요."
            )
        if not isinstance(data, dict):
            raise SystemExit("allowlist.json 형식이 올바르지 않습니다(객체가 아님). 추가를 중단합니다.")
    else:
        data = {}

    bucket = data.setdefault(key, [])
    entry = normalize_pypi(name) if eco == "pypi" else name.lower()
    if entry not in [x.lower() for x in bucket]:
        bucket.append(entry)
        bucket.sort()

    # 임시파일에 쓴 뒤 원자적 교체로 부분쓰기 손상을 예방한다.
    tmp = ALLOWLIST_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(tmp, ALLOWLIST_PATH)
    return entry


# ----------------------------------------------------------------------------
# 핵심 판정
# ----------------------------------------------------------------------------
def verdict_obj(name, eco, level, reason, action, signals=None):
    sym = {"block": "🔴", "warn": "🟡", "safe": "🟢"}[level]
    out = {
        "package": name,
        "ecosystem": eco,
        "level": level,
        "verdict": sym,
        "reason_ko": reason,
        "recommended_action_ko": action,
    }
    if signals is not None:
        out["signals"] = {
            "downloads": signals.get("downloads"),
            "age_days": days_since(signals.get("created")),
            "last_release_days": days_since(signals.get("last_release")),
            "maintainers": signals.get("maintainers"),
            "repo": signals.get("repo"),
            "deprecated": signals.get("deprecated"),
            "error_code": signals.get("error"),   # 진단용(사용자 문구엔 노출 안 함)
        }
    return out


def _neterr_text(err):
    """원시 에러코드를 비개발자용 한국어로 풀어준다."""
    if err.startswith("neterr:"):
        return ("지금 인터넷으로 확인을 못 했어요(연결 문제). 안전을 아직 확인하지 못했습니다.",
                "인터넷 연결을 확인한 뒤 다시 점검할게요. 그 전엔 설치하지 않을게요.")
    if err.startswith("http_"):
        return ("패키지 정보 서버가 잠시 응답하지 않았어요. 안전을 아직 확인하지 못했습니다.",
                "잠시 후 다시 점검할게요. 그 전엔 설치하지 않을게요.")
    return ("공식 패키지 목록 확인을 못 했어요. 안전을 아직 확인하지 못했습니다.",
            "인터넷 연결 후 다시 점검할게요. 그 전엔 설치하지 않을게요.")


def typosquat_hit(name, eco, signals):
    """유명 패키지와 매우 유사하고 '가용한' 평판 신호가 약하면 (target, dist, strong) 반환.
    strong=True 면 차단, False 면 주의로 강등."""
    cand = normalize_pypi(name) if eco == "pypi" else name.lower()
    target, dist = closest_popular(cand, eco)
    if target is None:
        return None
    age = days_since(signals.get("created"))
    dl = signals.get("downloads")
    low = LOW_DOWNLOADS.get(eco)
    is_new = age is not None and age <= NEW_PACKAGE_DAYS
    low_dl = dl is not None and low is not None and dl < low
    no_repo = not signals.get("repo")
    # 다운로드 데이터 결손(dl is None)은 그 자체로 '약함'이 아니다 → 가용 신호만 센다.
    if not (is_new or low_dl or no_repo):
        return None
    # 확인된 저평판(신생/저다운로드)과 저장소 부재가 함께면 사칭 패턴 → 차단,
    # 그 외(단일 신호/데이터 부족)는 주의로만 강등.
    strong = no_repo and (is_new or low_dl)
    return (target, dist, strong)


def assess(name, eco, timeout=HTTP_TIMEOUT, offline=False):
    eco = norm_eco(eco)
    if eco not in FETCHERS:
        return verdict_obj(name, eco, "warn",
                           "자동 검증을 지원하지 않는 패키지 종류라 확인을 못 했습니다(%s)." % eco_disp(eco),
                           "사람이 직접 패키지 출처를 확인한 뒤 진행하세요.")

    # 네트워크 호출 전에 이름 형식부터 검증(경로조작/이상문자/호모글리프 차단)
    if not valid_name(name, eco):
        if _looks_disguised(name):
            reason = "이름에 진짜처럼 보이게 하는 특수문자(유사 알파벳)가 섞여 있습니다(사칭 의심)."
        else:
            reason = "패키지 이름 형식이 비정상입니다(이름에 들어갈 수 없는 문자나 경로 기호가 섞여 있어요)."
        return verdict_obj(name, eco, "block", reason,
                           "정확한 패키지 이름을 다시 확인할게요. 그 전엔 설치하지 않을게요.")

    # 알려진 악성/사칭 차단 목록 — 레지스트리에 존재하더라도 항상 막는다(환각명 선점 대비).
    dl, dl_ok = load_denylist()
    if not dl_ok:
        return verdict_obj(name, eco, "warn",
                           "차단 목록(denylist)이 손상돼 안전을 확인하지 못했습니다.",
                           "차단 목록 파일을 고친 뒤 다시 검증할게요. 그 전엔 설치하지 않을게요.")
    if _name_in_list(dl, name, eco):
        return verdict_obj(name, eco, "block",
                           "알려진 악성·사칭 패키지 차단 목록에 있는 이름입니다(과거 악성 사례 보고).",
                           "이 이름은 설치하지 않을게요. 정말 필요한 정식 패키지인지 다시 확인하세요.")

    allow = is_allowlisted(name, eco)

    if offline:
        if allow:
            return verdict_obj(name, eco, "safe", "사전 승인(화이트리스트)된 패키지입니다.",
                               "정확한 버전 그대로(중간에 바꿔치기 못 하게 '정품 봉인'=해시 확인) 설치하겠습니다.")
        return verdict_obj(name, eco, "warn",
                           "오프라인 모드라 공식 패키지 목록(앱스토어 같은 공식 배포처) 확인을 못 했습니다.",
                           "인터넷 연결 후 다시 점검할게요. 그 전엔 설치하지 않을게요.")

    sig = FETCHERS[eco](name, timeout)

    # 0) 화이트리스트: 재검증 없이 통과(단 deprecated/보안경고면 예외)
    if allow:
        if sig.get("deprecated"):
            return verdict_obj(name, eco, "warn",
                               "승인된 패키지지만 더 이상 관리되지 않음(deprecated)으로 표시됩니다.",
                               "유지보수되는 대안을 검토할게요.", sig)
        has_vuln, _verr = osv_has_vuln(name, eco, sig.get("latest_version"), timeout)
        if has_vuln:
            return verdict_obj(name, eco, "warn",
                               "승인된 패키지지만 최신 버전에 알려진 보안 취약점(공개된 보안 경고)이 남아 있습니다.",
                               "취약점이 고쳐진 버전이 있는지 확인하고 설치할게요.", sig)
        # 보안 조회 실패(_verr)는 이미 신뢰된 패키지라 통과 유지(자동통과 금지 원칙은 '미검증' 패키지 대상).
        return verdict_obj(name, eco, "safe",
                           "사전 승인(화이트리스트)된 패키지이고 알려진 보안 취약점이 없습니다.",
                           "정확한 버전 그대로(정품 봉인=해시 확인) 설치하겠습니다.", sig)

    # 1) 네트워크 오류 → 검증 불가(자동 통과 금지). 원시 코드는 숨기고 사람말로.
    if sig.get("error"):
        reason, action = _neterr_text(sig["error"])
        return verdict_obj(name, eco, "warn", reason, action, sig)

    # 2) 실존하지 않음 → 환각/혼동
    if sig.get("exists") is False:
        for other, builder in EXISTS_URL.items():
            if other == eco:
                continue
            if url_exists(builder(name), timeout):
                return verdict_obj(name, eco, "block",
                                   "지금 받으려는 %s 패키지 목록엔 이 이름이 없는데, 엉뚱한 %s 쪽에 같은 이름이 있어요(설치 위치를 헷갈렸거나, 누군가 이 이름으로 악성코드를 심어뒀을 수 있어요)." % (eco_disp(eco), eco_disp(other)),
                                   "올바른 곳과 정확한 패키지 이름을 확인하기 전엔 설치하지 않을게요.", sig)
        return verdict_obj(name, eco, "block",
                           "%s 공식 패키지 목록(앱을 받는 공식 앱스토어 같은 곳)에 이런 이름이 없습니다(AI가 이름을 지어냈을 가능성)." % eco_disp(eco),
                           "제가 진짜 맞는 라이브러리 이름을 찾아드릴게요. 확인 전에는 설치하지 않을게요.", sig)

    # 3) 타이포/슬롭스쿼팅
    typo = typosquat_hit(name, eco, sig)
    if typo:
        target, _dist, strong = typo
        if strong:
            return verdict_obj(name, eco, "block",
                               "유명 패키지 '%s'와 한두 글자 차이인데 평판 신호가 약합니다(사칭 의심)." % target,
                               "원래 쓰려던 게 '%s'가 맞는지 확인할게요." % target, sig)
        return verdict_obj(name, eco, "warn",
                           "유명 패키지 '%s'와 이름이 비슷한데 평판을 끝까지 확인하지 못했습니다(사칭 가능성)." % target,
                           "원래 쓰려던 게 '%s'가 맞는지 확인한 뒤 진행할게요." % target, sig)

    # 4) deprecated
    if sig.get("deprecated"):
        return verdict_obj(name, eco, "warn",
                           "더 이상 관리되지 않는(deprecated) 패키지로 표시됩니다.",
                           "유지보수되는 대안을 검토한 뒤 진행할게요.", sig)

    # 5) 평판 종합 (신생/저다운로드/저장소 없음)
    age = days_since(sig.get("created"))
    dl = sig.get("downloads")
    low = LOW_DOWNLOADS.get(eco)
    is_new = age is not None and age <= NEW_PACKAGE_DAYS
    low_dl = dl is not None and low is not None and dl < low
    no_repo = not sig.get("repo")

    if is_new and low_dl and no_repo:
        return verdict_obj(name, eco, "block",
                           "최근 생성(%s일)·다운로드 적음·공개 코드 보관소 없음 — 악성 신규 패키지 패턴입니다." % age,
                           "패키지 출처와 평판을 사람이 확인하기 전엔 설치하지 않을게요.", sig)
    bits = []
    if is_new:
        bits.append("신생(%s일)" % age)
    if low_dl:
        bits.append("다운로드 적음(%s)" % dl)
    if no_repo:
        bits.append("공개 코드 보관소(GitHub 같은 출처) 없음")
    if bits:
        return verdict_obj(name, eco, "warn",
                           "평판 신호가 약합니다: " + ", ".join(bits) + ".",
                           "공식 문서나 출처를 확인하고 정말 필요한 패키지인지 점검할게요.", sig)

    # 6) 마지막 관문: 설치될 최신 버전에 알려진 보안 취약점(OSV)이 있으면 통과시키지 않는다.
    has_vuln, _verr = osv_has_vuln(name, eco, sig.get("latest_version"), timeout)
    if has_vuln:
        return verdict_obj(name, eco, "warn",
                           "정식 등록된 패키지지만 최신 버전에 알려진 보안 취약점(공개된 보안 경고)이 남아 있습니다.",
                           "취약점이 고쳐진 버전이 있는지 확인한 뒤 설치할게요.", sig)

    # 7) 통과
    return verdict_obj(name, eco, "safe",
                       "공식 패키지 목록에 정식 등록돼 있고 평판 신호가 정상입니다.",
                       "정확한 버전 그대로(정품 봉인=해시 확인) 설치하겠습니다.", sig)


def safe_assess(name, eco, timeout, offline):
    """패키지 하나의 예기치 못한 오류가 전체 일괄 검증을 죽이지 않도록 격리한다(fail-closed → 🟡)."""
    try:
        return assess(name, eco, timeout=timeout, offline=offline)
    except Exception as ex:
        sig = {"error": "internal:%s" % type(ex).__name__}     # 진단용 — 사용자 문구엔 노출 안 함
        return verdict_obj(name, norm_eco(eco), "warn",
                           "검증 중 예기치 못한 문제가 생겨 안전을 확인하지 못했습니다.",
                           "사람이 직접 출처를 확인하기 전엔 설치하지 않을게요.", sig)


def assess_many(items, timeout=HTTP_TIMEOUT, offline=False, jobs=8):
    """여러 패키지를 검증한다. 네트워크 바운드라 스레드풀로 병렬화하되 입력 순서를 유지한다."""
    if jobs and jobs > 1 and len(items) > 1 and not offline:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=min(int(jobs), len(items))) as ex:
            return list(ex.map(lambda it: safe_assess(it[0], it[1], timeout, offline), items))
    return [safe_assess(n, e, timeout, offline) for n, e in items]


# ----------------------------------------------------------------------------
# 리포트 렌더링 (references/REPORT_FORMAT.md 와 동일 포맷)
# ----------------------------------------------------------------------------
def render_report(results):
    label = {"safe": "🟢 안전", "warn": "🟡 주의", "block": "🔴 차단"}
    lines = ["📦 패키지 안전 점검 결과", ""]
    for r in results:
        line = "%s — %s : %s" % (label[r["level"]], r["package"], r["reason_ko"])
        if r["level"] == "block":
            line += " → 설치를 멈췄습니다. 진행하려면 승인이 필요합니다."
        elif r["level"] == "warn":
            line += " → " + r["recommended_action_ko"]
        lines.append(line)
    lines.append("")
    lines.append("※ 이 중 하나라도 🔴/🟡가 있으면 제가 임의로 설치하지 않습니다.")
    return "\n".join(lines)


# ----------------------------------------------------------------------------
# 안전 설치 명령 생성기 — 승인 후 잠금파일 고정 + 해시/무결성 검증 명령을 결정적으로 출력
# ----------------------------------------------------------------------------
INSTALL_CMDS = {
    "pypi": [
        "# pip-tools (해시 고정):",
        'echo "{name}=={ver}" >> requirements.in',
        "pip-compile --generate-hashes requirements.in",
        "pip install --require-hashes -r requirements.txt",
        "# 또는 uv:      uv add {name}=={ver}        (uv.lock 에 해시 기록)",
        "# 또는 poetry:  poetry add {name}=={ver}    (poetry.lock 에 해시 기록)",
    ],
    "npm": [
        "npm install {name}@{ver} --save-exact",
        "npm ci                         # package-lock.json 무결성(integrity) 검증 설치",
        "# pnpm:  pnpm add {name}@{ver} --save-exact && pnpm install --frozen-lockfile",
        "# yarn:  yarn add {name}@{ver} --exact && yarn install --immutable",
    ],
    "crates": [
        "cargo add {name}@{ver} --locked",
        "cargo build --locked           # Cargo.lock 체크섬 검증",
    ],
    "rubygems": [
        'bundle add {name} --version "{ver}"',
        "bundle install                 # Gemfile.lock 고정",
        "# 체크섬:  bundle lock --add-checksums   (Bundler 2.5+)",
    ],
}


def render_install(name, eco, version):
    """승인된 패키지의 안전 설치 명령 텍스트를 만든다(네트워크 불필요)."""
    eco = norm_eco(eco)
    tmpl = INSTALL_CMDS.get(eco)
    if not tmpl:
        return None
    ver = version or "<버전>"
    body = "\n".join(l.format(name=name, ver=ver) for l in tmpl)
    header = "# %s (%s) 안전 설치 — 잠금파일 고정 + 해시/무결성 검증" % (name, eco_disp(eco))
    return header + "\n" + body


# ----------------------------------------------------------------------------
# 입력 파싱
# ----------------------------------------------------------------------------
def items_from_json(blob):
    try:
        data = json.loads(blob)
    except json.JSONDecodeError as e:
        raise ValueError("JSON 형식이 올바르지 않습니다: %s" % e)
    items = []
    if isinstance(data, list):
        for i, d in enumerate(data):
            if not isinstance(d, dict) or "name" not in d or not isinstance(d["name"], str):
                raise ValueError(
                    "JSON 목록의 %d번째 항목에 패키지 이름('name')이 없습니다. "
                    '형식 예: [{"name":"react","ecosystem":"npm"}]' % (i + 1))
            items.append((d["name"], d.get("ecosystem") or d.get("eco")))
    elif isinstance(data, dict):
        for eco, names in data.items():
            if not isinstance(names, list):
                raise ValueError(
                    "'%s' 의 값은 패키지 이름 목록이어야 합니다(문자열 아님). "
                    '형식 예: {"npm":["react"],"pypi":["requests"]}' % eco)
            for n in names:
                if not isinstance(n, str):
                    raise ValueError("'%s' 목록 안에 문자열이 아닌 항목이 있습니다." % eco)
                items.append((n, eco))
    else:
        raise ValueError("JSON 은 목록 또는 객체여야 합니다.")
    return items


# ----------------------------------------------------------------------------
# 매니페스트 파싱 — requirements.txt / package.json / pyproject.toml / Cargo.toml / Gemfile
#   에서 패키지 이름 + 생태계를 자동 추출한다.
# ----------------------------------------------------------------------------
MANIFEST_ECO = {
    "requirements.txt": "pypi", "package.json": "npm",
    "pyproject.toml": "pypi", "cargo.toml": "crates", "gemfile": "rubygems",
}


def detect_manifest_kind(path):
    base = os.path.basename(path).lower()
    if base == "package.json":
        return "package.json"
    if base == "cargo.toml":
        return "cargo.toml"
    if base == "pyproject.toml":
        return "pyproject.toml"
    if base == "gemfile":
        return "gemfile"
    if base.startswith("requirements") and base.endswith(".txt"):
        return "requirements.txt"
    return None


def _toml_loads(text):
    for mod in ("tomllib", "tomli"):
        try:
            return __import__(mod).loads(text)
        except Exception:
            continue
    return None


def _req_name(req):
    """PEP 508 요구사항 문자열에서 패키지 이름만 뽑는다. URL/VCS 직접참조는 건너뛴다."""
    if not isinstance(req, str):
        return None
    s = req.strip()
    if not s or "://" in s:
        return None
    mt = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", s)
    return mt.group(1) if mt else None


def _parse_requirements(text):
    names = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):           # 빈 줄 / -r,-e,--hash 등 옵션
            continue
        if "://" in line or line.lower().startswith("git+"):
            continue                                    # URL/VCS 직접설치('://' 가 http(s) 도 처리)
        n = _req_name(line)
        if n:
            names.append(n)
    return names


def _parse_package_json(text):
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("package.json 의 최상위가 객체가 아닙니다.")
    names = []
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        dep = data.get(key)
        if not isinstance(dep, dict):                   # 값이 객체가 아니면 건너뜀(이상 형식 방어)
            continue
        for name, ver in dep.items():
            v = str(ver)
            if v.startswith(".") or any(p in v for p in ("file:", "link:", "workspace:", "git+", "://")):
                continue                                # 로컬/워크스페이스/git 의존성 제외
            names.append(name)
    return names


def _parse_gemfile(text):
    names = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        mt = re.match(r"""gem\s+['"]([^'"]+)['"]""", line)
        if mt:
            names.append(mt.group(1))
    return names


def _toml_fallback_keys(text, sections):
    """tomllib 가 없을 때(파이썬 <3.11) 의존성 테이블 키를 best-effort 로 긁는다."""
    names, cur = [], None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        h = re.match(r"^\[([^\]]+)\]$", line)
        if h:
            cur = h.group(1).strip()
            continue
        if cur and cur.split(".")[-1].strip().strip('"') in sections:
            mt = re.match(r'^["\']?([A-Za-z0-9][A-Za-z0-9._-]*)["\']?\s*=', line)
            if mt:
                names.append(mt.group(1))
    return names


def _parse_cargo(text):
    data = _toml_loads(text)
    sects = ("dependencies", "dev-dependencies", "build-dependencies")
    if data is None:
        return _toml_fallback_keys(text, sects)
    names = []

    def harvest(tbl):
        if not isinstance(tbl, dict):
            return
        for name, spec in tbl.items():
            if isinstance(spec, dict) and (spec.get("path") or spec.get("git")):
                continue                                # 로컬/git 의존성 제외
            names.append(name)

    for sect in sects:
        harvest(data.get(sect))
    for tval in (data.get("target") or {}).values():    # [target.'cfg(...)'.dependencies]
        for sect in sects:
            harvest((tval or {}).get(sect))
    return names


def _parse_pyproject(text):
    data = _toml_loads(text)
    if data is None:
        # PEP 621 dependencies 배열 + poetry 테이블 키를 best-effort 로.
        names = []
        for block in re.findall(r"dependencies\s*=\s*\[(.*?)\]", text, re.S):
            for q in re.findall(r"""['"]([^'"]+)['"]""", block):
                n = _req_name(q)
                if n:
                    names.append(n)
        names += [n for n in _toml_fallback_keys(text, ("dependencies",)) if n.lower() != "python"]
        return names
    names = []
    proj = data.get("project") or {}
    for req in (proj.get("dependencies") or []):
        n = _req_name(req)
        if n:
            names.append(n)
    for arr in (proj.get("optional-dependencies") or {}).values():
        for req in (arr or []):
            n = _req_name(req)
            if n:
                names.append(n)
    poetry = (data.get("tool") or {}).get("poetry") or {}
    pdeps = dict(poetry.get("dependencies") or {})
    for grp in (poetry.get("group") or {}).values():
        pdeps.update((grp or {}).get("dependencies") or {})
    for name in pdeps:
        if name.lower() != "python":
            names.append(name)
    return names


_MANIFEST_PARSERS = {
    "requirements.txt": _parse_requirements,
    "package.json": _parse_package_json,
    "pyproject.toml": _parse_pyproject,
    "cargo.toml": _parse_cargo,
    "gemfile": _parse_gemfile,
}


def parse_manifest_text(text, kind):
    """매니페스트 텍스트 → [(name, ecosystem)] (순서 유지, 중복 제거).

    형식은 맞지만 구조가 이상한 입력(최상위 배열, 값이 문자열 등)은 트레이스백 대신
    ValueError 로 정규화한다(main 이 깔끔한 한국어 오류로 처리).
    """
    eco = MANIFEST_ECO[kind]
    try:
        raw_names = _MANIFEST_PARSERS[kind](text)
    except (AttributeError, TypeError) as e:
        raise ValueError("매니페스트 형식이 올바르지 않습니다(%s): %s" % (kind, e))
    seen, pairs = set(), []
    for name in raw_names:
        if not isinstance(name, str):
            continue
        key = (name.lower(), eco)
        if key not in seen:
            seen.add(key)
            pairs.append((name, eco))
    return pairs


def parse_manifest(path):
    kind = detect_manifest_kind(path)
    if not kind:
        raise ValueError("매니페스트 종류를 알 수 없습니다: %s" % os.path.basename(path))
    with open(path, "r", encoding="utf-8") as f:
        return parse_manifest_text(f.read(), kind), kind


# ----------------------------------------------------------------------------
# 자체 점검 (네트워크 없이 결정적 검증) — `verify_packages.py selftest`
# ----------------------------------------------------------------------------
def _sig(**kw):
    s = _blank()
    s["exists"] = True
    s.update(kw)
    return s


def run_selftest(verbose=True):
    """순수 함수 + (몽키패치로) 모든 판정 경로를 네트워크 없이 검증한다."""
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    old = datetime.now(timezone.utc) - timedelta(days=4000)
    recent = datetime.now(timezone.utc) - timedelta(days=10)

    # --- 순수 함수 ---
    check(levenshtein("requests", "reqests") == 1, "levenshtein")
    check(levenshtein("", "abc") == 3, "levenshtein-empty")
    check(normalize_pypi("Flask__Login") == "flask-login", "normalize_pypi")
    check(valid_name("react-dom", "npm") and valid_name("@scope/pkg", "npm"), "valid_name-ok")
    check(not valid_name("../evil", "pypi") and not valid_name("a/b", "pypi"), "valid_name-block")
    check(eco_disp("pypi") == "Python(pip)", "eco_disp")
    check(parse_dt(12345) is None and parse_dt(None) is None, "parse_dt-nonstr")
    check(parse_dt("2020-01-02T03:04:05Z") is not None, "parse_dt-iso")

    # --- 타이포스쿼팅 강/약 ---
    strong = typosquat_hit("expresss", "npm", _sig(downloads=5, repo=None, created=recent))
    check(strong is not None and strong[2] is True, "typo-strong")
    weak = typosquat_hit("reqeusts", "pypi", _sig(downloads=None, repo=None, created=None))
    check(weak is not None and weak[2] is False, "typo-weak")
    check(typosquat_hit("fastai", "pypi", _sig(repo="https://github.com/fastai", created=old)) is None, "typo-established")
    check(typosquat_hit("react", "npm", _sig()) is None, "typo-itself")

    # --- 입력 검증 ---
    for bad in ('{"npm":"react"}', '[{"ecosystem":"npm"}]', 'not json', '"x"'):
        try:
            items_from_json(bad)
            check(False, "items_from_json should raise: %s" % bad)
        except ValueError:
            pass
    check(items_from_json('[{"name":"react","ecosystem":"npm"}]') == [("react", "npm")], "items_from_json-ok")

    # --- 리포트 포맷 ---
    rep = render_report([verdict_obj("x", "pypi", "block", "이유", "조치")])
    check(rep.startswith("📦 패키지 안전 점검 결과\n\n"), "report-header")
    check(rep.rstrip().endswith("※ 이 중 하나라도 🔴/🟡가 있으면 제가 임의로 설치하지 않습니다."), "report-footer")

    # --- 모든 판정 경로 (몽키패치) ---
    g = globals()
    saved = {k: g[k] for k in ("is_allowlisted", "osv_has_vuln", "url_exists")}
    saved_fetchers = dict(FETCHERS)
    try:
        g["is_allowlisted"] = lambda n, e: False
        g["osv_has_vuln"] = lambda *a, **k: (False, None)
        g["url_exists"] = lambda *a, **k: False

        FETCHERS["pypi"] = lambda n, t: _sig(downloads=10**6, created=old, last_release=old,
                                             maintainers=3, repo="https://github.com/x", latest_version="1.0")
        check(assess("goodpkg", "pypi")["level"] == "safe", "path-safe")

        g["osv_has_vuln"] = lambda *a, **k: (True, None)
        check(assess("goodpkg", "pypi")["level"] == "warn", "path-osv-vuln")
        g["osv_has_vuln"] = lambda *a, **k: (False, None)

        FETCHERS["pypi"] = lambda n, t: dict(_blank(), exists=False)
        check(assess("totallyfake", "pypi")["level"] == "block", "path-hallucination")

        g["url_exists"] = lambda *a, **k: True
        check(assess("react-dom", "pypi")["level"] == "block", "path-cross-registry")
        g["url_exists"] = lambda *a, **k: False

        FETCHERS["pypi"] = lambda n, t: _sig(error="neterr:TimeoutError")
        check(assess("anything", "pypi")["level"] == "warn", "path-neterr")

        FETCHERS["pypi"] = lambda n, t: _sig(deprecated=True, created=old, repo="https://x", latest_version="1.0")
        check(assess("oldpkg", "pypi")["level"] == "warn", "path-deprecated")

        FETCHERS["pypi"] = lambda n, t: _sig(downloads=1, created=recent, repo=None, latest_version="0.0.1")
        check(assess("brandnew", "pypi")["level"] == "block", "path-weak-block")

        FETCHERS["pypi"] = lambda n, t: _sig(downloads=10**6, created=recent, repo="https://x", latest_version="1.0")
        check(assess("youngbutpopular", "pypi")["level"] == "warn", "path-weak-warn")

        check(assess("../evil", "pypi")["level"] == "block", "path-invalid-name")

        g["is_allowlisted"] = lambda n, e: True
        FETCHERS["pypi"] = lambda n, t: _sig(created=old, repo="https://x", latest_version="1.0")
        check(assess("requests", "pypi")["level"] == "safe", "path-allowlist-safe")
        FETCHERS["pypi"] = lambda n, t: _sig(deprecated=True, created=old, latest_version="1.0")
        check(assess("requests", "pypi")["level"] == "warn", "path-allowlist-deprecated")

        # 오프라인
        check(assess("requests", "pypi", offline=True)["level"] == "safe", "path-offline-allow")
        g["is_allowlisted"] = lambda n, e: False
        check(assess("whatever", "pypi", offline=True)["level"] == "warn", "path-offline-unknown")
    finally:
        for k, v in saved.items():
            g[k] = v
        FETCHERS.clear()
        FETCHERS.update(saved_fetchers)

    if verbose:
        if fails:
            print("SELFTEST FAILED (%d):" % len(fails))
            for f in fails:
                print("  - " + f)
        else:
            print("SELFTEST PASSED — 모든 판정 경로 정상 (네트워크 없이 검증).")
    return 1 if fails else 0


def main(argv):
    explicit_cfg = None
    if "--config" in argv:
        i = argv.index("--config")
        if i + 1 < len(argv):
            explicit_cfg = argv[i + 1]
    cfg, _cfgpath = load_config(explicit_cfg)
    if cfg:
        apply_config(cfg)
    if "--no-cache" in argv:
        global _USE_CACHE
        _USE_CACHE = False

    if argv and argv[0] in ("--version", "-V", "version"):
        print("slopsquat-guard %s" % __version__)
        return 0

    if argv and argv[0] == "cache-clear":
        n = 0
        try:
            for fn in os.listdir(CACHE_DIR):
                if fn.endswith(".json"):
                    os.remove(os.path.join(CACHE_DIR, fn))
                    n += 1
        except Exception:
            pass
        print("캐시 %d개 삭제: %s" % (n, CACHE_DIR))
        return 0

    if argv and argv[0] in ("install-cmd", "install"):
        rest = argv[1:]
        if len(rest) < 2:
            print("usage: verify_packages.py install-cmd <name> <ecosystem> [version]", file=sys.stderr)
            return 2
        name, eco = rest[0], norm_eco(rest[1])
        version = rest[2] if len(rest) > 2 else None
        if eco not in INSTALL_CMDS:
            print("error: 지원하지 않는 생태계: %s" % eco, file=sys.stderr)
            return 2
        if version is None and eco in FETCHERS:          # 버전 미지정 → 최신 버전 best-effort 조회
            try:
                version = FETCHERS[eco](name, HTTP_TIMEOUT).get("latest_version")
            except Exception:
                version = None
        print(render_install(name, eco, version))
        if not version:
            print("# ⚠ 정확한 버전을 자동 조회하지 못했습니다 — <버전>을 실제 최신 버전으로 바꾸세요.")
        return 0

    if argv and argv[0] == "selftest":
        return run_selftest()

    if argv and argv[0] == "approve":
        rest = [a for a in argv[1:] if a != "--force"]
        force = "--force" in argv[1:]
        if len(rest) < 2:
            print("usage: verify_packages.py approve <name> <ecosystem> [--force]", file=sys.stderr)
            return 2
        entry = approve(rest[0], rest[1], force=force)
        print(json.dumps({"approved": entry, "ecosystem": norm_eco(rest[1])}, ensure_ascii=False))
        return 0

    ap = argparse.ArgumentParser(description="AI가 추가하려는 패키지의 실존·평판을 설치 직전에 검증한다.")
    ap.add_argument("packages", nargs="*", help="패키지 이름들 (--ecosystem 와 함께)")
    ap.add_argument("--ecosystem", "-e", help="npm|pypi|crates|rubygems (positional 패키지에 적용)")
    ap.add_argument("--json", help='[{"name":..,"ecosystem":..}] 또는 {"npm":[..],"pypi":[..]}')
    ap.add_argument("--manifest", action="append", metavar="FILE",
                    help="매니페스트에서 패키지 자동 추출 (requirements.txt/package.json/pyproject.toml/Cargo.toml/Gemfile)")
    ap.add_argument("--stdin", action="store_true", help="stdin 에서 JSON 입력")
    ap.add_argument("--report", action="store_true", help="JSON 대신 한국어 리포트로 출력")
    ap.add_argument("--timeout", type=float, default=HTTP_TIMEOUT)
    ap.add_argument("--jobs", "-j", type=int, default=8, help="동시 검사 수(기본 8, 1=순차)")
    ap.add_argument("--config", metavar="FILE", help="설정 파일 경로(.slopsquatrc.json)")
    ap.add_argument("--no-cache", action="store_true", help="디스크 응답 캐시 사용 안 함")
    ap.add_argument("--offline", action="store_true", help="네트워크 없이 화이트리스트만 통과(나머지 🟡)")
    args = ap.parse_args(argv)

    items = []
    try:
        if args.json:
            items += items_from_json(args.json)
        if args.stdin:
            items += items_from_json(sys.stdin.read())
    except ValueError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    if args.manifest:
        for path in args.manifest:
            try:
                pairs, kind = parse_manifest(path)
            except (ValueError, TypeError, AttributeError) as e:
                print("error: 매니페스트 파싱 실패(%s): %s" % (path, e), file=sys.stderr)
                return 2
            except OSError as e:
                print("error: 파일을 열 수 없습니다(%s): %s" % (path, e), file=sys.stderr)
                return 2
            print("• %s → %s, 패키지 %d개 추출" % (path, kind, len(pairs)), file=sys.stderr)
            items += pairs
    if args.packages:
        if not args.ecosystem:
            print("error: positional 패키지에는 --ecosystem 가 필요합니다.", file=sys.stderr)
            return 2
        items += [(p, args.ecosystem) for p in args.packages]

    if not items:
        ap.print_help()
        return 2

    results = assess_many(items, timeout=args.timeout, offline=args.offline, jobs=args.jobs)
    summary = {
        "total": len(results),
        "block": sum(r["level"] == "block" for r in results),
        "warn": sum(r["level"] == "warn" for r in results),
        "safe": sum(r["level"] == "safe" for r in results),
    }
    summary["blocked"] = summary["block"] > 0
    summary["requires_approval"] = (summary["block"] + summary["warn"]) > 0

    if args.report:
        print(render_report(results))
    else:
        print(json.dumps({"summary": summary, "results": results}, ensure_ascii=False, indent=2))

    # 종료코드: 🔴 있으면 2, 🟡 있으면 1, 전부 🟢 면 0 (셸에서 게이트로 쓰기 좋게)
    return 2 if summary["block"] else (1 if summary["warn"] else 0)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
