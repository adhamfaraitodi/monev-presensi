# Simplified Web Monev Presensi Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Telegram bot architecture with a secure, mobile-friendly Vercel web app for manual MagangHub Kemnaker attendance/logbook entry, automatic 10m-radius YIA coordinates, a hardened Cloudflare Worker reverse proxy, and a 17:00 WIB Monday–Friday automatic fallback using random unused entries from `templates.json`.

**Architecture:** Extract Kemnaker SSO/API logic into small Python modules under `lib/` (`config.py`, `geo.py`, `session.py`, `kemnaker.py`, `http_utils.py`), expose five thin Vercel Python serverless endpoints under `api/` (`auth.py`, `status.py`, `template.py`, `submit.py`, `cron.py`), and serve a zero-build static frontend from `public/`. Keep `cloudflare_worker.js` strictly as a secret-authenticated Kemnaker-only reverse proxy plus a single `0 10 * * 1-5` cron trigger.

**Tech Stack:** Python 3.10+ (stdlib `urllib`, `http.cookiejar`, `http.server`, `hmac`, `hashlib`, `math`, `unittest`) + `cryptography` (Fernet AES-128-CBC + HMAC-SHA256), vanilla HTML/CSS/JS, Vercel Serverless Python, Cloudflare Workers (ES module + Node `node:test`).

**Spec:** [`docs/superpowers/specs/2026-11-22-simple-web-monev-design.md`](file:///D:/laragon/www/monev-presensi/docs/superpowers/specs/2026-11-22-simple-web-monev-design.md)

## Global Constraints

- Default office pin: `OFFICE_LAT = -7.9021141`, `OFFICE_LONG = 110.065129`, `OFFICE_RADIUS_METERS = 10.0` (Kantor PT Angkasa Pura Indonesia — YIA).
- Sampling radius for coordinate generation: `9.8` meters inside the `10.0`-meter bound so 7-decimal rounding never exceeds `10.0` meters.
- Runtime compatibility: Python `3.10+` locally (`D:\laragon\bin\python\python-3.10\python.exe` or `python` on PATH) and Vercel Python runtime; Node `v20+` for Worker tests.
- External Python dependency limit: only `cryptography` in `requirements.txt` (no web framework).
- Fail-closed secrets: `SESSION_SECRET` must be `>= 32` chars; `CRON_SECRET` must be `>= 16` chars; `PROXY_SECRET` is required whenever `CLOUDFLARE_WORKER_URL` is configured.
- Strict auth separation: `/api/status`, `/api/template`, `/api/submit` ONLY read the encrypted `monev_session` cookie (TTL `19800`s) and NEVER read `KEMNAKER_USERNAME`/`KEMNAKER_PASSWORD`; `/api/cron` ONLY accepts `Authorization: Bearer <CRON_SECRET>` and NEVER `?secret=`.
- Hardened Cloudflare Worker: requires `X-Proxy-Secret` header (fails closed if unset), allows only `https:` to `maganghub.kemnaker.go.id`, `account.kemnaker.go.id`, `monev-api.maganghub.kemnaker.go.id` (including redirect `Location` targets), strips `X-Proxy-Secret` upstream, removes wildcard CORS, and runs one cron `0 10 * * 1-5`.
- Strict CSP on web UI: zero inline scripts, inline event handlers, or inline styles in `public/index.html`.
- No secrets, passwords, cookies, or Bearer tokens in logs, query strings, client JS, error payloads, or git.

## Review Focus

1. **Expired Kemnaker SSO token before cookie expiry:** Kemnaker returns HTTP 401 on `/api/status`, `/api/template`, or `/api/submit` → route must clear `monev_session` (`Max-Age=0`) and return `401` so the UI returns cleanly to login (pinned in Task 4).
2. **Malformed, oversized, or non-JSON payloads & bad coordinate types:** Invalid JSON, bodies `> 32768` bytes, or `NaN`/`Infinity`/boolean coordinates on `/api/auth` or `/api/submit` → must return `400` with a sanitized error and never a 500 traceback (pinned in Tasks 1, 2, 4).
3. **Proxy secret missing or upstream redirect escape:** `CLOUDFLARE_WORKER_URL` set without `PROXY_SECRET` must fail closed before sending any request; Worker receiving a non-Kemnaker URL, `http:` downgrade, or redirect to an unapproved host must reject with `403` (pinned in Tasks 1, 3, 6).
4. **Whitespace-only manual inputs & `templates.json` exhaustion:** Submitting whitespace-only `activity`/`learning`/`obstacles` must return `400`; when all 50 templates in `templates.json` appear in Kemnaker's daily logs, template selection must fall back to `random.choice(all_templates)` without crashing (pinned in Tasks 3, 4).
5. **CSRF cross-origin requests & query-string cron secrets:** `POST`/`DELETE` with mismatched `Origin` or `Sec-Fetch-Site: cross-site` must return `403`; `/api/cron?secret=<valid>` without `Authorization: Bearer` must return `401` (pinned in Tasks 2, 4).

---

### Task 1: Dependencies, Configuration & 10m Circular Coordinates

**Files:**
- Create: `lib/__init__.py`
- Create: `lib/config.py`
- Create: `lib/geo.py`
- Modify: `requirements.txt`
- Modify: `pyproject.toml`
- Modify: `.env.example`
- Test: `tests/test_geo.py`

**Interfaces:**
- Consumes: none (foundational layer)
- Produces:
  - `lib/config.py`:
    - `WIB: timezone` (`UTC+7`)
    - `class ConfigError(Exception)`
    - `load_dotenv(env_path: str = ".env") -> None`
    - `get_office_config() -> tuple[float, float, float]` (`lat, lon, radius_m`, defaults `-7.9021141, 110.065129, 10.0`)
    - `get_session_secret() -> str` (raises `ConfigError` if missing or `< 32` chars)
    - `get_cron_secret() -> str` (raises `ConfigError` if missing or `< 16` chars)
    - `get_proxy_config() -> tuple[str | None, str | None]` (returns `(url, secret)` or `(None, None)`; raises `ConfigError` if `CLOUDFLARE_WORKER_URL` is set but `PROXY_SECRET` is empty)
    - `get_allowed_username() -> str | None` (lowercased, stripped, or `None`)
    - `get_cron_credentials() -> tuple[str, str]` (raises `ConfigError` if `KEMNAKER_USERNAME` or `KEMNAKER_PASSWORD` missing)
  - `lib/geo.py`:
    - `DEFAULT_OFFICE_LAT = -7.9021141`
    - `DEFAULT_OFFICE_LONG = 110.065129`
    - `DEFAULT_RADIUS_METERS = 10.0`
    - `haversine_meters(lat1: float, lon1: float, lat2: float, lon2: float) -> float`
    - `generate_office_coordinates(center_lat: float | None = None, center_lon: float | None = None, max_radius_m: float | None = None, rng: random.Random | None = None) -> dict` (`{"latitude": float, "longitude": float, "distance_m": float}`)
    - `validate_office_coordinates(lat: object, lon: object, center_lat: float | None = None, center_lon: float | None = None, max_radius_m: float | None = None) -> dict` (raises `ValueError` on bool/NaN/Inf/non-numeric or distance `> max_radius_m`; returns `{"latitude": float, "longitude": float, "distance_m": float}`)

- [ ] **Step 1: Update `requirements.txt`, `pyproject.toml`, `.env.example`, and install `cryptography`**

  - `requirements.txt`: set to `cryptography>=42.0.0,<47.0.0`.
  - `pyproject.toml`: keep `[project]` (`name = "monev"`, `version = "2.0.0"`) and remove the `[tool.vercel]` `entrypoint = "api.cron:handler"` block so Vercel routes `public/` and all `api/*.py` files independently.
  - `.env.example`: document `SESSION_SECRET`, `CRON_SECRET`, `KEMNAKER_USERNAME`, `KEMNAKER_PASSWORD`, `ALLOWED_USERNAME`, `CLOUDFLARE_WORKER_URL`, `PROXY_SECRET`, `OFFICE_LAT=-7.9021141`, `OFFICE_LONG=110.065129`, `OFFICE_RADIUS_METERS=10` with placeholder values only and key generation command comment.
  - Install dependency locally:
    Run: `D:\laragon\bin\python\python-3.10\python.exe -m pip install -r requirements.txt` (or `python -m pip install -r requirements.txt`)
    Expected: `cryptography` installs cleanly and `python -c "import cryptography.fernet"` exits 0.

- [ ] **Step 2: Write failing tests in `tests/test_geo.py`**

```python
import math
import os
import random
import unittest
from unittest.mock import patch

from lib import config, geo


class TestConfigAndGeo(unittest.TestCase):
    def test_default_office_pin_is_yia_place_pin(self):
        with patch.dict(os.environ, {}, clear=True):
            lat, lon, radius = config.get_office_config()
        self.assertAlmostEqual(lat, -7.9021141, places=7)
        self.assertAlmostEqual(lon, 110.065129, places=7)
        self.assertEqual(radius, 10.0)

    def test_secrets_fail_closed(self):
        with patch.dict(os.environ, {"SESSION_SECRET": "short", "CRON_SECRET": "short"}, clear=True):
            with self.assertRaises(config.ConfigError):
                config.get_session_secret()
            with self.assertRaises(config.ConfigError):
                config.get_cron_secret()

    def test_proxy_url_without_secret_fails_closed(self):
        with patch.dict(os.environ, {"CLOUDFLARE_WORKER_URL": "https://p.workers.dev"}, clear=True):
            with self.assertRaises(config.ConfigError):
                config.get_proxy_config()

    def test_generated_coords_always_within_10m_circle(self):
        rng = random.Random(42)
        distances = []
        for _ in range(1000):
            c = geo.generate_office_coordinates(-7.9021141, 110.065129, 10.0, rng=rng)
            d = geo.haversine_meters(-7.9021141, 110.065129, c["latitude"], c["longitude"])
            self.assertLessEqual(d, 10.0)
            self.assertAlmostEqual(c["distance_m"], round(d, 2), places=2)
            distances.append(d)
        self.assertGreater(max(distances), 7.0)

    def test_validate_coordinates_rejects_bad_types_and_out_of_range(self):
        for bad_lat, bad_lon in [
            (True, 110.065129),
            (float("nan"), 110.065129),
            (float("inf"), 110.065129),
            ("abc", 110.065129),
            (-7.9022500, 110.065129),  # ~15m away
        ]:
            with self.assertRaises(ValueError):
                geo.validate_office_coordinates(bad_lat, bad_lon, -7.9021141, 110.065129, 10.0)

        ok = geo.validate_office_coordinates(-7.9021500, 110.065129, -7.9021141, 110.065129, 10.0)
        self.assertLessEqual(ok["distance_m"], 10.0)
```

- [ ] **Step 3: Run test to verify it fails**

  Run: `D:\laragon\bin\python\python-3.10\python.exe -m unittest tests.test_geo -v`
  Expected: FAIL (`ModuleNotFoundError: No module named 'lib'`).

- [ ] **Step 4: Implement `lib/__init__.py`, `lib/config.py`, and `lib/geo.py`**

  - `lib/config.py`: implement `load_dotenv`, `WIB`, `ConfigError`, and all getters matching the `Interfaces` block. Clamp `OFFICE_RADIUS_METERS` to `(0.5, 50.0]` (default `10.0`). Never call `load_dotenv` in a way that overwrites existing process env vars (`os.environ.setdefault`).
  - `lib/geo.py`: implement `haversine_meters` with Earth radius `6371000.0`, `generate_office_coordinates` using polar uniform disk sampling (`theta = rng.uniform(0, 2 * pi)`, `r = safe_radius * sqrt(rng.random())` with `safe_radius = max(0.0, max_radius_m - 0.2)` rounded to 7 decimals), and `validate_office_coordinates` rejecting `isinstance(v, bool)`, non-finite floats (`math.isfinite`), or distance `> max_radius_m`.

- [ ] **Step 5: Run tests to verify they pass**

  Run: `D:\laragon\bin\python\python-3.10\python.exe -m unittest tests.test_geo -v`
  Expected: All tests in `tests.test_geo` PASS.

- [ ] **Step 6: Commit**

```bash
git add requirements.txt pyproject.toml .env.example lib/__init__.py lib/config.py lib/geo.py tests/test_geo.py
git commit -m "feat: add fail-closed config and 10m circular coordinate module"
```

---

### Task 2: Encrypted Session Cookies & HTTP Security Utilities

**Files:**
- Create: `lib/session.py`
- Create: `lib/http_utils.py`
- Test: `tests/test_session.py`

**Interfaces:**
- Consumes: `lib/config.py` (`ConfigError`, `get_session_secret`)
- Produces:
  - `lib/session.py`:
    - `SESSION_COOKIE_NAME = "monev_session"`
    - `SESSION_TTL_SECONDS = 19800`
    - `encrypt_session(token: str, username: str, secret: str | None = None) -> str`
    - `decrypt_session(cookie_value: str | None, secret: str | None = None, ttl: int = SESSION_TTL_SECONDS) -> dict | None` (returns `{"token": str, "user": str}` or `None` on invalid/expired/tampered; raises `ConfigError` if `secret` missing/too short)
    - `parse_cookies(cookie_header: str | None) -> dict[str, str]`
    - `build_session_cookie(value: str, secure: bool = True, max_age: int = SESSION_TTL_SECONDS) -> str`
    - `build_clear_session_cookie(secure: bool = True) -> str`
  - `lib/http_utils.py`:
    - `MAX_BODY_BYTES = 32768`
    - `SECURITY_HEADERS: dict[str, str]` (`Cache-Control`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Content-Security-Policy`)
    - `is_local_host(host: str | None) -> bool`
    - `constant_time_equals(a: str | None, b: str | None) -> bool`
    - `verify_csrf(headers: dict, host: str | None) -> bool`
    - `sanitize_error(err: object, secrets: tuple[str, ...] = ()) -> str`
    - `read_json_body(rfile, headers, max_bytes: int = MAX_BODY_BYTES) -> tuple[dict | None, str | None]`
    - `send_json(handler, status: int, payload: dict, extra_headers: list[tuple[str, str]] | None = None) -> None`

- [ ] **Step 1: Write failing tests in `tests/test_session.py`**

```python
import io
import time
import unittest
from lib import session, http_utils

SECRET = "a" * 40


class TestSessionAndHttpUtils(unittest.TestCase):
    def test_fernet_session_roundtrip_and_tamper_rejection(self):
        cookie_val = session.encrypt_session("tok_123", "user1", secret=SECRET)
        self.assertNotIn("tok_123", cookie_val)
        data = session.decrypt_session(cookie_val, secret=SECRET)
        self.assertEqual(data, {"token": "tok_123", "user": "user1"})
        tampered = cookie_val[:-4] + "XXXX"
        self.assertIsNone(session.decrypt_session(tampered, secret=SECRET))
        self.assertIsNone(session.decrypt_session(cookie_val, secret="b" * 40))

    def test_fernet_session_ttl_expiry(self):
        cookie_val = session.encrypt_session("tok_123", "user1", secret=SECRET)
        time.sleep(1.1)
        self.assertIsNone(session.decrypt_session(cookie_val, secret=SECRET, ttl=0))

    def test_cookie_flags_secure_and_local(self):
        hdr = session.build_session_cookie("abc", secure=True)
        self.assertIn("HttpOnly", hdr)
        self.assertIn("SameSite=Strict", hdr)
        self.assertIn("Secure", hdr)
        self.assertIn("Max-Age=19800", hdr)
        clear_hdr = session.build_clear_session_cookie(secure=False)
        self.assertIn("Max-Age=0", clear_hdr)
        self.assertNotIn("Secure", clear_hdr)

    def test_csrf_same_origin_and_cross_origin(self):
        self.assertTrue(http_utils.verify_csrf({"Origin": "https://app.vercel.app"}, "app.vercel.app"))
        self.assertFalse(http_utils.verify_csrf({"Origin": "https://evil.example"}, "app.vercel.app"))
        self.assertFalse(http_utils.verify_csrf({"Sec-Fetch-Site": "cross-site"}, "app.vercel.app"))
        self.assertTrue(http_utils.verify_csrf({"Sec-Fetch-Site": "same-origin"}, "app.vercel.app"))

    def test_read_json_body_rejects_oversized_and_invalid(self):
        body, err = http_utils.read_json_body(io.BytesIO(b"{bad"), {"Content-Length": "4"})
        self.assertIsNone(body)
        self.assertIsNotNone(err)
        big_body, big_err = http_utils.read_json_body(io.BytesIO(b"x" * 100), {"Content-Length": "99999"})
        self.assertIsNone(big_body)
        self.assertIn("large", big_err.lower())

    def test_sanitize_error_redacts_secrets_and_bearer(self):
        msg = http_utils.sanitize_error("Failed Bearer eyJsecret123 pass=myPass99", secrets=("myPass99",))
        self.assertNotIn("eyJsecret123", msg)
        self.assertNotIn("myPass99", msg)
```

- [ ] **Step 2: Run test to verify it fails**

  Run: `D:\laragon\bin\python\python-3.10\python.exe -m unittest tests.test_session -v`
  Expected: FAIL (`ImportError`).

- [ ] **Step 3: Implement `lib/session.py` and `lib/http_utils.py`**

  - `lib/session.py`: derive Fernet key via `base64.urlsafe_b64encode(hashlib.sha256(secret.encode("utf-8")).digest())`. Catch `InvalidToken` in `decrypt_session` and return `None`. Validate secret length (`>= 32`) via `get_session_secret()` when `secret is None`, or raise `ConfigError` directly if caller supplies `< 32`.
  - `lib/http_utils.py`:
    - `SECURITY_HEADERS` carries exact CSP and headers from spec §5.3.
    - `verify_csrf`: rejects if `Sec-Fetch-Site` is present and not in `{"same-origin", "none"}`; if `Origin` header is present, its `netloc.lower()` must equal `(host or "").lower()`; if neither `Origin` nor `Sec-Fetch-Site` is present, rejects (`False`) so cross-site plain POSTs cannot bypass CSRF.
    - `read_json_body`: validates `Content-Length` is integer `0 <= n <= max_bytes`, parses UTF-8 JSON, requires `isinstance(obj, dict)`.
    - `sanitize_error`: strips `Bearer <token>`, `naco_access_token=<val>`, `monev_session=<val>`, and any passed `secrets`, truncates to 240 chars.

- [ ] **Step 4: Run tests to verify they pass**

  Run: `D:\laragon\bin\python\python-3.10\python.exe -m unittest tests.test_session -v`
  Expected: All tests in `tests.test_session` PASS.

- [ ] **Step 5: Commit**

```bash
git add lib/session.py lib/http_utils.py tests/test_session.py
git commit -m "feat: add Fernet session cookies and HTTP security utilities"
```

---

### Task 3: Kemnaker SSO Client, API Wrapper & Random Unused Template Picker

**Files:**
- Create: `lib/kemnaker.py`
- Test: `tests/test_kemnaker.py`

**Interfaces:**
- Consumes:
  - `lib/config.py`: `WIB`, `ConfigError`, `get_proxy_config`
  - `lib/geo.py`: `generate_office_coordinates`, `validate_office_coordinates`
  - `lib/http_utils.py`: `sanitize_error`
- Produces:
  - `lib/kemnaker.py`:
    - `class KemnakerError(Exception)`
    - `class KemnakerAuthError(KemnakerError)` (HTTP 401 or invalid login credentials)
    - `class AlreadySubmittedError(KemnakerError)`
    - `class SafeCookieJar(http.cookiejar.CookieJar)` (drops `acw_tc`)
    - `wrap_proxy_url(target_url: str, proxy_url: str | None) -> str`
    - `build_request_headers(base_headers: dict[str, str], proxy_url: str | None, proxy_secret: str | None) -> dict[str, str]`
    - `login_kemnaker(username: str, password: str) -> str` (returns `naco_access_token`; raises `KemnakerAuthError` on bad creds, `KemnakerError` on transport error; NEVER reads env creds)
    - `api_call(endpoint: str, token: str, method: str = "GET", payload: dict | None = None) -> dict` (raises `KemnakerAuthError` on HTTP 401)
    - `fetch_dashboard_state(token: str, today_wib: datetime | None = None) -> dict` (returns `{"date", "time_wib", "user": {"name", "mentor"}, "today": {"submitted", "submitted_at", "approval_status", "activity_log"}, "recent": [...]}`)
    - `load_templates(path: str | None = None) -> list[dict]`
    - `pick_random_unused_template(token: str, templates: list[dict] | None = None, rng: random.Random | None = None) -> tuple[dict, int, int]` (returns `(chosen_template, remaining_unused_count, total_count)`)
    - `submit_attendance(token: str, activity: str, learning: str, obstacles: str, lat: float | None = None, lon: float | None = None, today_wib: datetime | None = None) -> dict` (returns `{"date", "coords", "message", "response"}`; raises `ValueError` on blank fields or >10m coords, `AlreadySubmittedError` if already submitted today)

- [ ] **Step 1: Write failing tests in `tests/test_kemnaker.py`**

```python
import http.cookiejar
import io
import json
import os
import random
import unittest
import urllib.error
from datetime import datetime
from unittest.mock import patch

from lib import config, kemnaker


class TestKemnakerClient(unittest.TestCase):
    def test_safe_cookie_jar_drops_acw_tc(self):
        jar = kemnaker.SafeCookieJar()
        for name in ("acw_tc", "naco_access_token"):
            jar.set_cookie(http.cookiejar.Cookie(
                0, name, "val", None, False, "kemnaker.go.id", True, False,
                "/", True, True, None, False, None, None, {}
            ))
        self.assertEqual([c.name for c in jar], ["naco_access_token"])

    def test_proxy_headers_attach_secret_and_fail_closed(self):
        hdrs = kemnaker.build_request_headers({"Accept": "application/json"}, "https://p.workers.dev", "sec123")
        self.assertEqual(hdrs["X-Proxy-Secret"], "sec123")
        with self.assertRaises(config.ConfigError):
            kemnaker.build_request_headers({"Accept": "application/json"}, "https://p.workers.dev", "")

    def test_api_call_raises_auth_error_on_401(self):
        err = urllib.error.HTTPError("https://monev-api.maganghub.kemnaker.go.id/api/v1/users/me", 401, "Unauthorized", {}, io.BytesIO(b'{"message":"Unauthenticated"}'))
        with patch.dict(os.environ, {}, clear=True), patch("urllib.request.urlopen", side_effect=err):
            with self.assertRaises(kemnaker.KemnakerAuthError):
                kemnaker.api_call("https://monev-api.maganghub.kemnaker.go.id/api/v1/users/me", "tok")

    def test_pick_random_unused_template_excludes_history_and_handles_exhaustion(self):
        pool = [
            {"id": 1, "category": "a", "activity": "Alpha activity text here", "learning": "L1", "obstacles": "O1"},
            {"id": 2, "category": "b", "activity": "Beta activity text here", "learning": "L2", "obstacles": "O2"},
        ]
        with patch("lib.kemnaker.api_call", return_value={"data": [{"activity_log": "Alpha activity text here"}]}):
            chosen, remaining, total = kemnaker.pick_random_unused_template("tok", templates=pool, rng=random.Random(1))
        self.assertEqual(chosen["id"], 2)
        self.assertEqual((remaining, total), (1, 2))

        with patch("lib.kemnaker.api_call", return_value={"data": [
            {"activity_log": "Alpha activity text here"},
            {"activity_log": "Beta activity text here"},
        ]}):
            fallback, remaining2, total2 = kemnaker.pick_random_unused_template("tok", templates=pool, rng=random.Random(1))
        self.assertIn(fallback["id"], {1, 2})
        self.assertEqual((remaining2, total2), (0, 2))

    def test_submit_attendance_guards_duplicates_and_posts_payload(self):
        fixed_now = datetime(2026, 11, 23, 14, 0, 0, tzinfo=config.WIB)
        with patch("lib.kemnaker.api_call", return_value={"data": [{"date": "2026-11-23", "status": "PRESENT"}]}):
            with self.assertRaises(kemnaker.AlreadySubmittedError):
                kemnaker.submit_attendance("tok", "Work", "Learn", "None", today_wib=fixed_now)

        calls = []
        def fake_api(url, token, method="GET", payload=None):
            calls.append((method, url, payload))
            if method == "GET":
                return {"data": []}
            return {"message": "Saved"}

        with patch("lib.kemnaker.api_call", side_effect=fake_api):
            res = kemnaker.submit_attendance("tok", "  Build API  ", "  Learned X ", "  No issue ", today_wib=fixed_now)
        self.assertEqual(res["date"], "2026-11-23")
        self.assertLessEqual(res["coords"]["distance_m"], 10.0)
        post_payload = calls[1][2]
        self.assertEqual(post_payload["status"], "PRESENT")
        self.assertTrue(post_payload["is_reviewed"])
        self.assertEqual(post_payload["activity_log"], "Build API")
        self.assertEqual(post_payload["lesson_learned"], "Learned X")
        self.assertEqual(post_payload["obstacles"], "No issue")
```

- [ ] **Step 2: Run test to verify it fails**

  Run: `D:\laragon\bin\python\python-3.10\python.exe -m unittest tests.test_kemnaker -v`
  Expected: FAIL (`ImportError`).

- [ ] **Step 3: Implement `lib/kemnaker.py`**

  - Preserve the exact Kemnaker SSO sequence from existing `monev_bot.py:328-361` (`SafeCookieJar`, `GET https://maganghub.kemnaker.go.id/api/naco/login?redirect_url=/`, regex `name="csrf-token"\s+content="([^"]+)"`, `POST https://account.kemnaker.go.id/auth/login` with JSON `{username, password}` and `X-CSRF-TOKEN`/`Origin`/`Referer`, callback GET `redirect_uri`, extract `naco_access_token` cookie).
  - Route every Kemnaker HTTP request through `wrap_proxy_url` and `build_request_headers` using `get_proxy_config()`.
  - Sanitize all raised errors with `sanitize_error(..., secrets=(password, token))` so credentials never leak in exceptions.
  - Validate `activity`, `learning`, `obstacles` are non-empty after `.strip()` before contacting Kemnaker; raise `ValueError` otherwise.
  - `fetch_dashboard_state`: sort `/attendances` descending by `date`, take top 7 for `recent` (`date`, `status`, `approval_status`), and if today is submitted fetch `/daily-logs?date={today_str}` for `activity_log`.

- [ ] **Step 4: Run tests to verify they pass**

  Run: `D:\laragon\bin\python\python-3.10\python.exe -m unittest tests.test_kemnaker -v`
  Expected: All tests in `tests.test_kemnaker` PASS.

- [ ] **Step 5: Commit**

```bash
git add lib/kemnaker.py tests/test_kemnaker.py
git commit -m "feat: add clean Kemnaker SSO client and random unused template picker"
```

---

### Task 4: Vercel Python Serverless API Endpoints

**Files:**
- Create: `api/auth.py`
- Create: `api/status.py`
- Create: `api/template.py`
- Create: `api/submit.py`
- Modify: `api/cron.py` (full rewrite — remove all Telegram webhook/command/reminder logic)
- Test: `tests/test_api.py`

**Interfaces:**
- Consumes: `lib/config.py`, `lib/geo.py`, `lib/session.py`, `lib/http_utils.py`, `lib/kemnaker.py`
- Produces:
  - Each `api/*.py` defines `class handler(BaseHTTPRequestHandler)` plus testable pure/helper dispatch functions (`handle_post`, `handle_delete`, `handle_get`) matching the exact API contracts in Spec §5.4:
    - `api/auth.py`: `POST /api/auth`, `DELETE /api/auth`
    - `api/status.py`: `GET /api/status`
    - `api/template.py`: `GET /api/template` (supports `?coords_only=1`)
    - `api/submit.py`: `POST /api/submit`
    - `api/cron.py`: `POST /api/cron` and `GET /api/cron`

- [ ] **Step 1: Write failing tests in `tests/test_api.py`**

  Test helper invokes each endpoint's `handler` (or pure dispatcher) using in-memory headers/body/response buffers and asserts:
  1. `POST /api/auth`:
     - Cross-origin `Origin: https://evil.com` → `403`.
     - `ALLOWED_USERNAME=owner@mail.com` with `username=other@mail.com` → `403` and `login_kemnaker` is NOT called.
     - Valid login → `200` with `user: {name, mentor}` and `Set-Cookie: monev_session=...; HttpOnly; SameSite=Strict`.
     - `DELETE /api/auth` → `200` with `Set-Cookie: monev_session=; ... Max-Age=0`.
  2. `GET /api/status`:
     - Missing cookie (even when `KEMNAKER_USERNAME`/`KEMNAKER_PASSWORD` exist in env!) → `401` and `login_kemnaker` is NOT called.
     - Valid cookie when `fetch_dashboard_state` raises `KemnakerAuthError` → `401` AND response includes `Set-Cookie` clearing `monev_session` (`Max-Age=0`).
     - Valid cookie happy path → `200` with `date`, `time_wib`, `user`, `today`, `recent`, `coords` (`distance_m <= 10.0`), `templates: {remaining, total}`.
  3. `GET /api/template`:
     - Missing cookie → `401`.
     - `?coords_only=1` → `200` with `coords` and `template: None` (no Kemnaker API call needed).
     - Default → `200` with `coords` and `template: {id, category, activity, learning, obstacles}`.
  4. `POST /api/submit`:
     - Missing cookie → `401`.
     - Cross-site CSRF → `403`.
     - Blank/whitespace `activity`, `learning`, or `obstacles` → `400`.
     - Coordinates >10m away → `400`.
     - Already submitted (`AlreadySubmittedError`) → `409`.
     - `KemnakerAuthError` → `401` + clears cookie.
     - Valid submit → `200 {ok: True, date, coords, message}`.
  5. `POST /api/cron` & `GET /api/cron`:
     - Unset `CRON_SECRET` → `503`.
     - `?secret=<valid>` in URL WITHOUT `Authorization: Bearer` header → `401`.
     - Valid `Authorization: Bearer <CRON_SECRET>` on Saturday WIB → `200 {status: "weekend_skipped"}` and `login_kemnaker` NOT called.
     - Valid Bearer on weekday when already submitted → `200 {status: "already_submitted"}`.
     - Valid Bearer on weekday when not yet submitted → `200 {status: "submitted", date, template_id, coords}` using `KEMNAKER_USERNAME`/`KEMNAKER_PASSWORD` and `pick_random_unused_template`.

- [ ] **Step 2: Run test to verify it fails**

  Run: `D:\laragon\bin\python\python-3.10\python.exe -m unittest tests.test_api -v`
  Expected: FAIL (`ImportError` / missing handlers).

- [ ] **Step 3: Implement `api/auth.py`, `api/status.py`, `api/template.py`, `api/submit.py`, and rewrite `api/cron.py`**

  - Add root path bootstrap (`ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))`) at top of each `api/*.py` so Vercel imports `lib.*` reliably regardless of CWD.
  - Ensure every handler catches `ConfigError` → `503`, `KemnakerAuthError` → `401` (clearing `monev_session` on authenticated routes), `AlreadySubmittedError` → `409`, `ValueError` → `400`, unexpected `Exception` → `500` with `sanitize_error` (never returning tracebacks).
  - For `POST /api/auth`: also fetch `/api/v1/users/me` once after SSO login to return `{"name", "mentor"}`, and never echo password/token.
  - For `api/cron.py`: share one `_run_cron()` helper for both `do_POST` and `do_GET`, strictly checking `Authorization: Bearer <CRON_SECRET>` via `constant_time_equals`, never reading `query_params["secret"]`.

- [ ] **Step 4: Run tests to verify they pass**

  Run: `D:\laragon\bin\python\python-3.10\python.exe -m unittest tests.test_api -v`
  Expected: All tests in `tests.test_api` PASS.

- [ ] **Step 5: Commit**

```bash
git add api/auth.py api/status.py api/template.py api/submit.py api/cron.py tests/test_api.py
git commit -m "feat: add authenticated web API routes and Bearer-only 17:00 cron endpoint"
```

---

### Task 5: Mobile-First Static Web UI & Local Dev Server

**Files:**
- Create: `public/index.html`
- Create: `public/styles.css`
- Create: `public/app.js`
- Create: `dev_server.py`
- Test: `tests/test_ui_csp.py`

**Interfaces:**
- Consumes: `/api/auth`, `/api/status`, `/api/template`, `/api/submit` contracts from Task 4
- Produces:
  - `public/index.html`, `public/styles.css`, `public/app.js`: strict-CSP 2-screen UI (Login screen → Dashboard screen with Today's Status, auto ±10m YIA Location preview + Re-roll, manual Activity/Learning/Obstacles form + Fill random template + Submit, and 7-day Recent History).
  - `dev_server.py`: runnable via `python dev_server.py` on `http://127.0.0.1:8000` serving `public/` static files and dispatching `/api/*` requests to `api/*.py` handlers.

- [ ] **Step 1: Write failing tests in `tests/test_ui_csp.py`**

```python
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestUiCspAndStructure(unittest.TestCase):
    def test_index_html_strict_csp_and_required_elements(self):
        path = os.path.join(ROOT, "public", "index.html")
        with open(path, "r", encoding="utf-8") as f:
            html = f.read()
        self.assertIn('href="/styles.css"', html)
        self.assertIn('src="/app.js"', html)
        # No inline script bodies, inline event handlers, or inline styles
        self.assertFalse(re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html, re.I))
        self.assertFalse(re.search(r"\son[a-z]+\s*=", html, re.I))
        self.assertFalse(re.search(r"\sstyle\s*=", html, re.I))
        for field_id in ("login-form", "dashboard", "activity-input", "learning-input", "obstacles-input", "reroll-btn", "random-template-btn", "submit-btn"):
            self.assertIn(f'id="{field_id}"', html)

    def test_app_js_never_uses_local_or_session_storage_for_credentials(self):
        path = os.path.join(ROOT, "public", "app.js")
        with open(path, "r", encoding="utf-8") as f:
            js = f.read()
        self.assertNotIn("localStorage", js)
        self.assertNotIn("sessionStorage", js)
        self.assertIn("/api/auth", js)
        self.assertIn("/api/status", js)
        self.assertIn("/api/template", js)
        self.assertIn("/api/submit", js)

    def test_dev_server_imports_cleanly(self):
        import dev_server
        self.assertTrue(callable(dev_server.create_server))
```

- [ ] **Step 2: Run test to verify it fails**

  Run: `D:\laragon\bin\python\python-3.10\python.exe -m unittest tests.test_ui_csp -v`
  Expected: FAIL (`FileNotFoundError` for `public/index.html`).

- [ ] **Step 3: Build `public/index.html`, `public/styles.css`, `public/app.js`, and `dev_server.py`**

  - `public/index.html`: semantic HTML5, mobile viewport meta, login card (`id="login-form"` with username/password inputs and `autocomplete="username"`/`"current-password"`), dashboard (`id="dashboard"`, hidden via CSS class `.hidden` until authenticated) with top bar (name, mentor, Refresh, Logout), Today's Status card, Auto ±10m YIA Location card (`id="reroll-btn"`), manual form (`id="activity-input"`, `id="learning-input"`, `id="obstacles-input"`, live char counts, `id="random-template-btn"`, `id="submit-btn"`), and 7-day Recent History list.
  - `public/styles.css`: clean, responsive mobile-first design with clear status badges (submitted vs pending), accessible focus states, disabled state styling when already submitted today.
  - `public/app.js`:
    - On load: calls `GET /api/status` with `credentials: "same-origin"`. If `200`, renders dashboard; if `401`, shows login screen.
    - Login submit: `POST /api/auth` with `{username, password}`, clears password input value immediately in DOM, then calls `loadStatus()`.
    - Logout: `DELETE /api/auth`, wipes UI state, returns to login screen.
    - Re-roll button: `GET /api/template?coords_only=1` updates displayed `latitude, longitude` and distance in meters.
    - Fill random template button: `GET /api/template` populates `activity`, `learning`, `obstacles` (user can edit before submitting) and refreshes coordinates.
    - Attendance submit: validates non-empty inputs client-side, sends `POST /api/submit` with `{activity, learning, obstacles, latitude, longitude}`, disables double clicks during request, handles `401` (return to login), `409` (reload status), and `200` (show success + reload status).
    - Always uses `textContent` (never `innerHTML` with API data) to prevent XSS.
  - `dev_server.py`: `create_server(host="127.0.0.1", port=8000)` serving `public/` static files and delegating `/api/auth`, `/api/status`, `/api/template`, `/api/submit`, `/api/cron` to each module's `handler` class.

- [ ] **Step 4: Run tests to verify they pass**

  Run: `D:\laragon\bin\python\python-3.10\python.exe -m unittest tests.test_ui_csp -v`
  Expected: All tests in `tests.test_ui_csp` PASS.

- [ ] **Step 5: Commit**

```bash
git add public/index.html public/styles.css public/app.js dev_server.py tests/test_ui_csp.py
git commit -m "feat: add mobile-first strict-CSP web UI and local dev server"
```

---

### Task 6: Hardened Cloudflare Worker, Vercel Config, Legacy Cleanup & Docs

**Files:**
- Modify: `cloudflare_worker.js`
- Modify: `wrangler.toml`
- Modify: `vercel.json`
- Modify: `README.md`
- Delete: `monev_bot.py`, `telegram_polling.py`, `reminder_templates.json`, `used_templates.json`, `README_BOT.md`, `tests/test_monev.py`
- Test: `tests/test_worker.mjs`

**Interfaces:**
- Consumes: `/api/cron` Bearer contract (`Authorization: Bearer <CRON_SECRET>`) and `X-Proxy-Secret` header from `lib/kemnaker.py`
- Produces:
  - Hardened `cloudflare_worker.js` (`export default { fetch, scheduled }`)
  - `wrangler.toml` with single cron `crons = ["0 10 * * 1-5"]`
  - `vercel.json` with `regions: ["sin1"]`, Python `maxDuration: 60`, static security headers, and backup cron `/api/cron` at `0 10 * * 1-5`

- [ ] **Step 1: Write failing Cloudflare Worker tests in `tests/test_worker.mjs`**

```js
import test from "node:test";
import assert from "node:assert/strict";
import worker from "../cloudflare_worker.js";

const ENV = {
  PROXY_SECRET: "super_secret_proxy_key_123456",
  CRON_SECRET: "super_secret_cron_key_123456",
  VERCEL_DOMAIN: "https://monev.example.vercel.app",
};

test("fails closed with 503 when PROXY_SECRET env is missing", async () => {
  const req = new Request("https://w.workers.dev/?url=https://maganghub.kemnaker.go.id/");
  const res = await worker.fetch(req, {}, {});
  assert.equal(res.status, 503);
});

test("rejects missing or wrong X-Proxy-Secret with 403", async () => {
  const req = new Request("https://w.workers.dev/?url=https://maganghub.kemnaker.go.id/", {
    headers: { "X-Proxy-Secret": "wrong" },
  });
  const res = await worker.fetch(req, ENV, {});
  assert.equal(res.status, 403);
});

test("rejects non-allowlisted host and http downgrade with 403", async () => {
  for (const bad of ["https://evil.example.com/", "http://maganghub.kemnaker.go.id/"]) {
    const req = new Request(`https://w.workers.dev/?url=${encodeURIComponent(bad)}`, {
      headers: { "X-Proxy-Secret": ENV.PROXY_SECRET },
    });
    const res = await worker.fetch(req, ENV, {});
    assert.equal(res.status, 403);
  }
});

test("strips X-Proxy-Secret upstream, rejects redirect to non-Kemnaker host, no wildcard CORS", async () => {
  const origFetch = globalThis.fetch;
  let capturedHeaders;
  globalThis.fetch = async (_url, opts) => {
    capturedHeaders = opts.headers;
    return new Response(null, { status: 302, headers: { Location: "https://evil.example/steal" } });
  };
  try {
    const req = new Request(
      `https://w.workers.dev/?url=${encodeURIComponent("https://maganghub.kemnaker.go.id/api/naco/login")}`,
      { headers: { "X-Proxy-Secret": ENV.PROXY_SECRET } }
    );
    const res = await worker.fetch(req, ENV, {});
    assert.equal(capturedHeaders.has("x-proxy-secret"), false);
    assert.equal(res.status, 403);
    assert.equal(res.headers.get("access-control-allow-origin"), null);
  } finally {
    globalThis.fetch = origFetch;
  }
});

test("scheduled skips weekend and sends POST with Bearer header (not query string) on weekday", async () => {
  const origFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, opts) => {
    calls.push({ url, opts });
    return new Response('{"status":"submitted"}', { status: 200 });
  };
  try {
    const promises = [];
    const ctx = { waitUntil: (p) => promises.push(p) };
    // Sunday 2026-11-22 10:00 UTC (17:00 WIB)
    await worker.scheduled({ cron: "0 10 * * 1-5", scheduledTime: Date.UTC(2026, 10, 22, 10, 0, 0) }, ENV, ctx);
    await Promise.all(promises);
    assert.equal(calls.length, 0);

    // Monday 2026-11-23 10:00 UTC (17:00 WIB)
    await worker.scheduled({ cron: "0 10 * * 1-5", scheduledTime: Date.UTC(2026, 10, 23, 10, 0, 0) }, ENV, ctx);
    await Promise.all(promises);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, "https://monev.example.vercel.app/api/cron");
    assert.equal(calls[0].opts.method, "POST");
    assert.equal(calls[0].opts.headers["Authorization"], `Bearer ${ENV.CRON_SECRET}`);
    assert.equal(calls[0].url.includes("secret="), false);
  } finally {
    globalThis.fetch = origFetch;
  }
});
```

- [ ] **Step 2: Run Worker test to verify it fails**

  Run: `node --test tests/test_worker.mjs`
  Expected: FAIL (existing `cloudflare_worker.js` is unauthenticated open proxy and uses GET with `?secret=`).

- [ ] **Step 3: Harden `cloudflare_worker.js` and update `wrangler.toml`, `vercel.json`**

  - `cloudflare_worker.js`:
    - Define `ALLOWED_HOSTS = new Set(["maganghub.kemnaker.go.id", "account.kemnaker.go.id", "monev-api.maganghub.kemnaker.go.id"])`.
    - Implement constant-time string comparison `timingSafeEqual(a, b)` over UTF-8 bytes.
    - Fail closed (`503`) if `!env?.PROXY_SECRET`; return `403` if `X-Proxy-Secret` does not match.
    - Require `targetUrl.protocol === "https:"` and `ALLOWED_HOSTS.has(targetUrl.hostname)`; return `403` otherwise.
    - Strip `x-proxy-secret`, `host`, `cf-*` headers before forwarding; preserve `acw_tc` cookie stripping for non-`maganghub` hosts; preserve `redirect: "manual"` and `Set-Cookie` domain stripping.
    - On `Location` response header: resolve relative URLs against `targetUrl`, verify resolved URL is `https:` and in `ALLOWED_HOSTS` (returning `403` if not), then wrap through worker origin.
    - Remove all `Access-Control-Allow-Origin: *` headers and OPTIONS wildcard handler.
    - In `scheduled(event, env, ctx)`: use `new Date(event?.scheduledTime || Date.now())` shifted to WIB (`+7h`), skip if `dayOfWeek === 0 || dayOfWeek === 6`, require `env.VERCEL_DOMAIN` and `env.CRON_SECRET`, send `POST ${vercelDomain}/api/cron` with `Authorization: Bearer ${cronSecret}` header only (55s timeout, 1 retry on network/5xx).
  - `wrangler.toml`: update `crons = ["0 10 * * 1-5"]`.
  - `vercel.json`: set `regions: ["sin1"]`, `functions: { "api/**/*.py": { "maxDuration": 60 } }`, `crons: [{ "path": "/api/cron", "schedule": "0 10 * * 1-5" }]`, and `headers` applying strict CSP + security headers to `/(.*)`.

- [ ] **Step 4: Remove legacy Telegram/template-state files and rewrite `README.md`**

  - Delete: `monev_bot.py`, `telegram_polling.py`, `reminder_templates.json`, `used_templates.json`, `README_BOT.md`, `tests/test_monev.py`.
  - Rewrite `README.md` with updated architecture diagram, security model, environment variable table, local development instructions (`python dev_server.py`), and Vercel + Cloudflare Worker deploy steps.

- [ ] **Step 5: Run full test suite (Python + Cloudflare Worker)**

  Run:
  ```powershell
  D:\laragon\bin\python\python-3.10\python.exe -m unittest discover -s tests -v
  node --test tests/test_worker.mjs
  ```
  Expected: 100% of Python tests (`test_geo`, `test_session`, `test_kemnaker`, `test_api`, `test_ui_csp`) and Node Worker tests (`test_worker.mjs`) PASS with 0 errors and 0 skipped.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: harden Cloudflare proxy/cron, update Vercel config, remove Telegram bot"
```
