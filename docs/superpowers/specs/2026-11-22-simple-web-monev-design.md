# Simplified Web Monev Presensi — Design Specification

Date: 2026-11-22

## 1. Intent & Why

The user needs a simpler, Telegram-free way to submit daily MagangHub Kemnaker (SIAPkerja) attendance and logbooks while working away from the office for some time. They do not use Telegram, so the existing Telegram bot, webhook setup, polling runner, and multi-schedule reminders are unnecessary complexity.

They want:
1. A clean, safe, mobile-friendly **web UI** on Vercel where they can log in and manually enter daily **Activity**, **Learning**, and **Obstacles**.
2. **Automatic location coordinates** randomized within a **10-meter radius** of Kantor PT Angkasa Pura Indonesia — Yogyakarta International Airport (YIA): `-7.9021141, 110.065129` (the actual Google Maps place pin from the user's link, not the viewport center).
3. A **17:00 WIB Monday–Friday automatic safety net**: if they forget to submit manually by 17:00 WIB on a weekday, the backend automatically checks Kemnaker and submits a **random unused** entry from `templates.json` (which the user will personalize later).
4. **Strong security** across all keys, passwords, cookies, environment variables, and the Cloudflare Worker reverse proxy (still required because Kemnaker's WAF can return HTTP 403 to Vercel IPs directly).

## 2. Goals, Non-Goals, and Anti-Goals

### Goals
- Remove all Telegram dependencies, webhook endpoints, polling scripts, reminder templates, and persistent-file tracking (`used_templates.json`).
- Provide a secure 2-screen web UI (Login → Dashboard) to inspect today's attendance status, view the last 7 days, preview/re-roll 10m coordinates, optionally fill a random unused template, and submit manual `activity`, `learning`, and `obstacles`.
- Guarantee automatic coordinates fall strictly inside a 10-meter radius circle around `-7.9021141, 110.065129` (configurable via env vars, defaulting to that exact pin).
- Run a reliable 17:00 WIB (10:00 UTC) Mon–Fri fallback check that skips if attendance is already submitted, skips weekends, and selects a random unused entry from `templates.json` by cross-checking Kemnaker's `daily-logs` API.
- Harden the Cloudflare Worker so it acts strictly as an authenticated reverse proxy for Kemnaker domains plus the single 17:00 WIB Mon–Fri cron trigger.
- Protect all credentials, session tokens, and secrets with fail-closed validation and modern cryptography.

### Non-Goals
- No Telegram bot, notifications, or messaging integrations.
- No external database or KV store (Kemnaker's own `attendances` and `daily-logs` APIs remain the source of truth).
- No multi-user accounts, user registration, or role management (single personal deployment).
- No editing or deleting past attendance entries (MagangHub submission only).

### Anti-Goals (Failure Conditions)
- Exposing Kemnaker credentials, Bearer tokens, cookies, or secrets in logs, URL query strings, client-side JavaScript, API error payloads, or git history.
- Allowing web UI requests to fall back to server-side `KEMNAKER_USERNAME` / `KEMNAKER_PASSWORD` env vars (unauthenticated visitors must never be able to access or submit attendance).
- Leaving `cloudflare_worker.js` as an open proxy to arbitrary URLs or forwarding internal proxy secrets upstream to Kemnaker.
- Allowing duplicate submissions on the same day or triggering the 17:00 WIB cron on Saturday/Sunday.
- Generating coordinates in a bounding square (whose corners exceed 10m diagonally) instead of a true 10m circle.

## 3. Constraints

- **Hosting:** Vercel (Python serverless functions under `api/` + static assets under `public/`, region `sin1`, `maxDuration: 60`) and Cloudflare Workers (`cloudflare_worker.js`, `wrangler.toml`).
- **Runtime:** Python 3.10+ locally (Laragon Python 3.10.6 detected on the user's machine) and Vercel's Python runtime in production.
- **Kemnaker WAF & SSO Quirks:** Must preserve the existing SSO flow (`maganghub.kemnaker.go.id/api/naco/login` → CSRF token extraction → `account.kemnaker.go.id/auth/login` → redirect callback → `naco_access_token` cookie), `SafeCookieJar` filtering out `acw_tc`, and Cloudflare Worker `redirect: "manual"` with `Set-Cookie` domain stripping and wrapped redirect URLs.
- **Stateless Serverless:** Vercel filesystem outside `/tmp` is read-only and ephemeral. No state may depend on local disk persistence.
- **Schedule Precision:** Cloudflare Cron (`0 10 * * 1-5` UTC = 17:00 WIB Mon–Fri) is the primary exact trigger; Vercel Cron (`0 10 * * 1-5`) may remain as an optional redundant trigger since Kemnaker's attendance guard makes duplicate triggers idempotent.

## 4. Approaches Considered

| Approach | Summary | Trade-offs |
|---|---|---|
| **1. Lean Python API + Static Web UI (Selected)** | Extract Kemnaker SSO/API logic into Python modules under `lib/`, expose minimal Vercel Python serverless routes in `api/`, serve a mobile-first vanilla HTML/CSS/JS frontend from `public/`, and harden `cloudflare_worker.js` for proxy + 17:00 WIB cron. | **Pros:** Reuses proven Python SSO & `SafeCookieJar` WAF handling; zero JS build step or `node_modules`; tiny repo; fast deploys. **Cons:** Frontend uses vanilla HTML/CSS/JS instead of React (acceptable and simpler for a 2-screen form app). |
| **2. Full-Stack Next.js (TypeScript)** | Rewrite everything in Next.js App Router with React + Tailwind and Web Crypto sessions; keep Cloudflare Worker for proxy + cron. | **Pros:** Strong UI ergonomics if expanding to a large multi-page app. **Cons:** Heavy build pipeline and requires rewriting and re-verifying Kemnaker's quirky multi-redirect SSO & cookie-jar WAF workaround in JS. |
| **3. FastAPI + Server-Rendered Jinja2** | Single Python entrypoint (`api/index.py`) rendering Jinja2 HTML forms. | **Pros:** Built-in Python routing without `BaseHTTPRequestHandler` boilerplate. **Cons:** Extra framework deps, slower cold starts, and full-page reloads feel clunkier on mobile than JSON `fetch` updates for status refresh and coordinate re-roll. |

**Decision:** The user selected **Approach 1** with an explicit focus on keeping all security keys, passwords, and environment variables safe.

## 5. Architecture & Component Design

### 5.1 Repository Layout

```text
monev-presensi/
├── api/
│   ├── auth.py               # POST (login) & DELETE (logout)
│   ├── status.py             # GET today's status, profile, 7-day history, fresh 10m coords
│   ├── template.py           # GET random unused template and/or fresh 10m coords
│   ├── submit.py             # POST manual attendance + daily log submission
│   └── cron.py               # POST/GET 17:00 WIB Mon-Fri fallback (Bearer CRON_SECRET only)
├── lib/
│   ├── __init__.py
│   ├── config.py             # Env loading (.env for local dev), constants, secret checks
│   ├── geo.py                # 10m circular coordinate generator + Haversine validator
│   ├── session.py            # Fernet (AES-128-CBC + HMAC-SHA256) HttpOnly cookie helpers
│   ├── kemnaker.py           # SSO login, SafeCookieJar, proxy wrapper, API calls, template picker
│   └── http_utils.py         # JSON responses, security headers, CSRF check, safe error formatting
├── public/
│   ├── index.html            # Single-page 2-screen UI (Login + Dashboard)
│   ├── styles.css            # Mobile-first responsive styling (no inline styles)
│   └── app.js                # Vanilla JS client (no inline scripts, strict CSP compatible)
├── tests/
│   ├── __init__.py
│   ├── test_geo.py           # 10m radius circle math & Haversine bounds
│   ├── test_session.py       # Fernet encryption, tamper rejection, TTL expiry, fail-closed checks
│   ├── test_kemnaker.py      # SafeCookieJar, proxy headers, random unused template selection, double-submit guard
│   └── test_api.py           # Endpoint auth separation, CSRF check, cron auth & weekend skip
├── cloudflare_worker.js      # Hardened Kemnaker-only proxy + single 17:00 WIB Mon-Fri cron
├── wrangler.toml             # Single cron: ["0 10 * * 1-5"]
├── templates.json            # Preserved 50-item template pool (user will personalize later)
├── vercel.json               # Region sin1, Python maxDuration 60, static + API routing
├── requirements.txt          # cryptography (for standard Fernet authenticated encryption)
├── pyproject.toml            # Project metadata (remove single-entrypoint override)
├── .env.example              # Documented env vars with placeholders only
└── README.md                 # Updated setup, security, and Vercel + Cloudflare deploy guide
```

**Files to remove:** `monev_bot.py`, `telegram_polling.py`, `reminder_templates.json`, `used_templates.json`, `README_BOT.md`.

### 5.2 Coordinate Generation & Validation (`lib/geo.py`)

- **Default Office Pin:** `OFFICE_LAT = -7.9021141`, `OFFICE_LONG = 110.065129` (overridable via env vars).
- **Default Radius:** `OFFICE_RADIUS_METERS = 10.0` (overridable via env var, capped sensibly).
- **Polar Uniform Circle Sampling:**
  - Sample angle $\theta \sim \text{Uniform}(0, 2\pi)$ and distance $r = R_{\text{safe}} \cdot \sqrt{\text{Uniform}(0, 1)}$ where $R_{\text{safe}} = 9.8\text{m}$ (slight rounding buffer so 7-decimal rounding never drifts past 10.0m).
  - Convert meters to degrees using Earth radius $R_E = 6{,}371{,}000\text{m}$:
    - $\Delta\text{lat} = \frac{r \cos\theta}{R_E} \cdot \frac{180}{\pi}$
    - $\Delta\text{lon} = \frac{r \sin\theta}{R_E \cos(\text{lat}_0)} \cdot \frac{180}{\pi}$
  - Round to 7 decimal places (~1.1cm precision).
- **Server-Side Verification:** `haversine_meters(lat1, lon1, lat2, lon2)` verifies that any client-submitted preview coordinates are within `OFFICE_RADIUS_METERS` (10.0m) of the configured office pin. If omitted or outside 10.0m, the server rejects out-of-range input (400) or generates fresh valid coordinates when omitted.

### 5.3 Authentication & Security Model

1. **Strict Auth Boundary (Web UI vs. Cron):**
   - **Web UI (`POST /api/auth`):** User enters Kemnaker `username` and `password`.
     - If `ALLOWED_USERNAME` env var is configured, `username` is compared (lowercased, stripped) using `hmac.compare_digest` **before** calling Kemnaker. Mismatch returns `403 Forbidden` with a generic error.
     - Server authenticates against Kemnaker SSO via `lib/kemnaker.py` using the submitted credentials (never env credentials), obtains `naco_access_token`, and immediately discards the plaintext password from memory.
     - Server encrypts `{"token": naco_access_token, "user": username}` with Fernet (`SESSION_SECRET`) and sets cookie `monev_session`:
       - `HttpOnly; SameSite=Strict; Path=/; Max-Age=19800` (~5.5 hours, safely under Kemnaker's 6h token lifetime)
       - `Secure` enabled automatically unless running on local HTTP dev (`localhost` / `127.0.0.1`).
   - **Protected Web Routes (`/api/status`, `/api/template`, `/api/submit`):**
     - Require a valid, unexpired, untampered `monev_session` cookie.
     - Never read `KEMNAKER_USERNAME` or `KEMNAKER_PASSWORD` env vars.
     - If Kemnaker returns HTTP 401 (expired/revoked SSO token), the route clears the `monev_session` cookie and returns `401 Unauthorized` so the UI returns to the login screen cleanly.
   - **Cron Fallback Route (`/api/cron`):**
     - Accepts `POST /api/cron` (primary, called by Cloudflare Worker) and `GET /api/cron` (compatible with Vercel Cron, which sends `GET` with `Authorization: Bearer <CRON_SECRET>`).
     - **Fail-closed auth:** If `CRON_SECRET` env var is unset or shorter than 16 chars, returns `503 Service Unavailable`. Requires `Authorization: Bearer <CRON_SECRET>` matched via `hmac.compare_digest`. **Never** accepts `?secret=` in query strings.
     - Uses `KEMNAKER_USERNAME` and `KEMNAKER_PASSWORD` env vars exclusively for this scheduled fallback.

2. **Session Cryptography (`lib/session.py`):**
   - Uses `cryptography.fernet.Fernet` (AES-128-CBC + PKCS7 + HMAC-SHA256 + signed timestamp).
   - `SESSION_SECRET` is required (fail closed with `503` if missing or `< 32` characters). Key material is derived via `base64.urlsafe_b64encode(hashlib.sha256(secret.encode("utf-8")).digest())`.
   - `decrypt(..., ttl=19800)` enforces server-side expiration even if a client replays an old cookie.

3. **CSRF & HTTP Security Headers (`lib/http_utils.py`):**
   - Every response includes:
     - `Cache-Control: no-store`
     - `X-Content-Type-Options: nosniff`
     - `X-Frame-Options: DENY`
     - `Referrer-Policy: no-referrer`
     - `Content-Security-Policy: default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`
   - State-changing web requests (`POST`, `DELETE` on `/api/auth` and `/api/submit`) validate `Origin` (or `Sec-Fetch-Site: same-origin`) against the `Host` header, in addition to `SameSite=Strict` cookies.
   - Error sanitizer strips any bearer tokens, cookies, passwords, or raw stack traces before returning error JSON or printing logs.

4. **Hardened Cloudflare Worker (`cloudflare_worker.js` & `wrangler.toml`):**
   - **Proxy Auth:** Requires `X-Proxy-Secret` header matching `env.PROXY_SECRET` (using constant-time comparison; fails closed with `503` if `env.PROXY_SECRET` is not configured). Strips `X-Proxy-Secret` before forwarding to Kemnaker.
   - **Strict Domain Allowlist:** Only allows `https:` requests whose hostname is strictly in:
     - `maganghub.kemnaker.go.id`
     - `account.kemnaker.go.id`
     - `monev-api.maganghub.kemnaker.go.id`
     Also validates any `Location` redirect target against the same allowlist before wrapping it.
   - **No wildcard CORS:** Removes `Access-Control-Allow-Origin: *` since only the Vercel Python server calls the Worker server-to-server.
   - **Single Scheduled Trigger:** `wrangler.toml` defines `crons = ["0 10 * * 1-5"]` (17:00 WIB Mon–Fri). The `scheduled` handler checks WIB day-of-week (skips Sat/Sun), sends `POST ${env.VERCEL_DOMAIN}/api/cron` with `Authorization: Bearer ${env.CRON_SECRET}` header (never in URL), with 55s timeout and 1 retry on transient network/5xx errors.

### 5.4 API Contracts

| Endpoint | Method | Auth | Request | Response |
|---|---|---|---|---|
| `/api/auth` | `POST` | None (CSRF checked) | `{ "username": "...", "password": "..." }` | `200 { "ok": true, "user": { "name": "...", "mentor": "..." } }` + `Set-Cookie: monev_session=...` |
| `/api/auth` | `DELETE` | CSRF checked | None | `200 { "ok": true }` + expired `Set-Cookie` |
| `/api/status` | `GET` | `monev_session` cookie | None | `200 { "date": "YYYY-MM-DD", "time_wib": "HH:MM:SS", "user": { "name", "mentor" }, "today": { "submitted": bool, "submitted_at": str\|null, "approval_status": str\|null, "activity_log": str }, "recent": [...7 days], "coords": { "latitude", "longitude", "distance_m" }, "templates": { "remaining", "total" } }` |
| `/api/template` | `GET` | `monev_session` cookie | Optional `?coords_only=1` | `200 { "coords": { "latitude", "longitude", "distance_m" }, "template": { "id", "category", "activity", "learning", "obstacles" } \| null }` |
| `/api/submit` | `POST` | `monev_session` cookie + CSRF | `{ "activity": "...", "learning": "...", "obstacles": "...", "latitude"?: float, "longitude"?: float }` | `200 { "ok": true, "date": "...", "coords": { "latitude", "longitude", "distance_m" }, "message": "..." }` (or `409` if already submitted today, `400` if invalid/empty or >10m) |
| `/api/cron` | `POST` / `GET` | `Authorization: Bearer <CRON_SECRET>` | None | `200 { "status": "submitted" \| "already_submitted" \| "weekend_skipped", "date": "...", "template_id"?: int, "coords"?: {...} }` |

### 5.5 17:00 WIB Fallback Logic

1. Compute current WIB (`UTC+7`) date and weekday.
2. If Saturday (`5`) or Sunday (`6`), return `{"status": "weekend_skipped"}` immediately without contacting Kemnaker.
3. Log in to Kemnaker using `KEMNAKER_USERNAME` and `KEMNAKER_PASSWORD` env vars (via Cloudflare Worker if `CLOUDFLARE_WORKER_URL` is configured).
4. Call `GET /api/v1/attendances`; if today's date already exists, return `{"status": "already_submitted"}`.
5. Call `GET /api/v1/daily-logs?limit=100&page=1` and normalize the first 80 characters of each prior `activity_log`.
6. Load `templates.json`, filter out templates whose normalized 80-char `activity` prefix matches Kemnaker's history, and choose one at random using `random.choice(unused)` (if all templates were used, fall back to `random.choice(all_templates)`).
7. Generate coordinates strictly within 10m of the YIA pin via `lib/geo.py`.
8. Submit to `POST /api/v1/attendances/with-daily-log` with `status: "PRESENT"`, `is_reviewed: True`, and the chosen template fields.

### 5.6 Environment Variables

**Vercel Environment Variables:**
- `SESSION_SECRET` *(required, ≥32 random chars)* — Fernet key material for web session cookies.
- `CRON_SECRET` *(required, ≥16 random chars)* — Bearer token protecting `/api/cron`.
- `KEMNAKER_USERNAME` *(required for 17:00 WIB cron)* — SIAPkerja NIK/email used **only** by `/api/cron`.
- `KEMNAKER_PASSWORD` *(required for 17:00 WIB cron)* — SIAPkerja password used **only** by `/api/cron`.
- `ALLOWED_USERNAME` *(recommended)* — Locks web UI login to only this Kemnaker username.
- `CLOUDFLARE_WORKER_URL` *(required on Vercel)* — URL of the deployed Cloudflare Worker proxy.
- `PROXY_SECRET` *(required when `CLOUDFLARE_WORKER_URL` is set)* — Shared secret sent as `X-Proxy-Secret` header to the Worker.
- `OFFICE_LAT` *(optional, default `-7.9021141`)* — YIA Kantor PT Angkasa Pura Indonesia latitude.
- `OFFICE_LONG` *(optional, default `110.065129`)* — YIA Kantor PT Angkasa Pura Indonesia longitude.
- `OFFICE_RADIUS_METERS` *(optional, default `10`)* — Maximum coordinate jitter radius in meters.

**Cloudflare Worker Secrets/Variables:**
- `PROXY_SECRET` *(secret, must match Vercel)* — Authenticates proxy requests from Vercel.
- `CRON_SECRET` *(secret, must match Vercel)* — Sent as `Authorization: Bearer` to Vercel `/api/cron`.
- `VERCEL_DOMAIN` *(variable)* — Deployed Vercel origin (e.g., `https://your-app.vercel.app`).

### 5.7 Web UI Behavior (`public/`)

- **Login Screen:** Clean card with Kemnaker Username and Password inputs, submit spinner, clear error banner, no password saved in `localStorage`/`sessionStorage`.
- **Dashboard Screen:**
  - Top bar: Participant name, mentor name, Refresh button, Logout button.
  - **Today's Status Card:** Shows WIB date and either a warning badge (`Not submitted yet`) or success badge (`Submitted at HH:MM WIB`, approval status, and recorded activity text; disables submit form when already submitted).
  - **Location Card:** Displays auto-generated `latitude, longitude` and distance from the YIA office pin (e.g., `6.4m from Kantor PT Angkasa Pura YIA`) with a `Re-roll` button (calls `GET /api/template?coords_only=1`).
  - **Manual Attendance Form:** Three labeled textareas (`Activity`, `Learning`, `Obstacles`) with character counts, a secondary `Fill random template` button (calls `GET /api/template` and populates the fields so the user can review/edit before submitting), and primary `Submit Attendance` button with confirmation or clear loading/success feedback.
  - **Recent History (Last 7 Days):** Compact list of date, `PRESENT` badge, and mentor approval status (`APPROVED` / `SUBMITTED`).

## 6. Builder's Calls (Explicitly Left to Implementation)

- Exact visual palette, typography, spacing, and mobile breakpoint polish for `public/styles.css` (keep clean, accessible, high-contrast, mobile-first).
- Optional lightweight local dev server script (e.g., `dev_server.py`) so the user can run static files + `api/` handlers locally with Laragon Python 3.10 without needing Vercel CLI.
- Exact test mocking setup and fixtures under `tests/`.
- In-memory token caching inside `/api/cron` is unnecessary since the cron runs once per day; simple single-login per cron run is preferred to avoid stale state.
