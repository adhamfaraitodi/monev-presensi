from __future__ import annotations

import http.cookiejar
import json
import os
import random
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

from lib import config, geo, http_utils

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

SSO_INIT_URL = "https://maganghub.kemnaker.go.id/api/naco/login?redirect_url=/"
SSO_LOGIN_URL = "https://account.kemnaker.go.id/auth/login"
API_BASE = "https://monev-api.maganghub.kemnaker.go.id/api/v1"

DEFAULT_FALLBACK_TEMPLATE: dict = {
    "id": 1,
    "category": "default",
    "activity": "Melakukan penelusuran modul fungsional aplikasi serta dokumentasi teknis pendukung.",
    "learning": "Mempelajari alur integrasi sistem data dan prosedur validasi parameter operasional.",
    "obstacles": "Tidak ada kendala yang berarti, seluruh tugas berjalan dengan lancar.",
}


class KemnakerError(Exception):
    """Base error for Kemnaker SSO and API failures."""


class KemnakerAuthError(KemnakerError):
    """Raised when Kemnaker credentials are invalid or token is rejected (HTTP 401)."""


class AlreadySubmittedError(KemnakerError):
    """Raised when attendance for today has already been submitted."""


class SafeCookieJar(http.cookiejar.CookieJar):
    """CookieJar that drops WAF tracking cookie (acw_tc) across Kemnaker subdomains."""

    def set_cookie(self, cookie: http.cookiejar.Cookie) -> None:
        if cookie.name == "acw_tc":
            return
        super().set_cookie(cookie)


def wrap_proxy_url(target_url: str, proxy_url: str | None) -> str:
    clean_proxy = (proxy_url or "").strip().rstrip("/")
    if clean_proxy and clean_proxy not in target_url:
        return f"{clean_proxy}/?url={urllib.parse.quote(target_url, safe='')}"
    return target_url


def build_request_headers(
    base_headers: dict[str, str],
    proxy_url: str | None,
    proxy_secret: str | None,
) -> dict[str, str]:
    headers = dict(base_headers or {})
    clean_proxy = (proxy_url or "").strip()
    if clean_proxy:
        clean_secret = (proxy_secret or "").strip()
        if not clean_secret:
            raise config.ConfigError(
                "PROXY_SECRET is required when CLOUDFLARE_WORKER_URL is configured."
            )
        headers["X-Proxy-Secret"] = clean_secret
    return headers


def login_kemnaker(username: str, password: str) -> str:
    clean_user = (username or "").strip()
    clean_pass = password or ""
    if not clean_user or not clean_pass.strip():
        raise KemnakerAuthError("Username and password are required.")

    proxy_url, proxy_secret = config.get_proxy_config()
    cj = SafeCookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    browser_headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8",
    }

    try:
        req_init = urllib.request.Request(
            wrap_proxy_url(SSO_INIT_URL, proxy_url),
            headers=build_request_headers(browser_headers, proxy_url, proxy_secret),
        )
        res_init = opener.open(req_init, timeout=25)
        html_init = res_init.read().decode("utf-8", errors="ignore")
        csrf_match = re.search(r'name="csrf-token"\s+content="([^"]+)"', html_init)
        csrf = csrf_match.group(1) if csrf_match else ""
        referer_url = res_init.geturl()

        payload_login = json.dumps(
            {"username": clean_user, "password": clean_pass}
        ).encode("utf-8")
        login_headers = build_request_headers(
            {
                **browser_headers,
                "Content-Type": "application/json",
                "X-CSRF-TOKEN": csrf,
                "Origin": "https://account.kemnaker.go.id",
                "Referer": referer_url,
            },
            proxy_url,
            proxy_secret,
        )
        req_login = urllib.request.Request(
            wrap_proxy_url(SSO_LOGIN_URL, proxy_url),
            data=payload_login,
            headers=login_headers,
            method="POST",
        )
        res_login = opener.open(req_login, timeout=25)
        login_data = json.loads(res_login.read().decode("utf-8"))

        if not isinstance(login_data, dict) or not login_data.get("data", {}).get("authenticated"):
            msg = ""
            if isinstance(login_data, dict):
                msg = str(login_data.get("message") or login_data.get("error") or "Invalid credentials")
            raise KemnakerAuthError(
                http_utils.sanitize_error(
                    f"Authentication failed: {msg}",
                    secrets=(clean_pass, proxy_secret or ""),
                )
            )

        redirect_uri = login_data["data"].get("redirect_uri")
        if not redirect_uri:
            raise KemnakerAuthError("Authentication failed: missing redirect_uri.")

        req_cb = urllib.request.Request(
            wrap_proxy_url(str(redirect_uri), proxy_url),
            headers=build_request_headers(browser_headers, proxy_url, proxy_secret),
        )
        opener.open(req_cb, timeout=25)

        token = next((c.value for c in cj if c.name == "naco_access_token"), None)
        if not token:
            raise KemnakerAuthError("Failed to extract naco_access_token from Kemnaker SSO.")
        return token

    except KemnakerError:
        raise
    except config.ConfigError:
        raise
    except urllib.error.HTTPError as exc:
        body_text = ""
        try:
            body_text = exc.read().decode("utf-8", errors="ignore")
        except Exception:
            body_text = ""
        detail = http_utils.sanitize_error(
            f"HTTP {exc.code}: {body_text or exc.reason}",
            secrets=(clean_pass, proxy_secret or ""),
        )
        if exc.code in (401, 403, 422):
            raise KemnakerAuthError(detail) from None
        raise KemnakerError(detail) from None
    except Exception as exc:
        raise KemnakerError(
            http_utils.sanitize_error(exc, secrets=(clean_pass, proxy_secret or ""))
        ) from None


def api_call(
    endpoint: str,
    token: str,
    method: str = "GET",
    payload: dict | None = None,
) -> dict:
    clean_token = (token or "").strip()
    if not clean_token:
        raise KemnakerAuthError("Missing Kemnaker access token.")

    proxy_url, proxy_secret = config.get_proxy_config()
    base_headers: dict[str, str] = {
        "User-Agent": USER_AGENT,
        "Authorization": f"Bearer {clean_token}",
        "Accept": "application/json",
    }
    data_bytes = json.dumps(payload).encode("utf-8") if payload is not None else None
    if data_bytes is not None:
        base_headers["Content-Type"] = "application/json"

    headers = build_request_headers(base_headers, proxy_url, proxy_secret)
    req = urllib.request.Request(
        wrap_proxy_url(endpoint, proxy_url),
        data=data_bytes,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=25) as res:
            raw = res.read().decode("utf-8")
            parsed = json.loads(raw) if raw.strip() else {}
            return parsed if isinstance(parsed, dict) else {"data": parsed}
    except config.ConfigError:
        raise
    except urllib.error.HTTPError as exc:
        msg = f"HTTP {exc.code}: {exc.reason}"
        try:
            err_body = exc.read().decode("utf-8", errors="ignore")
            if err_body:
                err_data = json.loads(err_body)
                if isinstance(err_data, dict):
                    extracted = err_data.get("message") or err_data.get("error")
                    if extracted:
                        msg = f"{exc.code}: {extracted}"
        except Exception:
            pass
        clean_msg = http_utils.sanitize_error(
            msg,
            secrets=(clean_token, proxy_secret or ""),
        )
        if exc.code == 401:
            raise KemnakerAuthError(clean_msg) from None
        raise KemnakerError(clean_msg) from None
    except Exception as exc:
        raise KemnakerError(
            http_utils.sanitize_error(exc, secrets=(clean_token, proxy_secret or ""))
        ) from None


def _extract_submitted_time(attendance_item: dict) -> str | None:
    created_at = str(attendance_item.get("created_at") or "").strip()
    if "T" in created_at:
        return created_at.split("T", 1)[1][:8]
    if " " in created_at:
        return created_at.split(" ", 1)[1][:8]
    return created_at or None


def fetch_dashboard_state(
    token: str,
    today_wib: datetime | None = None,
) -> dict:
    now_wib = today_wib.astimezone(config.WIB) if today_wib else datetime.now(config.WIB)
    today_str = now_wib.strftime("%Y-%m-%d")
    time_str = now_wib.strftime("%H:%M:%S")

    me_res = api_call(f"{API_BASE}/users/me", token)
    me_data = me_res.get("data") if isinstance(me_res, dict) else {}
    if not isinstance(me_data, dict):
        me_data = {}

    att_res = api_call(f"{API_BASE}/attendances", token)
    attendances = att_res.get("data") if isinstance(att_res, dict) else []
    if not isinstance(attendances, list):
        attendances = []

    sorted_att = sorted(
        (item for item in attendances if isinstance(item, dict)),
        key=lambda x: str(x.get("date") or ""),
        reverse=True,
    )

    today_item: dict | None = None
    for item in sorted_att:
        d_str = str(item.get("date") or "")
        if d_str == today_str or d_str.startswith(today_str):
            today_item = item
            break

    activity_log: str | None = None
    if today_item is not None:
        try:
            logs_res = api_call(f"{API_BASE}/daily-logs?date={today_str}", token)
            logs_data = logs_res.get("data") if isinstance(logs_res, dict) else []
            if isinstance(logs_data, list) and logs_data and isinstance(logs_data[0], dict):
                activity_log = str(logs_data[0].get("activity_log") or "") or None
        except KemnakerAuthError:
            raise
        except Exception:
            activity_log = None

    recent = [
        {
            "date": str(item.get("date") or "")[:10],
            "status": str(item.get("status") or ""),
            "approval_status": str(item.get("approval_status") or ""),
        }
        for item in sorted_att[:7]
    ]

    return {
        "date": today_str,
        "time_wib": time_str,
        "user": {
            "name": str(me_data.get("name") or "-"),
            "mentor": str(me_data.get("mentor_name") or "-"),
        },
        "today": {
            "submitted": today_item is not None,
            "submitted_at": _extract_submitted_time(today_item) if today_item else None,
            "approval_status": str(today_item.get("approval_status") or "SUBMITTED") if today_item else None,
            "activity_log": activity_log,
        },
        "recent": recent,
    }


def load_templates(path: str | None = None) -> list[dict]:
    if path is None:
        root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(root_dir, "templates.json")
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    valid = [t for t in data if isinstance(t, dict) and t.get("activity")]
                    if valid:
                        return valid
    except Exception:
        pass
    return [dict(DEFAULT_FALLBACK_TEMPLATE)]


def _normalize_snippet(text: object) -> str:
    return str(text or "").strip().lower()[:80]


def pick_random_unused_template(
    token: str,
    templates: list[dict] | None = None,
    rng: random.Random | None = None,
) -> tuple[dict, int, int]:
    pool = list(templates) if templates is not None else load_templates()
    if not pool:
        pool = [dict(DEFAULT_FALLBACK_TEMPLATE)]
    total = len(pool)
    rand = rng if rng is not None else random.SystemRandom()

    used_snippets: set[str] = set()
    if token:
        logs_res = api_call(f"{API_BASE}/daily-logs?limit=100&page=1", token)
        logs_data = logs_res.get("data") if isinstance(logs_res, dict) else []
        if isinstance(logs_data, list):
            for item in logs_data:
                if isinstance(item, dict):
                    snippet = _normalize_snippet(item.get("activity_log"))
                    if snippet:
                        used_snippets.add(snippet)

    unused = [
        t for t in pool
        if _normalize_snippet(t.get("activity")) not in used_snippets
    ]
    remaining = len(unused)
    if unused:
        return (rand.choice(unused), remaining, total)
    return (rand.choice(pool), 0, total)


def submit_attendance(
    token: str,
    activity: str,
    learning: str,
    obstacles: str,
    lat: float | None = None,
    lon: float | None = None,
    today_wib: datetime | None = None,
) -> dict:
    clean_activity = str(activity if activity is not None else "").strip()
    clean_learning = str(learning if learning is not None else "").strip()
    clean_obstacles = str(obstacles if obstacles is not None else "").strip()

    if not clean_activity or not clean_learning or not clean_obstacles:
        raise ValueError("Activity, learning, and obstacles must not be blank.")

    if lat is None and lon is None:
        coords = geo.generate_office_coordinates()
    elif lat is not None and lon is not None:
        coords = geo.validate_office_coordinates(lat, lon)
    else:
        raise ValueError("Both latitude and longitude must be provided together.")

    now_wib = today_wib.astimezone(config.WIB) if today_wib else datetime.now(config.WIB)
    today_str = now_wib.strftime("%Y-%m-%d")

    att_res = api_call(f"{API_BASE}/attendances", token)
    attendances = att_res.get("data") if isinstance(att_res, dict) else []
    if isinstance(attendances, list):
        for item in attendances:
            if isinstance(item, dict):
                d_str = str(item.get("date") or "")
                if d_str == today_str or d_str.startswith(today_str):
                    raise AlreadySubmittedError(
                        f"Attendance for {today_str} has already been submitted."
                    )

    payload = {
        "date": today_str,
        "status": "PRESENT",
        "latitude": coords["latitude"],
        "longitude": coords["longitude"],
        "activity_log": clean_activity,
        "lesson_learned": clean_learning,
        "obstacles": clean_obstacles,
        "is_reviewed": True,
    }
    res = api_call(
        f"{API_BASE}/attendances/with-daily-log",
        token,
        method="POST",
        payload=payload,
    )
    msg = "Attendance submitted successfully."
    if isinstance(res, dict) and res.get("message"):
        msg = str(res["message"])

    return {
        "date": today_str,
        "coords": coords,
        "message": msg,
        "response": res,
    }
