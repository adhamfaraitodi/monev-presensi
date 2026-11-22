from __future__ import annotations

from http.server import BaseHTTPRequestHandler
import os
import sys

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from lib import config, http_utils, kemnaker, session


def _extract_header(headers: object, name: str) -> str | None:
    target = name.lower()
    if hasattr(headers, "items"):
        for k, v in headers.items():
            if str(k).lower() == target:
                return str(v) if v is not None else None
    if hasattr(headers, "get"):
        val = headers.get(name) or headers.get(target)
        if val is not None:
            return str(val)
    return None


def handle_post(
    headers: object,
    rfile,
) -> tuple[int, dict, list[tuple[str, str]]]:
    host = _extract_header(headers, "Host")
    secure = not http_utils.is_local_host(host)
    token = ""

    if not http_utils.verify_csrf(headers, host):
        return (403, {"error": "Forbidden: Cross-site request blocked."}, [])

    try:
        cookie_header = _extract_header(headers, "Cookie")
        cookies = session.parse_cookies(cookie_header)
        raw_cookie = cookies.get(session.SESSION_COOKIE_NAME)
        sess = session.decrypt_session(raw_cookie)
        if not sess or not sess.get("token"):
            return (401, {"error": "Unauthorized: Valid session required."}, [])

        token = str(sess["token"])
        body, err = http_utils.read_json_body(rfile, headers)
        if err or body is None:
            return (400, {"error": err or "Invalid request payload."}, [])

        activity = body.get("activity")
        learning = body.get("learning")
        obstacles = body.get("obstacles")
        lat = body.get("latitude")
        lon = body.get("longitude")

        res = kemnaker.submit_attendance(
            token,
            activity,
            learning,
            obstacles,
            lat=lat,
            lon=lon,
        )

        return (
            200,
            {
                "ok": True,
                "date": res["date"],
                "coords": res["coords"],
                "message": res["message"],
            },
            [],
        )

    except config.ConfigError as exc:
        return (
            503,
            {"error": http_utils.sanitize_error(exc, secrets=(token,))},
            [],
        )
    except kemnaker.KemnakerAuthError as exc:
        clear_cookie = session.build_clear_session_cookie(secure=secure)
        return (
            401,
            {"error": http_utils.sanitize_error(exc, secrets=(token,))},
            [("Set-Cookie", clear_cookie)],
        )
    except kemnaker.AlreadySubmittedError as exc:
        return (
            409,
            {"error": http_utils.sanitize_error(exc, secrets=(token,))},
            [],
        )
    except ValueError as exc:
        return (
            400,
            {"error": http_utils.sanitize_error(exc, secrets=(token,))},
            [],
        )
    except Exception as exc:
        return (
            500,
            {"error": http_utils.sanitize_error(exc, secrets=(token,))},
            [],
        )


class handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        status_code, payload, extra_headers = handle_post(self.headers, self.rfile)
        http_utils.send_json(self, status_code, payload, extra_headers=extra_headers)

    def log_message(self, format: str, *args) -> None:
        return
