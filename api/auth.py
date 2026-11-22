from __future__ import annotations

from http.server import BaseHTTPRequestHandler
import os
import sys

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from lib import config, http_utils, kemnaker, session


def _extract_host(headers: object) -> str | None:
    if hasattr(headers, "get"):
        val = headers.get("Host") or headers.get("host")
        if val is not None:
            return str(val)
    return None


def handle_post(
    headers: object,
    rfile,
) -> tuple[int, dict, list[tuple[str, str]]]:
    host = _extract_host(headers)
    secure = not http_utils.is_local_host(host)

    if not http_utils.verify_csrf(headers, host):
        return (403, {"error": "Forbidden: Cross-site request blocked."}, [])

    body, err = http_utils.read_json_body(rfile, headers)
    if err or body is None:
        return (400, {"error": err or "Invalid request payload."}, [])

    raw_username = body.get("username")
    raw_password = body.get("password")
    username = str(raw_username if raw_username is not None else "").strip()
    password = str(raw_password if raw_password is not None else "")

    if not username or not password.strip():
        return (400, {"error": "Username and password are required."}, [])

    token = ""
    try:
        allowed_username = config.get_allowed_username()
        if allowed_username is not None:
            if not http_utils.constant_time_equals(username.lower(), allowed_username):
                return (403, {"error": "Forbidden: Username is not authorized."}, [])

        token = kemnaker.login_kemnaker(username, password)
        me_res = kemnaker.api_call(f"{kemnaker.API_BASE}/users/me", token)
        me_data = me_res.get("data") if isinstance(me_res, dict) else {}
        if not isinstance(me_data, dict):
            me_data = {}

        user_info = {
            "name": str(me_data.get("name") or "-"),
            "mentor": str(me_data.get("mentor_name") or "-"),
        }

        cookie_val = session.encrypt_session(token, username)
        set_cookie = session.build_session_cookie(cookie_val, secure=secure)
        return (
            200,
            {"ok": True, "user": user_info},
            [("Set-Cookie", set_cookie)],
        )

    except config.ConfigError as exc:
        return (
            503,
            {"error": http_utils.sanitize_error(exc, secrets=(password, token))},
            [],
        )
    except kemnaker.KemnakerAuthError as exc:
        return (
            401,
            {"error": http_utils.sanitize_error(exc, secrets=(password, token))},
            [],
        )
    except kemnaker.AlreadySubmittedError as exc:
        return (
            409,
            {"error": http_utils.sanitize_error(exc, secrets=(password, token))},
            [],
        )
    except ValueError as exc:
        return (
            400,
            {"error": http_utils.sanitize_error(exc, secrets=(password, token))},
            [],
        )
    except Exception as exc:
        return (
            500,
            {"error": http_utils.sanitize_error(exc, secrets=(password, token))},
            [],
        )


def handle_delete(
    headers: object,
) -> tuple[int, dict, list[tuple[str, str]]]:
    host = _extract_host(headers)
    secure = not http_utils.is_local_host(host)

    if not http_utils.verify_csrf(headers, host):
        return (403, {"error": "Forbidden: Cross-site request blocked."}, [])

    clear_cookie = session.build_clear_session_cookie(secure=secure)
    return (200, {"ok": True}, [("Set-Cookie", clear_cookie)])


class handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        status, payload, extra_headers = handle_post(self.headers, self.rfile)
        http_utils.send_json(self, status, payload, extra_headers=extra_headers)

    def do_DELETE(self) -> None:
        status, payload, extra_headers = handle_delete(self.headers)
        http_utils.send_json(self, status, payload, extra_headers=extra_headers)

    def log_message(self, format: str, *args) -> None:
        return
