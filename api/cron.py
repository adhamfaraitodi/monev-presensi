from __future__ import annotations

from datetime import datetime
from http.server import BaseHTTPRequestHandler
import os
import sys

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from lib import config, http_utils, kemnaker


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


def _now_wib() -> datetime:
    return datetime.now(config.WIB)


def _run_cron(
    headers: object,
) -> tuple[int, dict, list[tuple[str, str]]]:
    secrets_to_redact: list[str] = []
    try:
        cron_secret = config.get_cron_secret()
        secrets_to_redact.append(cron_secret)

        auth_header = (_extract_header(headers, "Authorization") or "").strip()
        if not auth_header.startswith("Bearer "):
            return (401, {"error": "Unauthorized: Valid Bearer token required."}, [])
        provided_token = auth_header[len("Bearer "):].strip()
        if not http_utils.constant_time_equals(provided_token, cron_secret):
            return (401, {"error": "Unauthorized: Invalid Bearer token."}, [])

        now_wib = _now_wib()
        today_str = now_wib.strftime("%Y-%m-%d")

        if now_wib.weekday() >= 5:
            return (
                200,
                {
                    "status": "weekend_skipped",
                    "date": today_str,
                },
                [],
            )

        username, password = config.get_cron_credentials()
        secrets_to_redact.append(password)

        token = kemnaker.login_kemnaker(username, password)
        secrets_to_redact.append(token)

        state = kemnaker.fetch_dashboard_state(token, today_wib=now_wib)
        if state.get("today", {}).get("submitted"):
            return (
                200,
                {
                    "status": "already_submitted",
                    "date": today_str,
                },
                [],
            )

        chosen, _, _ = kemnaker.pick_random_unused_template(token)
        try:
            res = kemnaker.submit_attendance(
                token,
                chosen["activity"],
                chosen["learning"],
                chosen["obstacles"],
                today_wib=now_wib,
            )
        except kemnaker.AlreadySubmittedError:
            return (
                200,
                {
                    "status": "already_submitted",
                    "date": today_str,
                },
                [],
            )

        return (
            200,
            {
                "status": "submitted",
                "date": res["date"],
                "template_id": chosen.get("id"),
                "coords": res["coords"],
            },
            [],
        )

    except config.ConfigError as exc:
        return (
            503,
            {"error": http_utils.sanitize_error(exc, secrets=tuple(secrets_to_redact))},
            [],
        )
    except kemnaker.KemnakerAuthError as exc:
        return (
            401,
            {"error": http_utils.sanitize_error(exc, secrets=tuple(secrets_to_redact))},
            [],
        )
    except kemnaker.AlreadySubmittedError as exc:
        return (
            409,
            {"error": http_utils.sanitize_error(exc, secrets=tuple(secrets_to_redact))},
            [],
        )
    except ValueError as exc:
        return (
            400,
            {"error": http_utils.sanitize_error(exc, secrets=tuple(secrets_to_redact))},
            [],
        )
    except Exception as exc:
        return (
            500,
            {"error": http_utils.sanitize_error(exc, secrets=tuple(secrets_to_redact))},
            [],
        )


def handle_post(headers: object) -> tuple[int, dict, list[tuple[str, str]]]:
    return _run_cron(headers)


def handle_get(headers: object) -> tuple[int, dict, list[tuple[str, str]]]:
    return _run_cron(headers)


class handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        status_code, payload, extra_headers = _run_cron(self.headers)
        http_utils.send_json(self, status_code, payload, extra_headers=extra_headers)

    def do_GET(self) -> None:
        status_code, payload, extra_headers = _run_cron(self.headers)
        http_utils.send_json(self, status_code, payload, extra_headers=extra_headers)

    def log_message(self, format: str, *args) -> None:
        return
