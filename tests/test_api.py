import io
import json
import os
import unittest
from datetime import datetime
from email.message import Message
from unittest.mock import patch

from lib import config, kemnaker, session

from api import auth as api_auth
from api import cron as api_cron
from api import status as api_status
from api import submit as api_submit
from api import template as api_template

TEST_SESSION_SECRET = "s" * 36
TEST_CRON_SECRET = "c" * 24


def invoke_handler(
    handler_cls,
    method: str = "GET",
    path: str = "/",
    headers: dict | None = None,
    body: dict | bytes | str | None = None,
) -> tuple[int, dict[str, str], list[tuple[str, str]], dict]:
    raw_body = b""
    hdr_dict = dict(headers or {})
    if isinstance(body, dict):
        raw_body = json.dumps(body).encode("utf-8")
        hdr_dict.setdefault("Content-Type", "application/json")
        hdr_dict.setdefault("Content-Length", str(len(raw_body)))
    elif isinstance(body, str):
        raw_body = body.encode("utf-8")
        hdr_dict.setdefault("Content-Length", str(len(raw_body)))
    elif isinstance(body, bytes):
        raw_body = body
        hdr_dict.setdefault("Content-Length", str(len(raw_body)))

    hdr_dict.setdefault("Host", "monev.example.com")

    msg = Message()
    for k, v in hdr_dict.items():
        msg[k] = str(v)

    inst = handler_cls.__new__(handler_cls)
    inst.command = method.upper()
    inst.path = path
    inst.headers = msg
    inst.rfile = io.BytesIO(raw_body)
    inst.wfile = io.BytesIO()
    inst.requestline = f"{method.upper()} {path} HTTP/1.1"
    inst.request_version = "HTTP/1.1"
    inst.client_address = ("127.0.0.1", 12345)

    captured_status = [200]
    captured_headers: list[tuple[str, str]] = []

    def send_response(code, message=None):
        captured_status[0] = code

    def send_header(key, value):
        captured_headers.append((key, value))

    def end_headers():
        pass

    inst.send_response = send_response
    inst.send_header = send_header
    inst.end_headers = end_headers

    fn = getattr(inst, f"do_{method.upper()}")
    fn()

    raw_out = inst.wfile.getvalue().decode("utf-8")
    parsed_out = json.loads(raw_out) if raw_out.strip() else {}
    flat_headers = {k: v for k, v in captured_headers}
    return (captured_status[0], flat_headers, captured_headers, parsed_out)


class TestApiEndpoints(unittest.TestCase):
    def setUp(self):
        self.base_env = {
            "SESSION_SECRET": TEST_SESSION_SECRET,
            "CRON_SECRET": TEST_CRON_SECRET,
        }

    def _make_cookie_header(self, token: str = "naco-tok-123", user: str = "owner@mail.com") -> str:
        encrypted = session.encrypt_session(token, user, secret=TEST_SESSION_SECRET)
        return f"monev_session={encrypted}"

    # 1. POST /api/auth & DELETE /api/auth
    def test_auth_post_cross_origin_rejected_403(self):
        with patch.dict(os.environ, self.base_env, clear=True):
            code, _, _, data = invoke_handler(
                api_auth.handler,
                method="POST",
                path="/api/auth",
                headers={
                    "Host": "monev.example.com",
                    "Origin": "https://evil.com",
                    "Sec-Fetch-Site": "cross-site",
                },
                body={"username": "owner@mail.com", "password": "pw"},
            )
        self.assertEqual(code, 403)
        self.assertIn("error", data)

    def test_auth_post_allowed_username_mismatch_blocks_before_kemnaker_login(self):
        env = {**self.base_env, "ALLOWED_USERNAME": "owner@mail.com"}
        with patch.dict(os.environ, env, clear=True), patch("lib.kemnaker.login_kemnaker") as mock_login:
            code, _, _, data = invoke_handler(
                api_auth.handler,
                method="POST",
                path="/api/auth",
                headers={
                    "Host": "monev.example.com",
                    "Origin": "https://monev.example.com",
                    "Sec-Fetch-Site": "same-origin",
                },
                body={"username": "other@mail.com", "password": "pw"},
            )
            self.assertEqual(code, 403)
            self.assertIn("error", data)
            mock_login.assert_not_called()

    def test_auth_post_valid_login_sets_cookie_and_returns_user(self):
        with patch.dict(os.environ, self.base_env, clear=True), patch(
            "lib.kemnaker.login_kemnaker", return_value="naco-tok-xyz"
        ) as mock_login, patch(
            "lib.kemnaker.api_call",
            return_value={"data": {"name": "Ade", "mentor_name": "Budi"}},
        ) as mock_api:
            code, hdrs, _, data = invoke_handler(
                api_auth.handler,
                method="POST",
                path="/api/auth",
                headers={
                    "Host": "monev.example.com",
                    "Origin": "https://monev.example.com",
                    "Sec-Fetch-Site": "same-origin",
                },
                body={"username": "owner@mail.com", "password": "secret-password"},
            )
        self.assertEqual(code, 200)
        self.assertTrue(data.get("ok"))
        self.assertEqual(data.get("user"), {"name": "Ade", "mentor": "Budi"})
        self.assertNotIn("secret-password", json.dumps(data))
        self.assertNotIn("naco-tok-xyz", json.dumps(data))
        cookie = hdrs.get("Set-Cookie", "")
        self.assertIn("monev_session=", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertIn("Secure", cookie)
        mock_login.assert_called_once_with("owner@mail.com", "secret-password")
        mock_api.assert_called_once()

    def test_auth_delete_clears_cookie_and_enforces_csrf(self):
        with patch.dict(os.environ, self.base_env, clear=True):
            code_csrf, _, _, _ = invoke_handler(
                api_auth.handler,
                method="DELETE",
                path="/api/auth",
                headers={
                    "Host": "monev.example.com",
                    "Origin": "https://evil.com",
                    "Sec-Fetch-Site": "cross-site",
                },
            )
            code, hdrs, _, data = invoke_handler(
                api_auth.handler,
                method="DELETE",
                path="/api/auth",
                headers={
                    "Host": "monev.example.com",
                    "Origin": "https://monev.example.com",
                    "Sec-Fetch-Site": "same-origin",
                },
            )
        self.assertEqual(code_csrf, 403)
        self.assertEqual(code, 200)
        self.assertEqual(data, {"ok": True})
        cookie = hdrs.get("Set-Cookie", "")
        self.assertIn("monev_session=", cookie)
        self.assertIn("Max-Age=0", cookie)

    # 2. GET /api/status
    def test_status_missing_cookie_returns_401_even_when_env_credentials_exist(self):
        env = {
            **self.base_env,
            "KEMNAKER_USERNAME": "cron_user@mail.com",
            "KEMNAKER_PASSWORD": "cron_password",
        }
        with patch.dict(os.environ, env, clear=True), patch("lib.kemnaker.login_kemnaker") as mock_login:
            code, _, _, data = invoke_handler(
                api_status.handler,
                method="GET",
                path="/api/status",
            )
            self.assertEqual(code, 401)
            self.assertIn("error", data)
            mock_login.assert_not_called()

    def test_status_kemnaker_auth_error_returns_401_and_clears_cookie(self):
        with patch.dict(os.environ, self.base_env, clear=True), patch(
            "lib.kemnaker.fetch_dashboard_state",
            side_effect=kemnaker.KemnakerAuthError("Token expired"),
        ):
            code, hdrs, _, data = invoke_handler(
                api_status.handler,
                method="GET",
                path="/api/status",
                headers={"Cookie": self._make_cookie_header()},
            )
        self.assertEqual(code, 401)
        self.assertIn("error", data)
        cookie = hdrs.get("Set-Cookie", "")
        self.assertIn("monev_session=", cookie)
        self.assertIn("Max-Age=0", cookie)

    def test_status_valid_cookie_happy_path(self):
        fake_state = {
            "date": "2026-11-23",
            "time_wib": "14:05:12",
            "user": {"name": "Ade", "mentor": "Budi"},
            "today": {
                "submitted": True,
                "submitted_at": "08:12:40",
                "approval_status": "APPROVED",
                "activity_log": "Testing API",
            },
            "recent": [
                {"date": "2026-11-23", "status": "PRESENT", "approval_status": "APPROVED"}
            ],
        }
        fake_tpl = {
            "id": 12,
            "category": "dev",
            "activity": "A",
            "learning": "L",
            "obstacles": "O",
        }
        with patch.dict(os.environ, self.base_env, clear=True), patch(
            "lib.kemnaker.fetch_dashboard_state", return_value=fake_state
        ), patch(
            "lib.kemnaker.pick_random_unused_template", return_value=(fake_tpl, 24, 30)
        ):
            code, _, _, data = invoke_handler(
                api_status.handler,
                method="GET",
                path="/api/status",
                headers={"Cookie": self._make_cookie_header()},
            )
        self.assertEqual(code, 200)
        self.assertEqual(data["date"], "2026-11-23")
        self.assertEqual(data["time_wib"], "14:05:12")
        self.assertEqual(data["user"], {"name": "Ade", "mentor": "Budi"})
        self.assertEqual(data["today"]["submitted"], True)
        self.assertEqual(len(data["recent"]), 1)
        self.assertIn("coords", data)
        self.assertLessEqual(data["coords"]["distance_m"], 10.0)
        self.assertEqual(data["templates"], {"remaining": 24, "total": 30})

    # 3. GET /api/template
    def test_template_missing_cookie_returns_401(self):
        with patch.dict(os.environ, self.base_env, clear=True):
            code, _, _, _ = invoke_handler(
                api_template.handler,
                method="GET",
                path="/api/template",
            )
        self.assertEqual(code, 401)

    def test_template_coords_only_skips_kemnaker_api(self):
        with patch.dict(os.environ, self.base_env, clear=True), patch(
            "lib.kemnaker.pick_random_unused_template"
        ) as mock_pick:
            code, _, _, data = invoke_handler(
                api_template.handler,
                method="GET",
                path="/api/template?coords_only=1",
                headers={"Cookie": self._make_cookie_header()},
            )
            self.assertEqual(code, 200)
            self.assertIsNone(data["template"])
            self.assertIn("coords", data)
            self.assertLessEqual(data["coords"]["distance_m"], 10.0)
            mock_pick.assert_not_called()

    def test_template_default_returns_random_unused_template_and_coords(self):
        fake_tpl = {
            "id": 7,
            "category": "backend",
            "activity": "Act 7",
            "learning": "Learn 7",
            "obstacles": "Obs 7",
        }
        with patch.dict(os.environ, self.base_env, clear=True), patch(
            "lib.kemnaker.pick_random_unused_template", return_value=(fake_tpl, 19, 30)
        ):
            code, _, _, data = invoke_handler(
                api_template.handler,
                method="GET",
                path="/api/template",
                headers={"Cookie": self._make_cookie_header()},
            )
        self.assertEqual(code, 200)
        self.assertIn("coords", data)
        self.assertLessEqual(data["coords"]["distance_m"], 10.0)
        self.assertEqual(data["template"], fake_tpl)
        self.assertEqual(data["templates"], {"remaining": 19, "total": 30})

    def test_template_kemnaker_auth_error_returns_401_and_clears_cookie(self):
        with patch.dict(os.environ, self.base_env, clear=True), patch(
            "lib.kemnaker.pick_random_unused_template",
            side_effect=kemnaker.KemnakerAuthError("Expired token"),
        ):
            code, hdrs, _, _ = invoke_handler(
                api_template.handler,
                method="GET",
                path="/api/template",
                headers={"Cookie": self._make_cookie_header()},
            )
        self.assertEqual(code, 401)
        self.assertIn("Max-Age=0", hdrs.get("Set-Cookie", ""))

    # 4. POST /api/submit
    def test_submit_missing_cookie_returns_401(self):
        with patch.dict(os.environ, self.base_env, clear=True):
            code, _, _, _ = invoke_handler(
                api_submit.handler,
                method="POST",
                path="/api/submit",
                headers={
                    "Host": "monev.example.com",
                    "Origin": "https://monev.example.com",
                    "Sec-Fetch-Site": "same-origin",
                },
                body={"activity": "A", "learning": "L", "obstacles": "O"},
            )
        self.assertEqual(code, 401)

    def test_submit_cross_site_csrf_returns_403(self):
        with patch.dict(os.environ, self.base_env, clear=True):
            code, _, _, _ = invoke_handler(
                api_submit.handler,
                method="POST",
                path="/api/submit",
                headers={
                    "Host": "monev.example.com",
                    "Origin": "https://evil.example.com",
                    "Sec-Fetch-Site": "cross-site",
                    "Cookie": self._make_cookie_header(),
                },
                body={"activity": "A", "learning": "L", "obstacles": "O"},
            )
        self.assertEqual(code, 403)

    def test_submit_blank_fields_returns_400(self):
        with patch.dict(os.environ, self.base_env, clear=True):
            code, _, _, data = invoke_handler(
                api_submit.handler,
                method="POST",
                path="/api/submit",
                headers={
                    "Host": "monev.example.com",
                    "Origin": "https://monev.example.com",
                    "Sec-Fetch-Site": "same-origin",
                    "Cookie": self._make_cookie_header(),
                },
                body={"activity": "   ", "learning": "L", "obstacles": "O"},
            )
        self.assertEqual(code, 400)
        self.assertIn("error", data)

    def test_submit_coordinates_out_of_range_returns_400(self):
        with patch.dict(os.environ, self.base_env, clear=True):
            code, _, _, data = invoke_handler(
                api_submit.handler,
                method="POST",
                path="/api/submit",
                headers={
                    "Host": "monev.example.com",
                    "Origin": "https://monev.example.com",
                    "Sec-Fetch-Site": "same-origin",
                    "Cookie": self._make_cookie_header(),
                },
                body={
                    "activity": "Valid act",
                    "learning": "Valid learn",
                    "obstacles": "Valid obs",
                    "latitude": 0.0,
                    "longitude": 0.0,
                },
            )
        self.assertEqual(code, 400)
        self.assertIn("error", data)

    def test_submit_already_submitted_returns_409(self):
        with patch.dict(os.environ, self.base_env, clear=True), patch(
            "lib.kemnaker.submit_attendance",
            side_effect=kemnaker.AlreadySubmittedError("Already submitted today"),
        ):
            code, _, _, data = invoke_handler(
                api_submit.handler,
                method="POST",
                path="/api/submit",
                headers={
                    "Host": "monev.example.com",
                    "Origin": "https://monev.example.com",
                    "Sec-Fetch-Site": "same-origin",
                    "Cookie": self._make_cookie_header(),
                },
                body={"activity": "A", "learning": "L", "obstacles": "O"},
            )
        self.assertEqual(code, 409)
        self.assertIn("error", data)

    def test_submit_kemnaker_auth_error_returns_401_and_clears_cookie(self):
        with patch.dict(os.environ, self.base_env, clear=True), patch(
            "lib.kemnaker.submit_attendance",
            side_effect=kemnaker.KemnakerAuthError("Expired session"),
        ):
            code, hdrs, _, _ = invoke_handler(
                api_submit.handler,
                method="POST",
                path="/api/submit",
                headers={
                    "Host": "monev.example.com",
                    "Origin": "https://monev.example.com",
                    "Sec-Fetch-Site": "same-origin",
                    "Cookie": self._make_cookie_header(),
                },
                body={"activity": "A", "learning": "L", "obstacles": "O"},
            )
        self.assertEqual(code, 401)
        self.assertIn("Max-Age=0", hdrs.get("Set-Cookie", ""))

    def test_submit_valid_returns_200(self):
        fake_res = {
            "date": "2026-11-23",
            "coords": {"latitude": -7.902112, "longitude": 110.065128, "distance_m": 2.41},
            "message": "Attendance submitted successfully.",
            "response": {"status": "ok"},
        }
        with patch.dict(os.environ, self.base_env, clear=True), patch(
            "lib.kemnaker.submit_attendance", return_value=fake_res
        ) as mock_submit:
            code, _, _, data = invoke_handler(
                api_submit.handler,
                method="POST",
                path="/api/submit",
                headers={
                    "Host": "monev.example.com",
                    "Origin": "https://monev.example.com",
                    "Sec-Fetch-Site": "same-origin",
                    "Cookie": self._make_cookie_header(),
                },
                body={
                    "activity": "A",
                    "learning": "L",
                    "obstacles": "O",
                    "latitude": -7.902112,
                    "longitude": 110.065128,
                },
            )
        self.assertEqual(code, 200)
        self.assertEqual(
            data,
            {
                "ok": True,
                "date": "2026-11-23",
                "coords": {"latitude": -7.902112, "longitude": 110.065128, "distance_m": 2.41},
                "message": "Attendance submitted successfully.",
            },
        )
        mock_submit.assert_called_once_with(
            "naco-tok-123",
            "A",
            "L",
            "O",
            lat=-7.902112,
            lon=110.065128,
        )

    # 5. POST /api/cron & GET /api/cron
    def test_cron_unset_secret_returns_503(self):
        with patch.dict(os.environ, {"SESSION_SECRET": TEST_SESSION_SECRET}, clear=True):
            code, _, _, data = invoke_handler(
                api_cron.handler,
                method="POST",
                path="/api/cron",
                headers={"Authorization": f"Bearer {TEST_CRON_SECRET}"},
            )
        self.assertEqual(code, 503)
        self.assertIn("error", data)

    def test_cron_query_param_secret_without_bearer_header_rejected_401(self):
        with patch.dict(os.environ, self.base_env, clear=True):
            code_get, _, _, _ = invoke_handler(
                api_cron.handler,
                method="GET",
                path=f"/api/cron?secret={TEST_CRON_SECRET}",
            )
            code_post, _, _, _ = invoke_handler(
                api_cron.handler,
                method="POST",
                path=f"/api/cron?secret={TEST_CRON_SECRET}",
            )
        self.assertEqual(code_get, 401)
        self.assertEqual(code_post, 401)

    def test_cron_valid_bearer_on_saturday_skips_weekend_without_login(self):
        saturday_wib = datetime(2026, 11, 21, 17, 0, 0, tzinfo=config.WIB)  # 2026-11-21 is Saturday
        with patch.dict(os.environ, self.base_env, clear=True), patch(
            "api.cron._now_wib", return_value=saturday_wib
        ), patch("lib.kemnaker.login_kemnaker") as mock_login:
            code, _, _, data = invoke_handler(
                api_cron.handler,
                method="POST",
                path="/api/cron",
                headers={"Authorization": f"Bearer {TEST_CRON_SECRET}"},
            )
            self.assertEqual(code, 200)
            self.assertEqual(data["status"], "weekend_skipped")
            self.assertEqual(data["date"], "2026-11-21")
            mock_login.assert_not_called()

    def test_cron_valid_bearer_on_weekday_already_submitted(self):
        monday_wib = datetime(2026, 11, 23, 17, 0, 0, tzinfo=config.WIB)  # 2026-11-23 is Monday
        env = {
            **self.base_env,
            "KEMNAKER_USERNAME": "cron@mail.com",
            "KEMNAKER_PASSWORD": "cron_password",
        }
        fake_state = {
            "date": "2026-11-23",
            "today": {"submitted": True},
        }
        with patch.dict(os.environ, env, clear=True), patch(
            "api.cron._now_wib", return_value=monday_wib
        ), patch("lib.kemnaker.login_kemnaker", return_value="cron-tok") as mock_login, patch(
            "lib.kemnaker.fetch_dashboard_state", return_value=fake_state
        ), patch("lib.kemnaker.submit_attendance") as mock_submit:
            code, _, _, data = invoke_handler(
                api_cron.handler,
                method="GET",
                path="/api/cron",
                headers={"Authorization": f"Bearer {TEST_CRON_SECRET}"},
            )
            self.assertEqual(code, 200)
            self.assertEqual(data, {"status": "already_submitted", "date": "2026-11-23"})
            mock_login.assert_called_once_with("cron@mail.com", "cron_password")
            mock_submit.assert_not_called()

    def test_cron_valid_bearer_on_weekday_not_submitted_submits_random_template(self):
        monday_wib = datetime(2026, 11, 23, 17, 0, 0, tzinfo=config.WIB)
        env = {
            **self.base_env,
            "KEMNAKER_USERNAME": "cron@mail.com",
            "KEMNAKER_PASSWORD": "cron_password",
        }
        fake_state = {
            "date": "2026-11-23",
            "today": {"submitted": False},
        }
        fake_tpl = {
            "id": 18,
            "category": "ops",
            "activity": "Cron act",
            "learning": "Cron learn",
            "obstacles": "Cron obs",
        }
        fake_submit_res = {
            "date": "2026-11-23",
            "coords": {"latitude": -7.902112, "longitude": 110.065128, "distance_m": 2.41},
            "message": "Attendance submitted successfully.",
        }
        with patch.dict(os.environ, env, clear=True), patch(
            "api.cron._now_wib", return_value=monday_wib
        ), patch("lib.kemnaker.login_kemnaker", return_value="cron-tok") as mock_login, patch(
            "lib.kemnaker.fetch_dashboard_state", return_value=fake_state
        ), patch(
            "lib.kemnaker.pick_random_unused_template", return_value=(fake_tpl, 14, 30)
        ) as mock_pick, patch(
            "lib.kemnaker.submit_attendance", return_value=fake_submit_res
        ) as mock_submit:
            code, _, _, data = invoke_handler(
                api_cron.handler,
                method="POST",
                path="/api/cron",
                headers={"Authorization": f"Bearer {TEST_CRON_SECRET}"},
            )
            self.assertEqual(code, 200)
            self.assertEqual(
                data,
                {
                    "status": "submitted",
                    "date": "2026-11-23",
                    "template_id": 18,
                    "coords": {"latitude": -7.902112, "longitude": 110.065128, "distance_m": 2.41},
                },
            )
            mock_login.assert_called_once_with("cron@mail.com", "cron_password")
            mock_pick.assert_called_once_with("cron-tok")
            mock_submit.assert_called_once_with(
                "cron-tok",
                "Cron act",
                "Cron learn",
                "Cron obs",
                today_wib=monday_wib,
            )


if __name__ == "__main__":
    unittest.main()
