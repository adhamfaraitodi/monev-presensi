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

    def test_submit_attendance_validates_blank_fields_and_out_of_range_coords(self):
        with self.assertRaises(ValueError):
            kemnaker.submit_attendance("tok", "   ", "Learn", "Obstacles")
        with self.assertRaises(ValueError):
            kemnaker.submit_attendance("tok", "Work", "", "Obstacles")
        with self.assertRaises(ValueError):
            kemnaker.submit_attendance("tok", "Work", "Learn", "  ")
        with self.assertRaises(ValueError):
            kemnaker.submit_attendance("tok", "Work", "Learn", "Obstacles", lat=0.0, lon=0.0)

    def test_login_kemnaker_uses_arguments_and_routes_through_proxy_with_sanitized_errors(self):
        seen_requests = []

        class FakeResponse:
            def __init__(self, body: bytes, url: str = "https://account.kemnaker.go.id/auth/login"):
                self._body = body
                self._url = url

            def read(self):
                return self._body

            def geturl(self):
                return self._url

        class FakeOpener:
            def __init__(self, cj):
                self.cj = cj

            def open(self, req, timeout=25):
                seen_requests.append(req)
                if len(seen_requests) == 1:
                    return FakeResponse(b'<html><meta name="csrf-token" content="csrf-abc"></html>')
                if len(seen_requests) == 2:
                    return FakeResponse(
                        json.dumps({
                            "data": {
                                "authenticated": True,
                                "redirect_uri": "https://maganghub.kemnaker.go.id/callback?code=1",
                            }
                        }).encode("utf-8")
                    )
                self.cj.set_cookie(http.cookiejar.Cookie(
                    0, "naco_access_token", "naco-secret-tok", None, False, "kemnaker.go.id", True, False,
                    "/", True, True, None, False, None, None, {}
                ))
                return FakeResponse(b"ok")

        def build_fake_opener(processor):
            return FakeOpener(processor.cookiejar)

        env = {
            "KEMNAKER_USERNAME": "env_wrong_user",
            "KEMNAKER_PASSWORD": "env_wrong_password",
            "CLOUDFLARE_WORKER_URL": "https://proxy.example.workers.dev",
            "PROXY_SECRET": "proxy-secret-xyz",
        }
        with patch.dict(os.environ, env, clear=True), patch("urllib.request.build_opener", side_effect=build_fake_opener):
            tok = kemnaker.login_kemnaker("passed_user", "passed_super_secret_pw")

        self.assertEqual(tok, "naco-secret-tok")
        self.assertEqual(len(seen_requests), 3)
        for req in seen_requests:
            self.assertTrue(req.full_url.startswith("https://proxy.example.workers.dev/?url="))
            self.assertEqual(req.get_header("X-proxy-secret"), "proxy-secret-xyz")
        login_body = json.loads(seen_requests[1].data.decode("utf-8"))
        self.assertEqual(login_body, {"username": "passed_user", "password": "passed_super_secret_pw"})
        self.assertEqual(seen_requests[1].get_header("X-csrf-token"), "csrf-abc")

        class FailingOpener:
            def open(self, req, timeout=25):
                raise RuntimeError("Fatal failure with secret_pw_999 leaked in message")

        with patch.dict(os.environ, {}, clear=True), patch("urllib.request.build_opener", return_value=FailingOpener()):
            with self.assertRaises(kemnaker.KemnakerError) as ctx:
                kemnaker.login_kemnaker("u", "secret_pw_999")
            self.assertNotIn("secret_pw_999", str(ctx.exception))
            self.assertIn("[REDACTED]", str(ctx.exception))

    def test_fetch_dashboard_state_sorts_top_7_and_loads_today_log(self):
        fixed_now = datetime(2026, 11, 10, 15, 30, 45, tzinfo=config.WIB)
        attendances = [
            {"date": f"2026-11-{day:02d}", "status": "PRESENT", "approval_status": "APPROVED", "created_at": f"2026-11-{day:02d}T08:15:00Z"}
            for day in range(1, 11)
        ]
        random.Random(42).shuffle(attendances)

        def fake_api(endpoint, token, method="GET", payload=None):
            if endpoint.endswith("/users/me"):
                return {"data": {"name": "Peserta A", "mentor_name": "Mentor B"}}
            if endpoint.endswith("/attendances"):
                return {"data": attendances}
            if "/daily-logs?date=2026-11-10" in endpoint:
                return {"data": [{"activity_log": "Today activity text"}]}
            return {"data": []}

        with patch("lib.kemnaker.api_call", side_effect=fake_api):
            state = kemnaker.fetch_dashboard_state("tok", today_wib=fixed_now)

        self.assertEqual(state["date"], "2026-11-10")
        self.assertEqual(state["time_wib"], "15:30:45")
        self.assertEqual(state["user"], {"name": "Peserta A", "mentor": "Mentor B"})
        self.assertTrue(state["today"]["submitted"])
        self.assertEqual(state["today"]["submitted_at"], "08:15:00")
        self.assertEqual(state["today"]["approval_status"], "APPROVED")
        self.assertEqual(state["today"]["activity_log"], "Today activity text")
        self.assertEqual(len(state["recent"]), 7)
        self.assertEqual(
            [r["date"] for r in state["recent"]],
            ["2026-11-10", "2026-11-09", "2026-11-08", "2026-11-07", "2026-11-06", "2026-11-05", "2026-11-04"],
        )
