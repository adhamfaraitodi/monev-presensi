import io
import json
import time
import unittest
from lib import session, http_utils
from lib.config import ConfigError

SECRET = "a" * 40


class _DummyHandler:
    def __init__(self):
        self.status = None
        self.headers = []
        self.ended = False
        self.wfile = io.BytesIO()

    def send_response(self, status: int):
        self.status = status

    def send_header(self, key: str, value: str):
        self.headers.append((key, value))

    def end_headers(self):
        self.ended = True


class TestSessionAndHttpUtils(unittest.TestCase):
    def test_fernet_session_roundtrip_and_tamper_rejection(self):
        cookie_val = session.encrypt_session("tok_123", "user1", secret=SECRET)
        self.assertNotIn("tok_123", cookie_val)
        data = session.decrypt_session(cookie_val, secret=SECRET)
        self.assertEqual(data, {"token": "tok_123", "user": "user1"})
        tampered = cookie_val[:-4] + "XXXX"
        self.assertIsNone(session.decrypt_session(tampered, secret=SECRET))
        self.assertIsNone(session.decrypt_session(cookie_val, secret="b" * 40))
        self.assertIsNone(session.decrypt_session(None, secret=SECRET))
        self.assertIsNone(session.decrypt_session("", secret=SECRET))

    def test_fernet_session_secret_validation(self):
        with self.assertRaises(ConfigError):
            session.encrypt_session("tok_123", "user1", secret="short")
        with self.assertRaises(ConfigError):
            session.decrypt_session("some_cookie", secret="short")

    def test_fernet_session_ttl_expiry(self):
        cookie_val = session.encrypt_session("tok_123", "user1", secret=SECRET)
        time.sleep(1.1)
        self.assertIsNone(session.decrypt_session(cookie_val, secret=SECRET, ttl=0))

    def test_parse_cookies(self):
        self.assertEqual(session.parse_cookies(None), {})
        self.assertEqual(session.parse_cookies(""), {})
        parsed = session.parse_cookies("foo=bar; monev_session=abc=123; theme=dark")
        self.assertEqual(parsed, {"foo": "bar", "monev_session": "abc=123", "theme": "dark"})

    def test_cookie_flags_secure_and_local(self):
        hdr = session.build_session_cookie("abc", secure=True)
        self.assertIn("HttpOnly", hdr)
        self.assertIn("SameSite=Strict", hdr)
        self.assertIn("Secure", hdr)
        self.assertIn("Max-Age=19800", hdr)
        clear_hdr = session.build_clear_session_cookie(secure=False)
        self.assertIn("Max-Age=0", clear_hdr)
        self.assertNotIn("Secure", clear_hdr)

    def test_is_local_host_and_constant_time_equals(self):
        self.assertTrue(http_utils.is_local_host("localhost:8000"))
        self.assertTrue(http_utils.is_local_host("127.0.0.1:3000"))
        self.assertTrue(http_utils.is_local_host("[::1]:8000"))
        self.assertFalse(http_utils.is_local_host("app.vercel.app"))
        self.assertFalse(http_utils.is_local_host(None))

        self.assertTrue(http_utils.constant_time_equals("secret123", "secret123"))
        self.assertFalse(http_utils.constant_time_equals("secret123", "secret124"))
        self.assertFalse(http_utils.constant_time_equals(None, "secret123"))
        self.assertFalse(http_utils.constant_time_equals("", "secret123"))

    def test_csrf_same_origin_and_cross_origin(self):
        self.assertTrue(http_utils.verify_csrf({"Origin": "https://app.vercel.app"}, "app.vercel.app"))
        self.assertFalse(http_utils.verify_csrf({"Origin": "https://evil.example"}, "app.vercel.app"))
        self.assertFalse(http_utils.verify_csrf({"Sec-Fetch-Site": "cross-site"}, "app.vercel.app"))
        self.assertTrue(http_utils.verify_csrf({"Sec-Fetch-Site": "same-origin"}, "app.vercel.app"))
        self.assertFalse(http_utils.verify_csrf({}, "app.vercel.app"))

    def test_read_json_body_rejects_oversized_and_invalid(self):
        body, err = http_utils.read_json_body(io.BytesIO(b"{bad"), {"Content-Length": "4"})
        self.assertIsNone(body)
        self.assertIsNotNone(err)
        big_body, big_err = http_utils.read_json_body(io.BytesIO(b"x" * 100), {"Content-Length": "99999"})
        self.assertIsNone(big_body)
        self.assertIn("large", big_err.lower())
        arr_body, arr_err = http_utils.read_json_body(io.BytesIO(b"[1, 2]"), {"Content-Length": "6"})
        self.assertIsNone(arr_body)
        self.assertIsNotNone(arr_err)
        valid_body, valid_err = http_utils.read_json_body(io.BytesIO(b'{"a": 1}'), {"Content-Length": "8"})
        self.assertEqual(valid_body, {"a": 1})
        self.assertIsNone(valid_err)

    def test_sanitize_error_redacts_secrets_and_bearer(self):
        msg = http_utils.sanitize_error(
            "Failed Bearer eyJsecret123 pass=myPass99 naco_access_token=tok999 monev_session=sess888",
            secrets=("myPass99",),
        )
        self.assertNotIn("eyJsecret123", msg)
        self.assertNotIn("myPass99", msg)
        self.assertNotIn("tok999", msg)
        self.assertNotIn("sess888", msg)

    def test_send_json_includes_security_headers(self):
        handler = _DummyHandler()
        http_utils.send_json(handler, 200, {"ok": True}, extra_headers=[("Set-Cookie", "monev_session=xyz")])
        self.assertEqual(handler.status, 200)
        self.assertTrue(handler.ended)
        header_dict = dict(handler.headers)
        for k, v in http_utils.SECURITY_HEADERS.items():
            self.assertEqual(header_dict.get(k), v)
        self.assertEqual(header_dict.get("Set-Cookie"), "monev_session=xyz")
        self.assertEqual(json.loads(handler.wfile.getvalue().decode("utf-8")), {"ok": True})


if __name__ == "__main__":
    unittest.main()
