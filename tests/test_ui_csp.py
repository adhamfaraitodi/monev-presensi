import os
import re
import threading
import unittest
from unittest import mock
import urllib.error
import urllib.request

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
        self.assertNotIn("innerHTML", js)
        self.assertIn("/api/auth", js)
        self.assertIn("/api/status", js)
        self.assertIn("/api/template", js)
        self.assertIn("/api/submit", js)

    def test_dev_server_imports_cleanly(self):
        import dev_server
        self.assertTrue(callable(dev_server.create_server))

    def test_dev_server_serves_static_and_dispatches_api(self):
        import dev_server

        with mock.patch.dict(os.environ, {"SESSION_SECRET": "s" * 32}):
            server = dev_server.create_server(host="127.0.0.1", port=0)
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as res:
                    self.assertEqual(res.status, 200)
                    self.assertIn("text/html", res.headers.get("Content-Type", ""))
                    self.assertIn("default-src 'self'", res.headers.get("Content-Security-Policy", ""))
                    body = res.read().decode("utf-8")
                    self.assertIn('id="login-form"', body)

                with urllib.request.urlopen(f"http://127.0.0.1:{port}/styles.css", timeout=5) as res:
                    self.assertEqual(res.status, 200)
                    self.assertIn("text/css", res.headers.get("Content-Type", ""))

                with urllib.request.urlopen(f"http://127.0.0.1:{port}/app.js", timeout=5) as res:
                    self.assertEqual(res.status, 200)
                    self.assertIn("javascript", res.headers.get("Content-Type", ""))

                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status", timeout=5)
                self.assertEqual(ctx.exception.code, 401)
                ctx.exception.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
