from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import mimetypes
import os
import sys
import urllib.parse

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from api import auth, cron, status, submit, template
from lib import http_utils

PUBLIC_DIR = os.path.join(ROOT_DIR, "public")

API_ROUTES: dict[str, type[BaseHTTPRequestHandler]] = {
    "/api/auth": auth.handler,
    "/api/status": status.handler,
    "/api/template": template.handler,
    "/api/submit": submit.handler,
    "/api/cron": cron.handler,
}

CONTENT_TYPES: dict[str, str] = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
}


def load_dotenv_if_present(env_path: str | None = None) -> None:
    target = env_path or os.path.join(ROOT_DIR, ".env")
    if not os.path.isfile(target):
        return
    try:
        with open(target, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = val
    except Exception:
        pass


class DevRequestHandler(BaseHTTPRequestHandler):
    def _dispatch_api(self, method: str) -> bool:
        parsed = urllib.parse.urlparse(self.path)
        clean_path = parsed.path.rstrip("/") or "/"
        if not clean_path.startswith("/api/"):
            return False

        handler_cls = API_ROUTES.get(clean_path)
        if handler_cls is None:
            http_utils.send_json(self, 404, {"error": "API endpoint not found."})
            return True

        method_fn = getattr(handler_cls, f"do_{method}", None)
        if not callable(method_fn):
            http_utils.send_json(self, 405, {"error": f"Method {method} not allowed."})
            return True

        method_fn(self)
        return True

    def _serve_static(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        req_path = urllib.parse.unquote(parsed.path or "/")
        if req_path in ("", "/"):
            req_path = "/index.html"

        rel_path = req_path.lstrip("/")
        candidate = os.path.realpath(os.path.join(PUBLIC_DIR, rel_path))
        public_real = os.path.realpath(PUBLIC_DIR)

        if not (candidate == public_real or candidate.startswith(public_real + os.sep)):
            http_utils.send_json(self, 403, {"error": "Forbidden"})
            return

        if not os.path.isfile(candidate):
            http_utils.send_json(self, 404, {"error": "Not found"})
            return

        _, ext = os.path.splitext(candidate)
        content_type = CONTENT_TYPES.get(ext.lower())
        if not content_type:
            guessed, _ = mimetypes.guess_type(candidate)
            content_type = guessed or "application/octet-stream"

        with open(candidate, "rb") as f:
            body = f.read()

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in http_utils.SECURITY_HEADERS.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self._dispatch_api("GET"):
            return
        self._serve_static()

    def do_POST(self) -> None:
        if self._dispatch_api("POST"):
            return
        http_utils.send_json(self, 405, {"error": "Method POST not allowed on static route."})

    def do_DELETE(self) -> None:
        if self._dispatch_api("DELETE"):
            return
        http_utils.send_json(self, 405, {"error": "Method DELETE not allowed on static route."})

    def log_message(self, format: str, *args) -> None:
        return


def create_server(host: str = "127.0.0.1", port: int = 8000) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), DevRequestHandler)


if __name__ == "__main__":
    load_dotenv_if_present()
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    server = create_server(host=host, port=port)
    print(f"Monev Presensi local dev server listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
