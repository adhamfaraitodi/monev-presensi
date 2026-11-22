from __future__ import annotations

import hmac
import json
import re
from urllib.parse import urlparse

MAX_BODY_BYTES = 32768

SECURITY_HEADERS: dict[str, str] = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'self'; style-src 'self'; script-src 'self'; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    ),
}


def _get_header(headers: object, name: str) -> str | None:
    if headers is None:
        return None
    target = name.lower()
    if hasattr(headers, "items"):
        for k, v in headers.items():
            if str(k).lower() == target:
                return str(v) if v is not None else None
    if hasattr(headers, "get"):
        val = headers.get(name)
        if val is not None:
            return str(val)
    return None


def is_local_host(host: str | None) -> bool:
    if not host or not isinstance(host, str):
        return False
    cleaned = host.strip().lower()
    if cleaned.startswith("["):
        bracket_end = cleaned.find("]")
        hostname = cleaned[: bracket_end + 1] if bracket_end != -1 else cleaned
    else:
        hostname = cleaned.split(":", 1)[0]
    return hostname in {"localhost", "127.0.0.1", "[::1]", "::1"}


def constant_time_equals(a: str | None, b: str | None) -> bool:
    if not isinstance(a, str) or not isinstance(b, str) or not a or not b:
        return False
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def verify_csrf(headers: dict, host: str | None) -> bool:
    sec_fetch_site = _get_header(headers, "Sec-Fetch-Site")
    origin = _get_header(headers, "Origin")

    has_sec_fetch = bool(sec_fetch_site and sec_fetch_site.strip())
    has_origin = bool(origin and origin.strip())

    if not has_sec_fetch and not has_origin:
        return False

    if has_sec_fetch:
        if sec_fetch_site.strip().lower() not in {"same-origin", "none"}:
            return False

    if has_origin:
        parsed = urlparse(origin.strip())
        expected_host = (host or "").strip().lower()
        if not parsed.netloc or not expected_host or parsed.netloc.lower() != expected_host:
            return False

    return True


def sanitize_error(err: object, secrets: tuple[str, ...] = ()) -> str:
    text = str(err if err is not None else "")
    for secret in secrets or ():
        if secret:
            text = text.replace(str(secret), "[REDACTED]")
    text = re.sub(r"(?i)\bBearer\s+[^\s,;\"']+", "Bearer [REDACTED]", text)
    text = re.sub(r"(?i)naco_access_token=[^\s&;\"']+", "naco_access_token=[REDACTED]", text)
    text = re.sub(r"(?i)monev_session=[^\s&;\"']+", "monev_session=[REDACTED]", text)
    return text[:240]


def read_json_body(
    rfile,
    headers,
    max_bytes: int = MAX_BODY_BYTES,
) -> tuple[dict | None, str | None]:
    raw_len = _get_header(headers, "Content-Length")
    if raw_len is None or not str(raw_len).strip():
        return (None, "Missing Content-Length header.")
    try:
        content_len = int(str(raw_len).strip())
    except (ValueError, TypeError):
        return (None, "Invalid Content-Length header.")

    if content_len < 0:
        return (None, "Invalid Content-Length header.")
    if content_len > max_bytes:
        return (None, f"Request body too large (exceeds {max_bytes} bytes).")
    if content_len == 0:
        return (None, "Request body cannot be empty.")

    raw_bytes = rfile.read(content_len)
    if len(raw_bytes) > max_bytes:
        return (None, f"Request body too large (exceeds {max_bytes} bytes).")

    try:
        parsed = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return (None, "Invalid JSON payload.")

    if not isinstance(parsed, dict):
        return (None, "JSON payload must be an object.")

    return (parsed, None)


def send_json(
    handler,
    status: int,
    payload: dict,
    extra_headers: list[tuple[str, str]] | None = None,
) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    for key, value in SECURITY_HEADERS.items():
        handler.send_header(key, value)
    if extra_headers:
        for key, value in extra_headers:
            handler.send_header(key, value)
    handler.end_headers()
    handler.wfile.write(body)
