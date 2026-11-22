from __future__ import annotations

import base64
import hashlib
import json
from cryptography.fernet import Fernet, InvalidToken

from lib.config import ConfigError, get_session_secret

SESSION_COOKIE_NAME = "monev_session"
SESSION_TTL_SECONDS = 19800


def _resolve_fernet(secret: str | None = None) -> Fernet:
    if secret is None:
        raw_secret = get_session_secret()
    else:
        raw_secret = str(secret).strip()
        if len(raw_secret) < 32:
            raise ConfigError("SESSION_SECRET must be set and at least 32 characters long.")
    key = base64.urlsafe_b64encode(hashlib.sha256(raw_secret.encode("utf-8")).digest())
    return Fernet(key)


def encrypt_session(token: str, username: str, secret: str | None = None) -> str:
    fernet = _resolve_fernet(secret)
    payload = json.dumps({"token": str(token), "user": str(username)}, separators=(",", ":")).encode("utf-8")
    return fernet.encrypt(payload).decode("utf-8")


def decrypt_session(
    cookie_value: str | None,
    secret: str | None = None,
    ttl: int = SESSION_TTL_SECONDS,
) -> dict | None:
    fernet = _resolve_fernet(secret)
    if not cookie_value or not isinstance(cookie_value, str):
        return None
    try:
        decrypted = fernet.decrypt(cookie_value.strip().encode("utf-8"), ttl=ttl)
        data = json.loads(decrypted.decode("utf-8"))
    except (InvalidToken, ValueError, TypeError, UnicodeDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    token = data.get("token")
    user = data.get("user")
    if not isinstance(token, str) or not isinstance(user, str) or not token or not user:
        return None
    return {"token": token, "user": user}


def parse_cookies(cookie_header: str | None) -> dict[str, str]:
    if not cookie_header or not isinstance(cookie_header, str):
        return {}
    result: dict[str, str] = {}
    for chunk in cookie_header.split(";"):
        part = chunk.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        key = k.strip()
        val = v.strip()
        if key:
            result[key] = val
    return result


def build_session_cookie(
    value: str,
    secure: bool = True,
    max_age: int = SESSION_TTL_SECONDS,
) -> str:
    parts = [
        f"{SESSION_COOKIE_NAME}={value}",
        "Path=/",
        f"Max-Age={int(max_age)}",
        "HttpOnly",
        "SameSite=Strict",
    ]
    if secure:
        parts.append("Secure")
    return "; ".join(parts)


def build_clear_session_cookie(secure: bool = True) -> str:
    return build_session_cookie("", secure=secure, max_age=0)
