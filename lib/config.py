from __future__ import annotations

import math
import os
from datetime import timedelta, timezone

WIB: timezone = timezone(timedelta(hours=7))


class ConfigError(Exception):
    """Raised when required configuration or secret is missing or invalid."""


def load_dotenv(env_path: str = ".env") -> None:
    if not os.path.isabs(env_path):
        root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        candidate = os.path.join(root_dir, env_path)
        env_path = candidate if os.path.exists(candidate) else os.path.abspath(env_path)
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip("'\"")
                    os.environ.setdefault(k, v)


load_dotenv(".env")


def _safe_float(raw: str | None, default: float) -> float:
    if raw is None or not str(raw).strip():
        return default
    try:
        val = float(str(raw).strip())
        return val if math.isfinite(val) else default
    except (ValueError, TypeError):
        return default


def get_office_config() -> tuple[float, float, float]:
    lat = _safe_float(os.getenv("OFFICE_LAT"), -7.9021141)
    lon = _safe_float(os.getenv("OFFICE_LONG"), 110.065129)
    raw_radius = _safe_float(os.getenv("OFFICE_RADIUS_METERS"), 10.0)
    if raw_radius <= 0.5:
        radius_m = 0.5
    elif raw_radius > 50.0:
        radius_m = 50.0
    else:
        radius_m = raw_radius
    return (lat, lon, float(radius_m))


def get_session_secret() -> str:
    secret = (os.getenv("SESSION_SECRET") or "").strip()
    if len(secret) < 32:
        raise ConfigError("SESSION_SECRET must be set and at least 32 characters long.")
    return secret


def get_cron_secret() -> str:
    secret = (os.getenv("CRON_SECRET") or "").strip()
    if len(secret) < 16:
        raise ConfigError("CRON_SECRET must be set and at least 16 characters long.")
    return secret


def get_proxy_config() -> tuple[str | None, str | None]:
    url = (os.getenv("CLOUDFLARE_WORKER_URL") or "").strip().rstrip("/")
    secret = (os.getenv("PROXY_SECRET") or "").strip()
    if not url:
        return (None, None)
    if not secret:
        raise ConfigError("PROXY_SECRET is required when CLOUDFLARE_WORKER_URL is configured.")
    return (url, secret)


def get_allowed_username() -> str | None:
    raw = (os.getenv("ALLOWED_USERNAME") or "").strip().lower()
    return raw if raw else None


def get_cron_credentials() -> tuple[str, str]:
    username = (os.getenv("KEMNAKER_USERNAME") or "").strip()
    password = (os.getenv("KEMNAKER_PASSWORD") or "").strip()
    if not username or not password:
        raise ConfigError("KEMNAKER_USERNAME and KEMNAKER_PASSWORD are required for cron execution.")
    return (username, password)
