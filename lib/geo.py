from __future__ import annotations

import math
import random

from lib import config

DEFAULT_OFFICE_LAT = -7.9021141
DEFAULT_OFFICE_LONG = 110.065129
DEFAULT_RADIUS_METERS = 10.0

EARTH_RADIUS_METERS = 6371000.0


def haversine_meters(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2.0) ** 2
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(max(0.0, 1.0 - a)))
    return EARTH_RADIUS_METERS * c


def _resolve_center_and_radius(
    center_lat: float | None,
    center_lon: float | None,
    max_radius_m: float | None,
) -> tuple[float, float, float]:
    cfg_lat, cfg_lon, cfg_radius = config.get_office_config()
    lat = cfg_lat if center_lat is None else float(center_lat)
    lon = cfg_lon if center_lon is None else float(center_lon)
    radius = cfg_radius if max_radius_m is None else float(max_radius_m)
    return (lat, lon, radius)


def generate_office_coordinates(
    center_lat: float | None = None,
    center_lon: float | None = None,
    max_radius_m: float | None = None,
    rng: random.Random | None = None,
) -> dict:
    c_lat, c_lon, radius_m = _resolve_center_and_radius(center_lat, center_lon, max_radius_m)
    rand = rng if rng is not None else random.SystemRandom()
    safe_radius = max(0.0, radius_m - 0.2)
    theta = rand.uniform(0.0, 2.0 * math.pi)
    r = safe_radius * math.sqrt(rand.random())

    dlat_rad = (r * math.cos(theta)) / EARTH_RADIUS_METERS
    cos_lat = math.cos(math.radians(c_lat))
    dlon_rad = (r * math.sin(theta)) / (EARTH_RADIUS_METERS * cos_lat) if abs(cos_lat) > 1e-12 else 0.0

    lat = round(c_lat + math.degrees(dlat_rad), 7)
    lon = round(c_lon + math.degrees(dlon_rad), 7)
    dist = round(haversine_meters(c_lat, c_lon, lat, lon), 2)
    return {
        "latitude": lat,
        "longitude": lon,
        "distance_m": dist,
    }


def _coerce_finite_float(val: object, name: str) -> float:
    if isinstance(val, bool) or not isinstance(val, (int, float, str)):
        raise ValueError(f"Invalid {name}: must be a finite number.")
    try:
        num = float(val)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Invalid {name}: must be a finite number.") from exc
    if not math.isfinite(num):
        raise ValueError(f"Invalid {name}: must be finite.")
    return num


def validate_office_coordinates(
    lat: object,
    lon: object,
    center_lat: float | None = None,
    center_lon: float | None = None,
    max_radius_m: float | None = None,
) -> dict:
    f_lat = _coerce_finite_float(lat, "latitude")
    f_lon = _coerce_finite_float(lon, "longitude")
    if not (-90.0 <= f_lat <= 90.0) or not (-180.0 <= f_lon <= 180.0):
        raise ValueError("Coordinates out of geographic bounds.")

    c_lat, c_lon, radius_m = _resolve_center_and_radius(center_lat, center_lon, max_radius_m)
    dist = haversine_meters(c_lat, c_lon, f_lat, f_lon)
    if dist > radius_m:
        raise ValueError(
            f"Coordinates are {dist:.2f}m from office center (max allowed {radius_m:.2f}m)."
        )
    return {
        "latitude": round(f_lat, 7),
        "longitude": round(f_lon, 7),
        "distance_m": round(dist, 2),
    }
