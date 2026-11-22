import math
import os
import random
import unittest
from unittest.mock import patch

from lib import config, geo


class TestConfigAndGeo(unittest.TestCase):
    def test_default_office_pin_is_yia_place_pin(self):
        with patch.dict(os.environ, {}, clear=True):
            lat, lon, radius = config.get_office_config()
        self.assertAlmostEqual(lat, -7.9021141, places=7)
        self.assertAlmostEqual(lon, 110.065129, places=7)
        self.assertEqual(radius, 10.0)

    def test_secrets_fail_closed(self):
        with patch.dict(os.environ, {"SESSION_SECRET": "short", "CRON_SECRET": "short"}, clear=True):
            with self.assertRaises(config.ConfigError):
                config.get_session_secret()
            with self.assertRaises(config.ConfigError):
                config.get_cron_secret()

    def test_proxy_url_without_secret_fails_closed(self):
        with patch.dict(os.environ, {"CLOUDFLARE_WORKER_URL": "https://p.workers.dev"}, clear=True):
            with self.assertRaises(config.ConfigError):
                config.get_proxy_config()

    def test_generated_coords_always_within_10m_circle(self):
        rng = random.Random(42)
        distances = []
        for _ in range(1000):
            c = geo.generate_office_coordinates(-7.9021141, 110.065129, 10.0, rng=rng)
            d = geo.haversine_meters(-7.9021141, 110.065129, c["latitude"], c["longitude"])
            self.assertLessEqual(d, 10.0)
            self.assertAlmostEqual(c["distance_m"], round(d, 2), places=2)
            distances.append(d)
        self.assertGreater(max(distances), 7.0)

    def test_validate_coordinates_rejects_bad_types_and_out_of_range(self):
        for bad_lat, bad_lon in [
            (True, 110.065129),
            (float("nan"), 110.065129),
            (float("inf"), 110.065129),
            ("abc", 110.065129),
            (-7.9022500, 110.065129),  # ~15m away
        ]:
            with self.assertRaises(ValueError):
                geo.validate_office_coordinates(bad_lat, bad_lon, -7.9021141, 110.065129, 10.0)

        ok = geo.validate_office_coordinates(-7.9021500, 110.065129, -7.9021141, 110.065129, 10.0)
        self.assertLessEqual(ok["distance_m"], 10.0)
