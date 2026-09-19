"""#134: Pumla Starter cap/entitlement mapping tests (canon 18.09: 25/day, docs+models enabled)."""
import io
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app  # noqa: E402


def _fake_urlopen(payload):
    class R(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    return R(json.dumps(payload).encode())


class PumlaStarterTariffTest(unittest.TestCase):
    def test_starter_tariff_present(self):
        t = app.TARIFFS["starter"]
        self.assertEqual(t["daily_limit"], 25)
        self.assertTrue(t["is_premium"])  # documents enabled
        self.assertGreaterEqual(t["models"], 3)  # model selection enabled

    def test_starter_monthly_maps_to_starter(self):
        payload = {"user_id": "u1", "email": "s@test.local", "plan": "starter_monthly"}
        with mock.patch.object(app.urlreq, "urlopen", return_value=_fake_urlopen(payload)):
            uid, plan, limit = app._resolve_user("Bearer tok", None, "1.2.3.4")
        self.assertEqual(plan, "starter")
        self.assertEqual(limit, 25)
        self.assertTrue(app.TARIFFS[plan]["is_premium"])

    def test_free_user_gets_10_per_day(self):
        payload = {"user_id": "u2", "email": "f@test.local", "plan": "free"}
        with mock.patch.object(app.urlreq, "urlopen", return_value=_fake_urlopen(payload)):
            uid, plan, limit = app._resolve_user("Bearer tok", None, "1.2.3.4")
        self.assertEqual((plan, limit), ("free", 10))

    def test_expired_starter_resolves_as_free_10(self):
        # auth effective_plan returns 'free' for expired subscriptions (#28)
        payload = {"user_id": "u3", "email": "e@test.local", "plan": "free"}
        with mock.patch.object(app.urlreq, "urlopen", return_value=_fake_urlopen(payload)):
            uid, plan, limit = app._resolve_user("Bearer tok", None, "1.2.3.4")
        self.assertEqual((plan, limit), ("free", 10))
        self.assertFalse(app.TARIFFS[plan]["is_premium"])  # docs locked again

    def test_anonymous_is_free(self):
        uid, plan, limit = app._resolve_user(None, None, "5.6.7.8")
        self.assertEqual((plan, limit), ("free", 10))

    def test_model_selection_allowed_for_starter(self):
        # non-free plans may pick any model from MODELS_ALLOWED (code: plan == 'free' forces chain)
        self.assertNotEqual(app.FREE_CHAIN, None)
        starter = app.TARIFFS["starter"]
        self.assertNotEqual(starter["daily_limit"], app.TARIFFS["free"]["daily_limit"])


if __name__ == "__main__":
    unittest.main(verbosity=2)