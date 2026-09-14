import unittest

import _bootstrap  # noqa: F401
from mslm.l3 import (
    ExpiredToken,
    InvalidToken,
    KeyRing,
    PriceTokenService,
    ReplayDetected,
    ReplayStore,
    amount_to_minor,
)


class L3Tests(unittest.TestCase):
    def setUp(self):
        self.keys = KeyRing()
        self.keys.add("m1", "k1", b"a" * 32, active=True)
        self.service = PriceTokenService(self.keys, ReplayStore(), ttl_seconds=60)
        self.claims, self.signature = self.service.issue(
            "m1", "u1", "o1", 9999, "usd", now=1000, nonce="unique"
        )

    def verify(self, **changes):
        values = {
            "expected_merchant_id": "m1",
            "expected_user_id": "u1",
            "expected_order_id": "o1",
            "expected_amount_minor": 9999,
            "expected_currency": "USD",
            "now": 1001,
            "consume": False,
        }
        values.update(changes)
        self.service.verify(self.claims, self.signature, **values)

    def test_valid_token(self):
        self.verify()

    def test_signature_mutation_rejected(self):
        with self.assertRaises(InvalidToken):
            self.service.verify(
                self.claims,
                "0" * 64,
                expected_merchant_id="m1",
                expected_user_id="u1",
                expected_order_id="o1",
                expected_amount_minor=9999,
                expected_currency="USD",
                now=1001,
            )

    def test_each_bound_claim_is_enforced(self):
        changes = {
            "expected_merchant_id": "m2",
            "expected_user_id": "u2",
            "expected_order_id": "o2",
            "expected_amount_minor": 1,
            "expected_currency": "MMK",
        }
        for key, value in changes.items():
            with self.subTest(key=key), self.assertRaises(InvalidToken):
                self.verify(**{key: value})

    def test_expired_token_rejected(self):
        with self.assertRaises(ExpiredToken):
            self.verify(now=1060)

    def test_future_token_rejected(self):
        with self.assertRaises(InvalidToken):
            self.verify(now=990)

    def test_replay_is_rejected(self):
        self.verify(consume=True)
        with self.assertRaises(ReplayDetected):
            self.verify(consume=True)

    def test_key_rotation_preserves_old_verification(self):
        self.keys.rotate("m1", "k2", b"b" * 32)
        self.verify()
        new_claims, _ = self.service.issue("m1", "u1", "o2", 1, "USD", now=1001)
        self.assertEqual(new_claims.key_id, "k2")

    def test_short_key_rejected(self):
        with self.assertRaises(ValueError):
            self.keys.add("m2", "bad", b"short", active=True)

    def test_amount_conversion(self):
        cases = {"0": 0, "1": 100, "99.99": 9999, "1.20": 120}
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(amount_to_minor(value), expected)

    def test_invalid_amounts_rejected(self):
        for value in ("-1", "nan", "inf", "1.001", "abc"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                amount_to_minor(value)

    def test_invalid_currency_rejected(self):
        with self.assertRaises(ValueError):
            self.service.issue("m1", "u1", "o1", 1, "$", now=1000)

