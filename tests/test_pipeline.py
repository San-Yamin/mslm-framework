import unittest

import _bootstrap  # noqa: F401
from mslm.audit import AuditLog
from mslm.l2 import AccessDenied, Principal, Role
from mslm.l3 import KeyRing, PriceTokenService, ReplayStore
from mslm.pipeline import MSLMGateway, TransactionRequest


class PipelineTests(unittest.TestCase):
    def setUp(self):
        keys = KeyRing()
        keys.add("m1", "k1", b"k" * 32, active=True)
        self.audit = AuditLog()
        self.gateway = MSLMGateway(PriceTokenService(keys, ReplayStore()), self.audit)
        self.gateway.set_merchant_approval("m1", True)
        merchant = Principal("operator", Role.MERCHANT, "m1")
        claims, signature = self.gateway.issue_token(
            merchant,
            merchant_id="m1",
            user_id="u1",
            order_id="o1",
            amount_minor=1000,
            currency="USD",
            now=1000,
        )
        self.request = TransactionRequest("m1", "u1", "o1", 1000, "USD", claims, signature)

    def test_legitimate_payment_approved(self):
        decision = self.gateway.process(Principal("u1", Role.USER), self.request, now=1001)
        self.assertTrue(decision.approved)

    def test_l1_blocks_unapproved_merchant(self):
        self.gateway.set_merchant_approval("m1", False)
        decision = self.gateway.process(Principal("u1", Role.USER), self.request, now=1001)
        self.assertEqual(decision.blocked_at, "L1")

    def test_l2_blocks_idor(self):
        decision = self.gateway.process(Principal("attacker", Role.USER), self.request, now=1001)
        self.assertEqual(decision.blocked_at, "L2")

    def test_l3_blocks_price_tampering(self):
        tampered = TransactionRequest(
            "m1", "u1", "o1", 1, "USD", self.request.claims, self.request.signature
        )
        decision = self.gateway.process(Principal("u1", Role.USER), tampered, now=1001)
        self.assertEqual(decision.blocked_at, "L3")

    def test_second_payment_is_replay(self):
        principal = Principal("u1", Role.USER)
        self.assertTrue(self.gateway.process(principal, self.request, now=1001).approved)
        decision = self.gateway.process(principal, self.request, now=1002)
        self.assertEqual(decision.blocked_at, "L3")

    def test_user_cannot_issue_merchant_token(self):
        with self.assertRaises(AccessDenied):
            self.gateway.issue_token(
                Principal("u1", Role.USER),
                merchant_id="m1",
                user_id="u1",
                order_id="o2",
                amount_minor=1,
                currency="USD",
                now=1000,
            )

    def test_cross_merchant_operator_cannot_issue_token(self):
        with self.assertRaises(AccessDenied):
            self.gateway.issue_token(
                Principal("operator", Role.MERCHANT, "m2"),
                merchant_id="m1",
                user_id="u1",
                order_id="o2",
                amount_minor=1,
                currency="USD",
                now=1000,
            )

    def test_decisions_are_audited(self):
        self.gateway.process(Principal("attacker", Role.USER), self.request, now=1001)
        event = self.audit.snapshot()[-1]
        self.assertEqual(event["outcome"], "blocked")
        self.assertEqual(event["layer"], "L2")

    def test_onboarding_integration_rejects_malicious_source(self):
        decision = self.gateway.onboard_merchant(
            "m1", "def custom_auth(request):\n    return request\n"
        )
        self.assertFalse(decision.approved)
        self.assertFalse(self.gateway.merchant_status["m1"])
        blocked = self.gateway.process(Principal("u1", Role.USER), self.request, now=1001)
        self.assertEqual(blocked.blocked_at, "L1")

    def test_onboarding_integration_approves_clean_source(self):
        decision = self.gateway.onboard_merchant(
            "m1", "def health():\n    return 1\n"
        )
        self.assertTrue(decision.approved)
        self.assertTrue(self.gateway.merchant_status["m1"])

    def test_onboarding_decision_is_audited(self):
        self.gateway.onboard_merchant(
            "m1", "def custom_auth(request):\n    return request['amount']\n"
        )
        event = self.audit.snapshot()[-1]
        self.assertEqual(event["event"], "merchant.onboard")
        self.assertEqual(event["layer"], "L1")

