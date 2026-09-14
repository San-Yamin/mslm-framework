import unittest

import _bootstrap  # noqa: F401
from mslm.l1 import OnboardingAuditor


class L1Tests(unittest.TestCase):
    def setUp(self):
        self.auditor = OnboardingAuditor()

    def test_secure_code_approved(self):
        decision = self.auditor.analyze("def health():\n    return {'ok': True}\n")
        self.assertTrue(decision.approved)
        self.assertEqual(decision.findings, ())

    def test_syntax_error_is_fail_closed(self):
        decision = self.auditor.analyze("def broken(")
        self.assertFalse(decision.approved)
        self.assertIn("line", decision.parse_error)

    def test_custom_auth_detected(self):
        decision = self.auditor.analyze("def custom_auth(user):\n    return bool(user)\n")
        self.assertEqual(decision.findings[0].vulnerability_id, "V1")

    def test_hardcoded_auth_secret_detected(self):
        source = "def auth(password):\n    return password == 'secret123'\n"
        rules = {item.rule_id for item in self.auditor.analyze(source).findings}
        self.assertIn("L1.AUTH.HARDCODED_SECRET", rules)

    def test_weak_crypto_calls_detected(self):
        for call in ("hashlib.md5(b'x')", "hashlib.sha1(b'x')", "random.randint(1, 9)"):
            with self.subTest(call=call):
                rules = {item.rule_id for item in self.auditor.analyze(call).findings}
                self.assertIn("L1.CRYPTO.WEAK", rules)

    def test_client_price_detected(self):
        source = "def pay(request):\n    amount = request['amount']\n    return amount\n"
        findings = self.auditor.analyze(source).findings
        self.assertIn("V3", {item.vulnerability_id for item in findings})

    def test_direct_reference_detected(self):
        source = "def lookup(payload):\n    return payload['transaction_id']\n"
        self.assertIn("V2", {item.vulnerability_id for item in self.auditor.analyze(source).findings})

    def test_sensitive_admin_without_authorization_detected(self):
        source = "def admin_refund(order):\n    return order\n"
        self.assertIn("V6", {item.vulnerability_id for item in self.auditor.analyze(source).findings})

    def test_authorization_call_suppresses_missing_authz_rule(self):
        source = "def admin_refund(order):\n    authorize_permission('refund')\n    return order\n"
        rules = {item.rule_id for item in self.auditor.analyze(source).findings}
        self.assertNotIn("L1.AUTHZ.MISSING", rules)

    def test_finding_ids_are_stable(self):
        source = "def custom_auth(user):\n    return user\n"
        first = self.auditor.analyze(source).findings
        second = self.auditor.analyze(source).findings
        self.assertEqual(first, second)

    def test_high_risk_is_rejected(self):
        source = "def custom_auth(request):\n    return request['amount']\n"
        self.assertFalse(self.auditor.analyze(source).approved)

