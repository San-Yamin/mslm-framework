import unittest

import _bootstrap  # noqa: F401
from mslm.l2 import (
    AccessDenied,
    Principal,
    Role,
    minimize_response,
    require_merchant,
    require_owner,
    require_permission,
)


class L2Tests(unittest.TestCase):
    def test_user_can_read_own_transaction(self):
        require_permission(Principal("u1", Role.USER), "transaction:read:own")

    def test_user_cannot_grant_permission(self):
        with self.assertRaises(AccessDenied):
            require_permission(Principal("u1", Role.USER), "permission:grant")

    def test_unauthenticated_principal_denied(self):
        with self.assertRaises(AccessDenied):
            require_permission(Principal("u1", Role.USER, authenticated=False), "payment:create:own")

    def test_owner_accepted(self):
        require_owner(Principal("u1", Role.USER), "u1")

    def test_idor_denied(self):
        with self.assertRaises(AccessDenied):
            require_owner(Principal("u1", Role.USER), "u2")

    def test_matching_merchant_accepted(self):
        require_merchant(Principal("operator", Role.MERCHANT, "m1"), "m1")

    def test_cross_merchant_access_denied(self):
        with self.assertRaises(AccessDenied):
            require_merchant(Principal("operator", Role.MERCHANT, "m1"), "m2")

    def test_pan_masked_and_cvv_removed(self):
        result = minimize_response({"pan": "4111-1111-1111-1111", "cvv": "123"})
        self.assertEqual(result["pan"], "************1111")
        self.assertNotIn("cvv", result)

    def test_nested_secrets_removed(self):
        result = minimize_response({"user": {"password": "x", "name": "A"}})
        self.assertEqual(result, {"user": {"name": "A"}})

    def test_lists_are_recursively_minimized(self):
        result = minimize_response([{"secret_key": "x", "ssn": "123-45-6789"}])
        self.assertEqual(result, [{"ssn": "***-**-6789"}])

