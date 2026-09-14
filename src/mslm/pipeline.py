"""Composition of MSLM layers for controlled attack-chain experiments."""

from dataclasses import dataclass
from typing import Dict

from .audit import AuditLog
from .l2 import (
    AccessDenied,
    Principal,
    require_merchant,
    require_owner,
    require_permission,
)
from .l3 import PaymentClaims, PriceTokenService, TokenError


@dataclass(frozen=True)
class TransactionRequest:
    merchant_id: str
    user_id: str
    order_id: str
    amount_minor: int
    currency: str
    claims: PaymentClaims
    signature: str


@dataclass(frozen=True)
class Decision:
    approved: bool
    blocked_at: str
    reason: str


class MSLMGateway:
    def __init__(self, tokens: PriceTokenService, audit: AuditLog) -> None:
        self.tokens = tokens
        self.audit = audit
        self.merchant_status: Dict[str, bool] = {}

    def set_merchant_approval(self, merchant_id: str, approved: bool) -> None:
        self.merchant_status[merchant_id] = approved

    def issue_token(
        self,
        principal: Principal,
        *,
        merchant_id: str,
        user_id: str,
        order_id: str,
        amount_minor: int,
        currency: str,
        now: int,
    ):
        try:
            require_permission(principal, "token:issue:merchant")
            require_merchant(principal, merchant_id)
        except AccessDenied as exc:
            self.audit.record("token.issue", "blocked", "L2", actor_id=principal.subject_id)
            raise
        if not self.merchant_status.get(merchant_id, False):
            raise AccessDenied("merchant has not passed L1")
        return self.tokens.issue(
            merchant_id, user_id, order_id, amount_minor, currency, now=now
        )

    def process(self, principal: Principal, request: TransactionRequest, *, now: int) -> Decision:
        if not self.merchant_status.get(request.merchant_id, False):
            return self._blocked("L1", "merchant onboarding gate rejected", principal, request)
        try:
            require_permission(principal, "payment:create:own")
            require_owner(principal, request.user_id)
        except AccessDenied as exc:
            return self._blocked("L2", str(exc), principal, request)
        try:
            self.tokens.verify(
                request.claims,
                request.signature,
                expected_merchant_id=request.merchant_id,
                expected_user_id=request.user_id,
                expected_order_id=request.order_id,
                expected_amount_minor=request.amount_minor,
                expected_currency=request.currency,
                now=now,
            )
        except TokenError as exc:
            return self._blocked("L3", str(exc), principal, request)
        self.audit.record(
            "payment.process",
            "approved",
            "L3",
            actor_id=principal.subject_id,
            resource_id=request.order_id,
        )
        return Decision(True, "", "approved")

    def _blocked(
        self,
        layer: str,
        reason: str,
        principal: Principal,
        request: TransactionRequest,
    ) -> Decision:
        self.audit.record(
            "payment.process",
            "blocked",
            layer,
            actor_id=principal.subject_id,
            resource_id=request.order_id,
            details={"reason": reason},
        )
        return Decision(False, layer, reason)

