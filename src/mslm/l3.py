"""L3 signed price claims with replay resistance and key rotation."""

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import asdict, dataclass
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN
from threading import Lock
from typing import Dict, Optional, Set, Tuple


class TokenError(ValueError):
    pass


class InvalidToken(TokenError):
    pass


class ExpiredToken(TokenError):
    pass


class ReplayDetected(TokenError):
    pass


@dataclass(frozen=True)
class PaymentClaims:
    merchant_id: str
    user_id: str
    order_id: str
    amount_minor: int
    currency: str
    issued_at: int
    expires_at: int
    nonce: str
    key_id: str

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            asdict(self), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")


def amount_to_minor(amount: str, exponent: int = 2) -> int:
    try:
        decimal = Decimal(amount)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("invalid monetary amount") from exc
    if not decimal.is_finite() or decimal < 0:
        raise ValueError("amount must be finite and non-negative")
    quantum = Decimal(1).scaleb(-exponent)
    quantized = decimal.quantize(quantum, rounding=ROUND_HALF_EVEN)
    if quantized != decimal:
        raise ValueError("amount has too many fractional digits")
    return int(quantized.scaleb(exponent))


class KeyRing:
    def __init__(self) -> None:
        self._keys: Dict[Tuple[str, str], bytes] = {}
        self._active: Dict[str, str] = {}

    def add(self, merchant_id: str, key_id: str, key: bytes, *, active: bool = False) -> None:
        if len(key) < 32:
            raise ValueError("HMAC key must contain at least 32 bytes")
        self._keys[(merchant_id, key_id)] = bytes(key)
        if active:
            self._active[merchant_id] = key_id

    def rotate(self, merchant_id: str, key_id: str, key: Optional[bytes] = None) -> None:
        self.add(merchant_id, key_id, key or secrets.token_bytes(32), active=True)

    def active(self, merchant_id: str) -> Tuple[str, bytes]:
        try:
            key_id = self._active[merchant_id]
            return key_id, self._keys[(merchant_id, key_id)]
        except KeyError as exc:
            raise TokenError("no active merchant signing key") from exc

    def get(self, merchant_id: str, key_id: str) -> bytes:
        try:
            return self._keys[(merchant_id, key_id)]
        except KeyError as exc:
            raise InvalidToken("unknown signing key") from exc


class ReplayStore:
    """Atomic in-memory replay store suitable for controlled experiments.

    A production deployment must replace this with a shared durable store.
    """

    def __init__(self) -> None:
        self._consumed: Set[Tuple[str, str]] = set()
        self._lock = Lock()

    def consume(self, merchant_id: str, nonce: str) -> None:
        key = (merchant_id, nonce)
        with self._lock:
            if key in self._consumed:
                raise ReplayDetected("token nonce has already been consumed")
            self._consumed.add(key)


class PriceTokenService:
    def __init__(self, key_ring: KeyRing, replay_store: ReplayStore, ttl_seconds: int = 300) -> None:
        if not 1 <= ttl_seconds <= 3600:
            raise ValueError("ttl_seconds must be in [1, 3600]")
        self.key_ring = key_ring
        self.replay_store = replay_store
        self.ttl_seconds = ttl_seconds

    def issue(
        self,
        merchant_id: str,
        user_id: str,
        order_id: str,
        amount_minor: int,
        currency: str,
        *,
        now: Optional[int] = None,
        nonce: Optional[str] = None,
    ) -> Tuple[PaymentClaims, str]:
        if amount_minor < 0:
            raise ValueError("amount_minor must be non-negative")
        if len(currency) != 3 or not currency.isalpha():
            raise ValueError("currency must be a three-letter code")
        issued_at = int(time.time()) if now is None else int(now)
        key_id, key = self.key_ring.active(merchant_id)
        claims = PaymentClaims(
            merchant_id=merchant_id,
            user_id=user_id,
            order_id=order_id,
            amount_minor=amount_minor,
            currency=currency.upper(),
            issued_at=issued_at,
            expires_at=issued_at + self.ttl_seconds,
            nonce=nonce or secrets.token_urlsafe(24),
            key_id=key_id,
        )
        signature = hmac.new(key, claims.canonical_bytes(), hashlib.sha256).hexdigest()
        return claims, signature

    def verify(
        self,
        claims: PaymentClaims,
        signature: str,
        *,
        expected_merchant_id: str,
        expected_user_id: str,
        expected_order_id: str,
        expected_amount_minor: int,
        expected_currency: str,
        now: Optional[int] = None,
        consume: bool = True,
    ) -> None:
        key = self.key_ring.get(claims.merchant_id, claims.key_id)
        expected_signature = hmac.new(
            key, claims.canonical_bytes(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected_signature, signature):
            raise InvalidToken("signature mismatch")
        current = int(time.time()) if now is None else int(now)
        if claims.issued_at > current + 5:
            raise InvalidToken("token issued in the future")
        if current >= claims.expires_at:
            raise ExpiredToken("token expired")
        expected = (
            expected_merchant_id,
            expected_user_id,
            expected_order_id,
            expected_amount_minor,
            expected_currency.upper(),
        )
        actual = (
            claims.merchant_id,
            claims.user_id,
            claims.order_id,
            claims.amount_minor,
            claims.currency,
        )
        if not hmac.compare_digest(repr(actual), repr(expected)):
            raise InvalidToken("claims do not match payment request")
        if consume:
            self.replay_store.consume(claims.merchant_id, claims.nonce)

