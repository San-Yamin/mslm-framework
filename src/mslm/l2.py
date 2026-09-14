"""L2 authentication, authorisation, ownership and response minimisation."""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, FrozenSet, Mapping, Optional


class Role(str, Enum):
    USER = "user"
    MERCHANT = "merchant"
    ADMIN = "admin"


@dataclass(frozen=True)
class Principal:
    subject_id: str
    role: Role
    merchant_id: Optional[str] = None
    authenticated: bool = True


PERMISSIONS: Mapping[Role, FrozenSet[str]] = {
    Role.USER: frozenset({"transaction:read:own", "payment:create:own"}),
    Role.MERCHANT: frozenset({"transaction:read:merchant", "token:issue:merchant"}),
    Role.ADMIN: frozenset({"merchant:approve", "audit:read", "permission:grant"}),
}


class AccessDenied(PermissionError):
    pass


def require_permission(principal: Principal, permission: str) -> None:
    if not principal.authenticated:
        raise AccessDenied("authentication required")
    if permission not in PERMISSIONS.get(principal.role, frozenset()):
        raise AccessDenied("permission denied")


def require_owner(principal: Principal, owner_id: str) -> None:
    if not principal.authenticated or principal.subject_id != owner_id:
        raise AccessDenied("resource ownership check failed")


def require_merchant(principal: Principal, merchant_id: str) -> None:
    if (
        not principal.authenticated
        or principal.role is not Role.MERCHANT
        or principal.merchant_id != merchant_id
    ):
        raise AccessDenied("merchant boundary check failed")


_REMOVE = {"cvv", "pin", "password", "secret", "secret_key", "access_token"}


def minimize_response(value: Any) -> Any:
    """Recursively omit secrets and mask PAN/SSN values."""
    if isinstance(value, list):
        return [minimize_response(item) for item in value]
    if not isinstance(value, dict):
        return value
    result: Dict[str, Any] = {}
    for key, item in value.items():
        lowered = str(key).lower()
        if lowered in _REMOVE:
            continue
        if lowered in {"pan", "card_number"}:
            digits = "".join(character for character in str(item) if character.isdigit())
            result[key] = f"************{digits[-4:]}" if len(digits) >= 4 else "****"
        elif lowered == "ssn":
            result[key] = "***-**-" + str(item)[-4:]
        else:
            result[key] = minimize_response(item)
    return result

