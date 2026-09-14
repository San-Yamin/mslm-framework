"""Append-only, structured audit events for research observations."""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class AuditEvent:
    event: str
    outcome: str
    layer: str
    occurred_at: str
    actor_id: Optional[str]
    resource_id: Optional[str]
    details: Dict[str, Any]


class AuditLog:
    def __init__(self) -> None:
        self._events: List[AuditEvent] = []
        self._lock = Lock()

    def record(
        self,
        event: str,
        outcome: str,
        layer: str,
        *,
        actor_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        entry = AuditEvent(
            event=event,
            outcome=outcome,
            layer=layer,
            occurred_at=datetime.now(timezone.utc).isoformat(),
            actor_id=actor_id,
            resource_id=resource_id,
            details=details or {},
        )
        with self._lock:
            self._events.append(entry)
        return entry

    def snapshot(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [asdict(event) for event in self._events]

