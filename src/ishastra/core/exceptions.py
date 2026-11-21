"""Risk exception lifecycle: background expiration, webhook/email notifications, audit chain.

This module manages the lifecycle of risk exceptions for findings:
- Background worker flips expired exceptions from 'approved'/'pending' to 'expired'
- Webhook/email notifications on exception request → decision → expiry
- All state changes are audit-chained for tamper evidence
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

from ishastra.audit import AuditChain
from ishastra.config import get_settings
from ishastra.core import store
from ishastra.monitor import WebhookAlertSink

log = logging.getLogger(__name__)


EXCEPTION_NONE = "none"
EXCEPTION_PENDING = "pending"
EXCEPTION_APPROVED = "approved"
EXCEPTION_REJECTED = "rejected"
EXCEPTION_EXPIRED = "expired"

VALID_EXCEPTION_STATES = frozenset(
    {
        EXCEPTION_NONE,
        EXCEPTION_PENDING,
        EXCEPTION_APPROVED,
        EXCEPTION_REJECTED,
        EXCEPTION_EXPIRED,
    }
)


EVENT_EXCEPTION_REQUESTED = "exception_requested"
EVENT_EXCEPTION_APPROVED = "exception_approved"
EVENT_EXCEPTION_REJECTED = "exception_rejected"
EVENT_EXCEPTION_EXPIRED = "exception_expired"


DEFAULT_EXPIRATION_CHECK_INTERVAL = 3600


@dataclass
class ExceptionNotification:
    """Notification payload for exception lifecycle events."""

    event: str
    tenant_id: str
    fingerprint: str
    exception_state: str
    exception_until: float | None
    exception_reason: str
    requested_by: str
    decided_by: str | None = None
    note: str = ""
    timestamp: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "event": self.event,
            "tenant_id": self.tenant_id,
            "fingerprint": self.fingerprint,
            "exception_state": self.exception_state,
            "exception_until": self.exception_until,
            "exception_reason": self.exception_reason,
            "requested_by": self.requested_by,
            "decided_by": self.decided_by,
            "note": self.note,
            "timestamp": self.timestamp or time.time(),
        }


async def get_pending_exceptions(*, tenant: str | None = None) -> list[dict[str, Any]]:
    """Get all findings with pending or approved exceptions that may need expiration."""
    db = await store.get_database()
    async with db.transaction() as conn:
        where = "WHERE exception_state IN ('pending', 'approved') AND exception_until IS NOT NULL"
        params: list[Any] = []
        if tenant is not None:
            where += " AND tenant = ?"
            params.append(tenant)
        rows = await store._fetchall(
            conn,
            f"""SELECT tenant, fingerprint, exception_state, exception_until,
                       exception_reason, exception_requested_by, exception_decided_by,
                       exception_note, exception_requested_at, exception_decided_at
                  FROM finding_records
                  {where}
                  ORDER BY exception_until""",
            *params,
        )
    return [dict(row) for row in rows]


async def expire_exceptions(*, tenant: str | None = None) -> int:
    """Flip expired exceptions to 'expired' state. Returns count of expired exceptions.

    This is called by the background worker. It only processes exceptions
    that are currently 'pending' or 'approved' and whose until timestamp
    has passed.
    """
    now = time.time()
    expired_count = 0

    db = await store.get_database()
    async with db.transaction() as conn:
        where = (
            "WHERE exception_state IN ('pending', 'approved') "
            "AND exception_until IS NOT NULL "
            "AND exception_until <= ?"
        )
        params: list[Any] = [now]
        if tenant is not None:
            where += " AND tenant = ?"
            params.append(tenant)

        rows = await store._fetchall(
            conn,
            f"""SELECT tenant, fingerprint, exception_state, exception_until,
                       exception_reason, exception_requested_by, exception_decided_by,
                       exception_note, exception_requested_at, exception_decided_at
                  FROM finding_records
                  {where}""",
            *params,
        )

        for row in rows:
            await store._execute(
                conn,
                """UPDATE finding_records
                      SET exception_state = ?, updated_at = ?
                    WHERE tenant = ? AND fingerprint = ?""",
                EXCEPTION_EXPIRED,
                now,
                row["tenant"],
                row["fingerprint"],
            )

            audit_chain = AuditChain(
                persistent=True,
                hmac_key=get_settings().audit_hmac_key or "",
            )
            await audit_chain.append_async(
                {
                    "event": EVENT_EXCEPTION_EXPIRED,
                    "tenant": row["tenant"],
                    "fingerprint": row["fingerprint"],
                    "previous_state": row["exception_state"],
                    "expired_at": now,
                    "exception_until": row["exception_until"],
                }
            )

            await _notify_exception_event(
                tenant_id=row["tenant"],
                fingerprint=row["fingerprint"],
                event=EVENT_EXCEPTION_EXPIRED,
                exception_state=EXCEPTION_EXPIRED,
                exception_until=row["exception_until"],
                exception_reason=row["exception_reason"],
                requested_by=row["exception_requested_by"],
                decided_by=row["exception_decided_by"],
                note=f"Exception expired at {time.ctime(now)}",
            )

            expired_count += 1

    if expired_count:
        log.info("Expired %d risk exception(s)", expired_count)
    return expired_count


async def _notify_exception_event(
    *,
    tenant_id: str,
    fingerprint: str,
    event: str,
    exception_state: str,
    exception_until: float | None,
    exception_reason: str,
    requested_by: str,
    decided_by: str | None = None,
    note: str = "",
) -> None:
    """Send webhook notification for an exception lifecycle event."""
    try:
        settings = get_settings()
        sinks = await store.load_webhook_sinks()
        if not sinks:
            return

        notification = ExceptionNotification(
            event=event,
            tenant_id=tenant_id,
            fingerprint=fingerprint,
            exception_state=exception_state,
            exception_until=exception_until,
            exception_reason=exception_reason,
            requested_by=requested_by,
            decided_by=decided_by,
            note=note,
            timestamp=time.time(),
        )

        for sink_data in sinks:
            try:
                sink = WebhookAlertSink(
                    name=sink_data["name"],
                    url=sink_data["url"],
                    secret=settings.webhook_secret or "",
                )
                await sink.send(notification.to_dict())
            except Exception as exc:
                log.warning("Failed to send exception notification to webhook %s: %s", sink_data["name"], exc)
    except Exception as exc:
        log.exception("Error sending exception notifications: %s", exc)


async def record_exception_request(
    *,
    tenant: str,
    fingerprint: str,
    until: float,
    reason: str,
    requested_by: str,
) -> dict[str, Any] | None:
    """Record a new exception request and notify. Returns the updated finding record."""
    now = time.time()
    db = await store.get_database()
    async with db.transaction() as conn:
        await store._execute(
            conn,
            """INSERT INTO finding_records
                   (tenant, fingerprint, exception_until, exception_reason,
                    exception_state, exception_requested_by, exception_requested_at,
                    updated_at)
               VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)
               ON CONFLICT (tenant, fingerprint) DO UPDATE SET
                   exception_until = excluded.exception_until,
                   exception_reason = excluded.exception_reason,
                   exception_state = 'pending',
                   exception_requested_by = excluded.exception_requested_by,
                   exception_requested_at = excluded.exception_requested_at,
                   exception_decided_by = '',
                   exception_decided_at = NULL,
                   exception_note = '',
                   exception_approved_by = '',
                   updated_at = excluded.updated_at""",
            tenant,
            fingerprint,
            until,
            reason,
            requested_by,
            now,
            now,
        )
        row = await store._fetchone(
            conn,
            "SELECT * FROM finding_records WHERE tenant = ? AND fingerprint = ?",
            tenant,
            fingerprint,
        )

    if row is None:
        return None

    audit_chain = AuditChain(
        persistent=True,
        hmac_key=get_settings().audit_hmac_key or "",
    )
    await audit_chain.append_async(
        {
            "event": EVENT_EXCEPTION_REQUESTED,
            "tenant": tenant,
            "fingerprint": fingerprint,
            "until": until,
            "reason": reason,
            "requested_by": requested_by,
        }
    )

    await _notify_exception_event(
        tenant_id=tenant,
        fingerprint=fingerprint,
        event=EVENT_EXCEPTION_REQUESTED,
        exception_state=EXCEPTION_PENDING,
        exception_until=until,
        exception_reason=reason,
        requested_by=requested_by,
    )

    return dict(row)


async def record_exception_decision(
    *,
    tenant: str,
    fingerprint: str,
    approved: bool,
    decided_by: str,
    note: str = "",
) -> dict[str, Any] | None:
    """Record an exception decision (approve/reject) and notify."""
    now = time.time()
    new_state = EXCEPTION_APPROVED if approved else EXCEPTION_REJECTED

    db = await store.get_database()
    async with db.transaction() as conn:
        row = await store._fetchone(
            conn,
            "SELECT * FROM finding_records WHERE tenant = ? AND fingerprint = ?",
            tenant,
            fingerprint,
        )
        if row is None or row["exception_state"] != EXCEPTION_PENDING:
            return None

        await store._execute(
            conn,
            """UPDATE finding_records
                  SET exception_state = ?, exception_decided_by = ?,
                      exception_decided_at = ?, exception_note = ?,
                      exception_approved_by = ?, updated_at = ?
                WHERE tenant = ? AND fingerprint = ?""",
            new_state,
            decided_by,
            now,
            note,
            decided_by if approved else "",
            now,
            tenant,
            fingerprint,
        )
        updated = await store._fetchone(
            conn,
            "SELECT * FROM finding_records WHERE tenant = ? AND fingerprint = ?",
            tenant,
            fingerprint,
        )

    if updated is None:
        return None

    audit_chain = AuditChain(
        persistent=True,
        hmac_key=get_settings().audit_hmac_key or "",
    )
    await audit_chain.append_async(
        {
            "event": EVENT_EXCEPTION_APPROVED if approved else EVENT_EXCEPTION_REJECTED,
            "tenant": tenant,
            "fingerprint": fingerprint,
            "decided_by": decided_by,
            "note": note,
        }
    )

    await _notify_exception_event(
        tenant_id=tenant,
        fingerprint=fingerprint,
        event=EVENT_EXCEPTION_APPROVED if approved else EVENT_EXCEPTION_REJECTED,
        exception_state=new_state,
        exception_until=updated["exception_until"],
        exception_reason=updated["exception_reason"],
        requested_by=updated["exception_requested_by"],
        decided_by=decided_by,
        note=note,
    )

    return dict(updated)


async def run_exception_expiration_job() -> int:
    """Run one iteration of the exception expiration check.

    This is designed to be called by a scheduler (APScheduler, cron, etc.)
    rather than as a long-running worker.
    """
    return await expire_exceptions()
