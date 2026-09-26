"""
SentinelCore — AlertService
Creates Alerts from RiskAssessments and manages their full lifecycle.
Every state transition generates an AuditEntry (non-negotiable).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime

from config.settings import ALERT_MIN_SCORE
from domain.models import Alert, AuditEntry, RiskAssessment, _new_id

logger = logging.getLogger(__name__)


class AlertService:
    """Decides when to alert and manages the alert lifecycle."""

    ALERT_THRESHOLD: int = ALERT_MIN_SCORE

    def __init__(self) -> None:
        self._alerts: list[Alert] = []
        self._audit:  list[AuditEntry] = []

    # ── public API ───────────────────────────────────────────────────────────

    def shouldAlert(self, assessment: RiskAssessment) -> bool:
        return assessment.riskScore >= self.ALERT_THRESHOLD

    def createAlert(self, assessment: RiskAssessment) -> Alert:
        alert = Alert(
            alertId      = _new_id("ALT-"),
            severity     = assessment.riskLevel,
            status       = "NEW",
            createdAt    = datetime.now(),
            assessmentId = assessment.assessmentId,
        )
        self._alerts.append(alert)
        self._audit_transition(
            actor      = "system",
            action     = "ALERT_CREATED",
            alert      = alert,
            before     = {},
            after      = alert.toDict(),
        )
        logger.info(
            "Alert created: %s [%s] score=%d",
            alert.alertId, alert.severity, assessment.riskScore,
        )
        return alert

    def updateAlertStatus(
        self,
        alert:     Alert,
        newStatus: str,
        actorId:   str,
        note:      str = "",
    ) -> Alert:
        before = alert.toDict()
        method_map = {
            "ACKNOWLEDGED":  alert.acknowledge,
            "INVESTIGATING": alert.investigate,
            "ESCALATED":     alert.escalate,
            "RESOLVED":      lambda a=actorId: alert.resolve(a, note),
            "CLOSED":        alert.close,
        }
        method = method_map.get(newStatus)
        if not method:
            raise ValueError(f"Unknown target status: {newStatus}")

        if newStatus == "RESOLVED":
            method()
        else:
            method(actorId)

        self._audit_transition(
            actor  = actorId,
            action = f"ALERT_{newStatus}",
            alert  = alert,
            before = before,
            after  = alert.toDict(),
        )
        return alert

    def getAlerts(
        self,
        severity: str | None = None,
        status:   str | None = None,
    ) -> list[Alert]:
        result = self._alerts
        if severity:
            result = [a for a in result if a.severity == severity]
        if status:
            result = [a for a in result if a.status == status]
        # Most severe first, then most recent
        _level = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        return sorted(
            result,
            key=lambda a: (_level.get(a.severity, 0), a.createdAt),
            reverse=True,
        )

    def getAuditTrail(self) -> list[AuditEntry]:
        return list(self._audit)

    def getActiveCount(self) -> int:
        return sum(1 for a in self._alerts if a.status not in ("RESOLVED", "CLOSED"))

    # ── private ──────────────────────────────────────────────────────────────

    def _audit_transition(
        self,
        actor:  str,
        action: str,
        alert:  Alert,
        before: dict,
        after:  dict,
    ) -> None:
        entry = AuditEntry(
            entryId    = _new_id("AUD-"),
            actorId    = actor,
            action     = action,
            targetId   = alert.alertId,
            targetType = "alert",
            before     = json.dumps(before),
            after      = json.dumps(after),
            timestamp  = datetime.now(),
        )
        self._audit.append(entry)
        alert.auditEntries.append(entry.entryId)
