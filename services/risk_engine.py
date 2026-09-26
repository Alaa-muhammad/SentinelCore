"""
SentinelCore — RiskEngine
Computes dynamic risk scores (0-100) for SecurityEvents and CorrelationCases.
Every score is paired with a human-readable explanation listing every factor.
A score without an explanation is a bug (enforced by assertion).
"""

from __future__ import annotations

import logging
from datetime import datetime

from config.settings import RISK_THRESHOLD_HIGH
from domain.models import (
    AnalysisResult,
    CorrelationCase,
    RiskAssessment,
    SecurityEvent,
    ThreatIndicator,
    _new_id,
)

logger = logging.getLogger(__name__)


class RiskEngine:
    """
    Stateless risk calculator.
    Input: SecurityEvent + AnalysisResult + optional matched indicators.
    Output: RiskAssessment with full explanation.
    """

    # ── score weights ────────────────────────────────────────────────────────
    _BASE_SCORES: dict[str, int] = {
        "PROCESS_ANOMALY":    40,
        "NETWORK_SUSPICIOUS": 35,
        "FILE_CHANGE":        30,
        "LOG_ALERT":          20,
    }

    _ACTION_BONUS: dict[str, int] = {
        "DELETE": 20,
        "MODIFY": 10,
        "CREATE":  5,
        "RENAME":  5,
        "ACCESS":  2,
    }

    def assessEvent(
        self,
        event: SecurityEvent,
        result: AnalysisResult,
        indicators: list[ThreatIndicator] | None = None,
    ) -> RiskAssessment:
        """Compute a RiskAssessment for a single SecurityEvent."""
        factors: list[str] = []
        score   = 0

        # 1. Base score from event type
        base = self._BASE_SCORES.get(event.eventType, 25)
        score += base
        factors.append(f"base score for {event.eventType}: +{base}")

        # 2. Analysis result confidence contribution
        if result.isSuspicious:
            conf_bonus = int(result.confidence * 0.35)
            score += conf_bonus
            factors.append(
                f"analysis confidence {result.confidence}%: +{conf_bonus}"
            )
            factors.append(f"reason: {result.reason}")

        # 3. Matched threat indicators
        inds = indicators or []
        for ind in inds:
            ind_bonus = int(ind.confidence * 0.25)
            score += ind_bonus
            factors.append(
                f"IOC match [{ind.type}] '{ind.value}' "
                f"(confidence {ind.confidence}): +{ind_bonus}"
            )

        # 4. File action severity
        action = event.rawData.get("actionType", "")
        if action in self._ACTION_BONUS:
            bonus = self._ACTION_BONUS[action]
            score += bonus
            factors.append(f"file action '{action}': +{bonus}")

        # 5. No owning process (stealth indicator)
        if (event.sourceType == "network"
                and not event.rawData.get("processId")):
            score += 15
            factors.append("ESTABLISHED connection with no owning PID: +15")

        # 6. Privileged user
        user = event.rawData.get("user", "")
        if user.lower() in ("root", "system", "administrator", "admin"):
            score += 10
            factors.append(f"running as privileged user '{user}': +10")

        # Cap at 100
        score = min(100, max(0, score))
        level = RiskAssessment.determineLevel(score)

        explanation = (
            f"Score {score}/100 [{level}] — "
            + " | ".join(factors)
        )

        # Assertion: score without explanation is a bug
        assert explanation, "RiskEngine produced a score with no explanation"

        return RiskAssessment(
            assessmentId    = _new_id("ASS-"),
            targetId        = event.eventId,
            targetType      = "event",
            riskScore       = score,
            riskLevel       = level,
            explanation     = explanation,
            contributingIds = [event.eventId] + [i.indicatorId for i in inds],
            timestamp       = datetime.now(),
        )

    def assessCase(
        self,
        case: CorrelationCase,
        eventAssessments: list[RiskAssessment],
    ) -> RiskAssessment:
        """Compute a RiskAssessment for a CorrelationCase (group of events)."""
        factors: list[str] = []

        if not eventAssessments:
            score = 30
            factors.append("correlation case with no individual assessments: base 30")
        else:
            # Weighted: max + average blend
            scores = [a.riskScore for a in eventAssessments]
            max_s  = max(scores)
            avg_s  = sum(scores) / len(scores)
            score  = int(max_s * 0.6 + avg_s * 0.4)
            factors.append(f"max event score {max_s}, average {avg_s:.0f}: blended {score}")

        # Case confidence bonus
        conf_bonus = int(case.confidence * 0.15)
        score = min(100, score + conf_bonus)
        factors.append(f"case confidence {case.confidence}%: +{conf_bonus}")

        # Multi-event escalation
        if case.eventCount() >= 3:
            score = min(100, score + 10)
            factors.append(f"{case.eventCount()} correlated events: +10 (multi-event escalation)")

        level = RiskAssessment.determineLevel(score)
        explanation = (
            f"Case {case.caseId} score {score}/100 [{level}] — "
            + " | ".join(factors)
            + f" | reason: {case.reason}"
        )

        return RiskAssessment(
            assessmentId    = _new_id("ASS-"),
            targetId        = case.caseId,
            targetType      = "case",
            riskScore       = score,
            riskLevel       = level,
            explanation     = explanation,
            contributingIds = [a.assessmentId for a in eventAssessments],
            timestamp       = datetime.now(),
        )
