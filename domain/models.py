"""
SentinelCore — Domain Layer
All entity classes (Layer 3).  Every field is typed; every method is documented.
No business logic beyond what is intrinsic to the entity itself.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from config.settings import (
    RISK_THRESHOLD_LOW,
    RISK_THRESHOLD_MEDIUM,
    RISK_THRESHOLD_HIGH,
    SENSITIVE_PATH_FRAGMENTS,
)


# ── helpers ──────────────────────────────────────────────────────────────────

def _new_id(prefix: str = "") -> str:
    return f"{prefix}{uuid.uuid4().hex[:12]}"


# ════════════════════════════════════════════════════════════════════════════
# PROCESS
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class Process:
    """Represents a running OS process captured by the collector."""

    processId:  str
    name:       str
    path:       str
    startTime:  datetime
    parentPid:  str
    user:       str
    status:     str
    cmdline:    str = ""
    _activities: list[str] = field(default_factory=list, repr=False)

    # ── public API ───────────────────────────────────────────────────────────

    def getInfo(self) -> dict:
        """Return a serialisable dictionary of all fields."""
        return {
            "processId": self.processId,
            "name":      self.name,
            "path":      self.path,
            "startTime": self.startTime.isoformat(),
            "parentPid": self.parentPid,
            "user":      self.user,
            "status":    self.status,
            "cmdline":   self.cmdline,
        }

    def recordActivity(self, activityId: str) -> None:
        """Link a FileActivity ID to this process."""
        if activityId not in self._activities:
            self._activities.append(activityId)

    def isFromSuspiciousPath(self) -> bool:
        """Return True if the executable lives in a known high-risk location."""
        lower = self.path.lower()
        return any(frag in lower for frag in SENSITIVE_PATH_FRAGMENTS
                   if frag in ("/tmp/", "/dev/shm/", "\\temp\\",
                               "\\appdata\\local\\temp\\",
                               "\\users\\public\\", "\\programdata\\"))


# ════════════════════════════════════════════════════════════════════════════
# NETWORK CONNECTION
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class NetworkConnection:
    """Represents a single active network socket / connection."""

    connectionId:  str
    localAddress:  str
    localPort:     int
    destination:   str   # remote IP
    port:          int   # remote port
    protocol:      str   # TCP / UDP
    state:         str
    processId:     str   # FK → Process.processId

    def getInfo(self) -> dict:
        return {
            "connectionId": self.connectionId,
            "localAddress": self.localAddress,
            "localPort":    self.localPort,
            "destination":  self.destination,
            "port":         self.port,
            "protocol":     self.protocol,
            "state":        self.state,
            "processId":    self.processId,
        }

    def linkProcess(self, processId: str) -> None:
        """Update the owning process ID (e.g. after re-identification)."""
        self.processId = processId


# ════════════════════════════════════════════════════════════════════════════
# FILE ACTIVITY
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class FileActivity:
    """Represents a file system change event."""

    activityId: str
    filePath:   str
    actionType: str       # CREATE / MODIFY / DELETE / ACCESS / RENAME
    timestamp:  datetime
    processId:  str       # FK → Process.processId (may be empty)

    SENSITIVE_PATHS: list[str] = field(
        default_factory=lambda: SENSITIVE_PATH_FRAGMENTS, repr=False
    )

    def getInfo(self) -> dict:
        return {
            "activityId": self.activityId,
            "filePath":   self.filePath,
            "actionType": self.actionType,
            "timestamp":  self.timestamp.isoformat(),
            "processId":  self.processId,
            "isSensitive": self.isSensitive(),
        }

    def isSensitive(self) -> bool:
        """Return True if the file path falls under a sensitive directory."""
        lower = self.filePath.lower()
        return any(frag in lower for frag in self.SENSITIVE_PATHS)


# ════════════════════════════════════════════════════════════════════════════
# SECURITY EVENT  (normalization boundary)
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class SecurityEvent:
    """
    The central unified model.
    Every raw OS data point is converted to a SecurityEvent before analysis.
    Nothing downstream ever receives raw dicts from collectors.
    """

    eventId:    str
    eventType:  str       # PROCESS_ANOMALY / NETWORK_SUSPICIOUS / FILE_CHANGE / LOG_ALERT
    sourceId:   str       # FK to the originating object
    sourceType: str       # "process" / "network" / "file" / "log"
    timestamp:  datetime
    rawData:    dict      # original collected fields — preserved for traceability
    context:    str       # human-readable summary of why this was flagged
    indicators: list[str] = field(default_factory=list)  # FK → ThreatIndicator.indicatorId

    def addIndicator(self, indicatorId: str) -> None:
        if indicatorId not in self.indicators:
            self.indicators.append(indicatorId)

    def getContext(self) -> str:
        return self.context

    def toDict(self) -> dict:
        return {
            "eventId":    self.eventId,
            "eventType":  self.eventType,
            "sourceId":   self.sourceId,
            "sourceType": self.sourceType,
            "timestamp":  self.timestamp.isoformat(),
            "context":    self.context,
            "indicators": self.indicators,
            "rawData":    self.rawData,
        }


# ════════════════════════════════════════════════════════════════════════════
# THREAT INDICATOR
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class ThreatIndicator:
    """Represents an Indicator of Compromise (IOC)."""

    indicatorId: str
    type:        str   # IP / DOMAIN / HASH / PATH / BEHAVIOR
    value:       str
    source:      str   # "internal" or provider name
    confidence:  int   # 0–100

    def matches(self, value: str) -> bool:
        """Case-insensitive exact match."""
        return self.value.lower() == value.lower()

    def partialMatch(self, value: str) -> bool:
        """Check if indicator value is a substring of the target."""
        return self.value.lower() in value.lower()

    def updateConfidence(self, newValue: int) -> None:
        self.confidence = max(0, min(100, newValue))

    def toDict(self) -> dict:
        return {
            "indicatorId": self.indicatorId,
            "type":        self.type,
            "value":       self.value,
            "source":      self.source,
            "confidence":  self.confidence,
        }


# ════════════════════════════════════════════════════════════════════════════
# ANALYSIS RESULT  (intermediate VO used by SecurityAnalyzer)
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class AnalysisResult:
    """Value object returned by SecurityAnalyzer.analyze*() methods."""

    isSuspicious:  bool
    reason:        str
    indicatorIds:  list[str] = field(default_factory=list)
    confidence:    int = 0    # 0–100


# ════════════════════════════════════════════════════════════════════════════
# RISK ASSESSMENT
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class RiskAssessment:
    """
    The computed risk evaluation for a SecurityEvent or CorrelationCase.
    riskScore MUST always be paired with a non-empty explanation.
    """

    assessmentId:    str
    targetId:        str    # FK → SecurityEvent.eventId OR CorrelationCase.caseId
    targetType:      str    # "event" / "case"
    riskScore:       int    # 0–100
    riskLevel:       str    # LOW / MEDIUM / HIGH / CRITICAL
    explanation:     str
    contributingIds: list[str] = field(default_factory=list)
    timestamp:       datetime = field(default_factory=datetime.now)

    # ── static helpers ───────────────────────────────────────────────────────

    @staticmethod
    def determineLevel(score: int) -> str:
        if score >= RISK_THRESHOLD_HIGH:
            return "CRITICAL"
        if score >= RISK_THRESHOLD_MEDIUM:
            return "HIGH"
        if score >= RISK_THRESHOLD_LOW:
            return "MEDIUM"
        return "LOW"

    def explain(self) -> str:
        return self.explanation

    def toDict(self) -> dict:
        return {
            "assessmentId":    self.assessmentId,
            "targetId":        self.targetId,
            "targetType":      self.targetType,
            "riskScore":       self.riskScore,
            "riskLevel":       self.riskLevel,
            "explanation":     self.explanation,
            "contributingIds": self.contributingIds,
            "timestamp":       self.timestamp.isoformat(),
        }


# ════════════════════════════════════════════════════════════════════════════
# CORRELATION CASE
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class CorrelationCase:
    """Groups related SecurityEvents into a single investigable case."""

    caseId:     str
    confidence: int         # 0–100
    status:     str         # OPEN / UNDER_REVIEW / CLOSED
    reason:     str
    eventIds:   list[str] = field(default_factory=list)
    createdAt:  datetime   = field(default_factory=datetime.now)

    def addEvent(self, eventId: str) -> None:
        if eventId not in self.eventIds:
            self.eventIds.append(eventId)

    def eventCount(self) -> int:
        return len(self.eventIds)

    def toDict(self) -> dict:
        return {
            "caseId":     self.caseId,
            "confidence": self.confidence,
            "status":     self.status,
            "reason":     self.reason,
            "eventIds":   self.eventIds,
            "createdAt":  self.createdAt.isoformat(),
        }


# ════════════════════════════════════════════════════════════════════════════
# ALERT
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class Alert:
    """
    Security alert with full lifecycle state machine.
    State transitions: NEW → ACKNOWLEDGED → INVESTIGATING → RESOLVED → CLOSED
                                                ↓
                                           ESCALATED → INVESTIGATING
    Every transition creates an AuditEntry (enforced by AlertService).
    """

    alertId:      str
    severity:     str          # mirrors RiskAssessment.riskLevel
    status:       str          # NEW / ACKNOWLEDGED / INVESTIGATING / ESCALATED / RESOLVED / CLOSED
    createdAt:    datetime
    assessmentId: str          # FK → RiskAssessment
    assignedTo:   str = ""
    auditEntries: list[str] = field(default_factory=list)

    VALID_TRANSITIONS: dict[str, list[str]] = field(default_factory=lambda: {
        "NEW":           ["ACKNOWLEDGED"],
        "ACKNOWLEDGED":  ["INVESTIGATING", "ESCALATED"],
        "INVESTIGATING": ["RESOLVED", "ESCALATED"],
        "ESCALATED":     ["INVESTIGATING"],
        "RESOLVED":      ["CLOSED"],
        "CLOSED":        [],
    }, repr=False)

    def _transition(self, newStatus: str) -> None:
        allowed = self.VALID_TRANSITIONS.get(self.status, [])
        if newStatus not in allowed:
            raise ValueError(
                f"Invalid alert transition: {self.status} → {newStatus}. "
                f"Allowed: {allowed}"
            )
        self.status = newStatus

    def acknowledge(self, actorId: str) -> None:
        self._transition("ACKNOWLEDGED")

    def escalate(self, actorId: str) -> None:
        self._transition("ESCALATED")

    def investigate(self, actorId: str) -> None:
        self._transition("INVESTIGATING")

    def resolve(self, actorId: str, resolution: str = "") -> None:
        self._transition("RESOLVED")

    def close(self, actorId: str) -> None:
        self._transition("CLOSED")

    def toDict(self) -> dict:
        return {
            "alertId":      self.alertId,
            "severity":     self.severity,
            "status":       self.status,
            "createdAt":    self.createdAt.isoformat(),
            "assessmentId": self.assessmentId,
            "assignedTo":   self.assignedTo,
        }


# ════════════════════════════════════════════════════════════════════════════
# HISTORICAL RISK PROFILE
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class HistoricalRiskProfile:
    """Time-series history of risk assessments for trend analysis."""

    profileId:    str
    entityId:     str   # device ID, network segment, or "global"
    trend:        str   # RISING / STABLE / DECLINING
    averageScore: float
    assessments:  list[RiskAssessment] = field(default_factory=list)
    peaks:        list[datetime]       = field(default_factory=list)

    def addAssessment(self, assessment: RiskAssessment) -> None:
        self.assessments.append(assessment)
        scores = [a.riskScore for a in self.assessments]
        self.averageScore = sum(scores) / len(scores)
        self.trend = self.calculateTrend()
        if assessment.riskScore >= RISK_THRESHOLD_HIGH:
            self.peaks.append(assessment.timestamp)

    def calculateTrend(self) -> str:
        if len(self.assessments) < 3:
            return "STABLE"
        recent = [a.riskScore for a in self.assessments[-5:]]
        if recent[-1] > recent[0] + 10:
            return "RISING"
        if recent[-1] < recent[0] - 10:
            return "DECLINING"
        return "STABLE"

    def getPeaks(self, threshold: int = 75) -> list[datetime]:
        return [a.timestamp for a in self.assessments if a.riskScore >= threshold]

    def toDict(self) -> dict:
        return {
            "profileId":    self.profileId,
            "entityId":     self.entityId,
            "trend":        self.trend,
            "averageScore": round(self.averageScore, 1),
            "peakCount":    len(self.peaks),
            "totalSamples": len(self.assessments),
        }


# ════════════════════════════════════════════════════════════════════════════
# SCENARIO ANALYSIS
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class ScenarioAnalysis:
    """What-If simulation.  Never modifies live data."""

    scenarioId:     str
    name:           str
    description:    str
    baselineScore:  int
    hypotheses:     dict   # {"assumption": "changed value"}
    projectedScore: int = 0
    delta:          int = 0
    createdAt:      datetime = field(default_factory=datetime.now)
    profileId:      str = ""

    def run(self, profile: HistoricalRiskProfile) -> None:
        """
        Apply hypotheses to the baseline and compute a projected score.
        This is a simulation — it only reads from the profile.
        """
        base = profile.averageScore
        adjustment = 0

        for assumption, value in self.hypotheses.items():
            lower = assumption.lower()
            # Simple rule-based projection engine
            if "firewall" in lower and "remove" in lower:
                adjustment += 20
            elif "firewall" in lower and "add" in lower:
                adjustment -= 15
            elif "threat intel" in lower and "add" in lower:
                adjustment -= 10
            elif "patch" in lower:
                adjustment -= 12
            elif "admin" in lower and "remove" in lower:
                adjustment -= 8
            elif "encryption" in lower and "add" in lower:
                adjustment -= 5
            elif "monitoring" in lower and "disable" in lower:
                adjustment += 25
            else:
                # unknown hypothesis: neutral
                adjustment += 0

        self.projectedScore = max(0, min(100, int(base + adjustment)))
        self.delta = self.projectedScore - int(base)
        self.baselineScore = int(base)

    def compareBaseline(self) -> str:
        direction = "INCREASE" if self.delta > 0 else "DECREASE"
        return (
            f"Scenario '{self.name}': baseline {self.baselineScore} → "
            f"projected {self.projectedScore} "
            f"({direction} of {abs(self.delta)} points). "
            f"Hypotheses applied: {json.dumps(self.hypotheses)}"
        )

    def toDict(self) -> dict:
        return {
            "scenarioId":     self.scenarioId,
            "name":           self.name,
            "description":    self.description,
            "baselineScore":  self.baselineScore,
            "projectedScore": self.projectedScore,
            "delta":          self.delta,
            "hypotheses":     self.hypotheses,
            "createdAt":      self.createdAt.isoformat(),
        }


# ════════════════════════════════════════════════════════════════════════════
# AUDIT ENTRY
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class AuditEntry:
    """Records any sensitive action for the audit trail. Non-negotiable."""

    entryId:    str
    actorId:    str
    action:     str
    targetId:   str
    targetType: str
    before:     str   # JSON string of state before
    after:      str   # JSON string of state after
    timestamp:  datetime

    def describe(self) -> str:
        return (
            f"[{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] "
            f"Actor={self.actorId} | Action={self.action} | "
            f"Target={self.targetType}/{self.targetId}"
        )

    def toDict(self) -> dict:
        return {
            "entryId":    self.entryId,
            "actorId":    self.actorId,
            "action":     self.action,
            "targetId":   self.targetId,
            "targetType": self.targetType,
            "before":     self.before,
            "after":      self.after,
            "timestamp":  self.timestamp.isoformat(),
        }


# ════════════════════════════════════════════════════════════════════════════
# RECOMMENDATION
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class Recommendation:
    """Strategic security recommendation generated by the RecommendationEngine."""

    title:       str
    description: str
    priority:    str        # HIGH / MEDIUM / LOW
    evidenceIds: list[str]  # IDs of events/assessments that support this
    impact:      str        # expected risk reduction if implemented

    def toDict(self) -> dict:
        return {
            "title":       self.title,
            "description": self.description,
            "priority":    self.priority,
            "evidenceIds": self.evidenceIds,
            "impact":      self.impact,
        }
