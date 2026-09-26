"""
SentinelCore — SecurityAnalyzer
Analyzes SecurityEvents, extracts ThreatIndicators, assigns analysis results.
Single Responsibility: decides *whether* something is suspicious and *why*.
Does NOT compute risk scores — that is RiskEngine's job.
"""

from __future__ import annotations

import logging
from datetime import datetime

from config.settings import (
    SUSPICIOUS_PATH_FRAGMENTS,
    SUSPICIOUS_PORTS,
    SENSITIVE_PATH_FRAGMENTS,
    TRUSTED_PROCESS_NAMES,
    TRUSTED_PROCESS_PATH_PREFIXES,
)
from domain.models import (
    AnalysisResult,
    FileActivity,
    NetworkConnection,
    Process,
    SecurityEvent,
    ThreatIndicator,
    _new_id,
)

logger = logging.getLogger(__name__)


class SecurityAnalyzer:
    """
    Core analysis engine.  Stateless — pass in objects, get results out.
    Does not own or store any events.
    """

    def __init__(self, indicators: list[ThreatIndicator] | None = None) -> None:
        self._indicators: list[ThreatIndicator] = indicators or []

    def setIndicators(self, indicators: list[ThreatIndicator]) -> None:
        self._indicators = indicators

    # ── public analysis methods ──────────────────────────────────────────────

    def analyzeProcess(self, p: Process) -> AnalysisResult:
        reasons: list[str] = []
        matched_ids: list[str] = []
        confidence = 0

        path_lower = p.path.lower()
        name_lower = p.name.lower()

        # ── whitelist short-circuit ──────────────────────────────────────────
        # Signed Windows OS binaries and Microsoft Defender components (e.g.
        # PID 0/4, DefenderSessionHelper.exe, MpDefenderCoreService.exe,
        # NisSrv.exe) legitimately run under paths like C:\ProgramData, which
        # would otherwise match SUSPICIOUS_PATH_FRAGMENTS below and get scored
        # as HIGH/CRITICAL. Trust by exact name or by known-good install path
        # before running any suspicion heuristics.
        if name_lower in TRUSTED_PROCESS_NAMES or (
            path_lower and path_lower.startswith(TRUSTED_PROCESS_PATH_PREFIXES)
        ):
            return AnalysisResult(
                isSuspicious = False,
                reason       = "clean (trusted system/security binary)",
                indicatorIds = [],
                confidence   = 0,
            )

        for frag in SUSPICIOUS_PATH_FRAGMENTS:
            if frag in path_lower:
                reasons.append(f"executable in suspicious path: {p.path}")
                confidence = max(confidence, 70)
                break

        ind = self._match_indicators(p.path)
        if ind:
            reasons.append(f"path matches IOC [{ind.type}]: {ind.value}")
            matched_ids.append(ind.indicatorId)
            confidence = max(confidence, ind.confidence)

        ind2 = self._match_indicators(p.name)
        if ind2 and ind2 not in ([ind] if ind else []):
            reasons.append(f"name matches IOC [{ind2.type}]: {ind2.value}")
            matched_ids.append(ind2.indicatorId)
            confidence = max(confidence, ind2.confidence)

        if p.status == "zombie":
            reasons.append("zombie process")
            confidence = max(confidence, 40)

        if not p.path and p.status not in ("zombie", "dead", "stopped"):
            reasons.append("no executable path (possible hollow process)")
            confidence = max(confidence, 65)

        return AnalysisResult(
            isSuspicious = bool(reasons),
            reason       = "; ".join(reasons) if reasons else "clean",
            indicatorIds = matched_ids,
            confidence   = confidence,
        )

    def analyzeNetwork(self, n: NetworkConnection) -> AnalysisResult:
        reasons: list[str] = []
        matched_ids: list[str] = []
        confidence = 0

        if n.port in SUSPICIOUS_PORTS:
            reasons.append(f"suspicious remote port {n.port}")
            confidence = max(confidence, 75)

        ind = self._match_indicators(n.destination)
        if ind:
            reasons.append(f"destination matches IOC [{ind.type}]: {ind.value}")
            matched_ids.append(ind.indicatorId)
            confidence = max(confidence, ind.confidence)

        if n.port > 49000 and n.destination and not n.destination.startswith("127."):
            reasons.append(f"high ephemeral outbound port {n.port}")
            confidence = max(confidence, 50)

        if n.state == "ESTABLISHED" and not n.processId:
            reasons.append("established connection with no owning PID")
            confidence = max(confidence, 80)

        return AnalysisResult(
            isSuspicious = bool(reasons),
            reason       = "; ".join(reasons) if reasons else "clean",
            indicatorIds = matched_ids,
            confidence   = confidence,
        )

    def analyzeFile(self, f: FileActivity) -> AnalysisResult:
        reasons: list[str] = []
        matched_ids: list[str] = []
        confidence = 0

        path_lower = f.filePath.lower()

        if f.isSensitive():
            reasons.append(f"activity on sensitive path: {f.filePath}")
            confidence = max(confidence, 60)

            if f.actionType == "DELETE":
                reasons.append("DELETE on sensitive path (high severity)")
                confidence = max(confidence, 85)
            elif f.actionType == "MODIFY":
                confidence = max(confidence, 70)

        ind = self._match_indicators(f.filePath)
        if ind:
            reasons.append(f"file path matches IOC [{ind.type}]: {ind.value}")
            matched_ids.append(ind.indicatorId)
            confidence = max(confidence, ind.confidence)

        return AnalysisResult(
            isSuspicious = bool(reasons),
            reason       = "; ".join(reasons) if reasons else "clean",
            indicatorIds = matched_ids,
            confidence   = confidence,
        )

    def analyzeEvent(self, event: SecurityEvent) -> AnalysisResult:
        """Generic event analyzer dispatches to type-specific method."""
        raw = event.rawData

        if event.sourceType == "process":
            p = Process(
                processId = raw.get("processId", "?"),
                name      = raw.get("name", ""),
                path      = raw.get("path", ""),
                startTime = datetime.now(),
                parentPid = raw.get("parentPid", ""),
                user      = raw.get("user", ""),
                status    = raw.get("status", ""),
                cmdline   = raw.get("cmdline", ""),
            )
            result = self.analyzeProcess(p)
        elif event.sourceType == "network":
            n = NetworkConnection(
                connectionId = raw.get("connectionId", "?"),
                localAddress = raw.get("localAddress", ""),
                localPort    = raw.get("localPort", 0),
                destination  = raw.get("destination", ""),
                port         = raw.get("port", 0),
                protocol     = raw.get("protocol", "TCP"),
                state        = raw.get("state", ""),
                processId    = raw.get("processId", ""),
            )
            result = self.analyzeNetwork(n)
        elif event.sourceType == "file":
            f = FileActivity(
                activityId = raw.get("activityId", "?"),
                filePath   = raw.get("filePath", ""),
                actionType = raw.get("actionType", ""),
                timestamp  = datetime.now(),
                processId  = raw.get("processId", ""),
            )
            result = self.analyzeFile(f)
        else:
            result = AnalysisResult(isSuspicious=False, reason="unknown source type")

        # Attach matched indicator IDs to the event
        for ind_id in result.indicatorIds:
            event.addIndicator(ind_id)

        return result

    def extractIndicators(self, event: SecurityEvent) -> list[ThreatIndicator]:
        """Return any known ThreatIndicators that match data in this event."""
        matched: list[ThreatIndicator] = []
        for field in (
            event.rawData.get("path", ""),
            event.rawData.get("destination", ""),
            event.rawData.get("filePath", ""),
            event.rawData.get("name", ""),
        ):
            if not field:
                continue
            ind = self._match_indicators(field)
            if ind and ind not in matched:
                matched.append(ind)
        return matched

    # ── private ──────────────────────────────────────────────────────────────

    def _match_indicators(self, value: str) -> ThreatIndicator | None:
        if not value:
            return None
        lower = value.lower()
        for ind in self._indicators:
            if ind.value.lower() in lower:
                return ind
        return None