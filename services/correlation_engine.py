"""
SentinelCore — CorrelationEngine
Groups temporally and behaviourally related SecurityEvents into CorrelationCases.
Four correlation rules from the architecture spec are implemented.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from config.settings import CORRELATION_TIME_WINDOW_SEC
from domain.models import CorrelationCase, SecurityEvent, _new_id

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """
    Links SecurityEvents that are related temporally or behaviourally.
    Stateless: pass in the full recent-events list each call.
    """

    TIME_WINDOW_SECONDS: int = CORRELATION_TIME_WINDOW_SEC

    def correlate(self, events: list[SecurityEvent]) -> list[CorrelationCase]:
        """
        Run all four correlation rules against the event list.
        Returns a (possibly empty) list of new CorrelationCases.
        Each case's confidence is computed by _computeConfidence().
        """
        cases: list[CorrelationCase] = []
        cutoff = datetime.now() - timedelta(seconds=self.TIME_WINDOW_SECONDS)
        recent = [e for e in events if e.timestamp >= cutoff]

        if len(recent) < 2:
            return []

        # Rule 1: Same PID in both process + network or process + file events
        case1 = self._rule_same_pid_multitype(recent)
        if case1:
            cases.append(case1)

        # Rule 2: Multiple network connections to the same destination
        case2 = self._rule_repeated_destination(recent)
        if case2:
            cases.append(case2)

        # Rule 3: File change on sensitive path + new process spawn
        case3 = self._rule_file_then_process(recent)
        if case3:
            cases.append(case3)

        # Rule 4: Shared ThreatIndicator across multiple events
        case4 = self._rule_shared_indicator(recent)
        if case4:
            cases.append(case4)

        return cases

    def findRelated(self, event: SecurityEvent) -> list[SecurityEvent]:
        """Not used internally but exposed for UI drill-down."""
        return []

    # ── private rules ────────────────────────────────────────────────────────

    def _rule_same_pid_multitype(
        self, events: list[SecurityEvent]
    ) -> CorrelationCase | None:
        """Rule 1: Same process shows up in both process + network/file events."""
        pid_map: dict[str, list[SecurityEvent]] = {}
        for e in events:
            pid = e.rawData.get("processId") or e.rawData.get("pid") or ""
            if pid:
                pid_map.setdefault(pid, []).append(e)

        for pid, evts in pid_map.items():
            types = {e.sourceType for e in evts}
            if "process" in types and ("network" in types or "file" in types):
                case = CorrelationCase(
                    caseId     = _new_id("CASE-"),
                    confidence = self._computeConfidence(evts),
                    status     = "OPEN",
                    reason     = (
                        f"PID {pid} appears in multiple event types "
                        f"({', '.join(sorted(types))}) within time window"
                    ),
                )
                for e in evts:
                    case.addEvent(e.eventId)
                return case
        return None

    def _rule_repeated_destination(
        self, events: list[SecurityEvent]
    ) -> CorrelationCase | None:
        """Rule 2: Multiple network connections to the same remote IP."""
        dest_map: dict[str, list[SecurityEvent]] = {}
        for e in events:
            if e.sourceType == "network":
                dest = e.rawData.get("destination", "")
                if dest and dest not in ("", "0.0.0.0", "127.0.0.1", "::1"):
                    dest_map.setdefault(dest, []).append(e)

        for dest, evts in dest_map.items():
            if len(evts) >= 3:
                case = CorrelationCase(
                    caseId     = _new_id("CASE-"),
                    confidence = self._computeConfidence(evts),
                    status     = "OPEN",
                    reason     = (
                        f"{len(evts)} network connections to same destination "
                        f"{dest} within time window (possible beaconing)"
                    ),
                )
                for e in evts:
                    case.addEvent(e.eventId)
                return case
        return None

    def _rule_file_then_process(
        self, events: list[SecurityEvent]
    ) -> CorrelationCase | None:
        """Rule 3: Sensitive file modification followed by new process spawn."""
        file_events = [e for e in events if e.sourceType == "file"
                       and "sensitive" in e.context.lower()]
        proc_events = [e for e in events if e.sourceType == "process"]

        if file_events and proc_events:
            # Take the most recent pairing
            candidates = file_events[:1] + proc_events[:1]
            if len(candidates) >= 2:
                case = CorrelationCase(
                    caseId     = _new_id("CASE-"),
                    confidence = self._computeConfidence(candidates),
                    status     = "OPEN",
                    reason     = (
                        "Sensitive file modification followed by process spawn "
                        "within time window"
                    ),
                )
                for e in candidates:
                    case.addEvent(e.eventId)
                return case
        return None

    def _rule_shared_indicator(
        self, events: list[SecurityEvent]
    ) -> CorrelationCase | None:
        """Rule 4: Multiple events share the same ThreatIndicator ID."""
        ind_map: dict[str, list[SecurityEvent]] = {}
        for e in events:
            for ind_id in e.indicators:
                ind_map.setdefault(ind_id, []).append(e)

        for ind_id, evts in ind_map.items():
            if len(evts) >= 2:
                case = CorrelationCase(
                    caseId     = _new_id("CASE-"),
                    confidence = self._computeConfidence(evts),
                    status     = "OPEN",
                    reason     = (
                        f"{len(evts)} events share ThreatIndicator {ind_id}"
                    ),
                )
                for e in evts:
                    case.addEvent(e.eventId)
                return case
        return None

    def _computeConfidence(self, events: list[SecurityEvent]) -> int:
        """Confidence grows with event count and type diversity."""
        count      = len(events)
        type_count = len({e.sourceType for e in events})
        raw        = min(100, count * 15 + type_count * 20)
        return max(20, raw)
