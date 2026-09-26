"""
SentinelCore — DataSourceAdapter (Abstract Base)
All collectors inherit from this.  The normalize() method is the only place
raw OS data becomes a SecurityEvent.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime

from domain.models import SecurityEvent, _new_id

logger = logging.getLogger(__name__)


class CollectorUnavailable(Exception):
    """Raised when a collector cannot access its OS data source."""
    pass


class DataSourceAdapter(ABC):
    """
    Abstract base for all data collectors.
    Concrete subclasses implement read() and normalize().
    """

    def __init__(self, sourceId: str) -> None:
        self.sourceId = sourceId
        self.status   = "ACTIVE"   # ACTIVE / DEGRADED / OFFLINE
        self._lastRead: datetime | None = None

    # ── abstract interface ───────────────────────────────────────────────────

    @abstractmethod
    def read(self) -> list[dict]:
        """
        Read raw data from the OS / external source.
        Returns a list of raw dicts.
        If data cannot be read, sets self.status = "DEGRADED" and returns [].
        Never returns fake / mock data.
        """

    @abstractmethod
    def normalize(self, raw: dict) -> SecurityEvent | None:
        """
        Convert one raw dict into a SecurityEvent.
        Returns None if the raw item should be silently skipped.
        """

    # ── shared helpers ───────────────────────────────────────────────────────

    def checkStatus(self) -> str:
        return self.status

    def collect(self) -> list[SecurityEvent]:
        """
        Full collection cycle: read() → normalize() → return events.
        Handles exceptions gracefully so one bad collector never kills the pipeline.
        """
        events: list[SecurityEvent] = []
        try:
            raw_items = self.read()
            self._lastRead = datetime.now()
            self.status = "ACTIVE"
            for raw in raw_items:
                try:
                    event = self.normalize(raw)
                    if event is not None:
                        events.append(event)
                except Exception as norm_err:
                    logger.debug("Normalize error in %s: %s", self.sourceId, norm_err)
        except CollectorUnavailable as e:
            logger.warning("Collector %s OFFLINE: %s", self.sourceId, e)
            self.status = "OFFLINE"
        except Exception as e:
            logger.warning("Collector %s DEGRADED: %s", self.sourceId, e)
            self.status = "DEGRADED"
        return events

    def _make_event_id(self) -> str:
        return _new_id("EVT-")
