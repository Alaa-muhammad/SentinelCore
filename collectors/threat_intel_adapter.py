"""
SentinelCore — ThreatIntelAdapter
Loads IOCs from a local CSV and (optionally) a remote feed.
In the absence of an external feed, falls back to config/ioc_local.csv.
"""

from __future__ import annotations

import csv
import logging
import os
from datetime import datetime
from pathlib import Path

from collectors.base import DataSourceAdapter
from config.settings import LOCAL_IOC_IPS, LOCAL_IOC_DOMAINS
from domain.models import SecurityEvent, ThreatIndicator, _new_id

logger = logging.getLogger(__name__)

_LOCAL_IOC_FILE = Path(__file__).parent.parent / "config" / "ioc_local.csv"


class ThreatIntelAdapter(DataSourceAdapter):
    """
    Loads Threat Indicators from a local IOC file.
    External feed URL can be configured; if absent, local file is used.
    """

    def __init__(self, feedUrl: str = "") -> None:
        super().__init__("threat_intel")
        self.provider   = "local"
        self.feedUrl    = feedUrl
        self.lastUpdate: datetime | None = None
        self._indicators: list[ThreatIndicator] = []
        self._load_local_defaults()

    # ── DataSourceAdapter interface ──────────────────────────────────────────

    def read(self) -> list[dict]:
        """Return indicator dicts (used for normalize pipeline)."""
        return [i.toDict() for i in self._indicators]

    def normalize(self, raw: dict) -> SecurityEvent | None:
        """ThreatIntelAdapter does not produce SecurityEvents directly."""
        return None

    # ── Public API ───────────────────────────────────────────────────────────

    def importIndicators(self) -> list[ThreatIndicator]:
        self.refreshFeed()
        return list(self._indicators)

    def validate(self, indicator: ThreatIndicator) -> bool:
        return bool(indicator.value) and indicator.confidence >= 0

    def refreshFeed(self) -> None:
        """Reload from local file (extend to pull from feedUrl if configured)."""
        self._indicators.clear()
        self._load_local_defaults()
        if _LOCAL_IOC_FILE.exists():
            self._load_csv(_LOCAL_IOC_FILE)
        self.lastUpdate = datetime.now()
        logger.info(
            "ThreatIntel refreshed: %d indicators loaded", len(self._indicators)
        )

    def getIndicators(self) -> list[ThreatIndicator]:
        return list(self._indicators)

    def matchesAny(self, value: str) -> ThreatIndicator | None:
        """Return the first indicator that matches value, or None."""
        lower = value.lower()
        for ind in self._indicators:
            if ind.value.lower() in lower or lower in ind.value.lower():
                return ind
        return None

    # ── private helpers ──────────────────────────────────────────────────────

    def _load_local_defaults(self) -> None:
        for ip in LOCAL_IOC_IPS:
            self._indicators.append(ThreatIndicator(
                indicatorId = _new_id("IOC-"),
                type        = "IP",
                value       = ip,
                source      = "local-config",
                confidence  = 70,
            ))
        for domain in LOCAL_IOC_DOMAINS:
            self._indicators.append(ThreatIndicator(
                indicatorId = _new_id("IOC-"),
                type        = "DOMAIN",
                value       = domain,
                source      = "local-config",
                confidence  = 70,
            ))

    def _load_csv(self, path: Path) -> None:
        """
        Expects CSV columns: type, value, source, confidence
        Lines starting with # are treated as comments.
        """
        try:
            with open(path, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(
                    (row for row in f if not row.strip().startswith("#"))
                )
                for row in reader:
                    try:
                        ind = ThreatIndicator(
                            indicatorId = _new_id("IOC-"),
                            type        = row.get("type", "IP").upper(),
                            value       = row.get("value", "").strip(),
                            source      = row.get("source", "csv").strip(),
                            confidence  = int(row.get("confidence", 50)),
                        )
                        if self.validate(ind):
                            self._indicators.append(ind)
                    except Exception as e:
                        logger.debug("Skipping bad IOC row: %s — %s", row, e)
        except Exception as e:
            logger.warning("Could not load IOC CSV %s: %s", path, e)
