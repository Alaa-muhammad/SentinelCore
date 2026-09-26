"""
SentinelCore — FileWatcher
Polls sensitive paths for new / modified / deleted files.
Uses stat-based polling (cross-platform, no watchdog dependency).
On Linux inotify would be preferred but we stay zero-extra-deps here.
"""

from __future__ import annotations

import logging
import os
import platform
from datetime import datetime
from pathlib import Path

from collectors.base import DataSourceAdapter
from config.settings import SENSITIVE_PATHS, SENSITIVE_PATH_FRAGMENTS
from domain.models import FileActivity, SecurityEvent, _new_id

logger = logging.getLogger(__name__)


class FileWatcher(DataSourceAdapter):
    """
    Watches sensitive directories for file changes via stat polling.
    Builds a snapshot of (path → mtime) and diffs on each call to read().
    """

    def __init__(self) -> None:
        super().__init__("file_watcher")
        self._snapshot: dict[str, float] = {}   # path → mtime
        self._first_run = True

    # ── DataSourceAdapter interface ──────────────────────────────────────────

    def read(self) -> list[dict]:
        """
        Walk every SENSITIVE_PATH that exists on this machine and return
        a list of dicts describing files that have appeared, changed, or vanished
        since the last call.
        """
        current: dict[str, float] = {}
        changes: list[dict] = []
        now = datetime.now().isoformat()

        for base_path in SENSITIVE_PATHS:
            p = Path(base_path)
            if not p.exists():
                continue
            try:
                if p.is_file():
                    _add_file(current, p)
                elif p.is_dir():
                    for child in p.iterdir():
                        if child.is_file():
                            _add_file(current, child)
            except PermissionError:
                continue
            except Exception as e:
                logger.debug("FileWatcher scan error on %s: %s", base_path, e)

        if self._first_run:
            # On first run just establish the baseline snapshot
            self._snapshot = current
            self._first_run = False
            return []

        # ── diff: NEW files ──
        for path, mtime in current.items():
            if path not in self._snapshot:
                changes.append({
                    "activityId": _new_id("FA-"),
                    "filePath":   path,
                    "actionType": "CREATE",
                    "timestamp":  now,
                    "processId":  "",
                })

        # ── diff: MODIFIED files ──
        for path, mtime in current.items():
            if path in self._snapshot and mtime != self._snapshot[path]:
                changes.append({
                    "activityId": _new_id("FA-"),
                    "filePath":   path,
                    "actionType": "MODIFY",
                    "timestamp":  now,
                    "processId":  "",
                })

        # ── diff: DELETED files ──
        for path in self._snapshot:
            if path not in current:
                changes.append({
                    "activityId": _new_id("FA-"),
                    "filePath":   path,
                    "actionType": "DELETE",
                    "timestamp":  now,
                    "processId":  "",
                })

        self._snapshot = current
        return changes

    def normalize(self, raw: dict) -> SecurityEvent | None:
        """Every file change on a sensitive path becomes a SecurityEvent."""
        is_sensitive = self._path_is_sensitive(raw.get("filePath", ""))
        action = raw.get("actionType", "")

        # Deletions on sensitive paths are always high-priority
        severity_note = " [HIGH-RISK DELETE]" if action == "DELETE" else ""

        if not is_sensitive:
            return None

        return SecurityEvent(
            eventId    = _new_id("EVT-"),
            eventType  = "FILE_CHANGE",
            sourceId   = raw["activityId"],
            sourceType = "file",
            timestamp  = datetime.now(),
            rawData    = raw,
            context    = (
                f"Sensitive file {action}{severity_note}: {raw.get('filePath')}"
            ),
        )

    # ── helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _path_is_sensitive(path: str) -> bool:
        lower = path.lower()
        return any(frag in lower for frag in SENSITIVE_PATH_FRAGMENTS)

    def getFileActivityObjects(self) -> list[FileActivity]:
        """Return current-cycle file activity as domain objects."""
        objects: list[FileActivity] = []
        for raw in self.read():
            try:
                ts = datetime.fromisoformat(raw["timestamp"])
            except Exception:
                ts = datetime.now()
            objects.append(FileActivity(
                activityId = raw["activityId"],
                filePath   = raw["filePath"],
                actionType = raw["actionType"],
                timestamp  = ts,
                processId  = raw["processId"],
            ))
        return objects


# ── module-level helper ───────────────────────────────────────────────────────

def _add_file(current: dict[str, float], p: Path) -> None:
    try:
        current[str(p)] = p.stat().st_mtime
    except (PermissionError, FileNotFoundError, OSError):
        pass
