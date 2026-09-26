"""
SentinelCore — ProcessCollector
Reads live running processes from the host OS via psutil.
No mock data.  Gracefully handles access-denied errors per-process.
"""

from __future__ import annotations

import logging
from datetime import datetime

import psutil

from collectors.base import DataSourceAdapter, CollectorUnavailable
from config.settings import (
    SUSPICIOUS_PATH_FRAGMENTS,
    SUSPICIOUS_PROCESS_NAMES,
    TRUSTED_PROCESS_NAMES,
    TRUSTED_PROCESS_PATH_PREFIXES,
)
from domain.models import Process, SecurityEvent, _new_id

logger = logging.getLogger(__name__)


class ProcessCollector(DataSourceAdapter):
    """Collects all running processes and flags anomalous ones."""

    def __init__(self) -> None:
        super().__init__("process_collector")

    # ── DataSourceAdapter interface ──────────────────────────────────────────

    def read(self) -> list[dict]:
        """Enumerate every running process via psutil."""
        results: list[dict] = []
        try:
            for proc in psutil.process_iter(
                ["pid", "name", "exe", "cmdline", "username",
                 "status", "ppid", "create_time"]
            ):
                try:
                    info = proc.info
                    results.append({
                        "processId": str(info["pid"]),
                        "name":      info["name"] or "",
                        "path":      info["exe"] or "",
                        "cmdline":   " ".join(info["cmdline"] or []),
                        "user":      info["username"] or "UNKNOWN",
                        "status":    info["status"] or "unknown",
                        "parentPid": str(info["ppid"] or ""),
                        "startTime": datetime.fromtimestamp(
                            info["create_time"] or 0
                        ).isoformat(),
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied,
                        psutil.ZombieProcess):
                    # Individual process may disappear or be protected — skip
                    continue
        except Exception as e:
            raise CollectorUnavailable(f"psutil process_iter failed: {e}") from e
        return results

    def normalize(self, raw: dict) -> SecurityEvent | None:
        """
        Convert a raw process dict to a SecurityEvent IFF the process is anomalous.
        Clean processes return None (no event generated — they are not threats).
        """
        anomalies = self._detect_anomalies(raw)
        if not anomalies:
            return None

        context = "; ".join(anomalies)
        return SecurityEvent(
            eventId    = _new_id("EVT-"),
            eventType  = "PROCESS_ANOMALY",
            sourceId   = raw["processId"],
            sourceType = "process",
            timestamp  = datetime.now(),
            rawData    = raw,
            context    = f"[PID {raw['processId']}] {raw['name']}: {context}",
        )

    # ── whitelist: process names that are always legitimate ─────────────────
    # Kernel threads (Linux) and core Windows OS / security processes
    # never have an executable path by design — do NOT flag them.
    # Sourced from config.settings so ProcessCollector (event creation) and
    # SecurityAnalyzer (event scoring) share one authoritative whitelist —
    # previously they had separate, out-of-sync copies, which is how signed
    # Defender binaries could still be scored as HIGH even after being
    # exempted here (see services/security_analyzer.py::analyzeProcess).
    _WHITELISTED_NAMES: frozenset[str] = TRUSTED_PROCESS_NAMES

    # Path prefixes that are always considered legitimate system locations
    _TRUSTED_PATH_PREFIXES: tuple[str, ...] = TRUSTED_PROCESS_PATH_PREFIXES

    # ── anomaly detection logic ──────────────────────────────────────────────

    def _detect_anomalies(self, raw: dict) -> list[str]:
        """Return a list of human-readable anomaly descriptions, or [] if clean."""
        flags: list[str] = []
        path   = (raw.get("path") or "").lower()
        name   = (raw.get("name") or "").lower()
        user   = (raw.get("user") or "").lower()
        status = (raw.get("status") or "").lower()
        pid    = int(raw.get("processId") or -1)

        # ── Whitelist check — skip all further analysis for known-good processes
        # PID 0 (System Idle) and PID 4 (System) on Windows are always clean.
        if pid in (0, 4):
            return []
        # Exact name match against whitelist (case-insensitive)
        if name in self._WHITELISTED_NAMES:
            return []
        # Prefix match: kworker/*, ksoftirqd/*, irq/*, migration/* etc.
        for wl_prefix in ("kworker/", "ksoftirqd/", "migration/", "irq/",
                           "idle_inject/", "cpuhp/", "scsi_eh", "scsi_tmf",
                           "ext4-", "jbd2/"):
            if name.startswith(wl_prefix):
                return []
        # Processes running from trusted OS paths are always legitimate
        if path and any(path.startswith(pfx) for pfx in self._TRUSTED_PATH_PREFIXES):
            # Still check for actual suspicious sub-paths within trusted dirs
            # (e.g. c:\windows\temp\) but skip the "no path" rule
            for frag in SUSPICIOUS_PATH_FRAGMENTS:
                if frag in path:
                    flags.append(f"running from suspicious path: {raw.get('path')}")
                    break
            # Skip the no-path and privileged-user rules for trusted-path processes
            if not flags:
                return []
            return flags

        # 1. Executable in a suspicious path
        for frag in SUSPICIOUS_PATH_FRAGMENTS:
            if frag in path:
                flags.append(f"running from suspicious path: {raw.get('path')}")
                break

        # 2. Known malicious process name
        for mal in SUSPICIOUS_PROCESS_NAMES:
            if mal in name:
                flags.append(f"name matches known malicious pattern: {mal}")
                break

        # 3. No executable path — only flag if process is NOT a kernel thread
        #    Kernel threads on Linux legitimately have no path; they run in
        #    kernel address space.  We identify them by user being empty,
        #    "root", or a kernel-internal account AND PID > 0.
        if not path and status not in ("zombie", "dead", "stopped"):
            is_kernel_thread = (
                user in ("", "root", "unknown")
                and not raw.get("cmdline")
            )
            if not is_kernel_thread:
                flags.append("no executable path (possible process hollowing)")

        # 4. Running as SYSTEM / root from an unusual location
        if user in ("system", "root") and path:
            usual = (
                "system32", "syswow64", "/usr/", "/bin/", "/sbin/",
                "/lib/", "/lib64/", "c:\\windows\\", "c:\\program files",
                "c:\\programdata\\microsoft\\",
            )
            if not any(u in path for u in usual):
                flags.append(
                    f"privileged user '{raw.get('user')}' running from "
                    f"non-standard path: {raw.get('path')}"
                )

        # 5. Zombie process (shouldn't linger on healthy systems)
        if status == "zombie":
            flags.append("zombie process detected (parent not reaping children)")

        return flags

    # ── convenience: get rich domain objects (used by views) ─────────────────

    def getProcessObjects(self) -> list[Process]:
        """Return live Process domain objects (all processes, not just anomalous)."""
        objects: list[Process] = []
        for raw in self.read():
            try:
                start = datetime.fromisoformat(raw["startTime"])
            except Exception:
                start = datetime.now()
            objects.append(Process(
                processId = raw["processId"],
                name      = raw["name"],
                path      = raw["path"],
                startTime = start,
                parentPid = raw["parentPid"],
                user      = raw["user"],
                status    = raw["status"],
                cmdline   = raw["cmdline"],
            ))
        return objects