"""
SentinelCore — NetworkCollector
Reads live network connections from the host OS via psutil.
Works on both Linux and Windows without modification.
"""

from __future__ import annotations

import logging
import socket
from datetime import datetime

import psutil

from collectors.base import DataSourceAdapter, CollectorUnavailable
from config.settings import SUSPICIOUS_PORTS
from domain.models import NetworkConnection, SecurityEvent, _new_id

logger = logging.getLogger(__name__)

# Ports that are mundane and should not trigger events
_TRUSTED_PORTS = {
    80, 443, 22, 53, 123, 67, 68,   # HTTP, HTTPS, SSH, DNS, NTP, DHCP
    25, 465, 587, 993, 995,           # mail
    3389, 5900,                        # RDP, VNC (flag separately if needed)
    5353, 137, 138, 139, 445,          # mDNS, NetBIOS, SMB
}


class NetworkCollector(DataSourceAdapter):
    """Collects all active network connections and flags suspicious ones."""

    def __init__(self) -> None:
        super().__init__("network_collector")

    # ── DataSourceAdapter interface ──────────────────────────────────────────

    def read(self) -> list[dict]:
        """Return all active TCP/UDP connections via psutil."""
        results: list[dict] = []
        try:
            conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied as e:
            # On Windows, running without admin gives limited results
            logger.warning(
                "psutil.net_connections AccessDenied — "
                "run as Administrator for full network visibility: %s", e
            )
            try:
                conns = psutil.net_connections(kind="tcp")
            except Exception as e2:
                raise CollectorUnavailable(f"net_connections failed: {e2}") from e2
        except Exception as e:
            raise CollectorUnavailable(f"net_connections failed: {e}") from e

        for c in conns:
            laddr  = c.laddr
            raddr  = c.raddr
            proto  = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
            state  = c.status if c.status else "NONE"
            pid    = str(c.pid) if c.pid else ""

            results.append({
                "connectionId": _new_id("NET-"),
                "localAddress": laddr.ip   if laddr else "",
                "localPort":    laddr.port if laddr else 0,
                "destination":  raddr.ip   if raddr else "",
                "port":         raddr.port if raddr else 0,
                "protocol":     proto,
                "state":        state,
                "processId":    pid,
            })
        return results

    def normalize(self, raw: dict) -> SecurityEvent | None:
        """Generate a SecurityEvent only for suspicious connections."""
        anomalies = self._detect_anomalies(raw)
        if not anomalies:
            return None

        context = "; ".join(anomalies)
        dest    = raw.get("destination") or "?"
        port    = raw.get("port") or 0
        return SecurityEvent(
            eventId    = _new_id("EVT-"),
            eventType  = "NETWORK_SUSPICIOUS",
            sourceId   = raw["connectionId"],
            sourceType = "network",
            timestamp  = datetime.now(),
            rawData    = raw,
            context    = (
                f"[{raw['protocol']}] {raw['localAddress']}:{raw['localPort']} "
                f"→ {dest}:{port} (PID {raw['processId']}): {context}"
            ),
        )

    # ── anomaly detection ────────────────────────────────────────────────────

    def _detect_anomalies(self, raw: dict) -> list[str]:
        flags: list[str] = []
        dest  = raw.get("destination") or ""
        port  = raw.get("port") or 0
        state = raw.get("state") or ""

        # Skip listen-only or empty connections
        if not dest and state in ("LISTEN", "NONE", ""):
            return []

        # 1. Known suspicious port
        if port in SUSPICIOUS_PORTS:
            flags.append(f"connection on suspicious port {port}")

        # 2. Very high ephemeral port (>49000) to external host
        if port > 49000 and dest and not _is_private_ip(dest):
            flags.append(f"high ephemeral port {port} to external host {dest}")

        # 3. Connection with no associated PID (stealth?)
        if not raw.get("processId") and state == "ESTABLISHED":
            flags.append("ESTABLISHED connection with no owning process (possible rootkit)")

        # 4. Connections to non-routable / documentation ranges used as C2
        if dest in ("0.0.0.0", "255.255.255.255"):
            flags.append(f"connection to invalid/broadcast address {dest}")

        return flags

    # ── convenience ──────────────────────────────────────────────────────────

    def getConnectionObjects(self) -> list[NetworkConnection]:
        """Return all live NetworkConnection domain objects."""
        objects: list[NetworkConnection] = []
        for raw in self.read():
            objects.append(NetworkConnection(
                connectionId = raw["connectionId"],
                localAddress = raw["localAddress"],
                localPort    = raw["localPort"],
                destination  = raw["destination"],
                port         = raw["port"],
                protocol     = raw["protocol"],
                state        = raw["state"],
                processId    = raw["processId"],
            ))
        return objects


# ── helpers ──────────────────────────────────────────────────────────────────

def _is_private_ip(ip: str) -> bool:
    """Return True for RFC1918 / loopback / link-local addresses."""
    if not ip:
        return True
    try:
        packed = socket.inet_aton(ip)
        first  = packed[0]
        second = packed[1]
        return (
            first == 10
            or (first == 172 and 16 <= second <= 31)
            or (first == 192 and second == 168)
            or first == 127
            or (first == 169 and second == 254)
        )
    except OSError:
        return False
