"""
SentinelCore — Views Layer
SecurityDashboard  → detailed operational view (Analyst)
ExecutiveDashboard → high-level strategic view (CISO / Executive)

Role enforcement is done here (view layer), not in domain or service classes.
Display is 100% text-based (rich ANSI colour where available, plain text fallback).
"""

from __future__ import annotations

import os
import platform
import shutil
import textwrap
from datetime import datetime
from typing import TYPE_CHECKING

from config.settings import ROLES
from domain.models import (
    Alert,
    AuditEntry,
    CorrelationCase,
    HistoricalRiskProfile,
    NetworkConnection,
    Process,
    Recommendation,
    RiskAssessment,
    ScenarioAnalysis,
    SecurityEvent,
)

if TYPE_CHECKING:
    pass

# ── terminal helpers ──────────────────────────────────────────────────────────

def _term_width() -> int:
    return shutil.get_terminal_size((100, 24)).columns

def _clear() -> None:
    os.system("cls" if platform.system() == "Windows" else "clear")

def _truncate_path_middle(path: str, budget: int) -> str:
    """
    Middle-truncate a filesystem path to fit `budget` characters, keeping the
    root/drive at the front and the trailing binary name intact at the end
    (e.g. "C:\\Program Files\\WindowsApps\\...\\IGCC.exe") so the most
    important piece of information — *which .exe is actually running* — is
    never the part that gets cut off.  Falls back to a right-truncated
    ellipsis for paths with no separators (nothing to preserve at the end)
    or when the budget is too small for a meaningful split.
    """
    if len(path) <= budget:
        return path
    if budget <= 1:
        return path[:budget]

    sep = "\\" if "\\" in path else ("/" if "/" in path else "")
    if not sep:
        # No separators to anchor on — plain right-truncation is the best we
        # can do.
        return path[: budget - 1] + "…"

    filename = path.rsplit(sep, 1)[-1]
    # Root: drive letter ("C:\") or leading slash, whichever the path uses.
    if len(path) > 1 and path[1] == ":":
        root = path[:3]           # "C:\"
    elif path.startswith(sep):
        root = sep                # "/"
    else:
        root = ""

    # Reserve space for root + separator + ellipsis + filename; if even the
    # filename alone doesn't fit, fall back to truncating the filename itself
    # from the left so at least the tail (extension) stays visible.
    fixed = root + "…" + sep
    remaining = budget - len(fixed)
    if remaining < 1:
        return ("…" + filename)[-budget:]
    if len(filename) > remaining:
        filename = "…" + filename[-(remaining - 1):]

    return f"{fixed}{filename}"

# ANSI colour codes (gracefully degrade on terminals that don't support them)
_ANSI = {
    "reset":   "\033[0m",
    "bold":    "\033[1m",
    "red":     "\033[91m",
    "orange":  "\033[33m",
    "yellow":  "\033[93m",
    "green":   "\033[92m",
    "cyan":    "\033[96m",
    "blue":    "\033[94m",
    "magenta": "\033[95m",
    "white":   "\033[97m",
    "dim":     "\033[2m",
}

def _c(text: str, *codes: str) -> str:
    prefix = "".join(_ANSI.get(c, "") for c in codes)
    return f"{prefix}{text}{_ANSI['reset']}"

def _bar(score: int, width: int = 30) -> str:
    filled = int(score / 100 * width)
    empty  = width - filled
    colour = (
        "red"    if score >= 75 else
        "orange" if score >= 50 else
        "yellow" if score >= 25 else
        "green"
    )
    return _c("█" * filled, colour) + _c("░" * empty, "dim")

def _level_colour(level: str) -> str:
    return {
        "CRITICAL": "red",
        "HIGH":     "orange",
        "MEDIUM":   "yellow",
        "LOW":      "green",
    }.get(level, "white")

def _severity_badge(level: str) -> str:
    col = _level_colour(level)
    return _c(f"[{level}]", col, "bold")

def _divider(char: str = "─", label: str = "") -> str:
    w = _term_width()
    if label:
        pad   = (w - len(label) - 4) // 2
        return _c("─" * pad + f"  {label}  " + "─" * pad, "dim")
    return _c(char * w, "dim")

def _header(title: str, subtitle: str = "") -> str:
    w     = _term_width()
    lines = [_divider("═")]
    lines.append(_c(title.center(w), "cyan", "bold"))
    if subtitle:
        lines.append(_c(subtitle.center(w), "dim"))
    lines.append(_divider("═"))
    return "\n".join(lines)

def _wrap_field(prefix: str, text: str, min_width: int = 30) -> str:
    """
    Wrap `text` to the terminal width with a hanging indent that lines up
    under the first character after `prefix` (e.g. "  Explain : ").
    Replaces hard slicing (e.g. text[:80]) so long values — full file paths,
    long explanations — are never cut off, just wrapped onto extra lines.
    """
    indent    = " " * len(prefix)
    avail     = max(min_width, _term_width() - len(prefix))
    wrapped   = textwrap.wrap(text, width=avail) if text else [""]
    body      = ("\n" + indent).join(wrapped)
    return prefix + body


# ════════════════════════════════════════════════════════════════════════════
# SECURITY DASHBOARD  (Analyst / Operational)
# ════════════════════════════════════════════════════════════════════════════

class SecurityDashboard:
    """
    Role: security_user, analyst, admin.
    Shows live processes, connections, events, alerts, correlations.
    """

    ALLOWED_ROLES = {"security_user", "analyst", "admin"}

    def __init__(self, role: str = "analyst") -> None:
        self.role = role
        self._check_role("view_dashboard")

    def _check_role(self, permission: str) -> None:
        allowed = ROLES.get(self.role, [])
        if permission not in allowed:
            raise PermissionError(
                f"Role '{self.role}' does not have permission '{permission}'"
            )

    # ── Overview ──────────────────────────────────────────────────────────────

    def showOverview(
        self,
        events:      list[SecurityEvent],
        alerts:      list[Alert],
        assessments: list[RiskAssessment],
        processes:   list[Process],
        connections: list[NetworkConnection],
        collector_status: dict[str, str],
    ) -> None:
        _clear()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(_header("🛡  SentinelCore — Security Operations Dashboard",
                       f"Last refresh: {now}  |  Role: {self.role.upper()}"))

        # ── Collector Status ──
        print(_divider(label=" COLLECTOR STATUS "))
        for name, status in collector_status.items():
            col   = "green" if status == "ACTIVE" else "orange" if status == "DEGRADED" else "red"
            icon  = "●" if status == "ACTIVE" else "◑" if status == "DEGRADED" else "○"
            print(f"  {_c(icon, col)}  {name:<30} {_c(status, col, 'bold')}")
        print()

        # ── Risk Summary ──
        print(_divider(label=" RISK SUMMARY "))
        scores = [a.riskScore for a in assessments] if assessments else [0]
        avg_s  = sum(scores) / len(scores) if scores else 0
        max_s  = max(scores) if scores else 0
        crit   = sum(1 for a in assessments if a.riskLevel == "CRITICAL")
        high   = sum(1 for a in assessments if a.riskLevel == "HIGH")
        med    = sum(1 for a in assessments if a.riskLevel == "MEDIUM")

        print(f"  Average risk score : {_bar(int(avg_s))}  {_c(f'{avg_s:.0f}/100', 'bold')}")
        print(f"  Peak risk score    : {_bar(max_s)}  {_c(f'{max_s}/100', 'bold')}")
        print(
            f"  Events this cycle  : {_c(str(len(events)), 'cyan', 'bold')}  |  "
            f"CRITICAL: {_c(str(crit), 'red', 'bold')}  "
            f"HIGH: {_c(str(high), 'orange', 'bold')}  "
            f"MEDIUM: {_c(str(med), 'yellow', 'bold')}"
        )
        print(
            f"  Processes monitored: {_c(str(len(processes)), 'cyan')}  |  "
            f"Active connections : {_c(str(len(connections)), 'cyan')}"
        )
        print(
            f"  Active alerts      : {_c(str(sum(1 for a in alerts if a.status not in ('RESOLVED','CLOSED'))), 'red', 'bold')}"
        )
        print()

        # ── Top Events ──
        print(_divider(label=" TOP SECURITY EVENTS "))
        top_events = sorted(events, key=lambda e: e.timestamp, reverse=True)[:8]
        if top_events:
            for e in top_events:
                ts  = e.timestamp.strftime("%H:%M:%S")
                a   = next((x for x in assessments if x.targetId == e.eventId), None)
                lvl = a.riskLevel if a else "?"
                sc  = str(a.riskScore) if a else "?"
                badge = _severity_badge(lvl) if a else _c("[?]", "dim")
                # Plain (non-ANSI) prefix used only to compute alignment width —
                # avoids mis-measuring the invisible ANSI colour codes.
                plain_prefix = f"  {ts}  [{lvl}]  {sc:>3}  "
                indent  = " " * len(plain_prefix)
                width   = max(20, _term_width() - len(plain_prefix))
                lines   = textwrap.wrap(e.context, width=width) or [""]
                print(f"  {_c(ts, 'dim')}  {badge}  {_c(sc, 'bold'):>3}  {lines[0]}")
                for cont in lines[1:]:
                    print(indent + cont)
        else:
            print(_c("  No security events detected this cycle.", "green"))
        print()

        # ── Active Alerts ──
        print(_divider(label=" ACTIVE ALERTS "))
        active = [a for a in alerts if a.status not in ("RESOLVED", "CLOSED")]
        if active:
            for al in active[:6]:
                ts    = al.createdAt.strftime("%H:%M:%S")
                badge = _severity_badge(al.severity)
                print(
                    f"  {_c(ts, 'dim')}  {badge}  "
                    f"AlertID={_c(al.alertId, 'cyan')}  "
                    f"Status={_c(al.status, 'bold')}  "
                    f"AssessmentID={al.assessmentId}"
                )
        else:
            print(_c("  No active alerts.", "green"))
        print()

    # ── Process detail ────────────────────────────────────────────────────────

    def showProcesses(self, processes: list[Process], limit: int = 20) -> None:
        _clear()
        print(_header("📋  Live Process Monitor"))
        print(_divider(label=f" TOP {limit} PROCESSES "))
        hdr_fmt = "  {:<8} {:<25} {:<12} {:<16}"
        meta_width = len(hdr_fmt.format("", "", "", ""))
        print(_c(hdr_fmt.format("PID", "NAME", "STATUS", "USER") + "  PATH", "bold"))
        print(_divider())
        for p in processes[:limit]:
            meta = hdr_fmt.format(
                p.processId[:7],
                p.name[:24],
                p.status[:11],
                p.user[:15],
            )
            # Path column gets whatever width remains on the terminal line;
            # anything longer is middle-truncated (root drive kept at the
            # front, the trailing .exe filename kept at the end) so a single
            # row never wraps and overlaps the PID/NAME of the row below it,
            # while the one detail that actually matters for triage — which
            # binary is running — stays visible. The full, untruncated path
            # is always available via Event Detail / Explain.
            path_budget = max(10, _term_width() - meta_width - 2)
            raw_path    = p.path if p.path else "(no path)"
            path_str    = _truncate_path_middle(raw_path, path_budget)
            colour = "red" if not p.path else "dim"
            print(meta + "  " + _c(path_str, colour))
        print()

    # ── Network detail ────────────────────────────────────────────────────────

    def showConnections(self, connections: list[NetworkConnection], limit: int = 20) -> None:
        _clear()
        print(_header("🌐  Live Network Connections"))
        fmt = "  {:<8} {:<22} {:<22} {:<6} {:<14} {:<5}"
        print(_c(fmt.format("PID", "LOCAL", "REMOTE", "PROTO", "STATE", "PORT"), "bold"))
        print(_divider())
        established = [c for c in connections if c.state == "ESTABLISHED"]
        others      = [c for c in connections if c.state != "ESTABLISHED"]
        display     = (established + others)[:limit]
        for c in display:
            local  = f"{c.localAddress}:{c.localPort}"[:21]
            remote = f"{c.destination}:{c.port}"[:21] if c.destination else "(listen)"[:21]
            col    = "cyan" if c.state == "ESTABLISHED" else "dim"
            print(_c(fmt.format(
                c.processId[:7], local, remote,
                c.protocol[:5], c.state[:13], str(c.port)[:4]
            ), col))
        print()

    # ── Event detail ──────────────────────────────────────────────────────────

    def showEventDetail(self, event: SecurityEvent, assessment: RiskAssessment | None = None) -> None:
        print(_header(f"📌  Event Detail: {event.eventId}"))
        print(f"  Type      : {_c(event.eventType, 'cyan', 'bold')}")
        print(f"  Source    : {event.sourceType} / {event.sourceId}")
        print(f"  Timestamp : {event.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print(_wrap_field("  Context   : ", event.context))
        print(f"  Indicators: {', '.join(event.indicators) or 'none'}")
        if assessment:
            print()
            print(_divider(label=" RISK ASSESSMENT "))
            print(f"  Score   : {_bar(assessment.riskScore)}  {_c(str(assessment.riskScore), 'bold')}/100")
            print(f"  Level   : {_severity_badge(assessment.riskLevel)}")
            print(_wrap_field("  Explain : ", assessment.explanation))
        print()

    # ── Alert detail ──────────────────────────────────────────────────────────

    def showAlerts(self, alerts: list[Alert], assessments: list[RiskAssessment]) -> None:
        _clear()
        print(_header("🚨  Alert Management"))
        if not alerts:
            print(_c("  No alerts in system.", "green"))
            return
        ass_map = {a.assessmentId: a for a in assessments}
        for al in alerts:
            a   = ass_map.get(al.assessmentId)
            sc  = str(a.riskScore) if a else "?"
            exp = a.explanation if a else ""
            print(
                f"  {_severity_badge(al.severity)}  "
                f"{_c(al.alertId, 'cyan')}  "
                f"Status={_c(al.status, 'bold')}  "
                f"Score={sc}"
            )
            # Wrap the full explanation to the terminal width instead of
            # hard-slicing it, so words are never clipped mid-word
            # (e.g. "analysis c" instead of "analysis confidence").
            if exp:
                indent = "     "
                width  = max(20, _term_width() - len(indent))
                for line in textwrap.wrap(exp, width=width):
                    print(_c(indent + line, "dim"))
        print()

    # ── Correlation view ─────────────────────────────────────────────────────

    def showCorrelationCases(self, cases: list[CorrelationCase]) -> None:
        _clear()
        print(_header("🔗  Correlation Cases"))
        if not cases:
            print(_c("  No correlation cases this cycle.", "green"))
            return
        for case in cases:
            print(
                f"  {_c(case.caseId, 'cyan', 'bold')}  "
                f"Confidence={_c(str(case.confidence), 'bold')}%  "
                f"Events={case.eventCount()}  "
                f"Status={case.status}"
            )
            print(f"     {_c(case.reason, 'dim')}")
        print()

    # ── Audit log ────────────────────────────────────────────────────────────

    def showAuditLog(self, entries: list[AuditEntry]) -> None:
        self._check_role("view_audit")
        _clear()
        print(_header("📜  Audit Trail"))
        if not entries:
            print(_c("  Audit trail is empty.", "dim"))
            return
        for e in entries[:30]:
            print(f"  {_c(e.describe(), 'dim')}")
        print()


# ════════════════════════════════════════════════════════════════════════════
# EXECUTIVE DASHBOARD  (CISO / Executive)
# ════════════════════════════════════════════════════════════════════════════

class ExecutiveDashboard:
    """
    Role: ciso, executive.
    No raw logs.  KPIs, trends, scenarios, recommendations only.
    """

    ALLOWED_ROLES = {"ciso", "executive"}

    def __init__(self, role: str = "ciso") -> None:
        self.role = role
        self._check_role("view_executive")

    def _check_role(self, permission: str) -> None:
        allowed = ROLES.get(self.role, [])
        if permission not in allowed:
            raise PermissionError(
                f"Role '{self.role}' does not have permission '{permission}'"
            )

    # ── KPIs ──────────────────────────────────────────────────────────────────

    def showKPIs(
        self,
        total_events: int,
        active_alerts: int,
        avg_score: float,
        trend: str,
        critical_count: int,
        collector_status: dict[str, str],
    ) -> None:
        _clear()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(_header("📊  SentinelCore — Executive Security Dashboard",
                       f"Generated: {now}  |  Role: {self.role.upper()}"))

        print(_divider(label=" KEY PERFORMANCE INDICATORS "))
        kpis = [
            ("Events (last 24h)",   str(total_events),    "cyan"),
            ("Active Alerts",       str(active_alerts),   "red" if active_alerts else "green"),
            ("Avg Risk Score",      f"{avg_score:.0f}/100", "orange" if avg_score >= 50 else "green"),
            ("Risk Trend",          trend,                 "red" if trend == "RISING" else "green" if trend == "DECLINING" else "yellow"),
            ("Critical Events",     str(critical_count),  "red" if critical_count else "green"),
            ("Collectors Online",   str(sum(1 for s in collector_status.values() if s == "ACTIVE")),  "green"),
        ]
        for label, value, colour in kpis:
            print(f"  {label:<28}:  {_c(value, colour, 'bold')}")
        print()

        # Risk bar
        print(f"  Overall Risk  {_bar(int(avg_score))}  {_c(str(int(avg_score)), 'bold')}/100")
        print()

    # ── Trends ───────────────────────────────────────────────────────────────

    def showTrends(self, profile: HistoricalRiskProfile) -> None:
        self._check_role("view_trends")
        _clear()
        print(_header("📈  Risk Trend Analysis"))
        print(_divider(label=f" Entity: {profile.entityId} "))
        print(f"  Trend         : {_c(profile.trend, _level_colour('HIGH') if profile.trend == 'RISING' else 'green', 'bold')}")
        print(f"  Average Score : {_bar(int(profile.averageScore))}  {profile.averageScore:.1f}/100")
        print(f"  Total Samples : {len(profile.assessments)}")
        print(f"  Critical Peaks: {len(profile.peaks)}")

        if profile.assessments:
            print()
            print(_divider(label=" RECENT SCORE HISTORY "))
            recent = profile.assessments[-10:]
            for a in recent:
                ts  = a.timestamp.strftime("%H:%M:%S")
                bar = _bar(a.riskScore, 20)
                print(f"  {_c(ts, 'dim')}  {bar}  {_c(str(a.riskScore), 'bold'):>3}  {_severity_badge(a.riskLevel)}")
        print()

    # ── Scenarios ────────────────────────────────────────────────────────────

    def showScenarios(self, scenarios: list[ScenarioAnalysis]) -> None:
        self._check_role("view_trends")
        _clear()
        print(_header("🔮  What-If Scenario Analysis"))
        if not scenarios:
            print(_c("  No scenarios have been created yet.", "dim"))
            return
        for s in scenarios:
            direction = _c(f"▲ +{s.delta}", "red") if s.delta > 0 else _c(f"▼ {s.delta}", "green")
            print(
                f"  {_c(s.name, 'cyan', 'bold')}  "
                f"Baseline={s.baselineScore}  →  "
                f"Projected={s.projectedScore}  {direction}"
            )
            print(f"     {_c(s.description, 'dim')}")
        print()

    # ── Recommendations ───────────────────────────────────────────────────────

    def showRecommendations(self, recommendations: list[Recommendation]) -> None:
        _clear()
        print(_header("💡  Strategic Security Recommendations"))
        if not recommendations:
            print(_c("  No recommendations generated.", "dim"))
            return
        _pri_col = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}
        for i, rec in enumerate(recommendations, 1):
            col = _pri_col.get(rec.priority, "white")
            print(
                f"  {_c(str(i), 'bold', 'white')}. {_c(rec.priority, col, 'bold'):>8}  "
                f"{_c(rec.title, 'cyan', 'bold')}"
            )
            print(f"     {rec.description}")
            print(f"     {_c('Expected impact:', 'dim')} {rec.impact}")
            print()