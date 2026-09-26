"""
SentinelCore — Main Entry Point
================================
Interactive CLI that wires together all layers and runs a live scan loop.

Usage
-----
    pip install psutil
    python main.py

Works on Windows and Linux without any changes.
No mock data is ever used — all data comes from the live host OS.
"""

from __future__ import annotations

import logging
import os
import platform
import sys
import time
from datetime import datetime

# ── make imports work from any working directory ──────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── psutil availability guard ─────────────────────────────────────────────────
try:
    import psutil  # noqa: F401
except ImportError:
    print("\n[ERROR] psutil is not installed.")
    print("Run:  pip install psutil\n")
    sys.exit(1)

from collectors import (
    FileWatcher,
    NetworkCollector,
    ProcessCollector,
    ThreatIntelAdapter,
)
from domain.models import (
    HistoricalRiskProfile,
    RiskAssessment,
    ScenarioAnalysis,
    SecurityEvent,
    _new_id,
)
from services import (
    AlertService,
    CorrelationEngine,
    RecommendationEngine,
    RiskEngine,
    SecurityAnalyzer,
)
from storage.db import (
    AlertRepository,
    AssessmentRepository,
    AuditRepository,
    Database,
    EventRepository,
    ProfileRepository,
    ScenarioRepository,
)
from views.dashboards import ExecutiveDashboard, SecurityDashboard

# ── logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level  = logging.WARNING,
    format = "[%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinelcore.main")


# ════════════════════════════════════════════════════════════════════════════
# SCAN ENGINE  (stateful, runs one full pipeline cycle per call)
# ════════════════════════════════════════════════════════════════════════════

class ScanEngine:
    """
    Orchestrates one collection → analysis → correlation → scoring → alert cycle.
    Holds no God-class logic — it merely wires the services together.
    """

    def __init__(self) -> None:
        # ── collectors ──
        self.proc_collector = ProcessCollector()
        self.net_collector  = NetworkCollector()
        self.file_watcher   = FileWatcher()
        self.threat_intel   = ThreatIntelAdapter()

        # ── services ──
        self.analyzer    = SecurityAnalyzer()
        self.risk_engine = RiskEngine()
        self.correlator  = CorrelationEngine()
        self.alert_svc   = AlertService()
        self.rec_engine  = RecommendationEngine()

        # ── storage ──
        self.db           = Database()
        self.db.connect()
        self.event_repo   = EventRepository(self.db)
        self.ass_repo     = AssessmentRepository(self.db)
        self.alert_repo   = AlertRepository(self.db)
        self.audit_repo   = AuditRepository(self.db)
        self.profile_repo = ProfileRepository(self.db)
        self.scenario_repo= ScenarioRepository(self.db)

        # ── in-memory state ──
        self.current_events:      list[SecurityEvent]  = []
        self.current_assessments: list[RiskAssessment] = []
        self.global_profile = HistoricalRiskProfile(
            profileId    = _new_id("PRF-"),
            entityId     = "global",
            trend        = "STABLE",
            averageScore = 0.0,
        )

        # Load threat intel on startup
        self.threat_intel.refreshFeed()
        self.analyzer.setIndicators(self.threat_intel.getIndicators())

    # ── single full scan cycle ────────────────────────────────────────────────

    def run_cycle(self) -> None:
        self.current_events      = []
        self.current_assessments = []

        # Step 1: Collect from all sources
        proc_events = self.proc_collector.collect()
        net_events  = self.net_collector.collect()
        file_events = self.file_watcher.collect()

        all_events = proc_events + net_events + file_events

        # Step 2: Analyze + score each event
        for event in all_events:
            result      = self.analyzer.analyzeEvent(event)
            inds        = self.analyzer.extractIndicators(event)
            assessment  = self.risk_engine.assessEvent(event, result, inds)

            self.current_events.append(event)
            self.current_assessments.append(assessment)

            # Persist
            self.event_repo.save(event)
            self.ass_repo.save(assessment)

            # Update profile
            self.global_profile.addAssessment(assessment)

            # Alert if needed
            if self.alert_svc.shouldAlert(assessment):
                alert = self.alert_svc.createAlert(assessment)
                self.alert_repo.save(alert)

        # Step 3: Correlate
        self.correlator.correlate(self.current_events)

        # Step 4: Persist profile
        self.profile_repo.save(self.global_profile)

    # ── convenience accessors for views ──────────────────────────────────────

    def collector_status(self) -> dict[str, str]:
        return {
            "Process Collector": self.proc_collector.status,
            "Network Collector": self.net_collector.status,
            "File Watcher":      self.file_watcher.status,
            "Threat Intel":      self.threat_intel.status,
        }

    def live_processes(self):
        return self.proc_collector.getProcessObjects()

    def live_connections(self):
        return self.net_collector.getConnectionObjects()


# ════════════════════════════════════════════════════════════════════════════
# CLI  — interactive menu
# ════════════════════════════════════════════════════════════════════════════

def _print_menu() -> None:
    menu = """
  ┌─────────────────────────────────────────────────────┐
  │            SentinelCore  — Main Menu                │
  ├─────────────────────────────────────────────────────┤
  │  [1] Run Live Scan + Analyst Dashboard              │
  │  [2] Live Process Monitor                           │
  │  [3] Live Network Connections                       │
  │  [4] Alert Management                               │
  │  [5] Correlation Cases                              │
  │  [6] CISO Executive Dashboard                       │
  │  [7] Risk Trend Analysis                            │
  │  [8] What-If Scenario Builder                       │
  │  [9] Strategic Recommendations                      │
  │  [A] Audit Trail                                    │
  │  [C] Continuous Monitor (auto-refresh every 30s)    │
  │  [Q] Quit                                           │
  └─────────────────────────────────────────────────────┘
"""
    print(menu)

def _get_input(prompt: str = "  Choice > ") -> str:
    try:
        return input(prompt).strip().upper()
    except (EOFError, KeyboardInterrupt):
        return "Q"

def _pause() -> None:
    try:
        input("\n  Press Enter to return to menu...")
    except (EOFError, KeyboardInterrupt):
        pass


def _build_scenario(engine: ScanEngine) -> ScenarioAnalysis:
    """Interactive what-if scenario builder."""
    print("\n  === What-If Scenario Builder ===")
    name = input("  Scenario name: ").strip() or "Unnamed Scenario"
    desc = input("  Description  : ").strip() or ""
    print("  Enter hypotheses (one per line, empty line to finish).")
    print("  Examples:")
    print("    remove firewall rule X")
    print("    add threat intel feed")
    print("    patch critical CVEs")
    print("    add encryption")
    hypotheses: dict[str, str] = {}
    i = 1
    while True:
        h = input(f"  Hypothesis {i}: ").strip()
        if not h:
            break
        v = input(f"  Value/detail : ").strip() or "applied"
        hypotheses[h] = v
        i += 1

    scenario = ScenarioAnalysis(
        scenarioId    = _new_id("SCN-"),
        name          = name,
        description   = desc,
        baselineScore = int(engine.global_profile.averageScore),
        hypotheses    = hypotheses,
    )
    scenario.profileId = engine.global_profile.profileId
    scenario.run(engine.global_profile)
    engine.scenario_repo.save(scenario)
    return scenario


def main() -> None:
    # ── startup banner ────────────────────────────────────────────────────────
    os.system("cls" if platform.system() == "Windows" else "clear")
    print("""
  ╔══════════════════════════════════════════════════════════════╗
  ║                    S E N T I N E L C O R E                  ║
  ║        Live Real-Time Security Monitoring & Detection        ║
  ╠══════════════════════════════════════════════════════════════╣
  ║  Platform : {:<50}║
  ║  Python   : {:<50}║
  ╚══════════════════════════════════════════════════════════════╝
""".format(
        platform.system() + " " + platform.release(),
        sys.version.split()[0],
    ))
    print("  Initialising collectors and database...")

    engine   = ScanEngine()
    analyst  = SecurityDashboard(role="analyst")
    ciso_dsh = ExecutiveDashboard(role="ciso")
    recs: list = []
    scenarios: list[ScenarioAnalysis] = []
    cases: list = []

    print("  Ready.  Running initial scan...")
    engine.run_cycle()
    print("  Initial scan complete.\n")

    while True:
        _print_menu()
        choice = _get_input()

        # ── 1: Full scan + analyst overview ──────────────────────────────────
        if choice == "1":
            print("  Running live scan...")
            engine.run_cycle()
            processes   = engine.live_processes()
            connections = engine.live_connections()
            analyst.showOverview(
                events           = engine.current_events,
                alerts           = engine.alert_svc.getAlerts(),
                assessments      = engine.current_assessments,
                processes        = processes,
                connections      = connections,
                collector_status = engine.collector_status(),
            )
            # Show top event detail if available
            if engine.current_events:
                top = sorted(
                    engine.current_assessments,
                    key=lambda a: a.riskScore, reverse=True
                )
                if top:
                    ev = next(
                        (e for e in engine.current_events
                         if e.eventId == top[0].targetId), None
                    )
                    if ev:
                        analyst.showEventDetail(ev, top[0])
            _pause()

        # ── 2: Process monitor ───────────────────────────────────────────────
        elif choice == "2":
            print("  Fetching live processes...")
            processes = engine.live_processes()
            analyst.showProcesses(processes, limit=30)
            _pause()

        # ── 3: Network connections ────────────────────────────────────────────
        elif choice == "3":
            print("  Fetching live connections...")
            connections = engine.live_connections()
            analyst.showConnections(connections, limit=30)
            _pause()

        # ── 4: Alert management ───────────────────────────────────────────────
        elif choice == "4":
            alerts      = engine.alert_svc.getAlerts()
            assessments = engine.ass_repo.getAll()
            analyst.showAlerts(alerts, assessments)
            if alerts:
                print("  Update alert? Enter AlertID (or blank to skip): ", end="")
                try:
                    aid = input().strip()
                except (EOFError, KeyboardInterrupt):
                    aid = ""
                if aid:
                    alert = next((a for a in alerts if a.alertId == aid), None)
                    if alert:
                        print(
                            "  New status [ACKNOWLEDGED / INVESTIGATING / "
                            "ESCALATED / RESOLVED / CLOSED]: ", end=""
                        )
                        try:
                            ns = input().strip().upper()
                        except (EOFError, KeyboardInterrupt):
                            ns = ""
                        if ns:
                            try:
                                engine.alert_svc.updateAlertStatus(
                                    alert, ns, actorId="cli_user"
                                )
                                engine.alert_repo.save(alert)
                                print(f"  Alert {aid} → {ns}")
                            except ValueError as e:
                                print(f"  Error: {e}")
            _pause()

        # ── 5: Correlation cases ──────────────────────────────────────────────
        elif choice == "5":
            all_events = engine.event_repo.getRecent(limit=200)
            cases      = engine.correlator.correlate(all_events)
            analyst.showCorrelationCases(cases)
            _pause()

        # ── 6: CISO Executive Dashboard ───────────────────────────────────────
        elif choice == "6":
            assessments    = engine.ass_repo.getAll()
            scores         = [a.riskScore for a in assessments] if assessments else [0]
            avg_s          = sum(scores) / len(scores) if scores else 0
            critical_count = sum(1 for a in assessments if a.riskLevel == "CRITICAL")
            active_alerts  = engine.alert_svc.getActiveCount()
            ciso_dsh.showKPIs(
                total_events     = engine.event_repo.countLast24h(),
                active_alerts    = active_alerts,
                avg_score        = avg_s,
                trend            = engine.global_profile.trend,
                critical_count   = critical_count,
                collector_status = engine.collector_status(),
            )
            _pause()

        # ── 7: Risk trends ────────────────────────────────────────────────────
        elif choice == "7":
            ciso_dsh.showTrends(engine.global_profile)
            _pause()

        # ── 8: Scenario builder ───────────────────────────────────────────────
        elif choice == "8":
            try:
                scenario = _build_scenario(engine)
                scenarios.append(scenario)
                print()
                print(f"  {scenario.compareBaseline()}")
                print()
            except (EOFError, KeyboardInterrupt):
                print("\n  Scenario cancelled.")
            _pause()

        # ── 9: Recommendations ────────────────────────────────────────────────
        elif choice == "9":
            assessments = engine.ass_repo.getAll()
            recs = engine.rec_engine.generate(
                scenario    = scenarios[-1] if scenarios else None,
                profile     = engine.global_profile,
                assessments = assessments,
            )
            ciso_dsh.showRecommendations(recs)
            _pause()

        # ── A: Audit trail ────────────────────────────────────────────────────
        elif choice == "A":
            try:
                entries = engine.audit_repo.getAll()
                all_entries = engine.alert_svc.getAuditTrail() + entries
                analyst.showAuditLog(
                    sorted(all_entries, key=lambda e: e.timestamp, reverse=True)
                )
            except PermissionError:
                print()
                print(f"  [!] Access Denied — The Audit Trail requires the 'admin' role.")
                print(f"      Current role: {analyst.role}")
                print("      Contact your system administrator to request elevated access "
                      "if this view is required.")
                print()
            _pause()

        # ── C: Continuous monitor ─────────────────────────────────────────────
        elif choice == "C":
            interval = 30
            print(f"\n  Continuous monitor active (refresh every {interval}s).")
            print("  Press Ctrl+C to return to menu.\n")
            try:
                while True:
                    engine.run_cycle()
                    processes   = engine.live_processes()
                    connections = engine.live_connections()
                    analyst.showOverview(
                        events           = engine.current_events,
                        alerts           = engine.alert_svc.getAlerts(),
                        assessments      = engine.current_assessments,
                        processes        = processes,
                        connections      = connections,
                        collector_status = engine.collector_status(),
                    )
                    print(
                        f"\n  Next refresh in {interval}s — "
                        "press Ctrl+C to return to menu."
                    )
                    time.sleep(interval)
            except KeyboardInterrupt:
                print("\n  Continuous monitor stopped.\n")

        # ── Q: Quit ───────────────────────────────────────────────────────────
        elif choice in ("Q", "QUIT", "EXIT"):
            print("\n  SentinelCore shutdown.  Goodbye.\n")
            engine.db.close()
            sys.exit(0)

        else:
            print("  Invalid option.  Please try again.")


if __name__ == "__main__":
    main()