"""
SentinelCore — RecommendationEngine
Generates ranked strategic recommendations from ScenarioAnalysis results
and from live risk trends.
"""

from __future__ import annotations

from domain.models import (
    HistoricalRiskProfile,
    Recommendation,
    RiskAssessment,
    ScenarioAnalysis,
)


class RecommendationEngine:
    """Generates and ranks Recommendation objects. Stateless."""

    def generate(
        self,
        scenario:    ScenarioAnalysis | None = None,
        profile:     HistoricalRiskProfile | None = None,
        assessments: list[RiskAssessment] | None = None,
    ) -> list[Recommendation]:
        """
        Build recommendations from scenario outcomes and/or live assessments.
        At least one argument should be non-None for meaningful output.
        """
        recs: list[Recommendation] = []
        ev_ids: list[str] = [a.assessmentId for a in (assessments or [])]

        # ── Scenario-driven recommendations ──────────────────────────────────
        if scenario and scenario.delta != 0:
            if scenario.delta > 0:
                recs.append(Recommendation(
                    title       = f"Avoid: {scenario.name}",
                    description = (
                        f"The scenario '{scenario.name}' is projected to raise your "
                        f"risk score by {scenario.delta} points "
                        f"(from {scenario.baselineScore} to {scenario.projectedScore}). "
                        "Do not proceed without additional compensating controls."
                    ),
                    priority    = "HIGH" if scenario.delta > 15 else "MEDIUM",
                    evidenceIds = [scenario.scenarioId],
                    impact      = f"Prevents +{scenario.delta} point risk increase",
                ))
            else:
                recs.append(Recommendation(
                    title       = f"Implement: {scenario.name}",
                    description = (
                        f"Implementing '{scenario.name}' is projected to lower your "
                        f"risk score by {abs(scenario.delta)} points "
                        f"(from {scenario.baselineScore} to {scenario.projectedScore})."
                    ),
                    priority    = "HIGH" if abs(scenario.delta) > 15 else "MEDIUM",
                    evidenceIds = [scenario.scenarioId],
                    impact      = f"-{abs(scenario.delta)} points projected",
                ))

        # ── Profile-driven recommendations ────────────────────────────────────
        if profile:
            if profile.trend == "RISING":
                recs.append(Recommendation(
                    title       = "Investigate Rising Risk Trend",
                    description = (
                        f"The risk score for entity '{profile.entityId}' is trending "
                        "RISING. Review recent events, correlate anomalies, and "
                        "consider a threat hunt."
                    ),
                    priority    = "HIGH",
                    evidenceIds = [profile.profileId],
                    impact      = "Arrest risk escalation before critical threshold",
                ))
            if len(profile.peaks) >= 2:
                recs.append(Recommendation(
                    title       = "Address Recurring Critical Spikes",
                    description = (
                        f"{len(profile.peaks)} critical risk peaks detected in "
                        f"entity '{profile.entityId}'. Recurring peaks indicate an "
                        "unresolved root cause. Conduct a structured incident review."
                    ),
                    priority    = "HIGH",
                    evidenceIds = [profile.profileId],
                    impact      = "Eliminate root cause of recurring spikes",
                ))
            if profile.averageScore >= 50:
                recs.append(Recommendation(
                    title       = "Reduce Sustained Elevated Risk",
                    description = (
                        f"Average risk score is {profile.averageScore:.0f} — "
                        "persistently above MEDIUM. Deploy additional endpoint "
                        "detection, review privilege assignments, and audit network "
                        "egress rules."
                    ),
                    priority    = "MEDIUM",
                    evidenceIds = [profile.profileId],
                    impact      = "Bring average score below 50 (MEDIUM threshold)",
                ))

        # ── Assessment-driven recommendations ─────────────────────────────────
        if assessments:
            critical = [a for a in assessments if a.riskLevel == "CRITICAL"]
            if critical:
                recs.append(Recommendation(
                    title       = f"Immediate Response: {len(critical)} Critical Event(s)",
                    description = (
                        f"{len(critical)} event(s) scored CRITICAL in the last scan. "
                        "Activate the Incident Response playbook. Isolate affected "
                        "processes, capture memory, preserve evidence."
                    ),
                    priority    = "HIGH",
                    evidenceIds = [a.assessmentId for a in critical],
                    impact      = "Contain active threat before lateral movement",
                ))
            high = [a for a in assessments if a.riskLevel == "HIGH"]
            if high:
                recs.append(Recommendation(
                    title       = f"Investigate {len(high)} High-Risk Event(s)",
                    description = (
                        f"{len(high)} HIGH-severity event(s) require analyst review "
                        "within 4 hours. Check process lineage, network destinations, "
                        "and file modifications."
                    ),
                    priority    = "MEDIUM",
                    evidenceIds = [a.assessmentId for a in high],
                    impact      = "Prevent HIGH events from escalating to CRITICAL",
                ))

        # Default: if nothing was generated, add a baseline hygiene rec
        if not recs:
            recs.append(Recommendation(
                title       = "Maintain Security Hygiene",
                description = (
                    "No critical findings this cycle. Continue regular patching, "
                    "review least-privilege assignments quarterly, and ensure "
                    "collectors are ACTIVE."
                ),
                priority    = "LOW",
                evidenceIds = ev_ids,
                impact      = "Prevent drift from secure baseline",
            ))

        return self.rank(recs)

    def rank(self, recommendations: list[Recommendation]) -> list[Recommendation]:
        """Sort by priority: HIGH → MEDIUM → LOW."""
        _order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        return sorted(recommendations, key=lambda r: _order.get(r.priority, 9))
