"""
SentinelCore — Storage Layer
SQLite-backed repositories for SecurityEvents, RiskAssessments, Alerts,
CorrelationCases, HistoricalRiskProfile, and AuditEntries.
Single file for simplicity; split into per-entity files for larger deployments.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path

from config.settings import DB_PATH
from domain.models import (
    Alert,
    AuditEntry,
    CorrelationCase,
    HistoricalRiskProfile,
    RiskAssessment,
    ScenarioAnalysis,
    SecurityEvent,
    _new_id,
)

logger = logging.getLogger(__name__)

_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS security_events (
    event_id    TEXT PRIMARY KEY,
    event_type  TEXT NOT NULL,
    source_id   TEXT NOT NULL,
    source_type TEXT NOT NULL,
    timestamp   TEXT NOT NULL,
    raw_data    TEXT NOT NULL,
    context     TEXT NOT NULL,
    indicators  TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS risk_assessments (
    assessment_id    TEXT PRIMARY KEY,
    target_id        TEXT NOT NULL,
    target_type      TEXT NOT NULL,
    risk_score       INTEGER NOT NULL,
    risk_level       TEXT NOT NULL,
    explanation      TEXT NOT NULL,
    contributing_ids TEXT NOT NULL DEFAULT '[]',
    timestamp        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id       TEXT PRIMARY KEY,
    severity       TEXT NOT NULL,
    status         TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    assessment_id  TEXT NOT NULL,
    assigned_to    TEXT NOT NULL DEFAULT '',
    audit_entries  TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS correlation_cases (
    case_id    TEXT PRIMARY KEY,
    confidence INTEGER NOT NULL,
    status     TEXT NOT NULL,
    reason     TEXT NOT NULL,
    event_ids  TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_entries (
    entry_id    TEXT PRIMARY KEY,
    actor_id    TEXT NOT NULL,
    action      TEXT NOT NULL,
    target_id   TEXT NOT NULL,
    target_type TEXT NOT NULL,
    before_state TEXT NOT NULL DEFAULT '{}',
    after_state  TEXT NOT NULL DEFAULT '{}',
    timestamp   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS historical_risk_profiles (
    profile_id    TEXT PRIMARY KEY,
    entity_id     TEXT NOT NULL UNIQUE,
    trend         TEXT NOT NULL,
    average_score REAL NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scenario_analyses (
    scenario_id      TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    description      TEXT NOT NULL,
    baseline_score   INTEGER NOT NULL,
    hypotheses       TEXT NOT NULL DEFAULT '{}',
    projected_score  INTEGER NOT NULL,
    delta            INTEGER NOT NULL,
    profile_id       TEXT NOT NULL DEFAULT '',
    created_at       TEXT NOT NULL
);
"""


class Database:
    """Thin SQLite wrapper. All repositories use this."""

    def __init__(self, path: str = DB_PATH) -> None:
        self._path = path
        self._conn: sqlite3.Connection | None = None

    def connect(self) -> None:
        Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        logger.info("Database connected: %s", self._path)

    def close(self) -> None:
        if self._conn:
            self._conn.close()

    @property
    def conn(self) -> sqlite3.Connection:
        if not self._conn:
            self.connect()
        return self._conn

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        try:
            cur = self.conn.execute(sql, params)
            self.conn.commit()
            return cur
        except sqlite3.Error as e:
            logger.error("DB execute error: %s | SQL: %s", e, sql)
            raise

    def fetchall(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        return self.conn.execute(sql, params).fetchall()

    def fetchone(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        return self.conn.execute(sql, params).fetchone()


# ════════════════════════════════════════════════════════════════════════════
# REPOSITORIES
# ════════════════════════════════════════════════════════════════════════════

class EventRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def save(self, event: SecurityEvent) -> None:
        self._db.execute(
            """INSERT OR REPLACE INTO security_events
               (event_id, event_type, source_id, source_type,
                timestamp, raw_data, context, indicators)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                event.eventId,
                event.eventType,
                event.sourceId,
                event.sourceType,
                event.timestamp.isoformat(),
                json.dumps(event.rawData),
                event.context,
                json.dumps(event.indicators),
            ),
        )

    def saveBatch(self, events: list[SecurityEvent]) -> None:
        for e in events:
            self.save(e)

    def getLast24h(self) -> list[SecurityEvent]:
        from datetime import timedelta
        cutoff = (datetime.now() - timedelta(hours=24)).isoformat()
        rows = self._db.fetchall(
            "SELECT * FROM security_events WHERE timestamp >= ? ORDER BY timestamp DESC",
            (cutoff,),
        )
        return [_row_to_event(r) for r in rows]

    def getRecent(self, limit: int = 50) -> list[SecurityEvent]:
        rows = self._db.fetchall(
            "SELECT * FROM security_events ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )
        return [_row_to_event(r) for r in rows]

    def countLast24h(self) -> int:
        from datetime import timedelta
        cutoff = (datetime.now() - timedelta(hours=24)).isoformat()
        row = self._db.fetchone(
            "SELECT COUNT(*) AS cnt FROM security_events WHERE timestamp >= ?",
            (cutoff,),
        )
        return row["cnt"] if row else 0


class AssessmentRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def save(self, assessment: RiskAssessment) -> None:
        self._db.execute(
            """INSERT OR REPLACE INTO risk_assessments
               (assessment_id, target_id, target_type, risk_score, risk_level,
                explanation, contributing_ids, timestamp)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                assessment.assessmentId,
                assessment.targetId,
                assessment.targetType,
                assessment.riskScore,
                assessment.riskLevel,
                assessment.explanation,
                json.dumps(assessment.contributingIds),
                assessment.timestamp.isoformat(),
            ),
        )

    def getByTargetId(self, targetId: str) -> RiskAssessment | None:
        row = self._db.fetchone(
            "SELECT * FROM risk_assessments WHERE target_id = ?", (targetId,)
        )
        return _row_to_assessment(row) if row else None

    def getTopRisk(self, limit: int = 10) -> list[RiskAssessment]:
        rows = self._db.fetchall(
            "SELECT * FROM risk_assessments ORDER BY risk_score DESC LIMIT ?",
            (limit,),
        )
        return [_row_to_assessment(r) for r in rows]

    def getAll(self) -> list[RiskAssessment]:
        rows = self._db.fetchall(
            "SELECT * FROM risk_assessments ORDER BY timestamp DESC"
        )
        return [_row_to_assessment(r) for r in rows]


class AlertRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def save(self, alert: Alert) -> None:
        self._db.execute(
            """INSERT OR REPLACE INTO alerts
               (alert_id, severity, status, created_at, assessment_id,
                assigned_to, audit_entries)
               VALUES (?,?,?,?,?,?,?)""",
            (
                alert.alertId,
                alert.severity,
                alert.status,
                alert.createdAt.isoformat(),
                alert.assessmentId,
                alert.assignedTo,
                json.dumps(alert.auditEntries),
            ),
        )

    def getActive(self) -> list[Alert]:
        rows = self._db.fetchall(
            """SELECT * FROM alerts WHERE status NOT IN ('RESOLVED','CLOSED')
               ORDER BY created_at DESC"""
        )
        return [_row_to_alert(r) for r in rows]

    def getAll(self) -> list[Alert]:
        rows = self._db.fetchall(
            "SELECT * FROM alerts ORDER BY created_at DESC"
        )
        return [_row_to_alert(r) for r in rows]


class AuditRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def save(self, entry: AuditEntry) -> None:
        self._db.execute(
            """INSERT OR REPLACE INTO audit_entries
               (entry_id, actor_id, action, target_id, target_type,
                before_state, after_state, timestamp)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                entry.entryId, entry.actorId, entry.action,
                entry.targetId, entry.targetType,
                entry.before, entry.after,
                entry.timestamp.isoformat(),
            ),
        )

    def getAll(self) -> list[AuditEntry]:
        rows = self._db.fetchall(
            "SELECT * FROM audit_entries ORDER BY timestamp DESC"
        )
        return [_row_to_audit(r) for r in rows]


class ProfileRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def save(self, profile: HistoricalRiskProfile) -> None:
        self._db.execute(
            """INSERT OR REPLACE INTO historical_risk_profiles
               (profile_id, entity_id, trend, average_score, updated_at)
               VALUES (?,?,?,?,?)""",
            (
                profile.profileId,
                profile.entityId,
                profile.trend,
                profile.averageScore,
                datetime.now().isoformat(),
            ),
        )

    def getByEntityId(self, entityId: str) -> HistoricalRiskProfile | None:
        row = self._db.fetchone(
            "SELECT * FROM historical_risk_profiles WHERE entity_id = ?",
            (entityId,),
        )
        if not row:
            return None
        return HistoricalRiskProfile(
            profileId    = row["profile_id"],
            entityId     = row["entity_id"],
            trend        = row["trend"],
            averageScore = row["average_score"],
        )


class ScenarioRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def save(self, scenario: ScenarioAnalysis) -> None:
        self._db.execute(
            """INSERT OR REPLACE INTO scenario_analyses
               (scenario_id, name, description, baseline_score, hypotheses,
                projected_score, delta, profile_id, created_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                scenario.scenarioId,
                scenario.name,
                scenario.description,
                scenario.baselineScore,
                json.dumps(scenario.hypotheses),
                scenario.projectedScore,
                scenario.delta,
                scenario.profileId,
                scenario.createdAt.isoformat(),
            ),
        )

    def getAll(self) -> list[ScenarioAnalysis]:
        rows = self._db.fetchall(
            "SELECT * FROM scenario_analyses ORDER BY created_at DESC"
        )
        result = []
        for r in rows:
            s = ScenarioAnalysis(
                scenarioId     = r["scenario_id"],
                name           = r["name"],
                description    = r["description"],
                baselineScore  = r["baseline_score"],
                hypotheses     = json.loads(r["hypotheses"]),
                projectedScore = r["projected_score"],
                delta          = r["delta"],
                profileId      = r["profile_id"],
            )
            result.append(s)
        return result


# ════════════════════════════════════════════════════════════════════════════
# Row → Domain Object helpers
# ════════════════════════════════════════════════════════════════════════════

def _row_to_event(r: sqlite3.Row) -> SecurityEvent:
    return SecurityEvent(
        eventId    = r["event_id"],
        eventType  = r["event_type"],
        sourceId   = r["source_id"],
        sourceType = r["source_type"],
        timestamp  = datetime.fromisoformat(r["timestamp"]),
        rawData    = json.loads(r["raw_data"]),
        context    = r["context"],
        indicators = json.loads(r["indicators"]),
    )

def _row_to_assessment(r: sqlite3.Row) -> RiskAssessment:
    return RiskAssessment(
        assessmentId    = r["assessment_id"],
        targetId        = r["target_id"],
        targetType      = r["target_type"],
        riskScore       = r["risk_score"],
        riskLevel       = r["risk_level"],
        explanation     = r["explanation"],
        contributingIds = json.loads(r["contributing_ids"]),
        timestamp       = datetime.fromisoformat(r["timestamp"]),
    )

def _row_to_alert(r: sqlite3.Row) -> Alert:
    return Alert(
        alertId      = r["alert_id"],
        severity     = r["severity"],
        status       = r["status"],
        createdAt    = datetime.fromisoformat(r["created_at"]),
        assessmentId = r["assessment_id"],
        assignedTo   = r["assigned_to"],
        auditEntries = json.loads(r["audit_entries"]),
    )

def _row_to_audit(r: sqlite3.Row) -> AuditEntry:
    return AuditEntry(
        entryId    = r["entry_id"],
        actorId    = r["actor_id"],
        action     = r["action"],
        targetId   = r["target_id"],
        targetType = r["target_type"],
        before     = r["before_state"],
        after      = r["after_state"],
        timestamp  = datetime.fromisoformat(r["timestamp"]),
    )
