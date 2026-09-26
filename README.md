<div align="center">

# 🛡️ SentinelCore

### Live Real-Time Security Monitoring & Threat Detection

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?style=for-the-badge&logo=linux)](https://github.com)
[![Dependency](https://img.shields.io/badge/Dependency-psutil%20only-green?style=for-the-badge)](https://pypi.org/project/psutil/)
[![Tests](https://img.shields.io/badge/Tests-42%20Passed-brightgreen?style=for-the-badge)](./tests/test_core.py)
[![License](https://img.shields.io/badge/License-MIT-orange?style=for-the-badge)](LICENSE)

> **Zero mock data. Zero heavy dependencies.**  
> Every byte of telemetry comes from your live host OS.

</div>

---

## 📌 Overview

**SentinelCore** is a production-ready, modular security monitoring CLI built entirely in Python. It collects live telemetry from the host operating system — processes, network connections, and file system changes — analyzes it in real time through a clean layered architecture, scores every anomaly on a 0–100 risk scale, and surfaces actionable insights through both an **Analyst Dashboard** and a **CISO Executive Dashboard**.

No agents. No cloud. No heavy frameworks. Just `psutil` and Python.

---

## ⚡ Quick Start

```bash
# 1. Install the only dependency
pip install psutil

# 2. Run (Linux: sudo recommended for full network visibility)
python main.py

# Windows — run as Administrator for complete network socket access
```

---

## 🏗️ Architecture

SentinelCore follows a strict **4-layer model** with enforced separation of concerns:

```
┌──────────────────────────────────────────────────┐
│              PRESENTATION LAYER                  │
│   SecurityDashboard (Analyst) · ExecutiveDash    │
│              views/dashboards.py                 │
├──────────────────────────────────────────────────┤
│               BUSINESS LAYER                     │
│  SecurityAnalyzer · RiskEngine · CorrelationEng  │
│  AlertService · RecommendationEngine             │
│              services/                           │
├──────────────────────────────────────────────────┤
│                DOMAIN LAYER                      │
│  Process · NetworkConnection · FileActivity      │
│  SecurityEvent · ThreatIndicator · RiskAssessment│
│  CorrelationCase · Alert · HistoricalRiskProfile │
│  ScenarioAnalysis · AuditEntry · Recommendation  │
│              domain/models.py                    │
├──────────────────────────────────────────────────┤
│                  DATA LAYER                      │
│  ProcessCollector · NetworkCollector             │
│  FileWatcher · ThreatIntelAdapter                │
│  SQLite Repositories (EventRepo, AlertRepo …)    │
│              collectors/  ·  storage/            │
└──────────────────────────────────────────────────┘
```

**Design Principles:** Single Responsibility · High Cohesion · Open/Closed · Dependency Inversion

---

## 📁 Project Structure

```
SentinelCore/
│
├── main.py                        ← Interactive CLI entry point
│
├── config/
│   ├── settings.py                ← All thresholds, ports, paths, intervals
│   └── ioc_local.csv              ← Local IOC seed list (extend with real intel)
│
├── domain/
│   └── models.py                  ← 13 @dataclass entities (the full domain model)
│
├── collectors/
│   ├── base.py                    ← DataSourceAdapter abstract base class
│   ├── process_collector.py       ← Live process enumeration via psutil
│   ├── network_collector.py       ← Live socket monitoring via psutil
│   ├── file_watcher.py            ← Stat-based sensitive file change detection
│   └── threat_intel_adapter.py   ← IOC loader (local CSV + extensible feed URL)
│
├── services/
│   ├── security_analyzer.py       ← Stateless anomaly analysis engine
│   ├── risk_engine.py             ← 0–100 risk scoring with full explanation trace
│   ├── correlation_engine.py      ← 4 correlation rules → CorrelationCase objects
│   ├── alert_service.py           ← Alert lifecycle + mandatory audit trail
│   └── recommendation_engine.py  ← Ranked strategic recommendations
│
├── storage/
│   └── db.py                      ← SQLite + typed repositories for all entities
│
├── views/
│   └── dashboards.py              ← SecurityDashboard (Analyst) + ExecutiveDashboard (CISO)
│
└── tests/
    └── test_core.py               ← 42 unit tests — all pass
```

---

## 🖥️ CLI Navigation

```
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
│  [A] Audit Trail          (admin role required)     │
│  [C] Continuous Monitor   (auto-refresh every 30s)  │
│  [Q] Quit                                           │
└─────────────────────────────────────────────────────┘
```

---

## 🔍 Detection Coverage

### Process Anomalies
| Signal | Description |
|--------|-------------|
| Suspicious path | Executable in `/tmp/`, `/dev/shm/`, `AppData\Temp`, `Users\Public`, etc. |
| Known malicious name | Matches `mimikatz`, `procdump`, `mshta`, `certutil`, `bitsadmin`, and 20+ others |
| Process hollowing | Running process with no executable path (and not a known kernel thread) |
| Privilege escalation | `SYSTEM` / `root` process outside standard OS paths |
| Zombie process | Lingering zombie indicating parent failure |

> **Whitelisted:** PID 0 / PID 4 (Windows), all kernel threads, Windows Defender (`MpDefenderCoreService.exe`, `NisSrv.exe`, `MsMpEng.exe`), all `systemd` services, and 80+ known-good OS binaries — these are **never** flagged as false positives.

### Network Anomalies
| Signal | Description |
|--------|-------------|
| Suspicious port | Connections on 4444, 1337, 31337, 5555, 6666–6669, 1080, and more |
| High ephemeral port | Outbound port > 49000 to a public IP |
| Ownerless connection | ESTABLISHED socket with no owning PID (rootkit indicator) |
| IOC match | Destination IP or domain matches loaded threat intel |

### File System Anomalies
| Signal | Description |
|--------|-------------|
| Sensitive path change | Any `CREATE`/`MODIFY`/`RENAME` on `/etc/`, `/root/`, `System32`, `AppData\Roaming`, etc. |
| Sensitive path deletion | `DELETE` on a sensitive path — highest severity flag |
| IOC path match | File path matches a known-malicious path in the IOC list |

---

## 📊 Risk Scoring

Every security event is scored **0–100** with a fully traceable explanation.  
A score without an explanation is enforced as a bug via assertion.

| Score | Level | Recommended Action |
|-------|-------|--------------------|
| 0 – 24 | 🟢 **LOW** | Monitor passively |
| 25 – 49 | 🟡 **MEDIUM** | Schedule review |
| 50 – 74 | 🟠 **HIGH** | Investigate within 4 hours |
| 75 – 100 | 🔴 **CRITICAL** | Activate incident response immediately |

**Score composition:**
- Base score by event type (PROCESS_ANOMALY → 40, NETWORK_SUSPICIOUS → 35, FILE_CHANGE → 30)
- Analysis confidence contribution (up to +35 pts)
- Per-IOC-match bonus (up to +25 pts per indicator)
- File action severity bonus (DELETE → +20, MODIFY → +10)
- Privileged-user bonus (+10)
- Ownerless-connection bonus (+15)

---

## 🔗 Correlation Engine

Four rules group related `SecurityEvent` objects into `CorrelationCase` objects:

| Rule | Trigger |
|------|---------|
| **Same-PID Multi-Type** | Same process PID appears in both process + network/file events |
| **Repeated Destination** | 3+ network connections to the same external IP (beaconing) |
| **File → Process** | Sensitive file modification followed by a new process spawn |
| **Shared IOC** | 2+ events share the same `ThreatIndicator` ID |

---

## 🚨 Alert Lifecycle

```
NEW → ACKNOWLEDGED → INVESTIGATING → RESOLVED → CLOSED
                          ↕
                      ESCALATED
```

Every state transition generates an immutable `AuditEntry`.  
The Audit Trail is role-protected: requires `admin` role.

---

## 🔮 What-If Scenario Builder

The CISO view includes an interactive scenario builder. Type hypotheses in plain language and SentinelCore projects the risk score delta:

```
Hypothesis: "remove firewall rule"   → +20 pts projected
Hypothesis: "add threat intel feed"  → -10 pts projected
Hypothesis: "patch critical CVEs"    → -12 pts projected
Hypothesis: "add encryption"         → -5  pts projected
```

---

## 🧪 Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

```
tests/test_core.py::TestProcess::test_getinfo_returns_all_fields    PASSED
tests/test_core.py::TestSecurityAnalyzer::test_suspicious_port_network PASSED
tests/test_core.py::TestRiskEngine::test_explanation_never_empty    PASSED
tests/test_core.py::TestAlertService::test_alert_lifecycle          PASSED
... 42 passed in < 2s
```

---

## 🔧 Extending the IOC List

Add your own threat intel to `config/ioc_local.csv`:

```csv
# type,value,source,confidence
IP,198.51.100.1,my-threat-feed,90
DOMAIN,c2.malware-example.com,my-threat-feed,85
HASH,44d886121541551531e82e1278abb02f,virustotal,75
PATH,/tmp/implant,internal,95
BEHAVIOR,process_injection,internal,80
```

---

## 🔐 Role-Based Access

| Role | Permissions |
|------|-------------|
| `security_user` | Dashboard, Alerts |
| `analyst` | Dashboard, Alerts, Events, Correlations, Update Alerts |
| `admin` | All analyst permissions + **Audit Trail** |
| `ciso` | Executive dashboard, Trends, Scenarios, Recommendations |
| `executive` | Executive dashboard only |

---

## ⚙️ Requirements

| Item | Detail |
|------|--------|
| Python | 3.10 or higher |
| Dependency | `psutil` (pip install psutil) |
| OS | Windows 10/11 or any modern Linux distro |
| Privileges | Standard user (elevated recommended for full network visibility) |
| Storage | SQLite — auto-created as `SentinelCore.db` on first run |

---

## 📝 Notes

- **Linux:** `sudo python main.py` gives full `/proc` and `net_connections` visibility
- **Windows:** Run terminal as Administrator for complete socket enumeration
- **No outbound connections:** SentinelCore is read-only; it never sends data externally
- **Database:** `SentinelCore.db` is created in the working directory on first run; add it to `.gitignore`

---

## 📄 License

MIT License — free to use, modify, and distribute.

---

<div align="center">

Built with 🛡️ for the security community  

**SentinelCore** — Observe everything. Trust nothing.

<br>

**A CyberNestSec Security Project**

</div>
