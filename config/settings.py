"""
SentinelCore — Configuration Reference
All thresholds, paths, and intervals are defined here.
Edit this file to tune behaviour without touching any other module.
"""

import os
import platform

# ── Collection intervals (seconds) ─────────────────────────────────────────
PROCESS_POLL_INTERVAL_SEC   = 10
NETWORK_POLL_INTERVAL_SEC   = 10
FILE_POLL_INTERVAL_SEC      = 15
LOG_POLL_INTERVAL_SEC       = 30
THREAT_INTEL_REFRESH_HOURS  = 24

# ── Correlation ──────────────────────────────────────────────────────────────
CORRELATION_TIME_WINDOW_SEC = 300   # 5 minutes

# ── Risk scoring thresholds ─────────────────────────────────────────────────
RISK_THRESHOLD_LOW      = 25
RISK_THRESHOLD_MEDIUM   = 50
RISK_THRESHOLD_HIGH     = 75
# score >= 75 → CRITICAL

# ── Alerting ────────────────────────────────────────────────────────────────
ALERT_MIN_SCORE = 50

# ── Storage ──────────────────────────────────────────────────────────────────
DB_PATH = "./SentinelCore.db"

# ── Suspicious process path fragments (cross-platform) ──────────────────────
SUSPICIOUS_PATH_FRAGMENTS = [
    # Linux / macOS
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
    # Windows
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\users\\public\\",
    "\\programdata\\",
]

# ── Sensitive file paths to watch ───────────────────────────────────────────
if platform.system() == "Windows":
    _user = os.environ.get("USERNAME", "user")
    SENSITIVE_PATHS: list[str] = [
        r"C:\Windows\System32",
        r"C:\Windows\SysWOW64",
        rf"C:\Users\{_user}\AppData\Roaming",
        rf"C:\Users\{_user}\AppData\Local\Temp",
        r"C:\Users\Public",
        r"C:\ProgramData",
        r"C:\Windows\Temp",
    ]
    SENSITIVE_PATH_FRAGMENTS: list[str] = [
        "system32",
        "syswow64",
        "appdata\\roaming",
        "appdata\\local\\temp",
        "users\\public",
        "programdata",
        "windows\\temp",
    ]
else:
    SENSITIVE_PATHS: list[str] = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/crontab",
        "/etc/cron.d",
        "/root/",
        "/home/",
        "/var/log/",
        "/tmp/",
        "/dev/shm/",
        "/usr/bin/",
        "/usr/sbin/",
        "/bin/",
        "/sbin/",
    ]
    SENSITIVE_PATH_FRAGMENTS: list[str] = [
        "/etc/",
        "/root/",
        "/tmp/",
        "/dev/shm/",
        "/var/log/",
        "/usr/bin/",
        "/usr/sbin/",
    ]

# ── Suspicious ports (commonly abused) ──────────────────────────────────────
SUSPICIOUS_PORTS = {
    4444,   # Metasploit default
    1337,   # l33t hacker
    31337,  # Elite / Back Orifice
    12345,  # NetBus
    5555,   # ADB / common RAT
    6666,   # IRC botnet
    6667,
    6668,
    6669,
    1080,   # SOCKS proxy
    3128,   # Squid proxy
    8080,   # Proxy / C2
    8888,
    9999,
    2222,
    65535,
}

# ── Known malicious / suspicious process name fragments ─────────────────────
SUSPICIOUS_PROCESS_NAMES = {
    "mimikatz",
    "procdump",
    "wce",
    "fgdump",
    "pwdump",
    "meterpreter",
    "nc.exe",
    "ncat",
    "nmap",
    "masscan",
    "cobaltstrike",
    "beacon",
    "psexec",
    "at.exe",
    "schtasks",
    "regsvr32",
    "mshta",
    "wscript",
    "cscript",
    "certutil",
    "bitsadmin",
    "powershell_ise",
}

# ── Trusted process names — never flagged as threats, regardless of path ────
# Kernel threads (Linux) and core Windows OS / security processes legitimately
# have no standard user-mode executable path, or run from directories
# (e.g. C:\ProgramData) that otherwise look suspicious. Shared by the
# ProcessCollector (gates event creation) and the SecurityAnalyzer (gates
# scoring), so both layers agree on what is "known good".
TRUSTED_PROCESS_NAMES: frozenset[str] = frozenset({
    # ── Windows core / idle ──────────────────────────────────────────────
    "system idle process",
    "system",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "dwm.exe",
    "winlogon.exe",
    "fontdrvhost.exe",
    "sihost.exe",
    "taskhostw.exe",
    "explorer.exe",
    "ctfmon.exe",
    "spoolsv.exe",
    "searchindexer.exe",
    "runtimebroker.exe",
    "securityhealthservice.exe",
    "securityhealthsystray.exe",
    # ── Windows Defender / Microsoft Defender for Endpoint ──────────────
    "msmpeng.exe",              # Windows Defender antimalware
    "mpdefendercoreservice.exe",# Defender core service
    "nissrv.exe",               # Defender network inspection
    "antimalware service executable",
    "mssense.exe",              # Defender for Endpoint sensor
    "senseir.exe",
    "sensecncproxy.exe",
    "mpcmdrun.exe",
    "mpnotify.exe",
    "defendersessionhelper.exe",# Defender session helper (UI/session broker)
    "wscsvc.exe",               # Windows Security Center
    # ── Windows kernel / memory manager threads ───────────────────────
    "memory compression",
    "vmmem",                    # WSL/Hyper-V VM memory
    "wsl",
    "wslhost.exe",
    "wslservice.exe",
    # ── Common legitimate Windows background services ─────────────────
    "audiodg.exe",
    "conhost.exe",
    "dllhost.exe",
    "msdtc.exe",
    "wuauclt.exe",
    "trustedinstaller.exe",
    "tiworker.exe",
    "usocoreworker.exe",
    "wermgr.exe",
    "werFault.exe",
    "backgroundtaskhost.exe",
    "applicationframehost.exe",
    "shellexperiencehost.exe",
    "startmenuexperiencehost.exe",
    "textinputhost.exe",
    "searchhost.exe",
    "searchapp.exe",
    # ── Linux kernel threads (always have no path) ────────────────────
    "kthreadd",
    "rcu_gp",
    "rcu_par_gp",
    "kworker",
    "ksoftirqd",
    "migration",
    "idle_inject",
    "cpuhp",
    "kdevtmpfs",
    "kauditd",
    "khungtaskd",
    "oom_reaper",
    "writeback",
    "kcompactd",
    "ksmd",
    "khugepaged",
    "kintegrityd",
    "kblockd",
    "blkcg_punt_bio",
    "tpm_dev_wq",
    "ata_sff",
    "scsi_eh",
    "scsi_tmf",
    "ipv6_addrconf",
    "kstrp",
    "zswap",
    "charger_manager",
    "kswapd",
    "pool_workqueue_release",
    "process_api",
    "kthrotld",
    "irq",
    "acpi_thermal_pm",
    "xenbus_probe",
    "xenwatch",
    "ext4",
    "jbd2",
    "systemd",
    "systemd-journald",
    "systemd-logind",
    "systemd-networkd",
    "systemd-resolved",
    "systemd-udevd",
    "systemd-timesyncd",
    "dbus-daemon",
    "NetworkManager",
    "accounts-daemon",
    "polkitd",
    "rsyslogd",
    "cron",
    "atd",
    "sshd",
    "agetty",
    "login",
    # ── Common third-party / OEM background updater & agent services ────
    # These are signed, widely-deployed vendor binaries that legitimately
    # install into C:\ProgramData\<Vendor>\... or Program Files and run
    # unattended as SYSTEM/a service account. Historically this is the
    # single biggest source of false-positive PROCESS_ANOMALY noise (e.g.
    # Dell's InstallAssistService.exe or Intel's IGCC.exe getting scored
    # 64/100 HIGH purely for their install directory). Whitelisted by
    # exact name — NOT by trusting the vendor's whole ProgramData subtree
    # wholesale — so a malicious binary can't ride in just by sharing a
    # folder with one of these.
    "installassistservice.exe",       # Dell SupportAssist / OEM install-assist
    "sacoreservice.exe",               # Dell SupportAssist core service
    "dellsupportassistagent.exe",
    "igcc.exe",                        # Intel Graphics Command Center
    "igccservice.exe",
    "igfxem.exe",                      # Intel graphics executable main module
    "igfxtray.exe",
    "nvcontainer.exe",                 # NVIDIA container / telemetry
    "nvdisplay.container.exe",
    "nvupdatussvc.exe",                # NVIDIA update service
    "googleupdate.exe",                # Google Update ("Omaha")
    "googleupdater.exe",
    "googlecrashhandler.exe",
    "googlecrashhandler64.exe",
    "microsoftedgeupdate.exe",
    "onedrive.exe",
    "onedrivesetup.exe",
    "armsvc.exe",                      # Adobe Acrobat/Reader update service
    "adobearm.exe",
    "jusched.exe",                     # Java Update Scheduler
})

# ── Path prefixes that are always considered legitimate system locations ────
# NOTE: we deliberately trust "c:\programdata\microsoft\" as a whole (rather
# than just the "...\windows defender\" subfolder) because signed Microsoft
# security components install into several sibling directories there —
# Windows Defender, Windows Defender Advanced Threat Protection (the MDE
# sensor: MsSense.exe / SenseIR.exe / SenseCncProxy.exe), and Windows
# Security Health — and all of them legitimately run from C:\ProgramData.
# We intentionally do NOT trust all of C:\ProgramData\ (bare root), since
# that directory is world-writable and a common malware staging location;
# only the Microsoft-owned subtree is whitelisted.
TRUSTED_PROCESS_PATH_PREFIXES: tuple[str, ...] = (
    # Windows
    "c:\\windows\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
    "c:\\programdata\\microsoft\\windows defender\\",
    "c:\\programdata\\microsoft\\windows defender advanced threat protection\\",
    "c:\\programdata\\microsoft\\windows security health\\",
    # Common OEM/vendor updater trees under ProgramData. Scoped to the
    # specific vendor subfolder (never the bare ProgramData root) so this
    # can't be used as a general staging-directory bypass — see the
    # updater-service names above for the primary, name-based whitelist;
    # these path prefixes are additional coverage for Google Update, whose
    # versioned subfolders (...\Google\Update\<version>\GoogleUpdate.exe)
    # change on every update and can't all be enumerated by name alone.
    "c:\\programdata\\google\\update\\",
    # Linux / macOS
    "/usr/", "/bin/", "/sbin/", "/lib/",
    "/lib64/", "/opt/", "/snap/",
    "/usr/local/", "/system/", "/systemd/",
)

# ── Role permissions ─────────────────────────────────────────────────────────
ROLES: dict[str, list[str]] = {
    "security_user": ["view_dashboard", "view_alerts"],
    "analyst":       ["view_dashboard", "view_alerts", "view_events",
                      "view_correlations", "update_alert"],
    "admin":         ["view_dashboard", "view_alerts", "view_events",
                      "view_correlations", "update_alert", "view_audit"],
    "ciso":          ["view_executive", "view_trends", "create_scenario",
                      "view_recommendations"],
    "executive":     ["view_executive"],
}

# ── Local IOC seed list (fallback if no external feed) ───────────────────────
LOCAL_IOC_IPS: list[str] = [
    "0.0.0.0",      # placeholder — extend with real threat intel IPs
]

LOCAL_IOC_DOMAINS: list[str] = [
    "malware.example.com",   # placeholder
]