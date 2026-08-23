# 🛡 Windows Security Log Monitor

**Fundamentals of Cybersecurity — Academic Project**

A modular, Python-based Windows desktop application that demonstrates the complete audit log lifecycle:

```
Collect → Parse → Normalize → Store → Detect → Correlate → Investigate
```

---

## 📋 Project Objective

This tool answers the fundamental security investigation questions:

| Question | How the tool answers it |
|---|---|
| Who accessed the system? | Username extraction from event data |
| When did it happen? | Timestamp from Windows Event XML |
| What happened? | Event ID + human-readable description |
| Which account was involved? | Subject/Target user fields |
| Where did it originate? | Source IP address extraction |
| Which log recorded it? | Source log (Security/System/Application/etc.) |
| Is the activity suspicious? | Detection engine with rule-based analysis |
| Can we identify an attack? | Correlation engine building incident timelines |

---

## 🧠 Cybersecurity Concepts Demonstrated

### 1. Audit Logging
Windows records security events in structured XML format. The tool reads these events and shows exactly what Windows records about each security-relevant action.

### 2. Log Collection
The `collectors/` module reads from multiple Windows Event Log sources using `wevtutil`, the built-in Windows command-line tool. Collection is **incremental** — only new events are read on each cycle.

### 3. Log Normalization
Raw XML is parsed by `parsers/event_parser.py` into a consistent `NormalizedEvent` structure, making events from different sources comparable.

### 4. Detection (Rule-Based)
The `detection/` module applies simple, explainable rules:
- **BRUTE_FORCE_001**: ≥5 failed logins from same IP/username within 60 seconds
- **LOCKOUT_001**: Account lockout event (4740)
- **PRIVILEGE_001**: Special privileges assigned (4672)
- **NEWACCOUNT_001**: New user account created (4720)
- **PORTSCAN_001**: ≥10 unique destination ports from same IP within 30 seconds *(optional)*

### 5. Event Correlation
The `correlation/` module links related incidents:
- Brute Force + Account Lockout → **CRITICAL BRUTE_FORCE_LOCKOUT incident**
- Shows correlated timeline of all contributing events

### 6. Incident Investigation
The Incidents page shows every incident with:
- Full detection explanation (why it was detected, what thresholds were exceeded)
- Attack timeline (visual, ordered event sequence)
- Raw Windows Event XML (demonstrates parse → normalize pipeline)
- Export to PDF/CSV

### 7. Traceability
Every incident is linked to the specific Windows events that triggered it. You can trace from incident → event → raw XML → timestamp.

---

## 🏗 Architecture

```
Windows Event Logs  Firewall Log  PowerShell Log
        |                |              |
        +----------------+--------------+
                         |
                  [Log Collectors]
                  (incremental, per-source checkpoints)
                         |
                  [XML Parser / Normalizer]
                  (raw XML → NormalizedEvent)
                         |
                  [SQLite Database]
                  (events + checkpoints)
                         |
                  [Detection Engine]
                  BRUTE_FORCE_001 | LOCKOUT_001 | PRIVILEGE_001
                  NEWACCOUNT_001  | PORTSCAN_001 (optional)
                         |
                  [Correlation Engine]
                  (BRUTE_FORCE + LOCKOUT → CRITICAL incident)
                         |
              +----------+----------+
              |                     |
         [Dashboard]          [Incident Detail]
         (charts, stats)      (timeline, raw events, explanation)
```

---

## 📁 Project Structure

```
windows-security-monitor/
│
├── app/
│   ├── collectors/          # Log source readers (incremental)
│   │   ├── security_log.py  # Windows Security Event Log
│   │   ├── system_log.py    # Windows System Event Log
│   │   ├── application_log.py
│   │   ├── powershell_log.py
│   │   └── firewall_log.py  # pfirewall.log (optional)
│   ├── parsers/
│   │   ├── event_parser.py  # XML → NormalizedEvent
│   │   └── firewall_parser.py
│   ├── detection/
│   │   ├── engine.py        # Orchestrates all rules
│   │   └── rules/
│   │       ├── brute_force.py
│   │       ├── account_lockout.py
│   │       ├── privilege.py
│   │       ├── account_created.py
│   │       └── port_scan.py
│   ├── correlation/
│   │   └── correlator.py
│   ├── database/
│   │   └── db_manager.py    # SQLite (parameterized queries)
│   ├── ui/
│   │   ├── app_window.py    # Main window + navigation
│   │   ├── dashboard_frame.py
│   │   ├── live_monitor_frame.py
│   │   ├── incidents_frame.py
│   │   ├── search_frame.py
│   │   ├── analytics_frame.py
│   │   ├── config_frame.py
│   │   └── widgets/         # Reusable UI components
│   ├── reports/
│   │   ├── csv_exporter.py
│   │   └── pdf_exporter.py
│   ├── utils/
│   │   ├── helpers.py       # Event descriptions, IP validation
│   │   └── logger.py
│   └── demo_loader.py       # Loads demo data through real pipeline
│
├── demo_data/
│   └── scenarios.py         # Synthetic events (all is_demo=True)
│
├── config/
│   └── settings.ini         # Detection thresholds, log sources, DB path
│
├── tests/
│   ├── test_collectors.py
│   ├── test_detection.py
│   └── test_database.py
│
├── requirements.txt
├── main.py
└── README.md
```

---

## ⚙️ Windows Event IDs Monitored

| Event ID | Description | Default Severity |
|---|---|---|
| 4624 | Successful Logon | INFO |
| 4625 | Failed Logon | HIGH |
| 4634 | Logoff | INFO |
| 4647 | User Initiated Logoff | INFO |
| 4672 | Special Privileges Assigned | MEDIUM/HIGH |
| 4720 | User Account Created | HIGH |
| 4722 | User Account Enabled | LOW |
| 4725 | User Account Disabled | LOW |
| 4726 | User Account Deleted | HIGH |
| 4740 | Account Locked Out | HIGH |
| 6005 | System Startup | INFO |
| 6006 | System Shutdown | INFO |
| 7036 | Service State Change | INFO |
| 1102 | Audit Log Cleared | CRITICAL |

---

## 🚀 Installation

### Prerequisites
- Windows 10/11 or Windows Server
- Python 3.11+ (Python 3.14 tested)
- Internet connection for initial pip install

### Setup

```powershell
# 1. Clone or unzip the project
cd C:\Users\YourName\windows-security-monitor

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the application
python main.py

# For full Security log access (recommended for real monitoring):
# Right-click PowerShell → "Run as Administrator"
python main.py
```

---

## 🔑 Required Permissions

| Log Source | Requires Admin? |
|---|---|
| Security Log (4624, 4625, etc.) | ✅ Yes |
| System Log | ❌ No (usually) |
| Application Log | ❌ No |
| PowerShell Log | ❌ No (if logging enabled) |
| Firewall Log | ❌ No (if logging enabled) |
| Demo Mode | ❌ No |

The application **does not require administrator rights to run** — it will simply show reduced log visibility and display warning messages for inaccessible sources.

---

## 🔬 Demo Mode

Demo Mode loads 31 pre-built synthetic events through the **same detection and correlation pipeline** as real Windows events. All demo events are marked `[DEMO]` in the UI.

### How to use Demo Mode
1. Launch the application: `python main.py`
2. Click **"🔬 Load Demo Data"** in the sidebar
3. The following incidents will be detected:
   - **CRITICAL** Brute Force + Account Lockout (user: Administrator, IP: 192.168.1.50)
   - **HIGH** Unauthorized Account Created (hacker_backdoor)
   - **HIGH** Privilege Escalation (service_unknown)
   - **HIGH** Port Scan (10.0.0.99 → 15 ports in 20 seconds)
4. Click any incident → view detection explanation and timeline
5. Click any event → view raw XML alongside normalized fields

---

## 🎯 Controlled Attack Demonstration (Real Windows Logs)

> ⚠️ Perform only on a **dedicated lab machine** you own. Never test on production systems.

### Brute Force Simulation

1. Run the application **as Administrator**
2. Start Live Monitoring
3. In PowerShell (separate window), run:
   ```powershell
   # Trigger 5 failed login attempts for the Administrator account
   # Repeat 5 times rapidly:
   net use \\localhost /user:Administrator WrongPassword123
   net use \\localhost /user:Administrator WrongPassword123
   net use \\localhost /user:Administrator WrongPassword123
   net use \\localhost /user:Administrator WrongPassword123
   net use \\localhost /user:Administrator WrongPassword123
   ```
4. Watch for **Event 4625** entries appearing in Live Monitor
5. After ~60 seconds the detection engine will fire
6. **BRUTE_FORCE** incident appears in the Incidents page
7. If account locks out (Event 4740), incident upgrades to **CRITICAL BRUTE_FORCE_LOCKOUT**

### Expected Detection Output
```
Incident #N: BRUTE_FORCE_LOCKOUT
Severity: CRITICAL
Source IP: 127.0.0.1
Target: Administrator
Failed Attempts: 5
Account Locked: Yes

Detection Rule: CORRELATION_001
Rule BRUTE_FORCE_001: 5 failed authentication attempts within 9 seconds
Rule LOCKOUT_001: Account locked by Windows
Correlation: CRITICAL — brute force + lockout confirmed
```

---

## ⚙️ Enabling Windows Audit Logging

By default, Windows may not log all Security events. To enable full logging:

```powershell
# Enable logon/logoff auditing (as Administrator)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
```

### Enable PowerShell Script Block Logging
```powershell
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
```

### Enable Windows Firewall Logging
```
Control Panel → Windows Defender Firewall → Advanced Settings
→ Windows Firewall Properties → [Domain/Private/Public] Tab
→ Logging → Customize
→ Log dropped packets: Yes
→ Log successful connections: Yes
→ Log file path: C:\Windows\System32\LogFiles\Firewall\pfirewall.log
```

---

## 🔧 Configuration

Edit `config/settings.ini` or use the **Config** page in the UI:

```ini
[detection]
# Brute Force: trigger after N failures within W seconds
brute_force_threshold = 5
brute_force_window_seconds = 60

# Port Scan: trigger when N unique ports hit within W seconds
port_scan_threshold = 10
port_scan_window_seconds = 30

[monitoring]
# How often to check for new events (seconds)
interval_seconds = 30
```

---

## 📊 Severity Levels

| Level | Color | Meaning |
|---|---|---|
| INFO | Gray | Normal activity |
| LOW | Green | Minor anomaly |
| MEDIUM | Amber | Notable event (privilege assignment) |
| HIGH | Orange | Suspicious event (brute force, new account) |
| CRITICAL | Red | Confirmed attack pattern (correlated incident) |

---

## 🛡 Security Practices in This Application

- **Parameterized SQL queries** — no SQL injection possible
- **Input validation** — all user inputs sanitized before use
- **No command injection** — subprocess calls use list arguments, not shell strings
- **Least privilege** — application works without admin (with reduced visibility)
- **Demo/Real separation** — demo events stored with `is_demo=1`, never mixed in stats
- **No password storage** — zero credentials stored in any form
- **wevtutil** used instead of raw Windows API to avoid complex privilege handling

---

## ⚠️ Limitations

1. **Real-time alerts**: The tool polls on a configurable interval (default 30s), not true real-time
2. **Security log access**: Requires administrator rights for full Security log visibility
3. **Firewall log**: Windows Firewall logging must be manually enabled
4. **Scale**: Designed for demonstration — not intended for high-volume enterprise environments
5. **No network monitoring**: Monitors local Windows logs only
6. **Authentication**: The application itself has no login screen (it's a local desktop tool)

---

## 🔮 Future Improvements

- Real-time log subscription (Windows Event Log subscription API)
- Email/SIEM alerting
- Machine learning anomaly detection
- Remote machine monitoring
- Active Directory integration
- Log forwarding (Syslog/SIEM export)
- Authentication and user roles

---

## 📦 Dependencies

| Package | Purpose |
|---|---|
| customtkinter | Modern dark-themed GUI |
| matplotlib | Embedded charts |
| Pillow | Image handling |
| reportlab | PDF report generation |
| sqlite3 | Database (Python stdlib) |
| xml.etree | XML parsing (Python stdlib) |
| subprocess | wevtutil invocation (Python stdlib) |

---

## 👥 Academic Context

This project was developed for the **Fundamentals of Cybersecurity** course to demonstrate:
- How operating systems record security events
- How event logs are collected and normalized
- How rule-based detection identifies attack patterns
- How event correlation builds a complete incident picture
- How security analysts investigate incidents using audit trails

The project intentionally avoids enterprise complexity in favour of clear, explainable implementations that demonstrate the core security concepts.
