# 🛡️ Windows Security Monitor — Detailed Technical Presentation Guide

This guide is structured from the **most important/core technical features** down to the **least/peripheral features**. Use this to study the design choices, architecture, and testing commands for your presentation.

---

## 1. Threat Correlation Engine (Most Critical Core Feature)
The **Correlation Engine** (`correlator.py`) is the brain of the project. Rather than just raising independent alerts, it connects dots in a time window to identify unified threat scenarios.

### Key Concepts to Present:
* **The Brute Force + Lockout Pattern (CORRELATION_001):** 
  * If a user account suffers a brute-force attack (e.g. 5 failed logins within 60s) followed by an account lockout event (`Event ID 4740`) within **5 minutes**, they are merged.
  * The severity is automatically upgraded to **CRITICAL**.
  * All contributing event IDs are bound to a single incident ID in the `incident_events` junction table, creating a unified threat timeline.
* **No False Compromises (Security Best Practice):** 
  * **Design Choice:** If a successful login (`Event 4624`) occurs from the same IP shortly after a brute-force attempt, the system **does not** automatically assume the account is compromised.
  * Instead, the system appends a **post-attack advisory warning** to the incident description urging the analyst to manually inspect the logon, maintaining forensic integrity.

### 🧪 How to Test/Demonstrate:
Ensure local account lockout policy is configured on Windows (e.g., threshold of 5). Run in normal PowerShell:
```powershell
# 1. Create a dummy test account (Run in Admin PowerShell)
net user TargetTest DummyPass123! /add

# 2. Brute force it 6 times to trigger lockout (Run in normal PowerShell)
1..6 | ForEach-Object { net use \\localhost /user:TargetTest WrongPassword }

# 3. Clean up (Run in Admin PowerShell)
net user TargetTest /delete
```
* **Presentation Highlight:** Show the **CRITICAL** incident `BRUTE_FORCE_LOCKOUT` that unites both threat events under one incident with a single graphical timeline node.

---

## 2. Real-time File/Folder Desktop Watcher
* **The Challenge:** Windows Security Log File Auditing (`Event ID 4663`) is highly secure but requires administrative privileges and configuring System Access Control Lists (SACLs) manually on target folders.
* **The Solution (Desktop Watcher):** 
  * We built a native Python collector (`DesktopCollector`) that watches your Windows Desktop folder (`C:\Users\User\Desktop`) in real-time.
  * It uses Python's fast standard library directory scanning (`os.scandir`) to track file/folder creations, deletions, and edits.
  * When a change is made, it resolves the current actor username via `os.getlogin()` and automatically formats the change into a normalized Event `4663` event.

### 🧪 How to Test/Demonstrate:
1. Clear the database and click **"Start Monitoring"** on the Live Monitor page.
2. Run these commands in PowerShell or make folder modifications directly on your Desktop screen:
   ```powershell
   # Create a folder
   mkdir "$HOME\Desktop\AuditFolder"
   
   # Rename the folder
   Rename-Item "$HOME\Desktop\AuditFolder" "$HOME\Desktop\RenamedAuditFolder"
   
   # Delete the folder
   Remove-Item "$HOME\Desktop\RenamedAuditFolder"
   ```
* **Presentation Highlight:** Show that the actions appear instantly in the event grid with the actor's username, mapping directly to `Event ID 4663`.

---

## 3. Event Normalization & Database Architecture (Core Data Pipeline)
Windows Event Logs are inherently complex, nested, and verbose XML structures. The tool extracts, simplifies, and maps these into a flat structure.

### Key Concepts to Present:
* **Unstructured XML to Structured Object:** 
  * The XML parser uses Python's standard `xml.etree.ElementTree` to parse raw XML outputs from Windows commands.
  * Regardless of the source log (Security, Application, or Firewall), it outputs a unified `NormalizedEvent` structure:
    $$\text{NormalizedEvent} = \{\text{timestamp}, \text{event\_id}, \text{username}, \text{source\_ip}, \text{message}, \text{severity}, \text{raw\_xml}\}$$
* **SQLite Storage:**
  * Relational schema comprising `events`, `incidents`, `incident_events` (for N-to-N relationships), and `checkpoints` tables.
  * All queries use **parameterized SQL statements** (`?` placeholders) to prevent SQL injection.

---

## 4. Incremental Collection & Checkpointing
Reading massive Windows log files continuously causes high CPU and disk utilization. The tool implements a stateful collection checkpoint mechanism.

### Key Concepts to Present:
* **The Checkpoint Table:**
  * Stores the `last_timestamp` and `last_record_number` successfully fetched from each active log channel.
* **Dynamic XPath Queries:**
  * Instead of querying all logs, `wevtutil` is invoked dynamically using custom XPath filters targeting only specific Event IDs since the last checkpoint:
    ```xpath
    *[System[(EventID=4624 or EventID=4625) and TimeCreated[@SystemTime>='2026-08-23T19:00:00.000Z']]]
    ```

---

## 5. Security Detection Rules (Specific Auditing Logic)
Rules are applied batch-by-batch against new events. They contain custom detection parameters configured in `settings.ini`.

* **Brute Force (HIGH):** Groups events in a sliding time window by `(username, source_ip)`. 
  ```powershell
  1..5 | ForEach-Object { net use \\localhost /user:FakeUser WrongPassword123 }
  ```
* **Account Creation (HIGH):** Detects unauthorized user account creations (`Event 4720`):
  ```powershell
  net user BackdoorUser P@ssw0rd999! /add
  # Cleanup: net user BackdoorUser /delete
  ```
* **Privilege Escalation (HIGH/MEDIUM):** Detects privilege logons (`Event 4672`). Opening UAC elevation does *not* generate a new logon session, so we test this by forcing a new logon session under the SYSTEM context via Task Scheduler:
  ```powershell
  # Create a task (Run as Admin)
  schtasks /create /tn "SecMonitorTest" /tr "cmd.exe /c echo Test" /sc once /st 23:59 /ru "SYSTEM" /f
  # Run it immediately to trigger 4672
  schtasks /run /tn "SecMonitorTest"
  # Delete it
  schtasks /delete /tn "SecMonitorTest" /f
  ```
* **Port Scan (HIGH):** Detects connection drops on $\ge 10$ unique ports from the same IP within 30 seconds.
  * **Test Prerequisite (Run as Admin):**
    ```powershell
    netsh advfirewall set currentprofile logging droppedconnections enable
    ```
  * **Scan Command (Run in normal PowerShell):**
    ```powershell
    1..15 | ForEach-Object {
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $async = $client.BeginConnect("127.0.0.1", 1000 + $_, $null, $null)
            $null = $async.AsyncWaitHandle.WaitOne(50, $true) # 50ms timeout
            $client.Close()
        } catch {}
    }
    ```
  * **Disable Firewall Logging when finished (Run as Admin):**
    ```powershell
    netsh advfirewall set currentprofile logging droppedconnections disable
    ```
* **Defense Evasion / Log Clearing (CRITICAL):** Detects when audit logs are cleared (`Event 1102`):
  ```powershell
  # Clear Application log (Run as Admin)
  wevtutil cl Application
  ```

---

## 6. Least-Privilege & Graceful Degradation Model
A major academic SIEM project requirement is that it should not break or crash when running on lower-privileged environments.

### Key Concepts to Present:
* **Graceful Degradation:**
  * If a user runs the app without administrative rights, collecting the Security Event Log returns an `Access Denied` error (`exit code 5`).
  * The collector catches the `PermissionError`, changes its state to `access_denied = True`, logs a warnings label in the GUI status bar, and **continues running other logs** (System, Application, Desktop Watcher, and Demo Mode) smoothly.

---

## 7. Demo Mode Engine
To showcase the tool during a presentation without triggering real attacks, the app supports a fully integrated Demo Mode.

### Key Concepts to Present:
* **Unified Pipeline:** 
  * Demo Mode is **not** a mock GUI screen.
  * It generates synthetic events representing a brute-force attack, lockout, new user creation, privilege escalation, and file modifications.
  * These synthetic events are inserted into the database and fed directly through the **real** detection and correlation engines, demonstrating the exact performance of the live SIEM pipeline.

---

## 8. GUI Visualization & Analytics Reports (Peripheral Features)
* **Interactive Timeline Widget:** Draws a custom step-by-step graphical timeline diagram of all contributing event blocks leading to a correlation threat incident.
* **Report Exporters:** Generates professional, ready-to-print forensic PDF reports using ReportLab flowable paragraphs and grids, along with CSV exports for spreadsheet analysis.
* **Forensic Search:** An advanced database query frame supporting filtering by username, IP, keyword, time range, log source, and severity.
