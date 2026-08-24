# 🛡️ Windows Security Monitor — Detailed Technical Presentation Guide

This guide is structured from the **most important/core technical features** down to the **least/peripheral features**. Use this to study the design choices, architecture, and testing commands for your presentation.

---

## 1. MITRE ATT&CK Mapping Integration
The SIEM tool integrates **MITRE ATT&CK Mapping** natively into the detection logic and database schema. 
* **Database Schema Update:** The `incidents` table contains two dedicated columns: `mitre_tactic` and `mitre_technique`.
* **Automatic Mapping:** As incidents flow through the detection engine, the corresponding rule populates the MITRE values:
  * **Brute Force / Lockout:** Credential Access (TA0006) $\longrightarrow$ Brute Force (T1110)
  * **Privilege Escalation:** Privilege Escalation (TA0004) $\longrightarrow$ Valid Accounts (T1078)
  * **Account Creation:** Persistence (TA0003) $\longrightarrow$ Create Account (T1136)
  * **Port Scan:** Reconnaissance (TA0043) $\longrightarrow$ Active Scanning (T1595)
  * **File Integrity:** Defense Evasion (TA0005) $\longrightarrow$ File and Directory Permissions Modification (T1222)
* **GUI Display:** The Incident details pane dynamically displays these mappings in the Incident Summary card, providing professional cybersecurity context.

---

## 2. Threat Correlation Engine (Most Critical Core Feature)
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

## 3. Real-time File/Folder Desktop Watcher
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

## 4. UI Style and Theme Engine
* **Ttk Theme Configuration:** On Windows, standard `ttk.Treeview` tables default to a system theme that ignores manual styling and renders white backgrounds with light text, making content invisible.
* **The Fix:** The app initializes the `clam` theme globally (`style.theme_use("clam")`). This fixes the rendering treeviews inside scrollable panels, allowing custom dark colors, grid lines, and column layouts to draw perfectly.

---

## 5. Event Normalization & Database Architecture (Core Data Pipeline)
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

## 6. Security Detection Rules (Specific Auditing Logic)
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

## 7. Demo Mode Engine
To showcase the tool during a presentation without triggering real attacks, the app supports a fully integrated Demo Mode.

### Key Concepts to Present:
* **Unified Pipeline:** 
  * Demo Mode is **not** a mock GUI screen.
  * It generates synthetic events representing a brute-force attack, lockout, new user creation, privilege escalation, and file modifications.
  * These synthetic events are inserted into the database and fed directly through the **real** detection and correlation engines, demonstrating the exact performance of the live SIEM pipeline.
