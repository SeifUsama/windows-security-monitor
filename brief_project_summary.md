# 🛡️ Windows Security Monitor — Brief Project Summary

## 📌 What is the Project?
The **Windows Security Monitor** is a lightweight, local Security Information and Event Management (SIEM) tool designed for security auditing, log collection, automated threat detection, and event correlation on Windows systems. 

It demonstrates the complete lifecycle of a security log:
$$\text{Collect (wevtutil / Desktop Watcher)} \longrightarrow \text{Parse/Normalize (XML)} \longrightarrow \text{Store (SQLite)} \longrightarrow \text{Detect (Engine)} \longrightarrow \text{Correlate (Threads)} \longrightarrow \text{Visualize (GUI)}$$

---

## 🛠️ Implemented Features & How to Test Them

### 1. MITRE ATT&CK Mapping (New Feature)
All incident types are automatically mapped to standard MITRE ATT&CK tactics and techniques. This information is saved directly in the SQLite database and displayed in the incident details card:
* **Brute Force & Account Lockout:** Credential Access (TA0006) $\longrightarrow$ Brute Force (T1110)
* **Privilege Escalation:** Privilege Escalation (TA0004) $\longrightarrow$ Valid Accounts (T1078)
* **Unauthorized Account:** Persistence (TA0003) $\longrightarrow$ Create Account (T1136)
* **Port Scan:** Reconnaissance (TA0043) $\longrightarrow$ Active Scanning (T1595)
* **File Integrity:** Defense Evasion (TA0005) $\longrightarrow$ File and Directory Permissions Modification (T1222)

---

### 2. Brute Force Detection (BRUTE_FORCE_001)
* **MITRE ATT&CK:** Tactic: Credential Access (TA0006) | Technique: Brute Force (T1110)
* **How to Test Locally:**
  Open a standard PowerShell window and run the following loop to trigger 5 logon failures:
  ```powershell
  1..5 | ForEach-Object { net use \\localhost /user:FakeUser WrongPassword123 }
  ```
* **Expected Result:** A **HIGH** severity incident named `BRUTE_FORCE` will appear in the **Incidents** tab.

---

### 3. Account Lockout Detection (LOCKOUT_001)
* **MITRE ATT&CK:** Tactic: Credential Access (TA0006) | Technique: Brute Force (T1110)
* **How to Test Locally:**
  If your Windows local security policy has a lockout threshold enabled (e.g. 5 attempts), create a test account and brute-force it:
  ```powershell
  # 1. Create a dummy test account (Run in Admin PowerShell)
  net user TargetTest DummyPass123! /add
  
  # 2. Brute force it 6 times to lock the account (Run in normal PowerShell)
  1..6 | ForEach-Object { net use \\localhost /user:TargetTest WrongPassword }
  
  # 3. Clean up (Run in Admin PowerShell)
  net user TargetTest /delete
  ```
* **Expected Result:** The correlation engine links the failures and the lockout, generating a **CRITICAL** severity `BRUTE_FORCE_LOCKOUT` incident.

---

### 4. Privilege Escalation Detection (PRIVILEGE_001)
* **MITRE ATT&CK:** Tactic: Privilege Escalation (TA0004) | Technique: Valid Accounts (T1078)
* **How to Test/Force-Trigger Locally:**
  To force Windows to create a new logon session under the `SYSTEM` account, run this scheduled task script in **Administrator PowerShell**:
  ```powershell
  # 1. Create a temporary scheduled task that executes as SYSTEM
  schtasks /create /tn "SecMonitorTest" /tr "cmd.exe /c echo Test" /sc once /st 23:59 /ru "SYSTEM" /f
  
  # 2. Run the task immediately to force a privileged logon session
  schtasks /run /tn "SecMonitorTest"
  
  # 3. Clean up and delete the temporary task
  schtasks /delete /tn "SecMonitorTest" /f
  ```
* **Expected Result:** Windows logs `Event 4672` (Special Privileges Assigned) for the `SYSTEM` account. The tool immediately detects this and registers a `PRIVILEGE_ESCALATION` incident in the **Incidents** tab.

---

### 5. Account Creation Detection (NEWACCOUNT_001)
* **MITRE ATT&CK:** Tactic: Persistence (TA0003) | Technique: Create Account (T1136)
* **How to Test Locally:**
  Open **PowerShell as Administrator** and add a new user:
  ```powershell
  net user BackdoorUser P@ssw0rd999! /add
  ```
  *Cleanup command:* `net user BackdoorUser /delete`
* **Expected Result:** Both the creation (`4720`) and enabling (`4722`) logs appear as **HIGH** severity in the event grid. A **HIGH** severity `UNAUTHORIZED_ACCOUNT` incident is logged in the **Incidents** tab.

---

### 6. Port Scan Detection (PORTSCAN_001)
* **MITRE ATT&CK:** Tactic: Reconnaissance (TA0043) | Technique: Active Scanning (T1595)
* **How to Test Locally:**
  1. Enable dropped connection logging in Windows Firewall (Run in **Admin PowerShell**):
     ```powershell
     netsh advfirewall set currentprofile logging droppedconnections enable
     ```
  2. Run the following port scan script targeting 15 closed local ports:
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
  3. **Disable Firewall Logging when finished** (Run in **Admin PowerShell**):
     ```powershell
     netsh advfirewall set currentprofile logging droppedconnections disable
     ```
* **Expected Result:** The firewall logs the dropped packets to `pfirewall.log`, triggering a **HIGH** severity `PORT_SCAN` incident.

---

### 7. File Integrity Auditing (FILE_INTEGRITY_001)
* **MITRE ATT&CK:** Tactic: Defense Evasion (TA0005) | Technique: File and Directory Permissions Modification (T1222)
* **How to Test Locally (Desktop Watcher):**
  1. Start monitoring in the tool.
  2. Go to your **Desktop** and perform file actions:
     * **Create:** Right-click $\rightarrow$ New $\rightarrow$ Folder.
     * **Edit:** Create a text file, open it, add some text, and save.
     * **Delete:** Drag the file/folder to the Recycle Bin.
* **Expected Result:** A `FILE_INTEGRITY` incident will trigger, detailing the action, user, and process name.

---

## 🚀 Presentation Mode Quickstart

1. Navigate to the project directory and run the application:
   ```powershell
   cd C:\Users\NV\windows-security-monitor
   python main.py
   ```
2. Click **"Clear Database"** in the sidebar to clean out historical events and reset all UI charts and lists to zero.
3. Click **"Start Monitoring"** on the Live Monitor page.
4. Run any of the test commands above, and watch the events and incidents populate in real-time.
