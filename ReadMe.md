# TryHackMe SOC Simulation Write-Up: Phishing Unfolding

## Overview

This project documents my investigation of the **Phishing Unfolding** SOC simulation, where I triaged and analyzed multiple alerts to distinguish low-value phishing noise from the real compromise path. The investigation was performed using **Splunk**, alert context, and process telemetry from **Sysmon**.

A key part of this simulation was not just detecting phishing emails, but identifying **which alert chain actually mattered**. While many alerts were low-severity phishing attempts with suspicious content, only one path showed clear evidence of successful compromise, malicious execution, suspicious network share access, and probable DNS-based exfiltration.

## Analyst Performance Highlights

* **25 alerts closed** within the scenario
* **100% true positive identification rate**
* **Mean time to resolve: 2 minutes**
* Completed the alert investigation flow in **~25 minutes**, despite the scenario being designed to take **40+ minutes**

<p align="center">
  
  <img src="https://github.com/mnv1851/TryHackMe-SOC-Simulation-Write-Up-Phishing-Unfolding/blob/main/Screenshots/11-WON.png" width="50" />
  <img src="https://github.com/mnv1851/TryHackMe-SOC-Simulation-Write-Up-Phishing-Unfolding/blob/main/Screenshots/10-Quick-MTTR.png" width="50%" />
</p>

This project demonstrates practical SOC Level 1 skills in:

* alert triage
* phishing investigation
* Splunk-based log validation
* process analysis using Sysmon
* correlating email, endpoint, and network-related activity
* distinguishing real compromise from background alert noise

## Tools Used

* **Splunk Enterprise** for log searching and correlation
* **Sysmon telemetry** for process creation visibility
* **TryHackMe SOC simulation environment**
* **Alert queue / case reporting workflow** for classification and escalation decisions

## Scenario Objective

Investigate a stream of phishing and process alerts, identify all true positives, determine which activity is merely suspicious versus actually malicious, and escalate the alerts tied to real compromise.

## Initial Triage Approach

The scenario generated multiple phishing-themed alerts from suspicious external domains. Rather than treating every alert equally, I used the following workflow:

1. Review alert metadata such as sender, subject, recipient, content, attachment, and direction.
2. Validate the alert in Splunk.
3. Check whether the message was isolated or part of a wider campaign.
4. Look for user interaction or endpoint activity tied to the recipient.
5. Prioritize any host/process alerts correlated with a phishing recipient.
6. Escalate only when there was evidence of actual compromise or malicious post-delivery behavior.

This helped separate:

* **background phishing noise**
* from the **actual phishing-driven compromise chain**

## Key Finding

Most low-severity phishing alerts were **true positives**, but they were limited to suspicious email delivery only. They contained scam-like or spam-style social engineering content, but showed:

* no malicious attachment execution
* no suspicious host activity
* no signs of user compromise
* no lateral movement or exfiltration indicators

The **real incident path** was tied to:

* **Recipient:** `michael.ascot@tryhatme.com`
* **Host:** `win-3450`
* **Malicious domain:** `haz4rdw4re.io`

## Confirmed Initial Access

A phishing email delivered to Michael Ascot stood out as the likely initial access vector.

### Malicious Email Details

* **Sender:** `john@hatmakereurope.xyz`
* **Recipient:** `michael.ascot@tryhatme.com`
* **Subject:** `FINAL NOTICE: Overdue Payment - Account Suspension Imminent`
* **Attachment:** `ImportantInvoice-February.zip`
* **Timestamp:** `04/12/2026 20:39:18.151`

### Why it was malicious

The email used classic phishing pressure tactics:

* urgency
* threat of account suspension
* threat of legal action
* attachment-based lure
* request to open a ZIP file immediately

This was a much stronger indicator than the earlier background phishing emails because it included a **malicious-looking attachment** and later aligned directly with endpoint activity on Michael’s workstation.

## Endpoint Compromise Analysis

After the phishing email delivery, I pivoted into the alerts and Sysmon telemetry tied to **host `win-3450`**.

### Suspicious Execution Evidence

Sysmon Event ID 1 showed suspicious process activity executed from:

* `C:\Users\michael.ascot\downloads\`
* `C:\Users\michael.ascot\downloads\exfiltration\`

Observed behaviors included:

* `powershell.exe` spawning `net.exe`
* `powershell.exe` spawning `nslookup.exe`

### Network Share Access

One of the key alerts showed:

* `net.exe use Z: \\FILESRV-01\SSF-FinancialRecords`

This indicates the compromised host accessed a sensitive shared directory containing financial records.

A related command later removed the mapped drive:

* `net.exe use Z: /delete`

This suggests the share was mapped temporarily for access, staging, or collection.

## DNS-Based Suspicious Activity

The strongest evidence of malicious post-compromise behavior came from repeated PowerShell child processes executing `nslookup.exe` against long randomized subdomains under:

* `haz4rdw4re.io`

Example behavior observed:

* `powershell.exe -> nslookup.exe`
* working directory from Downloads and Downloads\exfiltration
* repeated lookups of encoded/randomized subdomains

### Why this was significant

This pattern is highly suspicious because:

* users do not normally trigger repeated `nslookup.exe` executions via PowerShell from Downloads
* the subdomains appeared encoded or randomized
* the path included an **exfiltration** folder
* the timing followed phishing delivery and suspicious execution

This behavior strongly suggests:

* malware execution
* DNS-based command and control
* or DNS-based exfiltration / staging

## Investigation Timeline

### 1. Phishing email delivered

Michael received a phishing email containing a ZIP attachment:

* `ImportantInvoice-February.zip`

### 2. Suspicious execution on endpoint

Shortly afterward, Sysmon process creation events appeared on `win-3450` under Michael’s Downloads directory.

### 3. PowerShell abuse observed

`powershell.exe` spawned suspicious child processes, including:

* `net.exe`
* `nslookup.exe`

### 4. Sensitive file share accessed

The host mapped:

* `\\FILESRV-01\SSF-FinancialRecords`

### 5. DNS-based suspicious traffic

Repeated `nslookup.exe` calls queried randomized subdomains of:

* `haz4rdw4re.io`

### 6. High-confidence conclusion

The evidence supported a phishing-driven compromise with likely access to sensitive shared data and probable DNS-based exfiltration activity.

## Alert Classification Strategy

A major lesson from this simulation was that **not every true positive is equally important**.

### Low-severity phishing noise

Many alerts were still classified as **true positives** because the emails were suspicious or malicious in content. However, they were not escalated because they showed:

* no attachment execution
* no host compromise
* no correlated endpoint activity
* no evidence of successful user interaction

### Escalated true positives

Alerts tied to `michael.ascot@tryhatme.com`, `win-3450`, PowerShell execution, `haz4rdw4re.io`, and suspicious access to `SSF-FinancialRecords` were escalated because they represented the **real incident path**.

This is an important SOC skill: correctly identifying all malicious alerts while still focusing escalation on activity that shows actual compromise.

## MITRE ATT&CK Mapping

### Initial Access

* **Phishing (T1566)**
  The attack began with a malicious email containing a ZIP attachment.

### Execution

* **User Execution (T1204)**
  The phishing attachment likely required user interaction to begin execution.
* **Command and Scripting Interpreter: PowerShell (T1059.001)**
  PowerShell spawned suspicious child processes on the compromised host.

### Collection

* **Data from Network Shared Drive (T1039)**
  The mapped `SSF-FinancialRecords` share suggests collection from a network location.

### Command and Control

* **Application Layer Protocol: DNS (T1071.004)**
  Repeated `nslookup.exe` traffic to randomized subdomains under `haz4rdw4re.io` indicates likely malicious DNS-based communications.

### Exfiltration

* **Exfiltration Over Alternative Protocol (T1048)** *(suspected)*
  Based on the repeated DNS requests and the `Downloads\exfiltration` path, DNS-based exfiltration is a strong possibility.

## Indicators of Compromise (IOCs)

### Email IOCs

* `john@hatmakereurope.xyz`
* `ImportantInvoice-February.zip`
* `FINAL NOTICE: Overdue Payment - Account Suspension Imminent`
* `michael.ascot@tryhatme.com`

### Host / Process IOCs

* `win-3450`
* `powershell.exe`
* `net.exe`
* `nslookup.exe`
* `C:\Users\michael.ascot\downloads\`
* `C:\Users\michael.ascot\downloads\exfiltration\`

### Network / Infrastructure IOCs

* `haz4rdw4re.io`
* randomized subdomains of `haz4rdw4re.io`
* `\\FILESRV-01\SSF-FinancialRecords`

## Containment and Remediation Recommendations

* Isolate `win-3450` from the network immediately
* Reset credentials associated with Michael Ascot
* Block or sinkhole `haz4rdw4re.io`
* Remove the phishing email and attachment from mailboxes
* Review access logs for `\\FILESRV-01\SSF-FinancialRecords`
* Preserve the Downloads and exfiltration folders for forensic analysis
* Hunt for similar PowerShell → `nslookup.exe` behavior across the environment
* Review DNS logs for matching `haz4rdw4re.io` queries from other hosts

## Lessons Learned

This simulation reinforced several important analyst lessons:

1. **A suspicious domain alone is not enough.**
   Some phishing emails came from domains that were not flagged as malicious, but the content and later host behavior still proved the threat.

2. **Context matters more than alert volume.**
   Many emails were malicious in content, but only one alert chain showed successful compromise.

3. **Correlating email with endpoint telemetry is critical.**
   The real breakthrough came from connecting Michael’s phishing email to host `win-3450`, PowerShell execution, network share access, and DNS activity.

4. **True positive does not always mean escalation.**
   Some alerts were correctly labeled as true positives but did not require escalation because there was no evidence of user compromise.

5. **Speed matters, but accuracy matters more.**
   I completed the scenario in approximately **25 minutes**, well below the expected **40+ minutes**, while maintaining **100% true positive identification accuracy**.

## Outcome

The scenario ended with:

* **100% true positive identification rate**
* **25 alerts closed**
* **Mean resolution time of 2 minutes**
* Successful prevention of a broader security breach through correct triage and escalation

## Final Reflection

This lab was a strong exercise in practical SOC analysis because it required more than simply spotting suspicious emails. The real challenge was identifying which alerts were just noisy phishing attempts and which alerts formed the genuine compromise path.

By correlating phishing telemetry, host-based process creation, network share access, and suspicious DNS activity, I was able to identify the real breach path quickly and accurately. This project reflects the kind of triage, prioritization, and investigation workflow expected from a SOC Analyst handling a live phishing-driven incident.

