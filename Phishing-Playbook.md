# Phishing-Driven Endpoint Compromise Playbook

## Purpose

This playbook provides a structured incident response workflow for investigating and responding to a phishing-driven endpoint compromise involving malicious email delivery, suspicious attachment execution, PowerShell abuse, network share access, and probable DNS-based command-and-control or exfiltration activity.

This playbook is based on a hands-on SOC investigation scenario where multiple phishing alerts were triaged, low-value phishing noise was separated from the true compromise path, and the real incident was traced from email delivery to endpoint execution and suspicious DNS activity.

## Incident Summary

A user received a phishing email containing a ZIP attachment themed as an overdue payment notice. After likely user interaction with the attachment, suspicious process activity was observed on the endpoint, including PowerShell spawning `net.exe` and `nslookup.exe`. The compromised host accessed a sensitive network file share and executed repeated DNS lookups to randomized subdomains of a suspicious external domain, indicating likely command-and-control or DNS-based exfiltration.

## Scope

Use this playbook when the following conditions are observed:

* phishing email delivered to a user mailbox
* suspicious or malicious attachment present
* execution activity observed shortly after email delivery
* PowerShell spawning unusual child processes
* access to sensitive internal shares after execution
* repeated DNS queries to suspicious or randomized subdomains
* possible staging or exfiltration directories observed on the host

## Severity Guidance

### Low Severity

* phishing email delivered
* suspicious content only
* no attachment execution
* no endpoint activity
* no evidence of user interaction

### Medium Severity

* phishing email with suspicious attachment or link
* suspicious process activity on endpoint
* PowerShell or script execution
* no confirmed collection or exfiltration yet

### High Severity

* phishing email clearly linked to endpoint compromise
* suspicious process chains from user directories
* access to sensitive network shares
* repeated communication with suspicious infrastructure
* probable command-and-control or exfiltration activity

## Trigger Conditions

Start this playbook if one or more of the following is detected:

* suspicious phishing email with urgent financial, legal, or business lure
* attachment such as ZIP, ISO, LNK, HTA, JS, VBS, EXE, BAT, or macro-enabled document
* Sysmon Event ID 1 showing execution from `Downloads` or temp directories
* `powershell.exe` spawning `net.exe`, `nslookup.exe`, `cmd.exe`, `wscript.exe`, or `rundll32.exe`
* unusual DNS requests to long or randomized subdomains
* access to sensitive file shares after phishing-related execution
* folder names suggesting staging or exfiltration

## Required Data Sources

* email logs
* SIEM alerts
* Sysmon process creation logs
* file creation telemetry
* DNS logs
* proxy or network connection logs
* file share access logs
* endpoint telemetry / EDR where available

## Key Detection Opportunities

### Email Indicators

* urgent payment notice themes
* account suspension or legal action pressure
* external sender with suspicious or unrelated domain
* ZIP or similar compressed attachment
* suspicious subject lines designed to force quick action

### Endpoint Indicators

* execution from `C:\Users\<user>\Downloads\`
* suspicious PowerShell command lines
* PowerShell spawning `nslookup.exe`
* PowerShell spawning `net.exe`
* execution from subfolders named `exfiltration`, `temp`, `invoice`, or similarly deceptive names

### Network Indicators

* repeated DNS requests to suspicious domains
* randomized or encoded-looking subdomains
* short burst of multiple DNS requests after process execution
* DNS communication from non-standard process chains

### Data Access Indicators

* mapping internal file shares after attachment execution
* use of `net.exe use`
* temporary drive mapping followed by deletion
* access to sensitive network shares unrelated to the user’s normal role

## Triage Workflow

### Step 1: Review the phishing alert

Capture:

* sender address
* recipient address
* subject line
* timestamp
* attachment name
* message content
* inbound or outbound direction

Questions to answer:

* is the email clearly suspicious or malicious in content
* does it contain an attachment or link
* is the sender external and unusual
* is the lure urgent, threatening, or financially themed

### Step 2: Validate in SIEM

Search for:

* sender address
* sender domain
* recipient mailbox
* subject line
* attachment name

Determine:

* was it sent to one user or many
* was the message isolated or part of a wider campaign
* were there replies, forwards, or follow-up actions

### Step 3: Pivot to the recipient endpoint

If the email contains an attachment or looks highly suspicious, pivot to the user’s host.

Search for:

* Sysmon Event ID 1 process creation
* Sysmon Event ID 11 file creation
* any events containing `Downloads`
* attachment filename
* user path associated with the mailbox owner

Questions to answer:

* was the attachment downloaded or written to disk
* did any process execute from Downloads shortly after the email arrived
* did PowerShell, cmd, wscript, cscript, mshta, or rundll32 run

### Step 4: Investigate process chain

Identify parent-child relationships such as:

* `explorer.exe -> powershell.exe`
* `powershell.exe -> net.exe`
* `powershell.exe -> nslookup.exe`
* `powershell.exe -> cmd.exe`

Collect:

* process name
* parent process name
* command line
* working directory
* timestamp
* host
* user context

### Step 5: Review network and DNS behavior

Search for:

* suspicious external domains
* repeated DNS lookups
* randomized subdomain patterns
* related connections from the compromised host

Questions to answer:

* does the domain appear malicious or suspicious
* are subdomains long, random, or encoded-looking
* is the process chain unusual for normal user activity
* do the DNS events begin after phishing-related execution

### Step 6: Check for collection or staging

Look for:

* `net.exe use`
* mapped drives to internal shares
* file access to sensitive directories
* folders such as `exfiltration`
* archiving or compression activity
* movement of files to staging locations

### Step 7: Classify and escalate

Classify the alert chain based on evidence:

#### True Positive, no escalation

Use when:

* the email is malicious or suspicious
* no user interaction observed
* no endpoint execution observed
* no host compromise evidence

#### True Positive, escalate

Use when:

* phishing email is linked to host execution
* suspicious child processes are observed
* sensitive file share access is identified
* DNS-based command-and-control or exfiltration is suspected

#### False Positive

Use only when:

* message is clearly legitimate after validation
* domain and content are benign
* no suspicious endpoint or related activity exists

## Investigation Checklist

* [ ] capture sender, recipient, subject, attachment, and timestamp
* [ ] validate message in SIEM
* [ ] search sender and domain for campaign scope
* [ ] pivot to user endpoint
* [ ] review Sysmon Event ID 1 process creation
* [ ] review Sysmon Event ID 11 file creation
* [ ] identify suspicious process chain
* [ ] review working directory and user path
* [ ] search for suspicious DNS activity
* [ ] investigate share access and staging folders
* [ ] determine whether compromise occurred
* [ ] decide whether escalation is required
* [ ] document IOCs, timeline, impact, and remediation

## Example MITRE ATT&CK Mapping

### Initial Access

* **Phishing (T1566)**

### Execution

* **User Execution (T1204)**
* **Command and Scripting Interpreter: PowerShell (T1059.001)**

### Collection

* **Data from Network Shared Drive (T1039)**

### Command and Control

* **Application Layer Protocol: DNS (T1071.004)**

### Exfiltration

* **Exfiltration Over Alternative Protocol (T1048)** *(if supported by evidence)*

## Containment Actions

If compromise is confirmed:

* isolate the affected host from the network
* suspend or reset the affected user account
* remove the phishing email from mailboxes
* block the malicious domain and related IOCs
* block DNS requests to suspicious infrastructure
* preserve forensic evidence from the endpoint
* review access to internal file shares
* initiate broader IOC sweep across the environment

## Eradication and Recovery

* remove malicious files and persistence mechanisms
* rebuild or reimage the affected host if needed
* rotate credentials for impacted users and service accounts
* verify no other hosts show the same DNS or process indicators
* restore normal access only after validation
* continue monitoring for recurrence

## Documentation Requirements

Record the following in the case notes:

* alert ID(s)
* timestamps
* affected user and host
* sender and recipient
* subject line and attachment
* suspicious process chain
* suspicious domains queried
* file share accessed
* why the alert was classified as TP or FP
* why escalation was or was not required
* remediation and containment steps

## Paste-Ready Case Note Template

### Time of activity

[Insert timestamp]

### Affected entities

* User: [insert user]
* Host: [insert host]
* Sender: [insert sender]
* Recipient: [insert recipient]
* Domain: [insert domain]
* Attachment: [insert attachment]

### Reason for classification

Investigation confirmed that the alert was [true positive / false positive]. Evidence included [email content, attachment, process execution, DNS activity, file share access, or lack of supporting malicious evidence].

### Escalation decision

[Escalate / Do not escalate]

### Reason for escalation decision

[Insert concise rationale]

### Recommended remediation

* [Insert actions]

### Attack indicators

* [Insert IOCs]

## Lessons Learned

* content review matters more than domain reputation alone
* not all true positives require escalation
* phishing investigations must be correlated with endpoint evidence
* PowerShell child-process analysis is critical in attachment-based compromise
* unusual DNS patterns can reveal command-and-control or exfiltration behavior
* good SOC triage means focusing on the real compromise path, not just the noisiest alert queue

## Outcome Goal

The goal of this playbook is to help analysts quickly separate simple phishing delivery from true phishing-driven compromise, contain affected hosts faster, and document incident evidence in a structured and escalation-ready format.
