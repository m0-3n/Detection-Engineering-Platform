# DET-012 - Suspicious Scheduled Task Creation

## Detection ID

DET-012

## Status

Draft

## Version

1.0

## Confidence

Medium

## Severity

High

---

# Threat Overview

Windows Scheduled Tasks provide administrators with a legitimate mechanism to automate system maintenance and recurring jobs. Threat actors frequently abuse Scheduled Tasks to establish persistence, execute malicious payloads after reboot or user logon, and maintain long-term access to compromised systems.

Monitoring suspicious scheduled task creation provides defenders with visibility into persistence mechanisms commonly used after initial compromise.

---

# MITRE ATT&CK Mapping

| Tactic | Technique |
|---------|-----------|
| Persistence | T1053.005 – Scheduled Task |
| Execution | T1059.001 – PowerShell |

---

# Attack Scenario

An attacker creates a scheduled task that executes an encoded PowerShell command whenever a user logs on.

Examples:

schtasks.exe /create /tn "WindowsUpdate" /tr "powershell.exe -enc SQBFAFgA..." /sc onlogon

schtasks.exe /create /tn "Updater" /tr "cmd.exe /c malware.exe" /sc minute

The scheduled task automatically executes the payload during future trigger events, allowing the attacker to maintain persistence.

---

# Required Telemetry

| Source | Event |
|---------|-------|
| Sysmon | Event ID 1 |
| Windows Security | Event ID 4688 |
| Task Scheduler | Event ID 106 |

Important fields:

- Image
- CommandLine
- User
- ParentImage
- ProcessGuid

---

# Detection Logic

Generate an alert when schtasks.exe creates a scheduled task that launches command interpreters or scripting engines.

Indicators include:

- schtasks.exe
- /create
- powershell.exe
- cmd.exe

---

# False Positives

Potential legitimate activity includes:

- Enterprise administration
- Windows maintenance
- Software deployment
- Backup automation
- IT operations

---

# Bypass Opportunities

Attackers may evade this detection by:

- WMI Event Subscriptions
- Registry Run Keys
- Startup Folder persistence
- Services
- Scheduled tasks created through PowerShell cmdlets

---

# Investigation Guide

When this detection triggers:

1. Identify the created task name.
2. Review the scheduled trigger.
3. Inspect the command being executed.
4. Determine the creating user.
5. Review subsequent process execution.
6. Check for network communication.
7. Correlate with previous detections.

---

# Related Detections

- DET-001 – PowerShell Encoded Command
- DET-003 – Execution Policy Bypass
- DET-006 – PowerShell Network Communication

---

# Future Improvements

- Detect suspicious task names
- Detect execution from AppData or Temp
- Parent process analysis
- Task XML inspection
- Multi-host correlation