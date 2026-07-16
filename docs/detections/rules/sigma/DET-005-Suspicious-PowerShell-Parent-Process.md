# DET-005 - Suspicious Parent Process Launching PowerShell

## Detection ID

DET-005

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

PowerShell is commonly abused by attackers after gaining initial access to a system. One strong behavioral indicator is PowerShell being launched by applications that rarely require scripting capabilities.

Office applications and document readers should not normally spawn PowerShell processes. Detecting these parent-child relationships can help identify phishing attacks, malicious macros, and document-based exploitation.

---

# MITRE ATT&CK Mapping

| Tactic | Technique |
|---------|-----------|
| Execution | T1059.001 – PowerShell |
| Initial Access | T1566 – Phishing |
| User Execution | T1204 – User Execution |

---

# Attack Scenario

A user opens a malicious Microsoft Word document containing a macro.

The macro launches PowerShell to download and execute additional payloads.

Example process tree:

WINWORD.EXE
└── powershell.exe

Similar activity may occur with Excel spreadsheets, Outlook attachments, or malicious PDF files.

---

# Required Telemetry

| Source | Event |
|---------|-------|
| Sysmon | Event ID 1 |
| Windows Security | Event ID 4688 |

Important fields:

- Image
- ParentImage
- ParentCommandLine
- CommandLine
- User
- ProcessGuid

---

# Detection Logic

Generate an alert when a PowerShell process is launched by applications that do not normally require PowerShell execution.

Suspicious parent processes include:

- WINWORD.EXE
- EXCEL.EXE
- POWERPNT.EXE
- OUTLOOK.EXE
- AcroRd32.exe

---

# False Positives

Potential legitimate activity includes:

- Office automation
- Administrative macros
- Enterprise document workflows
- Software management tools
- Third-party business applications

---

# Bypass Opportunities

Attackers may evade this detection by:

- Launching cmd.exe before PowerShell
- Using explorer.exe as the parent process
- Using WMI
- Using scheduled tasks
- Hosting PowerShell inside another process

---

# Investigation Guide

When this detection triggers:

1. Identify the parent application.
2. Determine how the document was obtained.
3. Review the PowerShell command line.
4. Check for EncodedCommand usage.
5. Review network activity.
6. Identify downloaded payloads.
7. Review subsequent child processes.

---

# Related Detections

This detection commonly correlates with:

- DET-001 – PowerShell Encoded Command
- DET-002 – PowerShell Remote Content Retrieval
- DET-003 – Execution Policy Bypass
- DET-004 – PowerShell Hidden Window

---

# Future Improvements

- Process ancestry analysis
- Office macro correlation
- Email telemetry correlation
- Parent process allowlists
- Behavioral risk scoring