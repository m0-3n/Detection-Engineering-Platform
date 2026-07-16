# DET-010 - WMI Remote Process Creation

## Detection ID

DET-010

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

Windows Management Instrumentation (WMI) is a legitimate Windows management framework used by administrators for system administration, monitoring, automation, and remote management. Adversaries frequently abuse WMI to execute processes remotely, allowing lateral movement and post-exploitation while blending with legitimate administrative activity.

Monitoring WMI process creation provides defenders with visibility into remote execution techniques commonly used by attackers.

---

# MITRE ATT&CK Mapping

| Tactic | Technique |
|---------|-----------|
| Lateral Movement | T1047 – Windows Management Instrumentation |
| Execution | T1059.001 – PowerShell |

---

# Attack Scenario

An attacker has obtained valid credentials on a workstation.

Instead of using PsExec or Remote Desktop, the attacker executes a remote process using WMI.

Examples:

wmic /node:192.168.1.20 process call create "powershell.exe -enc ..."

Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe"

The attacker gains remote code execution while leveraging legitimate Windows management functionality.

---

# Required Telemetry

| Source | Event |
|---------|-------|
| Sysmon | Event ID 1 |
| Windows Security | Event ID 4688 |
| WMI Activity | Event ID 5857-5861 |

Important fields:

- Image
- ParentImage
- CommandLine
- User
- ProcessGuid

---

# Detection Logic

Generate an alert when WMI is used to remotely create a process.

Indicators include:

- wmic.exe
- process call create
- powershell.exe
- cmd.exe

---

# False Positives

Potential legitimate activity includes:

- Enterprise administration
- SCCM
- Intune
- Asset management
- Monitoring software
- Remote administration

---

# Bypass Opportunities

Attackers may evade this detection by:

- Using PsExec
- Using WinRM
- Using Scheduled Tasks
- Using DCOM
- Using Remote Desktop

---

# Investigation Guide

When this detection triggers:

1. Identify the initiating user.
2. Review the target host.
3. Review the executed command.
4. Determine whether PowerShell was launched.
5. Review authentication logs.
6. Identify additional lateral movement.
7. Correlate with previous detections.

---

# Related Detections

- DET-001 – PowerShell Encoded Command
- DET-002 – PowerShell Remote Content Retrieval
- DET-005 – Suspicious Parent Process
- DET-006 – PowerShell Network Communication

---

# Future Improvements

- Authentication correlation
- Process ancestry
- WinRM correlation
- PsExec correlation
- Risk scoring
- Lateral movement graphing