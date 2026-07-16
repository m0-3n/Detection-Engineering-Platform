# DET-011 - PsExec Remote Execution

## Detection ID

DET-011

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

PsExec is a legitimate Microsoft Sysinternals utility that enables administrators to execute commands remotely on Windows systems. Threat actors frequently abuse PsExec after obtaining valid credentials to perform lateral movement, execute malicious payloads, and establish privileged access across an environment.

Because PsExec is widely used for legitimate administration, detections should focus on suspicious execution behavior rather than the utility itself.

---

# MITRE ATT&CK Mapping

| Tactic | Technique |
|---------|-----------|
| Lateral Movement | T1021.002 – SMB/Windows Admin Shares |
| Execution | T1569.002 – Service Execution |

---

# Attack Scenario

After obtaining administrator credentials, an attacker remotely executes PowerShell on another host.

Examples:

PsExec.exe \\SERVER powershell.exe

PsExec.exe \\DC01 cmd.exe

PsExec temporarily installs the **PSEXESVC** service on the remote system before executing the requested process.

---

# Required Telemetry

| Source | Event |
|---------|-------|
| Sysmon | Event ID 1 |
| Windows Security | Event ID 4688 |
| Windows Service Logs | Event ID 7045 |

Important fields:

- Image
- CommandLine
- ParentImage
- User
- ProcessGuid

---

# Detection Logic

Generate an alert when PsExec is used to remotely execute interactive shells or scripting engines.

Indicators include:

- PsExec.exe
- Remote target (\\)
- powershell.exe
- cmd.exe

---

# False Positives

Potential legitimate activity includes:

- Enterprise administration
- Helpdesk operations
- SCCM
- Software deployment
- IT maintenance

---

# Bypass Opportunities

Attackers may evade this detection by:

- Using WMI
- Using WinRM
- Using Scheduled Tasks
- Using Remote Desktop
- Using DCOM

---

# Investigation Guide

When this detection triggers:

1. Identify the initiating user.
2. Review the remote host.
3. Review the executed command.
4. Check for encoded PowerShell.
5. Determine whether PSEXESVC was installed.
6. Review authentication logs.
7. Correlate with additional detections.

---

# Related Detections

- DET-001 – PowerShell Encoded Command
- DET-003 – Execution Policy Bypass
- DET-004 – Hidden Window
- DET-010 – WMI Remote Process Creation

---

# Future Improvements

- Detect PSEXESVC service creation.
- Authentication correlation.
- SMB session correlation.
- Process ancestry.
- Risk scoring.