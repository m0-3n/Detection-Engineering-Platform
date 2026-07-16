# DET-004 - PowerShell Hidden Window

## Detection ID

DET-004

## Status

Draft

## Version

1.0

## Confidence

Medium

## Severity

Medium

---

# Threat Overview

PowerShell allows processes to execute with hidden windows using the `-WindowStyle Hidden` or `-w hidden` parameters. While legitimate administrators may use this feature for background automation, attackers frequently abuse it to conceal malicious activity from users during execution.

Monitoring hidden PowerShell execution provides visibility into stealth techniques commonly used during malware execution, persistence, and post-exploitation.

---

# MITRE ATT&CK Mapping

| Tactic | Technique |
|---------|-----------|
| Defense Evasion | T1564 – Hide Artifacts |
| Execution | T1059.001 – PowerShell |

---

# Attack Scenario

An attacker launches PowerShell with a hidden window:

powershell.exe -WindowStyle Hidden

or

powershell.exe -w hidden

The PowerShell process executes without displaying a visible console window, reducing the likelihood that the user notices malicious activity.

---

# Required Telemetry

| Source | Event |
|---------|-------|
| Sysmon | Event ID 1 |
| Windows Security | Event ID 4688 |
| PowerShell Operational | Event ID 4104 |

Important fields:

- Image
- CommandLine
- ParentImage
- User
- ProcessGuid

---

# Detection Logic

Generate an alert when a PowerShell process is executed with hidden window arguments.

Indicators include:

- -WindowStyle Hidden
- -w hidden

---

# False Positives

Possible legitimate activity:

- Enterprise automation
- Silent software installation
- Administrative scripts
- Scheduled maintenance
- Login scripts

---

# Bypass Opportunities

Attackers may evade this detection by:

- Hosting PowerShell inside another process
- Executing PowerShell through .NET APIs
- Using alternate interpreters
- Obfuscating command-line arguments
- Leveraging LOLBins instead of PowerShell

---

# Investigation Guide

When this detection triggers:

1. Review the complete command line.
2. Identify the parent process.
3. Determine the user context.
4. Check for EncodedCommand usage.
5. Review network connections.
6. Inspect spawned child processes.
7. Correlate with additional detections.

---

# Related Detections

This detection commonly correlates with:

- DET-001 – PowerShell Encoded Command
- DET-002 – PowerShell Remote Content Retrieval
- DET-003 – PowerShell Execution Policy Bypass

---

# Future Improvements

- Parent process scoring
- Detection correlation engine
- Risk scoring
- Threat intelligence enrichment
- Behavioral clustering