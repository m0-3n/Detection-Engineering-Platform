# DET-006 - PowerShell Network Communication

## Detection ID

DET-006

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

PowerShell includes multiple networking capabilities that allow communication with remote systems over HTTP and HTTPS. While these features are commonly used for administration and automation, attackers frequently abuse them to establish command-and-control communication, retrieve instructions, download payloads, or exfiltrate sensitive information.

Monitoring PowerShell network communication provides defenders with visibility into post-exploitation activity and command-and-control behavior.

---

# MITRE ATT&CK Mapping

| Tactic | Technique |
|---------|-----------|
| Command and Control | T1071.001 – Web Protocols |
| Execution | T1059.001 – PowerShell |

---

# Attack Scenario

After executing PowerShell, an attacker communicates with a remote server.

Examples include:

Invoke-WebRequest

Invoke-RestMethod

System.Net.WebClient

System.Net.Http.HttpClient

The attacker may download instructions, send stolen information, or communicate with a command-and-control server.

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

Generate an alert when PowerShell utilizes networking-related functionality commonly associated with HTTP or HTTPS communication.

Indicators include:

- Invoke-WebRequest
- Invoke-RestMethod
- Net.WebClient
- System.Net.Http.HttpClient
- WebRequest.Create

---

# False Positives

Possible legitimate activity:

- Enterprise automation
- Cloud management
- Azure administration
- Microsoft Intune
- SCCM
- Software deployment
- Monitoring tools

---

# Bypass Opportunities

Attackers may evade this detection by:

- Using curl.exe
- Using certutil.exe
- Using BITS
- Using custom .NET networking classes
- Using third-party tooling
- Obfuscating PowerShell commands

---

# Investigation Guide

When this detection triggers:

1. Review the complete command line.
2. Identify the destination URL or IP.
3. Review DNS activity.
4. Determine whether content was downloaded or uploaded.
5. Review subsequent PowerShell activity.
6. Identify child processes.
7. Correlate with additional detections.

---

# Related Detections

This detection commonly correlates with:

- DET-001 – PowerShell Encoded Command
- DET-002 – PowerShell Remote Content Retrieval
- DET-003 – Execution Policy Bypass
- DET-004 – Hidden Window
- DET-005 – Suspicious Parent Process

---

# Future Improvements

- Threat intelligence correlation
- DNS correlation
- JA3/TLS fingerprint correlation
- Process ancestry
- Beacon detection
- Risk scoring