# DET-003 - PowerShell Execution Policy Bypass

## Detection ID

DET-003

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

PowerShell execution policies are designed to help prevent the accidental execution of untrusted scripts. Although they are not considered a security boundary, adversaries frequently bypass these policies to ensure malicious scripts execute successfully.

Monitoring the use of execution policy bypass arguments provides visibility into attacker attempts to weaken PowerShell's built-in safeguards.

---

# MITRE ATT&CK Mapping

| Tactic | Technique |
|---------|-----------|
| Execution | T1059.001 – PowerShell |

---

# Attack Scenario

After gaining access to a system, an attacker launches PowerShell using an execution policy bypass.

Examples:

powershell.exe -ExecutionPolicy Bypass payload.ps1

powershell.exe -ep bypass payload.ps1

This allows the attacker to execute scripts even when restrictive execution policies are configured.

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

Generate an alert when a PowerShell process is started using execution policy bypass arguments.

Indicators include:

- -ExecutionPolicy
- -executionpolicy
- -ep

Combined with:

- Bypass

---

# False Positives

Potential legitimate activity includes:

- Enterprise deployment scripts
- Software installation
- Administrative automation
- Build pipelines
- IT maintenance tasks

---

# Bypass Opportunities

An attacker may evade this detection by:

- Encoding the PowerShell command
- Setting the execution policy within the script
- Hosting PowerShell through another application
- Using alternate PowerShell APIs

---

# Investigation Guide

When this detection triggers:

1. Review the full PowerShell command.
2. Determine who executed the process.
3. Identify the parent process.
4. Look for EncodedCommand usage.
5. Check for subsequent network activity.
6. Determine whether additional payloads were downloaded.
7. Review any child processes.

---

# Future Improvements

Future enhancements include:

- Correlate with EncodedCommand detections.
- Correlate with remote content retrieval.
- Parent process correlation.
- Threat intelligence enrichment.
- Risk scoring.