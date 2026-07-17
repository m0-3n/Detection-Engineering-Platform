# DET-014 - Microsoft Defender Tampering

## Detection ID

DET-014

## Status

Draft

## Version

1.0

## Confidence

High

## Severity

High

---

# Threat Overview

Attackers frequently attempt to disable or weaken Microsoft Defender before executing malware, dumping credentials, or establishing persistence. By impairing Defender's protection mechanisms, attackers reduce the likelihood of detection and increase the success rate of subsequent malicious activities.

This detection identifies common methods used to disable Microsoft Defender through PowerShell, Service Control Manager, and registry modifications.

---

# MITRE ATT&CK Mapping

| Tactic | Technique |
|---------|-----------|
| Defense Evasion | T1562.001 – Impair Defenses |

---

# Attack Scenario

An attacker gains initial access through PowerShell and disables Microsoft Defender before performing credential dumping or deploying ransomware.

Example commands:

Set-MpPreference -DisableRealtimeMonitoring $true

Set-MpPreference -DisableBehaviorMonitoring $true

Set-MpPreference -DisableScriptScanning $true

sc stop WinDefend

reg add HKLM\SOFTWARE\Microsoft\Windows Defender

---

# Required Telemetry

| Source | Event |
|---------|-------|
| Sysmon | Event ID 1 |
| Windows Security | Event ID 4688 |
| Microsoft Defender | Operational Logs |

Important fields:

- Image
- ParentImage
- CommandLine
- User
- ProcessGuid

---

# Detection Logic

Generate an alert when one or more of the following behaviors are observed:

- Set-MpPreference
- DisableRealtimeMonitoring
- DisableBehaviorMonitoring
- DisableScriptScanning
- DisableIOAVProtection
- sc stop WinDefend
- Registry modifications targeting Microsoft Defender

---

# False Positives

Potential legitimate activity includes:

- Enterprise software deployment
- Installation of third-party endpoint protection
- Security testing
- IT maintenance

---

# Bypass Opportunities

Attackers may evade this detection by:

- Using Defender exclusions
- Group Policy modifications
- Tamper Protection bypasses
- Direct registry manipulation
- Living-off-the-land binaries

---

# Investigation Guide

When this detection triggers:

1. Identify the executing user.
2. Determine whether Defender protection was successfully disabled.
3. Review the parent process.
4. Review previous alerts on the host.
5. Check for credential dumping attempts.
6. Review subsequent network activity.
7. Determine whether persistence mechanisms were created.

---

# Related Detections

- DET-001 – PowerShell Encoded Command
- DET-003 – PowerShell Execution Policy Bypass
- DET-005 – Suspicious Parent Process
- DET-006 – PowerShell Network Communication
- DET-012 – Suspicious Scheduled Task Creation
- DET-013 – Suspicious Local Administrator Creation

---

# Future Improvements

- Detect Defender exclusion abuse
- Correlate with credential dumping
- Registry value monitoring
- Tamper Protection bypass detection
- Business-hours correlation
- Risk scoring based on previous detections