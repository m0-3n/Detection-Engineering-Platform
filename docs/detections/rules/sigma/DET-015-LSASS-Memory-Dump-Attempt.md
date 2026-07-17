# DET-015 - LSASS Memory Dump Attempt

## Detection ID

DET-015

## Status

Draft

## Version

1.0

## Confidence

High

## Severity

Critical

---

# Threat Overview

Attackers frequently target the Local Security Authority Subsystem Service (LSASS) process to extract credentials stored in memory. Successful credential dumping enables attackers to perform Pass-the-Hash, Pass-the-Ticket, privilege escalation, lateral movement, and ultimately compromise additional systems within the environment.

LSASS dumping is one of the most common post-exploitation techniques observed in ransomware operations and advanced persistent threat (APT) campaigns.

---

# Why This Detection Matters

Credential dumping from LSASS often represents a critical turning point during an intrusion. Once credentials are extracted, attackers can authenticate as legitimate users, move laterally across systems, and compromise privileged accounts without relying on exploits.

Detecting attempts to access or dump LSASS memory provides defenders with an opportunity to interrupt an attack before stolen credentials are reused throughout the environment.

---

# MITRE ATT&CK Mapping

| Tactic | Technique |
|---------|-----------|
| Credential Access | T1003.001 – OS Credential Dumping: LSASS Memory |

---

# Attack Scenario

An attacker gains initial access to a workstation and disables Microsoft Defender before attempting to dump LSASS memory.

Common techniques include:

procdump.exe -ma lsass.exe lsass.dmp

rundll32.exe comsvcs.dll MiniDump

Mimikatz

NanoDump

Task Manager "Create Dump File"

The extracted credentials are later used for lateral movement through PsExec, SMB, WinRM, or Remote Desktop.

---

# Required Telemetry

| Source | Event |
|---------|-------|
| Sysmon | Event ID 1 |
| Windows Security | Event ID 4688 |
| Sysmon | Event ID 11 (File Create) |
| Microsoft Defender | Operational Logs |

Important fields:

- Image
- ParentImage
- CommandLine
- ProcessGuid
- TargetFilename
- User

---

# Detection Logic

Generate an alert when one or more LSASS dumping techniques are observed.

Indicators include:

- procdump.exe with -ma targeting lsass
- rundll32.exe loading comsvcs.dll with MiniDump
- Known Mimikatz execution patterns
- NanoDump execution
- Creation of lsass.dmp

---

# False Positives

Potential legitimate activity includes:

- Incident response
- Digital forensics
- Memory acquisition by security teams
- Authorized troubleshooting

---

# Bypass Opportunities

Attackers may evade this detection by:

- Direct system calls
- Custom dump utilities
- Handle duplication
- Protected Process Light (PPL) bypasses
- Kernel-mode tooling

---

# Investigation Guide

When this detection triggers:

1. Identify the executing process.
2. Determine which dumping technique was used.
3. Verify whether an LSASS dump file was created.
4. Review parent process activity.
5. Review previous detections on the host.
6. Identify subsequent authentication attempts.
7. Review lateral movement activity.
8. Isolate the affected endpoint if malicious activity is confirmed.

---

# Related Detections

- DET-001 – PowerShell Encoded Command
- DET-005 – Suspicious Parent Process
- DET-006 – PowerShell Network Communication
- DET-008 – Rundll32 Suspicious DLL Execution
- DET-011 – PsExec Remote Execution
- DET-014 – Microsoft Defender Tampering

---

# Future Improvements

- Process access (Sysmon Event ID 10) correlation
- LSASS handle access monitoring
- ETW-based detection
- Cross-host credential reuse correlation
- Risk scoring using previous detections
- Sigma correlation rules (Version 2)