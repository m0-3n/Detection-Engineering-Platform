# DET-008 - Rundll32 Suspicious DLL Execution

## Detection ID

DET-008

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

Rundll32.exe is a legitimate Windows utility used to execute exported functions from Dynamic Link Library (DLL) files. Because it is a trusted Microsoft-signed binary, attackers frequently abuse it to execute malicious DLLs or scripts while blending into normal system activity.

Monitoring suspicious Rundll32 execution provides visibility into Living-off-the-Land Binary (LOLBin) abuse commonly observed during malware execution and post-exploitation.

---

# MITRE ATT&CK Mapping

| Tactic | Technique |
|---------|-----------|
| Defense Evasion | T1218.011 – Rundll32 |
| Execution | T1059 – Command and Scripting Interpreter |

---

# Attack Scenario

An attacker downloads a malicious DLL and executes it using Rundll32.

Examples:

rundll32.exe malware.dll,EntryPoint

rundll32.exe javascript:"\..\mshtml,RunHTMLApplication"

The trusted Windows binary executes attacker-controlled code while reducing suspicion.

---

# Required Telemetry

| Source | Event |
|---------|-------|
| Sysmon | Event ID 1 |
| Windows Security | Event ID 4688 |

Important fields:

- Image
- ParentImage
- CommandLine
- ParentCommandLine
- User
- ProcessGuid

---

# Detection Logic

Generate an alert when Rundll32 executes suspicious script-based arguments.

Indicators include:

- javascript:
- mshtml

Future enhancements may include detecting DLL execution from user-writable directories.

---

# False Positives

Potential legitimate activity includes:

- Windows Control Panel applets
- Graphics driver utilities
- Printer management software
- Vendor configuration tools

---

# Bypass Opportunities

Attackers may evade this detection by:

- Executing DLLs without script-based arguments
- Using Regsvr32
- Using Mshta
- Using custom loaders
- Reflective DLL loading

---

# Investigation Guide

When this detection triggers:

1. Review the complete command line.
2. Identify the executed DLL.
3. Determine the DLL location.
4. Review the parent process.
5. Check for downloaded payloads.
6. Identify child processes.
7. Correlate with previous detections.

---

# Related Detections

- DET-005 – Suspicious Parent Process
- DET-007 – Certutil Remote Download

---

# Future Improvements

- Detect DLL execution from user profile directories
- Process ancestry analysis
- Threat intelligence enrichment
- DLL reputation lookup
- Correlation with LOLBins