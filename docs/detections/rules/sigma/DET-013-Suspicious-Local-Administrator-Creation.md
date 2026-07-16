# DET-013 - Suspicious Local Administrator Creation

## Detection ID

DET-013

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

Attackers frequently create new local administrator accounts after compromising a system to establish persistence and maintain privileged access. By creating a new account and adding it to the local Administrators group, an attacker can regain access even if malware, scheduled tasks, or malicious services are removed.

Monitoring suspicious administrator account creation provides defenders with visibility into privilege escalation and persistence techniques commonly observed during post-exploitation.

---

# MITRE ATT&CK Mapping

| Tactic | Technique |
|---------|-----------|
| Persistence | T1136.001 – Create Local Account |
| Privilege Escalation | T1098 – Account Manipulation |

---

# Attack Scenario

An attacker creates a new local account:

net user backupadmin P@ssw0rd123 /add

The attacker immediately grants administrator privileges:

net localgroup administrators backupadmin /add

The account is later used for interactive logins or remote administration.

---

# Required Telemetry

| Source | Event |
|---------|-------|
| Sysmon | Event ID 1 |
| Windows Security | Event ID 4688 |
| Windows Security | Event ID 4720 |
| Windows Security | Event ID 4732 |

Important fields:

- Image
- CommandLine
- User
- ParentImage
- ProcessGuid

---

# Detection Logic

Generate an alert when a local user is created or added to the Administrators group.

Indicators include:

- net user
- /add
- net localgroup administrators
- New-LocalUser
- Add-LocalGroupMember

---

# False Positives

Potential legitimate activity includes:

- IT onboarding
- Helpdesk account provisioning
- Enterprise administration
- Temporary maintenance accounts

---

# Bypass Opportunities

Attackers may evade this detection by:

- Renaming existing accounts
- Modifying group memberships through other tools
- Using domain accounts
- Abusing Group Policy
- Using WMI or PowerShell remoting

---

# Investigation Guide

When this detection triggers:

1. Identify the creating user.
2. Review the created account name.
3. Verify whether administrator privileges were assigned.
4. Review authentication logs.
5. Determine the parent process.
6. Review previous alerts on the host.
7. Identify subsequent logons using the new account.

---

# Related Detections

- DET-001 – PowerShell Encoded Command
- DET-005 – Suspicious Parent Process
- DET-010 – WMI Remote Process Creation
- DET-011 – PsExec Remote Execution
- DET-012 – Suspicious Scheduled Task Creation

---

# Future Improvements

- Detect suspicious account names
- Business-hours correlation
- Parent process scoring
- User behavior analytics
- Authentication correlation
- Multi-host account tracking